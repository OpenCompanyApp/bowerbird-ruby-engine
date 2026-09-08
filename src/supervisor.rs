//! Owns one guest and its deadline. Host effects are not owned by this process;
//! termination cannot roll back or prove non-delivery of a dispatched mutation.
use crate::{
    failure, isolation,
    protocol::{Request, PROTOCOL},
    transport::{self, Reader, Writer},
};
use serde_json::Value;
use std::{
    io,
    os::{fd::AsRawFd, unix::process::ExitStatusExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn initial_request() -> Result<Value, String> {
    transport::nonblocking(0).map_err(|e| e.to_string())?;
    transport::nonblocking(1).map_err(|e| e.to_string())?;
    let mut reader = Reader::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(value) = reader.receive(0).map_err(|e| e.to_string())? {
            return Ok(value);
        }
        transport::poll(&[(0, libc::POLLIN)]).map_err(|e| e.to_string())?;
    }
    Err("Initial request deadline exceeded".into())
}

pub fn run(request: Request) -> Result<(), String> {
    request.validate()?;
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg("--guest")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let parent = unsafe { libc::getpid() };
        // Install before exec, checking the race where the supervisor dies
        // between fork and prctl. The kernel kills a guest on supervisor loss.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(io::Error::other("Supervisor already exited"));
                }
                Ok(())
            });
        }
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    let outcome = (|| -> io::Result<()> {
        transport::nonblocking(input.as_raw_fd())?;
        transport::nonblocking(output.as_raw_fd())?;
        let deadline = Instant::now() + Duration::from_millis(request.limits.wall_ms);
        let mut host = Reader::default();
        let mut guest = Reader::default();
        let mut to_guest = Writer::default();
        let mut to_host = Writer::default();
        to_guest.enqueue(&serde_json::to_value(&request)?)?;
        let mut completed = false;
        let mut guest_closed = false;
        let mut pending_sequence = None;
        let mut sequence = 0_u64;
        loop {
            // Never wait on guest exit or host I/O ahead of this watchdog.
            if Instant::now() >= deadline {
                let _ = child.kill();
                // Do not append a diagnostic behind a partially delivered frame.
                // Close instead: a stopped reader cannot receive a safe result.
                if !to_host.pending() {
                    to_host.enqueue(&failure(&request.execution_id, "wall_timeout",
                        "Execution deadline exceeded; dispatched host effects may already have occurred"))?;
                    to_host.send(1)?;
                }
                return Ok(());
            }
            if !completed
                && isolation::resident_bytes(child.id()).is_some_and(|n| n > 256 * 1024 * 1024)
            {
                let _ = child.kill();
                if !to_host.pending() {
                    to_host.enqueue(&failure(
                        &request.execution_id,
                        "memory_limit",
                        "Guest process memory ceiling exceeded",
                    ))?;
                    completed = true;
                } else {
                    return Err(io::Error::other(
                        "Guest memory ceiling exceeded during output",
                    ));
                }
            }
            // Host input is consumed even during output backpressure so closing
            // stdin cancels promptly. Unsolicited or pipelined replies are invalid.
            if let Some(reply) = host.receive(0)? {
                if reply["protocol"] != PROTOCOL || reply["execution_id"] != request.execution_id {
                    return Err(io::Error::other("Host identity mismatch"));
                }
                if reply["kind"] == "cancel" {
                    return Err(io::Error::other(
                        "Execution cancelled; inspect dispatched effects",
                    ));
                }
                if reply["kind"] != "reply"
                    || pending_sequence.is_none()
                    || reply["sequence"].as_u64() != pending_sequence.take()
                {
                    return Err(io::Error::other("Unexpected host reply"));
                }
                to_guest.enqueue(&reply)?;
            }
            to_guest.send(input.as_raw_fd())?;
            to_host.send(1)?;
            if completed && !to_host.pending() {
                return Ok(());
            }
            if !completed && !to_host.pending() && !guest_closed {
                match guest.receive(output.as_raw_fd()) {
                    Ok(Some(event)) => {
                        if event["protocol"] != PROTOCOL
                            || event["execution_id"] != request.execution_id
                        {
                            return Err(io::Error::other("Guest identity mismatch"));
                        }
                        match event["kind"].as_str() {
                            Some("completed") => completed = true,
                            Some("log") => (),
                            Some("call") => {
                                sequence += 1;
                                if request.validate_only
                                    || pending_sequence.is_some()
                                    || event["sequence"].as_u64() != Some(sequence)
                                    || sequence > request.limits.calls as u64
                                    || !event["path"].as_str().is_some_and(|path| {
                                        request.catalog.iter().any(|allowed| allowed == path)
                                    })
                                {
                                    return Err(io::Error::other(
                                        "Invalid guest capability request",
                                    ));
                                }
                                pending_sequence = Some(sequence);
                            }
                            _ => return Err(io::Error::other("Unknown guest event")),
                        }
                        to_host.enqueue(&event)?;
                    }
                    Ok(None) => (),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => guest_closed = true,
                    Err(e) => return Err(e),
                }
            }
            if guest_closed && !completed {
                if let Some(status) = child.try_wait()? {
                    let (kind, message) = match status.code() {
                        Some(124) => ("instruction_limit", "Ruby instruction budget exceeded"),
                        Some(125) => ("memory_limit", "Ruby allocation budget exceeded"),
                        _ if status.signal() == Some(libc::SIGPROF) || status.signal() == Some(libc::SIGXCPU) => ("cpu_limit", "Ruby CPU budget exceeded"),
                        _ if status.signal() == Some(libc::SIGALRM) => ("wall_timeout", "Ruby wall deadline exceeded; inspect dispatched effects before retrying"),
                        _ => ("guest_terminated", "Guest terminated without a result; inspect dispatched effects before retrying"),
                    };
                    to_host.enqueue(&failure(&request.execution_id, kind, message))?;
                    completed = true;
                }
            }
            let mut fds = vec![(0, libc::POLLIN)];
            if to_guest.pending() {
                fds.push((input.as_raw_fd(), libc::POLLOUT));
            }
            if to_host.pending() {
                fds.push((1, libc::POLLOUT));
            }
            if !completed && !guest_closed && !to_host.pending() {
                fds.push((output.as_raw_fd(), libc::POLLIN));
            }
            transport::poll(&fds)?;
        }
    })();
    // Reap after sending SIGKILL, on every return path. No protocol reader
    // threads retain descriptors or global stdio locks after completion.
    let _ = child.kill();
    let _ = child.wait();
    outcome.map_err(|e| e.to_string())
}
