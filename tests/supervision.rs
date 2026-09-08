//! Adversarial transport regressions use bounded test reads/waits so a broken
//! watchdog fails the test rather than hanging the qualification job itself.
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Runner {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
}
impl Runner {
    fn new(source: &str, wall_ms: u64) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ruby-engine"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let fd = output.as_raw_fd();
        unsafe {
            assert_eq!(libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK), 0);
        }
        let mut run = Self {
            child,
            input: Some(input),
            output,
        };
        run.send(&json!({"protocol": "ruby-local-v1", "profile": "opencompany-code-v1",
            "execution_id": "supervision-test", "source": source, "catalog": ["records.list"],
            "limits": {"memory_bytes": 33554432, "instructions": 100000000, "wall_ms": wall_ms,
                "cpu_ms": 1000, "source_bytes": 262144, "result_bytes": 1048576, "calls": 50, "log_bytes": 1048576}}));
        run
    }
    fn send(&mut self, value: &Value) {
        let bytes = serde_json::to_vec(value).unwrap();
        let input = self.input.as_mut().unwrap();
        input
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        input.write_all(&bytes).unwrap();
    }
    fn bytes(&mut self, count: usize) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut bytes = vec![0; count];
        let mut offset = 0;
        while offset < count {
            assert!(Instant::now() < deadline, "engine response hung");
            match self.output.read(&mut bytes[offset..]) {
                Ok(0) => panic!("engine response truncated"),
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(e) => panic!("{e}"),
            }
        }
        bytes
    }
    fn event(&mut self) -> Value {
        let size = u32::from_be_bytes(self.bytes(4).try_into().unwrap()) as usize;
        assert!(size <= 8 * 1024 * 1024);
        serde_json::from_slice(&self.bytes(size)).unwrap()
    }
    fn exited(&mut self, within: Duration) {
        let deadline = Instant::now() + within;
        while self.child.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "supervisor failed to exit promptly"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Runner {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn partial_host_reply_cannot_suspend_deadline() {
    let mut run = Runner::new("app.records.list", 200);
    assert_eq!(run.event()["kind"], "call");
    run.input.as_mut().unwrap().write_all(&[0, 0]).unwrap();
    assert_eq!(run.event()["error"]["type"], "wall_timeout");
    run.exited(Duration::from_secs(1));
}

#[test]
fn stopped_output_reader_cannot_suspend_deadline() {
    let mut run = Runner::new("puts('x' * 900000); 42", 200);
    // Leave stdout unread: one log exceeds either platform's pipe capacity.
    run.exited(Duration::from_secs(2));
}

#[test]
fn host_eof_cancels_waiting_callback_without_waiting_for_wall_budget() {
    let mut run = Runner::new("app.records.list", 30000);
    assert_eq!(run.event()["kind"], "call");
    drop(run.input.take());
    run.exited(Duration::from_secs(1));
}

#[test]
fn cancellation_requires_the_current_execution_identity() {
    for execution in ["supervision-test", "some-other-run"] {
        let mut run = Runner::new("app.records.list", 30000);
        assert_eq!(run.event()["kind"], "call");
        run.send(
            &json!({"protocol": "ruby-local-v1", "execution_id": execution, "kind": "cancel"}),
        );
        let event = run.event();
        let message = event["error"]["message"].as_str().unwrap();
        assert!(message.contains(if execution == "supervision-test" {
            "cancelled"
        } else {
            "identity mismatch"
        }));
        run.exited(Duration::from_secs(1));
    }
}

#[test]
fn callback_wait_does_not_consume_guest_cpu_budget() {
    let mut run = Runner::new("app.records.list", 5000);
    let call = run.event();
    thread::sleep(Duration::from_millis(1100));
    run.send(
        &json!({"protocol": "ruby-local-v1", "execution_id": "supervision-test", "kind": "reply",
        "sequence": call["sequence"], "ok": true, "value": 42}),
    );
    let result = run.event();
    assert_eq!(result["result"], 42, "{result}");
    run.exited(Duration::from_secs(1));
}

#[test]
fn repeated_invocations_exit_even_while_host_keeps_stdin_open() {
    for _ in 0..100 {
        let mut run = Runner::new("{answer: 42}", 5000);
        assert_eq!(run.event()["result"], json!({"answer": 42}));
        run.exited(Duration::from_secs(1));
    }
}

#[test]
fn abrupt_supervisor_loss_terminates_the_guest() {
    let mut run = Runner::new("app.records.list", 30000);
    assert_eq!(run.event()["kind"], "call");
    #[cfg(target_os = "linux")]
    let guest: i32 =
        std::fs::read_to_string(format!("/proc/{0}/task/{0}/children", run.child.id()))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
    #[cfg(target_os = "macos")]
    let guest = {
        let mut children = [0_i32; 8];
        let count = unsafe {
            libc::proc_listchildpids(
                run.child.id() as _,
                children.as_mut_ptr().cast(),
                std::mem::size_of_val(&children) as _,
            )
        };
        assert!(count > 0 && children[0] > 1);
        children[0]
    };
    run.child.kill().unwrap();
    run.child.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        #[cfg(target_os = "linux")]
        let alive = std::fs::read_to_string(format!("/proc/{guest}/status")).is_ok_and(|status| {
            !status
                .lines()
                .any(|line| line.starts_with("State:") && line.contains('Z'))
        });
        #[cfg(target_os = "macos")]
        let alive = {
            let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of_val(&info) as i32;
            let count = unsafe {
                libc::proc_pidinfo(
                    guest,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    (&mut info as *mut libc::proc_bsdinfo).cast(),
                    size,
                )
            };
            // Darwin sys/proc.h: SZOMB=5. Reaping belongs to the new parent;
            // this assertion checks termination, not PID-table disappearance.
            count == size && info.pbi_status != 5
        };
        if !alive {
            break;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(guest, libc::SIGKILL);
            }
            panic!("orphan guest survived supervisor loss");
        }
        thread::sleep(Duration::from_millis(1));
    }
}
