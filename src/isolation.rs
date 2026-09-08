//! Fail-closed OS policy for the disposable guest, applied before mruby exists.
use std::io;

/// Operator/CI probe of OS enforcement, independent of Ruby's method allowlist.
/// Targets are fixed, non-mutating and contain no application credentials.
pub fn probe(capability: &str) -> io::Result<bool> {
    enter(1000, 1000)?;
    let denied = |error: io::Error| error.kind() == io::ErrorKind::PermissionDenied;
    Ok(match capability {
        "file" => std::fs::read("/etc/hosts").err().is_some_and(denied),
        "network" => std::net::TcpStream::connect("127.0.0.1:9")
            .err()
            .is_some_and(denied),
        "process" => match std::process::Command::new("/usr/bin/true").status() {
            // Linux seccomp rejects the spawn with EPERM. macOS Seatbelt can
            // instead create the child and deny its exec, which is observable
            // as a non-success status. `/usr/bin/true` has one success result,
            // so either form reports that this fixed executable did not run
            // successfully. This is a smoke probe, not a complete exec audit.
            Ok(status) => !status.success(),
            Err(error) => denied(error),
        },
        _ => false,
    })
}

pub fn enter(wall_ms: u64, cpu_ms: u64) -> io::Result<()> {
    unsafe {
        // Kernel wall timer survives supervisor loss and covers blocked host
        // callbacks and long native operations, not just interpreter dispatch.
        unsafe extern "C" {
            fn setitimer(
                which: libc::c_int,
                new: *const libc::itimerval,
                old: *mut libc::itimerval,
            ) -> libc::c_int;
        }
        let timer = libc::itimerval {
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: libc::timeval {
                tv_sec: (wall_ms / 1000) as _,
                tv_usec: ((wall_ms % 1000) * 1000) as _,
            },
        };
        libc::signal(libc::SIGALRM, libc::SIG_DFL);
        if setitimer(libc::ITIMER_REAL, &timer, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        // CPU time is independent of host/network wait time. ITIMER_PROF covers
        // native compiler, VM, JSON and allocation work, including kernel time.
        let cpu_timer = libc::itimerval {
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: libc::timeval {
                tv_sec: (cpu_ms / 1000) as _,
                tv_usec: ((cpu_ms % 1000) * 1000) as _,
            },
        };
        libc::signal(libc::SIGPROF, libc::SIG_DFL);
        if setitimer(libc::ITIMER_PROF, &cpu_timer, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let cpu = libc::rlimit {
            rlim_cur: cpu_ms.div_ceil(1000) + 1,
            rlim_max: cpu_ms.div_ceil(1000) + 1,
        };
        if libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0 {
            return Err(io::Error::last_os_error());
        }
        let core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
            return Err(io::Error::last_os_error());
        }
        close_ambient_descriptors()?;
    }
    watch_parent()?;
    platform()
}

/// macOS has no PR_SET_PDEATHSIG. Register a kernel watch on this invocation's
/// supervisor before applying Seatbelt, then let a Rust-only watcher terminate
/// the process if that parent disappears. It never enters mruby or touches its
/// allocator. Only this private kqueue survives the ambient-descriptor close.
#[cfg(target_os = "macos")]
fn watch_parent() -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err(io::Error::other("Guest has no owning supervisor"));
    }
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let queue = unsafe { OwnedFd::from_raw_fd(raw) };
    let change = libc::kevent {
        ident: parent as _,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    if unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            &change,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != parent {
        return Err(io::Error::other("Supervisor exited during guest startup"));
    }
    std::thread::Builder::new()
        .name("parent-watch".into())
        .spawn(move || {
            loop {
                let mut event: libc::kevent = unsafe { std::mem::zeroed() };
                let count = unsafe {
                    libc::kevent(
                        queue.as_raw_fd(),
                        std::ptr::null(),
                        0,
                        &mut event,
                        1,
                        std::ptr::null(),
                    )
                };
                if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // Parent death and watcher failure both terminate fail-closed.
                unsafe {
                    libc::_exit(126);
                }
            }
        })?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn watch_parent() -> io::Result<()> {
    Ok(())
}

/// Close actual inherited handles before applying the filesystem policy. This
/// guest is single-threaded, so no concurrent opener can race enumeration. A
/// failure aborts startup; scanning a million nonexistent descriptor numbers
/// needlessly consumed much of the CPU budget on high-ulimit developer hosts.
fn close_ambient_descriptors() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } == 0 {
            return Ok(());
        }
    }
    #[cfg(target_os = "macos")]
    let directory = "/dev/fd";
    #[cfg(not(target_os = "macos"))]
    let directory = "/proc/self/fd";
    let descriptors: Vec<i32> = std::fs::read_dir(directory)?
        .map(|entry| {
            entry?
                .file_name()
                .to_string_lossy()
                .parse::<i32>()
                .map_err(|_| io::Error::other("Invalid process descriptor listing"))
        })
        .collect::<io::Result<_>>()?;
    // The directory iterator has closed its own handle before these closes.
    for fd in descriptors.into_iter().filter(|fd| *fd >= 3) {
        unsafe {
            libc::close(fd);
        }
    }
    Ok(())
}

/// Measured process CPU time, not wall duration or a fabricated zero metric.
pub fn cpu_milliseconds() -> Option<f64> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return None;
    }
    Some(
        (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as f64 * 1000.0
            + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1000.0,
    )
}

#[cfg(target_os = "macos")]
pub fn resident_bytes(pid: u32) -> Option<u64> {
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as i32;
    let read = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            size,
        )
    };
    (read == size).then_some(info.pti_resident_size)
}

#[cfg(not(target_os = "macos"))]
pub fn resident_bytes(_pid: u32) -> Option<u64> {
    None
} // Linux also has RLIMIT_AS.

#[cfg(target_os = "macos")]
fn platform() -> io::Result<()> {
    use std::ffi::CString;
    unsafe extern "C" {
        fn sandbox_init(
            profile: *const libc::c_char,
            flags: u64,
            error: *mut *mut libc::c_char,
        ) -> i32;
        fn sandbox_free_error(error: *mut libc::c_char);
    }
    // The process is already loaded. No filesystem path, socket, subprocess or
    // Mach service is granted. Existing protocol pipes are the sole I/O channel.
    // Deny-default alone is not sufficient evidence that current Seatbelt
    // profiles will reject fork/exec on every macOS runner. Keep these
    // operation-level denials explicit so the containment probe covers the
    // policy we actually require, rather than an undocumented default.
    let policy = CString::new(
        "(version 1)(deny default)(deny process-fork)(deny process-exec)(allow signal (target self))(allow sysctl-read)",
    )
    .unwrap();
    let mut error = std::ptr::null_mut();
    let status = unsafe { sandbox_init(policy.as_ptr(), 0, &mut error) };
    if status != 0 {
        if !error.is_null() {
            unsafe { sandbox_free_error(error) };
        }
        return Err(io::Error::other("macOS guest containment is unavailable"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform() -> io::Result<()> {
    // Reject foreign syscall architectures before checking syscall numbers.
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    let allow = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_mremap,
        libc::SYS_clock_gettime,
        libc::SYS_getrusage,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_futex,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_tgkill,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_sched_yield,
    ];
    let stmt = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k, jt, jf| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    let mut filter = vec![
        stmt(0x20, 4),
        jump(ARCH, 1, 0),
        stmt(0x06, 0x80000000),
        stmt(0x20, 0),
    ];
    for syscall in allow {
        filter.push(jump(syscall as u32, 0, 1));
        filter.push(stmt(0x06, 0x7fff0000));
    }
    filter.push(stmt(0x06, 0x80000000));
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    unsafe {
        let memory = libc::rlimit {
            rlim_cur: 256 * 1024 * 1024,
            rlim_max: 256 * 1024 * 1024,
        };
        if libc::setrlimit(libc::RLIMIT_AS, &memory) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_SECCOMP, 2, &program) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform() -> io::Result<()> {
    Err(io::Error::other("Unsupported guest containment platform"))
}
