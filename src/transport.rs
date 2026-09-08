//! Single-owner, bounded nonblocking pipes for the supervisor. Neither an
//! incomplete frame nor a peer that stops reading may suspend its watchdog.
use crate::protocol::{write_frame, MAX_FRAME};
use serde_json::Value;
use std::io;
use std::os::fd::RawFd;

pub fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Default)]
pub struct Reader {
    bytes: Vec<u8>,
}

impl Reader {
    /// Read at most one bounded chunk. Never read ahead into the next frame:
    /// this keeps ownership explicit across initial admission and supervision.
    pub fn receive(&mut self, fd: RawFd) -> io::Result<Option<Value>> {
        let target = if self.bytes.len() < 4 {
            4
        } else {
            let length = u32::from_be_bytes(self.bytes[..4].try_into().unwrap()) as usize;
            if length == 0 || length > MAX_FRAME {
                return Err(io::Error::other("Frame size limit"));
            }
            length + 4
        };
        let mut chunk = [0_u8; 65536];
        let count = (target - self.bytes.len()).min(chunk.len());
        let read = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), count) };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Peer disconnected",
            ));
        }
        if read < 0 {
            let error = io::Error::last_os_error();
            return match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
                _ => Err(error),
            };
        }
        self.bytes.extend_from_slice(&chunk[..read as usize]);
        if target > 4 && self.bytes.len() == target {
            let value = serde_json::from_slice(&self.bytes[4..])?;
            self.bytes.clear();
            return Ok(Some(value));
        }
        Ok(None)
    }
}

#[derive(Default)]
pub struct Writer {
    bytes: Vec<u8>,
    offset: usize,
}

impl Writer {
    pub fn pending(&self) -> bool {
        self.offset < self.bytes.len()
    }

    /// A producer must wait for the previous frame to drain. This is deliberate
    /// backpressure, not an unbounded queue of guest-controlled log events.
    pub fn enqueue(&mut self, value: &Value) -> io::Result<()> {
        if self.pending() {
            return Err(io::Error::other("Protocol producer exceeded backpressure"));
        }
        self.bytes.clear();
        self.offset = 0;
        write_frame(&mut self.bytes, value)
    }

    pub fn send(&mut self, fd: RawFd) -> io::Result<()> {
        if !self.pending() {
            return Ok(());
        }
        let remaining = &self.bytes[self.offset..];
        let sent =
            unsafe { libc::write(fd, remaining.as_ptr().cast(), remaining.len().min(65536)) };
        if sent < 0 {
            let error = io::Error::last_os_error();
            return match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(()),
                _ => Err(error),
            };
        }
        if sent == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Peer stopped accepting data",
            ));
        }
        self.offset += sent as usize;
        Ok(())
    }
}

/// Wait for useful work, but return at least every five milliseconds to run the
/// independent deadline/RSS watchdog. POLLHUP/POLLERR are observed on the next
/// nonblocking read/write; they cannot strand a detached reader thread.
pub fn poll(descriptors: &[(RawFd, i16)]) -> io::Result<()> {
    let mut fds: Vec<libc::pollfd> = descriptors
        .iter()
        .map(|&(fd, events)| libc::pollfd {
            fd,
            events,
            revents: 0,
        })
        .collect();
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 5) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}
