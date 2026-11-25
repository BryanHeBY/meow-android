//! Wakes the worker for queued TUN packets or shutdown, without polling idle.
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    time::Duration,
};

pub(super) struct Wake(OwnedFd);

impl Wake {
    pub(super) fn new() -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: eventfd returned a newly owned descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    pub(super) fn signal(&self) {
        let bytes = 1u64.to_ne_bytes();
        loop {
            // SAFETY: bytes is valid for exactly one eventfd write.
            if unsafe { libc::write(self.0.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) } >= 0 {
                return;
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                // A full counter is already readable. Other errors cannot
                // occur while this owned nonblocking eventfd is live.
                return;
            }
        }
    }

    pub(super) fn clear(&self) -> io::Result<()> {
        let mut bytes = [0u8; 8];
        loop {
            // SAFETY: bytes is valid for exactly one eventfd read.
            if unsafe { libc::read(self.0.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) }
                >= 0
            {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => return Ok(()),
                io::ErrorKind::Interrupted => continue,
                _ => return Err(error),
            }
        }
    }

    pub(super) fn wait(&self, sockets: [RawFd; 2], delay: Duration) -> io::Result<()> {
        let mut fds = [self.0.as_raw_fd(), sockets[0], sockets[1]].map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
        let timeout = delay.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
        // SAFETY: the poll array is writable and socket lifetime is owned
        // by the caller for the duration. Negative fds are ignored.
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        } else if fds.iter().any(|fd| fd.revents & libc::POLLNVAL != 0) {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::UdpSocket, time::Instant};

    #[test]
    fn idle_waits_for_deadline_and_signal_is_coalesced() {
        let wake = Wake::new().unwrap();
        let budget = Duration::from_millis(30);
        let started = Instant::now();
        wake.wait([-1, -1], budget).unwrap();
        assert!(started.elapsed() >= budget);
        wake.signal();
        wake.signal();
        let mut readable = libc::pollfd {
            fd: wake.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut readable, 1, 0) }, 1);
        wake.clear().unwrap();
        assert_eq!(unsafe { libc::poll(&mut readable, 1, 0) }, 0);
    }

    #[test]
    fn ready_udp_socket_wakes_without_a_tun_signal() {
        let wake = Wake::new().unwrap();
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"zt", rx.local_addr().unwrap()).unwrap();
        let started = Instant::now();
        wake.wait([rx.as_raw_fd(), -1], Duration::from_secs(2))
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
