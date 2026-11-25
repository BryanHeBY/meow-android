//! Bounded packet queues keep transient TUN backpressure from consuming the VPN heap.
use std::{
    io,
    os::fd::RawFd,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
        Arc,
    },
    time::Instant,
};
use tokio::{
    io::unix::AsyncFd,
    sync::{mpsc, OwnedSemaphorePermit, Semaphore},
};

#[derive(Default)]
pub(super) struct Stats {
    current: AtomicUsize,
    high_water: AtomicUsize,
    slot_drops: AtomicU64,
    budget_drops: AtomicU64,
    would_block: AtomicU64,
    wait_micros: AtomicU64,
    write_errors: AtomicU64,
}

impl Stats {
    pub(super) fn summary(&self) -> String {
        format!(
            "high_water_bytes={} slot_drops={} budget_drops={} stale_writable={} write_us={} write_errors={}",
            self.high_water.load(Relaxed),
            self.slot_drops.load(Relaxed),
            self.budget_drops.load(Relaxed),
            self.would_block.load(Relaxed),
            self.wait_micros.load(Relaxed),
            self.write_errors.load(Relaxed),
        )
    }
}

#[derive(Clone)]
pub(crate) struct Tx {
    tx: mpsc::Sender<Packet>,
    budget: Arc<Semaphore>,
    stats: Arc<Stats>,
}

pub(super) struct Packet {
    data: Vec<u8>,
    bytes: usize,
    stats: Arc<Stats>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for Packet {
    fn drop(&mut self) {
        self.stats.current.fetch_sub(self.bytes, Relaxed);
    }
}

pub(super) fn channel(slots: usize, bytes: usize) -> (Tx, mpsc::Receiver<Packet>, Arc<Stats>) {
    let (tx, rx) = mpsc::channel(slots);
    let stats = Arc::new(Stats::default());
    (
        Tx {
            tx,
            budget: Arc::new(Semaphore::new(bytes)),
            stats: stats.clone(),
        },
        rx,
        stats,
    )
}

impl Tx {
    /// Drop the newest packet on overflow; waiting here could deadlock the
    /// lwIP pump or stall the ZeroTier SDK owner thread.
    pub(crate) fn enqueue(&self, data: Vec<u8>) {
        let bytes = data.capacity();
        let Ok(slot) = self.tx.try_reserve() else {
            if !self.tx.is_closed() {
                self.stats.slot_drops.fetch_add(1, Relaxed);
            }
            return;
        };
        let Some(permit) = u32::try_from(bytes)
            .ok()
            .and_then(|n| self.budget.clone().try_acquire_many_owned(n).ok())
        else {
            self.stats.budget_drops.fetch_add(1, Relaxed);
            return;
        };
        let used = self.stats.current.fetch_add(bytes, Relaxed) + bytes;
        self.stats.high_water.fetch_max(used, Relaxed);
        slot.send(Packet {
            data,
            bytes,
            stats: self.stats.clone(),
            _permit: permit,
        });
    }
}

pub(super) async fn write(tun: &AsyncFd<RawFd>, packet: Packet) -> io::Result<()> {
    let start = Instant::now();
    let result = loop {
        let mut ready = match tun.writable().await {
            Ok(ready) => ready,
            Err(error) => break Err(error),
        };
        let result = ready.try_io(|fd| {
            let written = unsafe {
                libc::write(
                    *fd.get_ref(),
                    packet.data.as_ptr().cast(),
                    packet.data.len(),
                )
            };
            if written < 0 {
                return Err(io::Error::last_os_error());
            }
            if written as usize != packet.data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short TUN packet write",
                ));
            }
            Ok(())
        });
        match result {
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
            Ok(result) => break result,
            Err(_) => {
                packet.stats.would_block.fetch_add(1, Relaxed);
            }
        }
    };
    packet
        .stats
        .wait_micros
        .fetch_add(start.elapsed().as_micros() as u64, Relaxed);
    if result.is_err() {
        packet.stats.write_errors.fetch_add(1, Relaxed);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::{fd::AsRawFd, unix::net::UnixDatagram},
        time::Duration,
    };
    use tokio::io::Interest;

    #[test]
    fn charges_capacity_and_keeps_in_flight_packet_inside_budget() {
        let (tx, mut rx, stats) = channel(2, 128);
        let mut packet = Vec::with_capacity(128);
        packet.push(1);
        tx.enqueue(packet);
        let packet = rx.try_recv().unwrap();
        tx.enqueue(vec![2]);
        assert!(rx.try_recv().is_err());
        assert_eq!(stats.high_water.load(Relaxed), 128);
        assert_eq!(stats.budget_drops.load(Relaxed), 1);
        drop(packet);
        tx.enqueue(vec![3]);
        assert_eq!(rx.try_recv().unwrap().data, [3]);
    }

    #[test]
    fn slot_overflow_drops_newest() {
        let (tx, mut rx, stats) = channel(1, 128);
        tx.enqueue(vec![1]);
        tx.enqueue(vec![2]);
        assert_eq!(rx.try_recv().unwrap().data, [1]);
        assert!(rx.try_recv().is_err());
        assert_eq!(stats.slot_drops.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn cancelling_a_stalled_write_releases_its_budget() {
        let (sender, _receiver) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        while sender.send(&[0; 1024]).is_ok() {}
        // The sender stays alive until after deregistration of fd.
        let fd = unsafe { AsyncFd::register_with_interest(sender.as_raw_fd(), Interest::WRITABLE) }
            .unwrap();
        let (tx, mut rx, stats) = channel(2, 128);
        tx.enqueue(vec![0; 128]);
        let mut pending = Box::pin(write(&fd, rx.try_recv().unwrap()));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut pending)
                .await
                .is_err()
        );
        drop(pending);
        assert_eq!(stats.current.load(Relaxed), 0);
        tx.enqueue(vec![1]);
        assert_eq!(rx.try_recv().unwrap().data, [1]);
    }

    #[tokio::test]
    async fn full_socket_waits_until_writable_and_keeps_whole_packet() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        // First drain the cached reactor readiness into EAGAIN.
        // The sender stays alive until after deregistration of fd.
        let fd = unsafe { AsyncFd::register_with_interest(sender.as_raw_fd(), Interest::WRITABLE) }
            .unwrap();
        drop(fd.writable().await.unwrap());
        while sender.send(&[0; 1024]).is_ok() {}
        let (tx, mut rx, stats) = channel(2, 128);
        tx.enqueue(vec![42]);
        let mut pending = Box::pin(write(&fd, rx.try_recv().unwrap()));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut pending)
                .await
                .is_err()
        );
        let mut data = [0; 1024];
        while receiver.recv(&mut data).is_ok() {}
        tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receiver.recv(&mut data).unwrap(), 1);
        assert_eq!(data[0], 42);
        assert_eq!(stats.current.load(Relaxed), 0);
    }
}
