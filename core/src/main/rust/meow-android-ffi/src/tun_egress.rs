//! Bounded packet queues keep transient TUN backpressure from consuming the VPN heap.
use std::{
    io,
    os::fd::AsRawFd,
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

/// Serializes the enable/disable boundary against the nonblocking write
/// syscall, and cancels a stalled or queued packet from the old generation.
#[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
pub(super) struct Gate(parking_lot::Mutex<Option<tokio_util::sync::CancellationToken>>);

#[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
impl Gate {
    pub(super) fn new(enabled: bool) -> Arc<Self> {
        Arc::new(Self(parking_lot::Mutex::new(
            enabled.then(tokio_util::sync::CancellationToken::new),
        )))
    }

    pub(super) fn snapshot(&self) -> Option<tokio_util::sync::CancellationToken> {
        self.0.lock().clone()
    }

    pub(super) fn set(&self, enabled: bool) {
        let mut current = self.0.lock();
        if current.is_some() == enabled {
            return;
        }
        if let Some(old) = current.take() {
            old.cancel();
        }
        if enabled {
            *current = Some(tokio_util::sync::CancellationToken::new());
        }
    }
}

#[derive(Clone)]
pub(crate) struct Tx {
    tx: mpsc::Sender<Packet>,
    budget: Arc<Semaphore>,
    #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
    gate: Option<Arc<Gate>>,
    stats: Arc<Stats>,
}

pub(super) struct Packet {
    data: Vec<u8>,
    bytes: usize,
    stats: Arc<Stats>,
    _permit: OwnedSemaphorePermit,
    #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
    gate: Option<(Arc<Gate>, tokio_util::sync::CancellationToken)>,
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
            #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
            gate: None,
            stats: stats.clone(),
        },
        rx,
        stats,
    )
}

impl Tx {
    #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
    pub(super) fn gated(&self, gate: Arc<Gate>) -> Self {
        Self {
            gate: Some(gate),
            ..self.clone()
        }
    }

    /// Drop the newest packet on overflow; waiting here could deadlock the
    /// lwIP pump or stall the ZeroTier SDK owner thread.
    pub(crate) fn enqueue(&self, data: Vec<u8>) {
        #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
        let gate = if let Some(gate) = &self.gate {
            let Some(generation) = gate.snapshot() else {
                return;
            };
            Some((gate.clone(), generation))
        } else {
            None
        };
        self.enqueue_inner(
            data,
            #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
            gate,
        );
    }

    #[cfg(all(target_os = "android", feature = "zerotier"))]
    pub(super) fn enqueue_at(
        &self,
        data: Vec<u8>,
        generation: tokio_util::sync::CancellationToken,
    ) {
        if generation.is_cancelled() {
            return;
        }
        if let Some(gate) = &self.gate {
            self.enqueue_inner(data, Some((gate.clone(), generation)));
        }
    }

    fn enqueue_inner(
        &self,
        data: Vec<u8>,
        #[cfg(any(test, all(target_os = "android", feature = "zerotier")))] gate: Option<(
            Arc<Gate>,
            tokio_util::sync::CancellationToken,
        )>,
    ) {
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
            #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
            gate,
        });
    }
}

pub(super) async fn write(tun: &AsyncFd<impl AsRawFd>, packet: Packet) -> io::Result<()> {
    let start = Instant::now();
    let result = loop {
        let writable = tun.writable();
        #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
        let writable = async {
            if let Some((_, generation)) = &packet.gate {
                tokio::select! {
                    biased;
                    _ = generation.cancelled() => return None,
                    r = writable => return Some(r),
                }
            }
            Some(writable.await)
        };
        #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
        let Some(writable) = writable.await
        else {
            break Ok(());
        };
        #[cfg(not(any(test, all(target_os = "android", feature = "zerotier"))))]
        let writable = writable.await;
        let mut ready = match writable {
            Ok(ready) => ready,
            Err(error) => break Err(error),
        };
        let result = ready.try_io(|fd| {
            #[cfg(any(test, all(target_os = "android", feature = "zerotier")))]
            let _guard = if let Some((gate, generation)) = &packet.gate {
                let guard = gate.0.lock();
                if generation.is_cancelled() {
                    return Ok(());
                }
                Some(guard)
            } else {
                None
            };
            let written = unsafe {
                libc::write(
                    fd.get_ref().as_raw_fd(),
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
    use std::{os::unix::net::UnixDatagram, time::Duration};
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
    async fn closed_gate_discards_old_packets_even_after_reenable() {
        let (tx, mut rx, _stats) = channel(4, 128);
        let gate = Gate::new(true);
        let tx = tx.gated(gate.clone());
        tx.enqueue(vec![1]);
        gate.set(false);
        assert!(!gate.snapshot().is_some());
        tx.enqueue(vec![2]);
        gate.set(true);
        assert!(gate.snapshot().is_some());
        tx.enqueue(vec![3]);

        let (sender, receiver) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        // SAFETY: registration owns the already nonblocking socket.
        let fd = unsafe { AsyncFd::register_with_interest(sender, Interest::WRITABLE) }.unwrap();
        write(&fd, rx.try_recv().unwrap()).await.unwrap();
        write(&fd, rx.try_recv().unwrap()).await.unwrap();
        let mut received = [0; 1];
        assert_eq!(receiver.recv(&mut received).unwrap(), 1);
        assert_eq!(received, [3]);
        assert_eq!(
            receiver.recv(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn cancelling_a_stalled_write_releases_its_budget() {
        let (sender, _receiver) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        while sender.send(&[0; 1024]).is_ok() {}
        // The sender stays alive until after deregistration of fd.
        // SAFETY: registration owns a duplicate of the nonblocking socket.
        let fd = unsafe {
            AsyncFd::register_with_interest(sender.try_clone().unwrap(), Interest::WRITABLE)
        }
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
        // SAFETY: registration owns a duplicate of the nonblocking socket.
        let fd = unsafe {
            AsyncFd::register_with_interest(sender.try_clone().unwrap(), Interest::WRITABLE)
        }
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
