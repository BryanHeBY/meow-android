//! Bounded owner-classification lanes. Each flow always uses the same lane;
//! receivers resolve and dispatch one packet at a time, including when an
//! owner is unknown or a route changes. The reader never awaits a lane.

use meow_overlay_policy::Destination;
use std::future::Future;
use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::Arc;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

pub(super) struct Lanes<T> {
    routes: Vec<mpsc::Sender<Queued<T>>>,
    hashes: RandomState,
    budget: Arc<Semaphore>,
    tasks: JoinSet<()>,
}

type Queued<T> = (T, OwnedSemaphorePermit);

impl<T: Send + 'static> Lanes<T> {
    pub(super) fn new<H, F>(lanes: usize, capacity: usize, bytes: usize, handler: H) -> Self
    where
        H: Fn(T) -> F + Clone + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        assert!(lanes > 0);
        let mut tasks = JoinSet::new();
        let mut routes = Vec::with_capacity(lanes);
        for _ in 0..lanes {
            let handler = handler.clone();
            let (tx, mut rx) = mpsc::channel::<Queued<T>>(capacity);
            routes.push(tx);
            tasks.spawn(async move {
                while let Some((packet, _budget)) = rx.recv().await {
                    handler(packet).await;
                }
            });
        }
        Self {
            routes,
            hashes: RandomState::new(),
            budget: Arc::new(Semaphore::new(bytes)),
            tasks,
        }
    }

    fn lane(&self, key: impl Hash) -> usize {
        self.hashes.hash_one(key) as usize % self.routes.len()
    }

    /// A full/closed lane or byte budget drops the whole packet; no fallback.
    /// Reserve first so the reader doesn't copy rejected TUN frames.
    pub(super) fn enqueue(&self, key: impl Hash, bytes: u32, make: impl FnOnce() -> T) -> bool {
        let Ok(slot) = self.routes[self.lane(key)].try_reserve() else {
            return false;
        };
        let Ok(permit) = Arc::clone(&self.budget).try_acquire_many_owned(bytes) else {
            return false;
        };
        slot.send((make(), permit));
        true
    }

    pub(super) async fn shutdown(mut self) {
        self.tasks.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn a_slow_lookup_does_not_block_another_lane_or_reorder_its_own_flow() {
        let blocked = Arc::new(Notify::new());
        let unblock = Arc::clone(&blocked);
        let (output, mut observed) = mpsc::unbounded_channel();
        let lanes = Lanes::new(8, 2, 16, move |packet| {
            let blocked = Arc::clone(&blocked);
            let output = output.clone();
            async move {
                if packet == 1 {
                    blocked.notified().await;
                }
                output.send(packet).unwrap();
            }
        });
        let other = (1_u64..)
            .find(|key| lanes.lane(key) != lanes.lane(0_u64))
            .unwrap();
        assert!(lanes.enqueue(0_u64, 1, || 1));
        assert!(lanes.enqueue(0_u64, 1, || 2));
        assert!(lanes.enqueue(other, 1, || 3));
        let wait = Duration::from_secs(1);
        assert_eq!(
            tokio::time::timeout(wait, observed.recv()).await.unwrap(),
            Some(3)
        );
        assert!(observed.try_recv().is_err());
        unblock.notify_one();
        assert_eq!(
            tokio::time::timeout(wait, observed.recv()).await.unwrap(),
            Some(1)
        );
        assert_eq!(
            tokio::time::timeout(wait, observed.recv()).await.unwrap(),
            Some(2)
        );
        lanes.shutdown().await;
        assert_eq!(observed.recv().await, None);
    }

    #[tokio::test]
    async fn overflow_does_not_copy_and_shutdown_does_not_drain() {
        let (started, mut active) = mpsc::unbounded_channel();
        let lanes = Lanes::new(1, 1, 3, move |packet| {
            let started = started.clone();
            async move {
                started.send(packet).unwrap();
                std::future::pending::<()>().await;
            }
        });
        assert!(lanes.enqueue(1, 2, || 1));
        assert_eq!(active.recv().await, Some(1));
        assert!(!lanes.enqueue(1, 2, || panic!("over byte budget")));
        assert!(lanes.enqueue(1, 1, || 2));
        assert!(!lanes.enqueue(1, 1, || panic!("over message cap")));
        lanes.shutdown().await;
        assert_eq!(active.recv().await, None);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OverlayExit {
    Transmit,
    Clash,
    Drop,
}

/// Retain any protected destination observed before or during owner lookup.
pub(super) fn route_history(initial: Destination, current: Destination) -> Destination {
    use Destination::*;
    if matches!(initial, DropOverlayUnavailable) || matches!(current, DropOverlayUnavailable) {
        DropOverlayUnavailable
    } else if matches!(initial, ZeroTier) || matches!(current, ZeroTier) {
        ZeroTier
    } else {
        current
    }
}

/// DNS in the approved overlay still takes precedence. An unavailable private
/// route, or one removed while a packet was queued, cannot escape to Clash.
pub(super) fn overlay_route(
    initial: Destination,
    current: Destination,
    dns: bool,
    permitted: bool,
) -> OverlayExit {
    use Destination::*;
    if dns && permitted {
        return OverlayExit::Transmit;
    }
    match (initial, current) {
        (DropOverlayUnavailable, _) | (_, DropOverlayUnavailable) => OverlayExit::Drop,
        (_, ZeroTier) if permitted => OverlayExit::Transmit,
        (ZeroTier, _) | (_, ZeroTier) => OverlayExit::Drop,
        (_, ZeroTierDefault) if permitted => OverlayExit::Transmit,
        _ => OverlayExit::Clash,
    }
}

#[cfg(test)]
mod policy_tests {
    use super::{
        overlay_route, route_history, Destination,
        Destination::{DropOverlayUnavailable, ZeroTier, ZeroTierDefault},
        OverlayExit::*,
    };

    #[test]
    fn unknown_owner_only_falls_back_for_optional_default_or_dns() {
        assert_eq!(overlay_route(ZeroTier, ZeroTier, false, false), Drop);
        assert_eq!(
            overlay_route(ZeroTierDefault, ZeroTierDefault, false, false),
            Clash
        );
        assert_eq!(
            overlay_route(ZeroTierDefault, ZeroTierDefault, false, true),
            Transmit
        );
        assert_eq!(
            overlay_route(ZeroTierDefault, ZeroTierDefault, true, false),
            Clash
        );
        assert_eq!(
            overlay_route(Destination::Clash, Destination::Clash, true, true),
            Transmit
        );
    }

    #[test]
    fn a_route_removed_during_lookup_never_leaks_to_clash_or_default() {
        assert_eq!(
            overlay_route(
                route_history(Destination::Clash, ZeroTier),
                Destination::Clash,
                false,
                true,
            ),
            Drop
        );
        for current in [Destination::Clash, ZeroTierDefault, DropOverlayUnavailable] {
            assert_eq!(overlay_route(ZeroTier, current, false, true), Drop);
        }
        assert_eq!(
            overlay_route(DropOverlayUnavailable, Destination::Clash, false, false),
            Drop
        );
        assert_eq!(
            overlay_route(Destination::Clash, ZeroTier, false, false),
            Drop
        );
    }
}
