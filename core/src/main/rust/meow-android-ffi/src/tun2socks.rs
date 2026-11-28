//! tun2socks using lwip netstack: reads raw IP packets from the Android
//! TUN fd, routes packets through a userspace TCP/IP stack (lwIP), and
//! dispatches accepted flows to their selected VPN owner.
//!
//! DNS is handled in-process: the same session policy selects IPv4/IPv6
//! UDP and TCP on port 53. IPv4 UDP retains its raw-packet fast path;
//! lwIP supplies streams and reassembled datagrams for all other cases.

#[cfg(all(feature = "zerotier", any(test, target_os = "android")))]
#[path = "tun_owner_ingress.rs"]
mod tun_owner_ingress;

#[cfg(test)]
#[path = "tun_dns_tests.rs"]
mod tun_dns_tests;

#[path = "tun_dns.rs"]
mod tun_dns;
#[cfg(all(target_os = "android", not(feature = "zerotier")))]
pub(crate) use tun_dns::parse_lite_session;
pub(crate) use tun_dns::DnsHijackPolicy;

use crate::engine;
use crate::logging;
use crate::owner;
use meow_common::{ConnType, Metadata, Network, ProxyConn};
use meow_dns::DnsServer;
#[cfg(feature = "zerotier")]
use meow_overlay_policy::apps::AppFilter;
use meow_tunnel::udp::UdpSession;
use parking_lot::Mutex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::raw::c_void;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::JoinHandle;
use tracing::{trace, warn};

mod stack_endpoint;

pub(crate) struct UdpDatagram {
    pub(crate) payload: Vec<u8>,
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
}

impl UdpDatagram {
    fn reply(&self, payload: Vec<u8>) -> Self {
        Self {
            payload,
            src: self.dst,
            dst: self.src,
        }
    }
}
type AnyIpPktFrame = Vec<u8>;
#[cfg(all(target_os = "android", feature = "zerotier"))]
type StackFrame = (AnyIpPktFrame, tokio_util::sync::CancellationToken);
#[cfg(not(all(target_os = "android", feature = "zerotier")))]
type StackFrame = AnyIpPktFrame;
type FlowTasks = Arc<Mutex<Vec<JoinHandle<()>>>>;
type NatKey = (SocketAddr, SocketAddr);
/// The NAT session each running reply reader serves, by NAT key. Holding the
/// session (not just the key) lets a replacement session get its own reader
/// while the evicted one's reader is still winding down.
type ReplyReaders = Arc<Mutex<HashMap<NatKey, Arc<UdpSession>>>>;

#[cfg(feature = "zerotier")]
type ClashGate = AppFilter;
#[cfg(not(feature = "zerotier"))]
type ClashGate = ();

#[derive(Clone, Debug, Eq, PartialEq)]
enum FlowExit {
    Clash,
    #[cfg(all(feature = "zerotier", any(test, target_os = "android")))]
    Direct(Vec<String>),
    #[cfg(feature = "zerotier")]
    Drop,
}

#[cfg(feature = "zerotier")]
fn owner_exit(gate: &ClashGate, packages: &[&str]) -> FlowExit {
    if gate.permits_owner(packages) {
        return FlowExit::Clash;
    }
    #[cfg(all(feature = "zerotier", any(test, target_os = "android")))]
    if !packages.is_empty() && packages.iter().all(|name| !gate.permits(name)) {
        let mut identity: Vec<_> = packages.iter().map(|name| (*name).to_owned()).collect();
        identity.sort_unstable();
        identity.dedup();
        return FlowExit::Direct(identity);
    }
    FlowExit::Drop
}

#[cfg(feature = "zerotier")]
async fn flow_exit(
    gate: Option<&ClashGate>,
    _protocol: i32,
    _src: SocketAddr,
    _dst: SocketAddr,
) -> FlowExit {
    let Some(gate) = gate else {
        return FlowExit::Clash;
    };
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    let packages = owner::overlay_packages(_protocol, _src, _dst).await;
    #[cfg(not(all(target_os = "android", feature = "zerotier")))]
    let packages: Vec<String> = Vec::new();
    let refs: Vec<&str> = packages.iter().map(String::as_str).collect();
    owner_exit(gate, &refs)
}

#[cfg(not(feature = "zerotier"))]
async fn flow_exit(_: Option<&ClashGate>, _: i32, _: SocketAddr, _: SocketAddr) -> FlowExit {
    FlowExit::Clash
}

/// Called only for app UDP from the TUN stack, after ownership and overlay
/// handling. A blocked Meow datagram is dropped before Rule, Global, or
/// Direct can open an outbound session.
fn drop_app_udp(exit: &FlowExit, block_app_udp443: bool, dst: SocketAddr) -> bool {
    matches!(exit, FlowExit::Clash) && block_app_udp443 && dst.port() == 443
}

static TUN2SOCKS_ACTIVE: AtomicBool = AtomicBool::new(false);
static TUN2SOCKS_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
// Wakes the TUN reader, which sleeps until the fd is readable and so would
// not notice the flag above on an idle VPN.
static TUN2SOCKS_STOP_NOTIFY: Notify = Notify::const_new();
// Handle of the running session's top-level task, so `stop()` can wait for
// it to finish touching the TUN fd before Kotlin closes it.
static TUN2SOCKS_TASK: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);
#[cfg(all(target_os = "android", feature = "zerotier"))]
type MeowGate = Arc<crate::tun_egress::Gate>;

#[cfg(all(target_os = "android", feature = "zerotier"))]
struct TunControl {
    overlay: mpsc::Sender<OverlayCommand>,
    meow: MeowGate,
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
static TUN_CONTROL: Mutex<Option<TunControl>> = Mutex::new(None);

#[cfg(all(target_os = "android", feature = "zerotier"))]
struct OverlayCommand {
    target: Overlay,
    claim: Arc<CommandClaim>,
    reply: tokio::sync::oneshot::Sender<Result<bool, String>>,
}

#[cfg(all(feature = "zerotier", any(test, target_os = "android")))]
#[derive(Default)]
struct CommandClaim(std::sync::atomic::AtomicU8);

#[cfg(all(feature = "zerotier", any(test, target_os = "android")))]
impl CommandClaim {
    fn claim(&self) -> bool {
        self.0
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Returns true only when the reader can no longer begin this command.
    fn cancel_before_apply(&self) -> bool {
        self.0
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
pub enum OverlayApplyError {
    NotApplied(String),
    OutcomeUnknown,
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
pub fn apply_overlay(target: Overlay) -> Result<bool, OverlayApplyError> {
    use OverlayApplyError::{NotApplied, OutcomeUnknown};
    let sender = TUN_CONTROL
        .lock()
        .as_ref()
        .ok_or_else(|| NotApplied("TUN is not active".into()))?
        .overlay
        .clone();
    let claim = Arc::new(CommandClaim::default());
    let (reply, mut response) = tokio::sync::oneshot::channel();
    sender
        .try_send(OverlayCommand {
            target,
            claim: claim.clone(),
            reply,
        })
        .map_err(|_| NotApplied("ZeroTier apply is busy or TUN has stopped".into()))?;
    let reply = crate::get_runtime()
        .block_on(async { tokio::time::timeout(TUN2SOCKS_STOP_TIMEOUT, &mut response).await });
    match reply {
        Ok(Ok(result)) => result.map_err(NotApplied),
        Ok(Err(_)) => Err(OutcomeUnknown),
        Err(_) if claim.cancel_before_apply() => Err(NotApplied(
            "ZeroTier apply timed out before it could start".into(),
        )),
        Err(_) => response
            .try_recv()
            .map_err(|_| OutcomeUnknown)?
            .map_err(NotApplied),
    }
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
pub fn set_meow_forwarding(enabled: bool) -> Result<(), &'static str> {
    let active = TUN_CONTROL.lock();
    let control = active.as_ref().ok_or("TUN is not active")?;
    control.meow.set(enabled);
    Ok(())
}
const TUN2SOCKS_STOP_TIMEOUT: Duration = Duration::from_secs(3);

const DNS_BURST_CAP: usize = 256;
const DNS_TASK_TIMEOUT: Duration = Duration::from_secs(5);
static DNS_CAP_LOG_LAST_MS: AtomicU64 = AtomicU64::new(0);
const TCP_DNS_CONNECTION_CAP: usize = 64;
const TCP_DNS_LIFETIME: Duration = Duration::from_secs(120);
static TCP_DNS_CAP_LOG_LAST_MS: AtomicU64 = AtomicU64::new(0);

/// How often a UDP reply reader checks whether its session is still live.
/// A DIRECT session's read never ends on its own, so this bounds how long a
/// reader outlives a swept (or flushed) session.
const UDP_REPLY_CHECK_INTERVAL: Duration = Duration::from_secs(5);

fn warn_capped(slot: &AtomicU64, msg: &str) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let last = slot.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) >= 1000
        && slot
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        warn!("{}", msg);
    }
}

#[cfg(test)]
fn start(fd: i32, _dns_port: u16) -> Result<(), String> {
    start_with_packet_policy(fd, false, DnsHijackPolicy::default())
}

#[cfg(any(test, not(target_os = "android")))]
pub fn start_with_packet_policy(
    fd: i32,
    block_app_udp443: bool,
    dns_hijacking: DnsHijackPolicy,
) -> Result<(), String> {
    start_inner(
        fd,
        block_app_udp443,
        dns_hijacking,
        #[cfg(all(target_os = "android", feature = "zerotier"))]
        None,
        #[cfg(target_os = "android")]
        None,
        #[cfg(all(target_os = "android", feature = "zerotier"))]
        true,
        || Ok(()),
    )
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
type Overlay = Option<(std::path::PathBuf, crate::zerotier_config::Config)>;

#[cfg(target_os = "android")]
pub fn start_android(
    fd: i32,
    block_app_udp443: bool,
    dns_hijacking: DnsHijackPolicy,
    #[cfg(feature = "zerotier")] config: Overlay,
    report_exit: Option<Box<dyn FnOnce(i32) + Send>>,
    #[cfg(feature = "zerotier")] meow_enabled: bool,
    install_service_hooks: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    start_inner(
        fd,
        block_app_udp443,
        dns_hijacking,
        #[cfg(feature = "zerotier")]
        config,
        report_exit,
        #[cfg(feature = "zerotier")]
        meow_enabled,
        install_service_hooks,
    )
}

fn start_inner(
    fd: i32,
    block_app_udp443: bool,
    dns_hijacking: DnsHijackPolicy,
    #[cfg(all(target_os = "android", feature = "zerotier"))] overlay: Overlay,
    #[cfg(target_os = "android")] report_exit: Option<Box<dyn FnOnce(i32) + Send>>,
    #[cfg(all(target_os = "android", feature = "zerotier"))] meow_enabled: bool,
    install_service_hooks: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let mut task = TUN2SOCKS_TASK.lock();
    if task.as_ref().is_some_and(|task| !task.is_finished()) {
        return Err("previous TUN forwarding is still shutting down".into());
    }
    if TUN2SOCKS_ACTIVE
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("tun2socks already running".into());
    }
    TUN2SOCKS_STOP_REQUESTED.store(false, Ordering::SeqCst);

    logging::bridge_log(&format!("tun2socks starting: fd={}", fd));

    if let Err(error) = set_nonblocking(fd) {
        TUN2SOCKS_ACTIVE.store(false, Ordering::SeqCst);
        return Err(error.to_string());
    }

    // The OS/service owner keeps the source descriptor. Every async task
    // retains an owned duplicate, so even a crash or shutdown timeout cannot
    // read/write an unrelated fd after its number is reused by Android.
    let tun_fd = match unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned() {
        Ok(owned) => owned,
        Err(error) => {
            TUN2SOCKS_ACTIVE.store(false, Ordering::SeqCst);
            return Err(error.to_string());
        }
    };
    // Only the admitted session may publish its process-global Android
    // hooks. Do this while holding the same lock that rejects duplicate
    // starts, and after descriptor setup can no longer fail.
    if let Err(error) = install_service_hooks() {
        TUN2SOCKS_ACTIVE.store(false, Ordering::SeqCst);
        return Err(error);
    }
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    let (overlay_tx, overlay_rx) = mpsc::channel(1);
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    let meow = crate::tun_egress::Gate::new(meow_enabled);
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    let meow_task = meow.clone();
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    {
        *TUN_CONTROL.lock() = Some(TunControl {
            overlay: overlay_tx,
            meow,
        });
    }

    let rt = crate::get_runtime();
    let handle = rt.spawn(async move {
        let run = run_tun2socks(
            tun_fd,
            block_app_udp443,
            dns_hijacking,
            #[cfg(all(target_os = "android", feature = "zerotier"))]
            overlay,
            #[cfg(all(target_os = "android", feature = "zerotier"))]
            Some(overlay_rx),
            #[cfg(all(target_os = "android", feature = "zerotier"))]
            meow_task,
        );
        let result = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(run)).await;
        let reason = match result {
            Ok(Ok(())) => 1, // unexpectedly completed without an explicit shutdown
            Ok(Err(e)) => {
                logging::bridge_log(&format!("tun2socks error: {e}"));
                2
            }
            Err(_) => {
                logging::bridge_log("tun2socks supervisor panicked");
                3
            }
        };
        let requested = TUN2SOCKS_STOP_REQUESTED.swap(false, Ordering::SeqCst);
        #[cfg(all(target_os = "android", feature = "zerotier"))]
        {
            *TUN_CONTROL.lock() = None;
        }
        TUN2SOCKS_ACTIVE.store(false, Ordering::SeqCst);
        #[cfg(target_os = "android")]
        if let Some(report) = report_exit.filter(|_| !requested || reason != 1) {
            report(reason);
        }
        #[cfg(not(target_os = "android"))]
        let _ = (requested, reason);
        logging::bridge_log("tun2socks exited");
    });
    *task = Some(handle);

    Ok(())
}

// Establish the reader/writer precondition before publishing a session. Keep
// all existing status flags and report either fcntl failure to the JNI caller.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Request shutdown and block until the session's reader/writer tasks have
/// stopped using the TUN fd (bounded by `TUN2SOCKS_STOP_TIMEOUT`).
pub fn stop() -> bool {
    // Do not consume a handle that cannot be joined by this caller. A later
    // retry still waits for the original tasks, before any new session starts.
    if tokio::runtime::Handle::try_current().is_ok() {
        return false;
    }
    let mut task = TUN2SOCKS_TASK.lock();
    TUN2SOCKS_STOP_REQUESTED.store(true, Ordering::SeqCst);
    TUN2SOCKS_STOP_NOTIFY.notify_waiters();
    let Some(handle) = task.as_mut() else {
        TUN2SOCKS_STOP_REQUESTED.store(false, Ordering::SeqCst);
        return true;
    };
    let stopped = crate::get_runtime()
        .block_on(async { tokio::time::timeout(TUN2SOCKS_STOP_TIMEOUT, handle).await })
        .is_ok();
    if stopped {
        task.take();
    } else {
        logging::bridge_log("tun2socks: stop timed out waiting for shutdown");
    }
    stopped
}

// ---------------------------------------------------------------------------
// Main tun2socks loop
// ---------------------------------------------------------------------------

async fn run_tun2socks(
    fd: OwnedFd,
    block_app_udp443: bool,
    dns_hijacking: DnsHijackPolicy,
    #[cfg(all(target_os = "android", feature = "zerotier"))] overlay: Overlay,
    #[cfg(all(target_os = "android", feature = "zerotier"))] mut overlay_control: Option<
        mpsc::Receiver<OverlayCommand>,
    >,
    #[cfg(all(target_os = "android", feature = "zerotier"))] meow: MeowGate,
) -> io::Result<()> {
    logging::bridge_log("tun2socks: building lwip netstack");

    let stack_endpoint::Endpoint {
        mut frames,
        mut tcp,
        udp_tx,
        mut udp_rx,
    } = stack_endpoint::Endpoint::open()?;

    let (udp_reply_tx, mut udp_reply_rx) = mpsc::channel::<UdpDatagram>(256);
    let (dns_reply_tx, mut dns_reply_rx) = mpsc::channel::<StackDnsReply>(64);
    let reply_readers: ReplyReaders = Arc::new(Mutex::new(HashMap::new()));

    let (stack_ingress_tx, mut stack_ingress_rx) = mpsc::channel::<StackFrame>(256);
    // One reactor registration for both directions; the tasks each own
    // their readiness guard and stop waits for both before the fd closes.
    // SAFETY: the owned fd stays open and nonblocking until the registration
    // and all AsyncFd handles are dropped. No one else can close this dup.
    let tun = Arc::new(unsafe {
        AsyncFd::register_with_interest(fd, Interest::READABLE | Interest::WRITABLE)?
    });
    let (egress_tx, mut egress_rx, egress_stats) = crate::tun_egress::channel(256, 2 * 1024 * 1024);
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    let egress_tx = egress_tx.gated(meow.clone());
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    let (overlay_out, mut overlay_in, overlay_stats) = crate::tun_egress::channel(128, 512 * 1024);
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    let clash_gate = overlay
        .as_ref()
        .map(|(_, config)| &config.clash_filter)
        .filter(|filter| !filter.permits_owner(&[]))
        .map(|filter| Arc::new(filter.clone()));
    #[cfg(not(all(target_os = "android", feature = "zerotier")))]
    let clash_gate: Option<Arc<ClashGate>> = None;
    let stack_clash_gate = clash_gate.clone();
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    let direct_udp = Arc::new(crate::direct_exit::udp::Flows::default());
    let dns_sem = Arc::new(Semaphore::new(DNS_BURST_CAP));
    let dns_sem_lwip = Arc::clone(&dns_sem);
    let tcp_dns = TcpDnsLimits::new();
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    let meow_lwip = meow.clone();
    let flow_tasks: FlowTasks = Arc::new(Mutex::new(Vec::new()));

    let egress_tx_lwip = egress_tx.clone();
    let udp_reply_tx_lwip = udp_reply_tx.clone();
    let reply_readers_lwip = reply_readers.clone();
    let flow_tasks_lwip = flow_tasks.clone();
    let flow_tasks_dns = flow_tasks.clone();
    // lwip's Rust listener/socket wrappers are backed by C callbacks that
    // mutate Rust queues and wakers through raw pointers. Keep all wrapper
    // polling and UDP writes on one task; detached tasks only own accepted
    // streams or proxy-side work.
    let lwip_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                pkt = stack_ingress_rx.recv() => {
                    match pkt {
                        Some(frame) => {
                            #[cfg(all(target_os = "android", feature = "zerotier"))]
                            let result = {
                                let (bytes, generation) = frame;
                                // Reserve in the Sink before submitting; select
                                // cancellation first to discard a blocked old frame.
                                tokio::select! {
                                    biased;
                                    _ = generation.cancelled() => continue,
                                    result = frames.send(bytes) => result,
                                }
                            };
                            #[cfg(not(all(target_os = "android", feature = "zerotier")))]
                            let result = frames.send(frame).await;
                            if let Err(e) = result {
                                logging::bridge_log(&format!("stack send error: {}", e));
                                break;
                            }
                        }
                        None => break,
                    }
                }
                pkt = frames.receive() => {
                    match pkt {
                        Some(Ok(frame)) => { egress_tx_lwip.enqueue(frame); }
                        Some(Err(e)) => {
                            logging::bridge_log(&format!("stack recv error: {}", e));
                            break;
                        }
                        None => break,
                    }
                }
                accepted = tcp.accept() => {
                    match accepted {
                        Some(accepted) => {
                            let gate = stack_clash_gate.clone();
                            let dns = dns_hijacking.captures(accepted.dst).then(|| tcp_dns.clone());
                            #[cfg(all(target_os = "android", feature = "zerotier"))]
                            let generation = dns.as_ref().and_then(|_| meow_lwip.snapshot());
                            let handle = tokio::spawn(dispatch_accepted_tcp(
                                accepted,
                                gate,
                                dns,
                                #[cfg(all(target_os = "android", feature = "zerotier"))]
                                generation,
                            ));
                            track_flow_task(&flow_tasks_lwip, handle);
                        }
                        None => break,
                    }
                }
                udp_pkt = udp_rx.receive() => {
                    match udp_pkt {
                        Some(packet) => {
                            let reply_tx = udp_reply_tx_lwip.clone();
                            let readers = reply_readers_lwip.clone();
                            let gate = stack_clash_gate.clone();
                            let dns = dns_hijacking.captures(packet.dst).then(|| {
                                (Arc::clone(&dns_sem_lwip), dns_reply_tx.clone())
                            });
                            #[cfg(all(target_os = "android", feature = "zerotier"))]
                            let generation = dns.as_ref().and_then(|_| meow_lwip.snapshot());
                            #[cfg(all(target_os = "android", feature = "zerotier"))]
                            let direct = direct_udp.clone();
                            let handle = tokio::spawn(dispatch_accepted_udp(
                                packet,
                                UdpDispatch {
                                    gate, block_app_udp443, dns, reply_tx, readers,
                                    #[cfg(all(target_os = "android", feature = "zerotier"))]
                                    generation,
                                    #[cfg(all(target_os = "android", feature = "zerotier"))]
                                    direct,
                                },
                            ));
                            track_flow_task(&flow_tasks_lwip, handle);
                        }
                        None => break,
                    }
                }
                Some(reply) = dns_reply_rx.recv() => {
                    #[cfg(all(target_os = "android", feature = "zerotier"))]
                    if reply.generation.is_none_or(|gen| gen.is_cancelled()) {
                        continue;
                    }
                    let packet = reply.packet;
                    if udp_tx.send(&packet).is_err() {
                        trace!("tun2socks: dropping undeliverable UDP DNS reply");
                    }
                }
                msg = udp_reply_rx.recv() => {
                    match msg {
                        Some(msg) => {
                            if let Err(e) = udp_tx.send(&msg) {
                                logging::bridge_log(&format!("tun2socks: UDP reply send error: {}", e));
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    let tun_writer = Arc::clone(&tun);
    let tun_writer_handle = tokio::spawn(async move {
        loop {
            #[cfg(not(all(target_os = "android", feature = "zerotier")))]
            let next = egress_rx.recv().await;
            #[cfg(all(target_os = "android", feature = "zerotier"))]
            let next = tokio::select! {
                Some(pkt) = overlay_in.recv() => Some(pkt),
                next = egress_rx.recv() => next,
            };
            let Some(pkt) = next else { break };
            // The reactor clears stale writable readiness on EAGAIN. A stop
            // aborts this task and drops any in-flight byte permit.
            let _ = crate::tun_egress::write(&tun_writer, pkt).await;
        }
    });

    // TUN reader: reads raw IP packets, intercepts DNS pre-stack. It sleeps in
    // epoll until the fd is readable: an idle VPN must not keep waking the
    // CPU, as polling the fd every 200 µs did (~750 wakeups a second).
    let tun_reader_handle = tokio::spawn(async move {
        // Taken before the flag is read: notify_waiters() reaches a Notified
        // from the moment it exists, so a stop() in between is not lost.
        let stopped = TUN2SOCKS_STOP_NOTIFY.notified();
        tokio::pin!(stopped);
        if TUN2SOCKS_STOP_REQUESTED.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut read_buf = vec![0u8; 65535];
        let ingress = ClashIngress {
            stack: stack_ingress_tx,
            dns_sem,
            dns_hijacking,
            tasks: flow_tasks_dns,
            egress: egress_tx,
            gate: clash_gate,
        };
        #[cfg(all(target_os = "android", feature = "zerotier"))]
        let (mut overlay, mut owner_lanes) = match overlay {
            Some((root, config)) => {
                let active = LiveOverlay::start(root, config, &overlay_out)?;
                let lanes = make_owner_lanes(&active, &ingress);
                (Some(active), lanes)
            }
            None => (None, None),
        };

        let result = 'reader: loop {
            #[cfg(all(target_os = "android", feature = "zerotier"))]
            let mut ready = tokio::select! {
                biased;
                _ = &mut stopped => break Ok(()),
                command = recv_overlay_command(&mut overlay_control) => {
                    if let Some(command) = command {
                        handle_overlay_command(command, &mut overlay, &mut owner_lanes, &ingress, &overlay_out).await;
                    } else {
                        overlay_control = None;
                    }
                    continue;
                }
                ready = tun.readable() => match ready {
                    Ok(ready) => ready,
                    Err(e) => break Err(e),
                },
            };
            #[cfg(not(all(target_os = "android", feature = "zerotier")))]
            let mut ready = tokio::select! {
                biased;
                _ = &mut stopped => break Ok(()),
                ready = tun.readable() => match ready {
                    Ok(ready) => ready,
                    Err(e) => {
                        break Err(e);
                    }
                },
            };

            // Bound each drain batch: with active lanes and a perpetually
            // readable fd, a synchronous enqueue loop must yield to workers.
            for _ in 0..64 {
                let n = unsafe {
                    libc::read(
                        tun.get_ref().as_raw_fd(),
                        read_buf.as_mut_ptr() as *mut c_void,
                        read_buf.len(),
                    )
                };
                if n == 0 {
                    break 'reader Err(io::ErrorKind::UnexpectedEof.into());
                }
                if n < 0 {
                    let error = io::Error::last_os_error();
                    match error.kind() {
                        io::ErrorKind::WouldBlock => {
                            ready.clear_ready();
                            break;
                        }
                        io::ErrorKind::Interrupted => continue,
                        _ => break 'reader Err(error),
                    }
                }
                let n = n as usize;
                let ip_data = &read_buf[..n];

                #[cfg(all(target_os = "android", feature = "zerotier"))]
                let meow_generation = meow.snapshot();
                #[cfg(all(target_os = "android", feature = "zerotier"))]
                if let Some(active) = &overlay {
                    let overlay = &active.worker;
                    let initial = overlay.classify(ip_data);
                    let unrestricted = owner_lanes.is_none();
                    if let Some(lanes) = &owner_lanes {
                        if let Ok(flow) = meow_overlay_policy::wire::flow(ip_data) {
                            // Keep even immediate Clash packets on this lane: the
                            // route can change while an earlier packet awaits JNI.
                            if !lanes.enqueue(flow, n as u32, || {
                                (ip_data.to_vec(), initial, meow_generation.clone())
                            }) {
                                warn_capped(
                                    &OWNER_CAP_LOG_LAST_MS,
                                    "tun2socks: app-owner queue full, dropping packet",
                                );
                            }
                            continue;
                        }
                    }
                    // No binder calls or queueing on the unrestricted fast
                    // path. Invalid flows also cannot authorize overlay use.
                    let dns = overlay.wants_dns(ip_data);
                    let permitted = unrestricted
                        && (dns
                            || matches!(
                                initial,
                                Destination::ZeroTier | Destination::ZeroTierDefault
                            ))
                        && meow_overlay_policy::wire::flow(ip_data).is_ok();
                    match overlay_route(initial, initial, dns, permitted) {
                        OverlayExit::Transmit => {
                            overlay.transmit(ip_data.to_vec());
                            continue;
                        }
                        OverlayExit::Drop => continue,
                        OverlayExit::Clash => {}
                    }
                }

                #[cfg(all(target_os = "android", feature = "zerotier"))]
                let Some(generation) = meow_generation
                else {
                    continue;
                };
                if ingress.spawn_dns(
                    ip_data,
                    #[cfg(all(target_os = "android", feature = "zerotier"))]
                    generation.clone(),
                ) {
                    continue;
                }
                #[cfg(all(target_os = "android", feature = "zerotier"))]
                let frame = (ip_data.to_vec(), generation);
                #[cfg(not(all(target_os = "android", feature = "zerotier")))]
                let frame = ip_data.to_vec();
                #[cfg(all(target_os = "android", feature = "zerotier"))]
                let forwarded = tokio::select! {
                    biased;
                    command = recv_overlay_command(&mut overlay_control) => {
                        // Policy changes cut this packet at the owner boundary:
                        // do not enqueue a frame classified under older rules.
                        if let Some(command) = command {
                            handle_overlay_command(command, &mut overlay, &mut owner_lanes, &ingress, &overlay_out).await;
                        } else {
                            overlay_control = None;
                        }
                        continue 'reader;
                    }
                    success = send_ingress(&ingress.stack, frame, &mut stopped) => success,
                };
                #[cfg(not(all(target_os = "android", feature = "zerotier")))]
                let forwarded = send_ingress(&ingress.stack, frame, &mut stopped).await;
                if !forwarded {
                    break 'reader Ok(());
                }
            }
            tokio::task::yield_now().await;
        };
        #[cfg(all(target_os = "android", feature = "zerotier"))]
        retire_overlay(overlay, owner_lanes).await;
        result
    });

    let reader = tun_reader_handle.await;

    abort_flow_tasks(&flow_tasks).await;
    drop(udp_reply_tx);
    let _ = lwip_handle.await;
    abort_flow_tasks(&flow_tasks).await;
    tun_writer_handle.abort();
    let _ = tun_writer_handle.await;

    logging::bridge_log(&format!("tun2socks: egress {}", egress_stats.summary()));
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    logging::bridge_log(&format!(
        "tun2socks: ZeroTier egress {}",
        overlay_stats.summary()
    ));
    logging::bridge_log("tun2socks: exiting");
    reader.map_err(io::Error::other)?
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
struct LiveOverlay {
    worker: Arc<crate::zerotier_worker::Worker>,
    // Only this generation can emit ZeroTier packets. A detached worker's
    // queue is discarded even if the shared TUN writer was backpressured.
    egress: Arc<crate::tun_egress::Gate>,
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
impl LiveOverlay {
    fn start(
        root: std::path::PathBuf,
        config: crate::zerotier_config::Config,
        out: &crate::tun_egress::Tx,
    ) -> io::Result<Self> {
        let egress = crate::tun_egress::Gate::new(true);
        let worker =
            crate::zerotier_worker::Worker::start(config, root, out.gated(egress.clone()))?;
        Ok(Self {
            worker: Arc::new(worker),
            egress,
        })
    }
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
type OwnerPacket = (
    Vec<u8>,
    Destination,
    Option<tokio_util::sync::CancellationToken>,
);

#[cfg(all(target_os = "android", feature = "zerotier"))]
type OwnerLanes = tun_owner_ingress::Lanes<OwnerPacket>;

#[cfg(all(target_os = "android", feature = "zerotier"))]
fn make_owner_lanes(overlay: &LiveOverlay, ingress: &ClashIngress) -> Option<OwnerLanes> {
    if overlay.worker.config.filter.permits_owner(&[]) {
        return None;
    }
    let worker = overlay.worker.clone();
    let ingress = ingress.clone();
    Some(tun_owner_ingress::Lanes::new(
        8,
        16,
        512 * 1024,
        move |(packet, initial, generation): OwnerPacket| {
            let overlay = worker.clone();
            let ingress = ingress.clone();
            async move {
                match overlay_exit(&overlay, initial, &packet).await {
                    OverlayExit::Transmit => overlay.transmit(packet),
                    OverlayExit::Drop => (),
                    OverlayExit::Clash => {
                        let Some(generation) = generation.filter(|g| !g.is_cancelled()) else {
                            return;
                        };
                        if !ingress.spawn_dns(&packet, generation.clone()) {
                            let _ = ingress.stack.send((packet, generation)).await;
                        }
                    }
                }
            }
        },
    ))
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
async fn retire_overlay(overlay: Option<LiveOverlay>, lanes: Option<OwnerLanes>) {
    if let Some(active) = &overlay {
        active.egress.set(false);
    }
    if let Some(lanes) = lanes {
        lanes.shutdown().await;
    }
    if let Some(overlay) = overlay {
        // Worker::drop joins its OS thread. Never block Tokio on that join.
        let _ = tokio::task::spawn_blocking(move || drop(overlay)).await;
    }
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
async fn replace_overlay(
    target: Overlay,
    active: &mut Option<LiveOverlay>,
    lanes: &mut Option<OwnerLanes>,
    ingress: &ClashIngress,
    out: &crate::tun_egress::Tx,
) -> Result<bool, String> {
    if active.is_none() && target.is_none() {
        return Ok(true);
    }
    // A live replacement could open the same identity/state concurrently.
    // Changes to the static Clash gate or DNS interception need a new
    // native TUN forwarding generation instead. Public IPv4 changes are
    // intentional when the user enables default-route ownership; the same
    // fail-closed classifier used at cold start handles them without edits.
    if active.is_some() && target.is_some() {
        return Ok(false);
    }
    if !crate::zerotier_config::hot_overlay_allowed(
        active.as_ref().map(|old| old.worker.config.as_ref()),
        target.as_ref().map(|(_, config)| config),
    ) {
        return Ok(false);
    }
    if let Some((root, config)) = target {
        let next = LiveOverlay::start(root, config, out).map_err(|err| err.to_string())?;
        *lanes = make_owner_lanes(&next, ingress);
        *active = Some(next);
    } else {
        retire_overlay(active.take(), lanes.take()).await;
    }
    Ok(true)
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
async fn handle_overlay_command(
    command: OverlayCommand,
    active: &mut Option<LiveOverlay>,
    lanes: &mut Option<OwnerLanes>,
    ingress: &ClashIngress,
    out: &crate::tun_egress::Tx,
) {
    if command.claim.claim() {
        let result = replace_overlay(command.target, active, lanes, ingress, out).await;
        let _ = command.reply.send(result);
    }
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
async fn recv_overlay_command(
    control: &mut Option<mpsc::Receiver<OverlayCommand>>,
) -> Option<OverlayCommand> {
    match control {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
use meow_overlay_policy::Destination;
#[cfg(all(target_os = "android", feature = "zerotier"))]
use tun_owner_ingress::{overlay_route, route_history, OverlayExit};

#[cfg(all(target_os = "android", feature = "zerotier"))]
static OWNER_CAP_LOG_LAST_MS: AtomicU64 = AtomicU64::new(0);

#[cfg(all(target_os = "android", feature = "zerotier"))]
async fn overlay_exit(
    overlay: &crate::zerotier_worker::Worker,
    initial: Destination,
    packet: &[u8],
) -> OverlayExit {
    let dns = overlay.wants_dns(packet);
    let current = overlay.classify(packet);
    let allowed = if dns
        || matches!(
            current,
            Destination::ZeroTier | Destination::ZeroTierDefault
        ) {
        // One fresh lookup per packet, never cached by tuple. Echo and
        // unparsable packets cannot block here; Worker::permits rejects them
        // without querying the binder under a restricted filter.
        overlay.permits(packet).await
    } else {
        return overlay_route(initial, current, dns, false);
    };
    // Runtime membership can change while owner resolution is in flight.
    overlay_route(
        route_history(initial, current),
        overlay.classify(packet),
        dns,
        allowed,
    )
}

#[derive(Clone)]
struct ClashIngress {
    stack: mpsc::Sender<StackFrame>,
    dns_sem: Arc<Semaphore>,
    dns_hijacking: DnsHijackPolicy,
    tasks: FlowTasks,
    egress: crate::tun_egress::Tx,
    gate: Option<Arc<ClashGate>>,
}

impl ClashIngress {
    // The DNS handler keeps its original per-request concurrency and deadline.
    fn spawn_dns(
        &self,
        ip_data: &[u8],
        #[cfg(all(target_os = "android", feature = "zerotier"))]
        generation: tokio_util::sync::CancellationToken,
    ) -> bool {
        // Unfragmented IPv4 fast path. IPv6 and reassembled UDP arrive
        // through lwIP and use the same destination policy and budget.
        if parse_udp_packet(ip_data).is_some_and(|p| {
            self.dns_hijacking
                .captures_raw_ipv4(p.dst, self.gate.is_some())
        }) {
            let permit = match self.dns_sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn_dns_burst();
                    return true;
                }
            };
            let request = ip_data.to_vec();
            let egress = self.egress.clone();
            let gate = self.gate.clone();
            let handle = tokio::spawn(async move {
                let _permit = permit;
                let work = async {
                    let Some(parsed) = parse_udp_packet(&request) else {
                        return;
                    };
                    let response_payload = match flow_exit(
                        gate.as_deref(),
                        owner::IPPROTO_UDP,
                        parsed.src,
                        parsed.dst,
                    )
                    .await
                    {
                        FlowExit::Clash => {
                            let Some(bytes) = answer_dns(parsed.payload).await else {
                                return;
                            };
                            bytes
                        }
                        #[cfg(all(target_os = "android", feature = "zerotier"))]
                        FlowExit::Direct(_) if DnsHijackPolicy::is_vpn_endpoint(parsed.dst) => {
                            let Some(bytes) = crate::direct_exit::system_dns(parsed.payload).await
                            else {
                                return;
                            };
                            bytes
                        }
                        #[cfg(feature = "zerotier")]
                        _ => return,
                    };
                    let Some(reply_pkt) = build_udp_reply(&request, &response_payload) else {
                        return;
                    };
                    #[cfg(all(target_os = "android", feature = "zerotier"))]
                    egress.enqueue_at(reply_pkt, generation.clone());
                    #[cfg(not(all(target_os = "android", feature = "zerotier")))]
                    egress.enqueue(reply_pkt);
                };
                #[cfg(all(target_os = "android", feature = "zerotier"))]
                let work = async {
                    tokio::select! {
                        biased;
                        _ = generation.cancelled() => (),
                        _ = work => (),
                    }
                };
                if tokio::time::timeout(DNS_TASK_TIMEOUT, work).await.is_err() {
                    trace!(
                        "tun2socks: DNS task exceeded {:?}, aborting",
                        DNS_TASK_TIMEOUT
                    );
                }
            });
            track_flow_task(&self.tasks, handle);
            return true;
        }
        false
    }
}

struct StackDnsReply {
    packet: UdpDatagram,
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    generation: Option<tokio_util::sync::CancellationToken>,
}

#[derive(Clone)]
struct TcpDnsLimits {
    connections: Arc<Semaphore>,
    queries: Arc<Semaphore>,
}

impl TcpDnsLimits {
    fn new() -> Self {
        Self {
            connections: Arc::new(Semaphore::new(TCP_DNS_CONNECTION_CAP)),
            queries: Arc::new(Semaphore::new(TCP_DNS_CONNECTION_CAP)),
        }
    }

    async fn serve(&self, stream: impl AsyncRead + AsyncWrite + Unpin) {
        let Ok(_connection) = self.connections.try_acquire() else {
            warn_capped(
                &TCP_DNS_CAP_LOG_LAST_MS,
                "tun2socks: TCP DNS connections capped",
            );
            return;
        };
        let Some(resolver) = crate::DNS_RESOLVER.read().clone() else {
            return;
        };
        // The core bounds each frame and takes the latest resolver generation
        // after each complete request. This cap also releases long-lived clients
        // that keep sending valid frames without ever idling.
        let _ = tokio::time::timeout(
            TCP_DNS_LIFETIME,
            meow_dns::server::serve_tcp_stream(stream, resolver, Arc::clone(&self.queries)),
        )
        .await;
    }
}

fn warn_dns_burst() {
    warn_capped(
        &DNS_CAP_LOG_LAST_MS,
        "tun2socks: DNS burst cap reached, dropping query",
    );
}

async fn answer_dns(query: &[u8]) -> Option<Vec<u8>> {
    let slot = crate::DNS_RESOLVER.read().clone()?;
    let resolver = Arc::clone(&slot.read().resolver);
    DnsServer::handle_query(query, &resolver).await.ok()
}

async fn run_selected_dns(
    work: impl std::future::Future<Output = ()>,
    #[cfg(all(target_os = "android", feature = "zerotier"))] generation: Option<
        tokio_util::sync::CancellationToken,
    >,
) {
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    {
        let Some(generation) = generation else {
            return;
        };
        tokio::select! {
            biased;
            _ = generation.cancelled() => (),
            _ = work => (),
        }
    }
    #[cfg(not(all(target_os = "android", feature = "zerotier")))]
    work.await;
}

async fn send_ingress<T>(
    tx: &mpsc::Sender<T>,
    frame: T,
    stopped: &mut (impl std::future::Future<Output = ()> + Unpin),
) -> bool {
    // A full ingress queue must not hide stop from the TUN reader. Cancelling
    // send drops this whole packet; it never leaves a partial frame queued.
    tokio::select! {
        biased;
        () = stopped => false,
        result = tx.send(frame) => result.is_ok(),
    }
}

fn track_flow_task(flow_tasks: &FlowTasks, handle: JoinHandle<()>) {
    let mut tasks = flow_tasks.lock();
    tasks.retain(|task| !task.is_finished());
    tasks.push(handle);
}

async fn abort_flow_tasks(flow_tasks: &FlowTasks) {
    let tasks = {
        let mut tasks = flow_tasks.lock();
        tasks.drain(..).collect::<Vec<_>>()
    };
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
}

// ---------------------------------------------------------------------------
// TCP dispatch
// ---------------------------------------------------------------------------

/// Original tuple plus stream as seen by the app. The stack is responsible
/// only for accepting the stream; routing and socket protection remain here.
struct AcceptedTcp<C> {
    conn: C,
    src: SocketAddr,
    dst: SocketAddr,
}

impl<C> AcceptedTcp<C> {
    fn metadata(&self) -> Metadata {
        Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            src_ip: Some(self.src.ip()),
            src_port: self.src.port(),
            dst_ip: Some(self.dst.ip()),
            dst_port: self.dst.port(),
            ..Default::default()
        }
    }
}

async fn dispatch_accepted_tcp(
    accepted: AcceptedTcp<impl ProxyConn + 'static>,
    gate: Option<Arc<ClashGate>>,
    dns: Option<TcpDnsLimits>,
    #[cfg(all(target_os = "android", feature = "zerotier"))] generation: Option<
        tokio_util::sync::CancellationToken,
    >,
) {
    match flow_exit(
        gate.as_deref(),
        owner::IPPROTO_TCP,
        accepted.src,
        accepted.dst,
    )
    .await
    {
        FlowExit::Clash => {
            if let Some(dns) = dns {
                run_selected_dns(
                    dns.serve(accepted.conn),
                    #[cfg(all(target_os = "android", feature = "zerotier"))]
                    generation,
                )
                .await;
            } else {
                dispatch_clash_tcp(accepted).await;
            }
        }
        #[cfg(all(target_os = "android", feature = "zerotier"))]
        FlowExit::Direct(_) => {
            let _ = crate::direct_exit::tcp(accepted.conn, accepted.dst).await;
        }
        #[cfg(feature = "zerotier")]
        _ => {}
    }
}

async fn dispatch_clash_tcp(accepted: AcceptedTcp<impl ProxyConn + 'static>) {
    let src_addr = accepted.src;
    let dst_addr = accepted.dst;
    let tunnel = match engine::tunnel() {
        Some(t) => t,
        None => {
            warn!(
                "tun2socks: TCP {} -> {} dropped: engine not running",
                src_addr, dst_addr
            );
            return;
        }
    };

    tracing::debug!("tun2socks: dispatch {} -> {}", src_addr, dst_addr);

    let mut metadata = accepted.metadata();
    apply_flow_owner(tunnel.process_lookup_mode(), &mut metadata, || {
        owner::lookup(owner::IPPROTO_TCP, src_addr, dst_addr)
    })
    .await;

    let proxy_conn: Box<dyn ProxyConn> = Box::new(accepted.conn);
    let inner = tunnel.inner().clone();
    meow_tunnel::tcp::handle_tcp(&inner, proxy_conn, metadata).await;
    tracing::debug!("tun2socks: flow done {} -> {}", src_addr, dst_addr);
}

/// Tag a flow with the app that opened it (see [`owner`]): the uid feeds
/// UID rules, the package name PROCESS-NAME rules and the connections list.
async fn apply_flow_owner<F>(
    mode: meow_common::ProcessLookupMode,
    metadata: &mut Metadata,
    lookup: impl FnOnce() -> F,
) where
    F: std::future::Future<Output = Option<owner::Owner>>,
{
    if engine::android_process_lookup(mode) != meow_common::ProcessLookupMode::Off {
        apply_owner(metadata, lookup().await);
    }
}

fn apply_owner(metadata: &mut Metadata, owner: Option<owner::Owner>) {
    let Some(owner) = owner else {
        metadata.flow_lookup.record_process(None);
        return;
    };
    metadata.uid = Some(owner.uid);
    if let Some(package) = owner.package {
        metadata.process = (&*package).into();
    } else {
        metadata.flow_lookup.record_process(None);
    }
}

struct NetstackConn<S>(S);

impl<S: AsyncRead + Unpin> AsyncRead for NetstackConn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for NetstackConn<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> ProxyConn for NetstackConn<S> {}

// ---------------------------------------------------------------------------
// UDP dispatch
// ---------------------------------------------------------------------------

struct UdpDispatch {
    gate: Option<Arc<ClashGate>>,
    block_app_udp443: bool,
    dns: Option<(Arc<Semaphore>, mpsc::Sender<StackDnsReply>)>,
    reply_tx: mpsc::Sender<UdpDatagram>,
    readers: ReplyReaders,
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    generation: Option<tokio_util::sync::CancellationToken>,
    #[cfg(all(target_os = "android", feature = "zerotier"))]
    direct: Arc<crate::direct_exit::udp::Flows>,
}

async fn dispatch_accepted_udp(packet: UdpDatagram, route: UdpDispatch) {
    let exit = flow_exit(
        route.gate.as_deref(),
        owner::IPPROTO_UDP,
        packet.src,
        packet.dst,
    )
    .await;
    if drop_app_udp(&exit, route.block_app_udp443, packet.dst) {
        return;
    }
    match exit {
        FlowExit::Clash => {
            if let Some((budget, dns_reply)) = route.dns {
                #[cfg(all(target_os = "android", feature = "zerotier"))]
                let reply_generation = route.generation.clone();
                let work = async {
                    let Ok(_permit) = budget.try_acquire() else {
                        warn_dns_burst();
                        return;
                    };
                    if let Ok(Some(bytes)) =
                        tokio::time::timeout(DNS_TASK_TIMEOUT, answer_dns(&packet.payload)).await
                    {
                        let _ = dns_reply.try_send(StackDnsReply {
                            packet: packet.reply(bytes),
                            #[cfg(all(target_os = "android", feature = "zerotier"))]
                            generation: reply_generation,
                        });
                    }
                };
                run_selected_dns(
                    work,
                    #[cfg(all(target_os = "android", feature = "zerotier"))]
                    route.generation,
                )
                .await;
            } else {
                dispatch_udp(packet, route.reply_tx, route.readers).await;
            }
        }
        #[cfg(all(target_os = "android", feature = "zerotier"))]
        FlowExit::Direct(owner) => route.direct.transmit(
            (packet.src, packet.dst),
            owner,
            packet.payload,
            route.reply_tx,
        ),
        #[cfg(feature = "zerotier")]
        _ => {}
    }
}

async fn dispatch_udp(
    packet: UdpDatagram,
    reply_tx: mpsc::Sender<UdpDatagram>,
    reply_readers: ReplyReaders,
) {
    let UdpDatagram { payload, src, dst } = packet;
    let Some(tunnel) = engine::tunnel() else {
        return;
    };
    let inner = tunnel.inner();

    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Inner,
        src_ip: Some(src.ip()),
        src_port: src.port(),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        ..Default::default()
    };

    // Derive the NAT key exactly as `handle_udp` does, so the session it
    // creates is the one found below. An unmapped fake-IP is dropped (#618),
    // and a fake-IP rewritten back to its hostname still needs a real
    // address even when no rule asks for one.
    if matches!(
        inner.pre_handle_metadata(&mut metadata),
        meow_tunnel::PreHandleVerdict::Drop
    ) {
        return;
    }
    inner.pre_resolve(&mut metadata).await;
    if metadata.dst_ip.is_none() && !metadata.host.is_empty() {
        metadata.dst_ip = inner.resolver().resolve_ip_real(&metadata.host).await;
    }
    let Some(resolved_ip) = metadata.dst_ip else {
        return;
    };
    let key = (src, SocketAddr::new(resolved_ip, metadata.dst_port));

    // Rules run once per flow, on the packet that opens its session; the
    // packets after it skip the owner lookup's binder round trip.
    if !inner.nat_table.contains_key(&key) {
        apply_flow_owner(tunnel.process_lookup_mode(), &mut metadata, || {
            owner::lookup(owner::IPPROTO_UDP, src, dst)
        })
        .await;
    }

    meow_tunnel::udp::handle_udp(inner, &payload, src, metadata).await;

    let Some(session) = inner.nat_table.get(&key).map(|r| Arc::clone(r.value())) else {
        return;
    };
    {
        let mut readers = reply_readers.lock();
        if readers
            .get(&key)
            .is_some_and(|served| Arc::ptr_eq(served, &session))
        {
            return;
        }
        readers.insert(key, Arc::clone(&session));
    }

    spawn_udp_reply_reader(
        key,
        session,
        src,
        dst,
        reply_tx,
        reply_readers,
        Arc::clone(inner),
    );
}

fn spawn_udp_reply_reader(
    key: NatKey,
    session: Arc<UdpSession>,
    app_src: SocketAddr,
    app_dst: SocketAddr,
    reply_tx: mpsc::Sender<UdpDatagram>,
    reply_readers: ReplyReaders,
    tunnel_inner: Arc<meow_tunnel::tunnel::TunnelInner>,
) {
    tokio::spawn(async move {
        let relay = relay_udp_replies(&session, app_src, app_dst, &reply_tx);
        tokio::pin!(relay);
        // The read is polled in place rather than raced against a timeout:
        // cancelling a read mid-datagram would desync a stream-framed
        // (Trojan, VLESS, …) packet conn.
        let mut check = tokio::time::interval(UDP_REPLY_CHECK_INTERVAL);
        check.tick().await;
        loop {
            tokio::select! {
                () = &mut relay => break,
                _ = check.tick() => {
                    // Stop once the session left the NAT table (swept, failed
                    // a write, flushed) or went idle both ways.
                    let live = tunnel_inner
                        .nat_table
                        .get(&key)
                        .is_some_and(|s| Arc::ptr_eq(s.value(), &session));
                    if !live || session.idle_for() >= meow_tunnel::udp::DEFAULT_UDP_IDLE {
                        break;
                    }
                }
            }
        }
        // Compare-and-remove: a newer session under the same key keeps its
        // NAT entry and its own reader.
        tunnel_inner
            .nat_table
            .remove_if(&key, |_, s| Arc::ptr_eq(s, &session));
        let mut readers = reply_readers.lock();
        if readers
            .get(&key)
            .is_some_and(|served| Arc::ptr_eq(served, &session))
        {
            readers.remove(&key);
        }
    });
}

const UDP_REPLY_CAPACITY: usize = u16::MAX as usize;

thread_local! {
    // Allocate lazily on the runtime thread, not for every idle NAT flow.
    static NATIVE_UDP_REPLY_SCRATCH: RefCell<Vec<u8>> =
        RefCell::new(vec![0; UDP_REPLY_CAPACITY]);
}

// Native poll cannot retain a caller buffer across Pending. Copy the
// completed payload while borrowed; neither the buffer nor its borrow
// crosses an await, so tasks may migrate between runtime workers.
fn poll_native_udp_payload(
    cx: &mut Context<'_>,
    poll: impl FnOnce(&mut Context<'_>, &mut [u8]) -> Poll<meow_common::Result<(usize, SocketAddr)>>,
) -> Poll<meow_common::Result<Vec<u8>>> {
    NATIVE_UDP_REPLY_SCRATCH.with(|scratch| {
        let mut buf = scratch.borrow_mut();
        poll(cx, &mut buf).map(|result| result.map(|(n, _)| buf[..n].to_vec()))
    })
}

async fn relay_udp_replies(
    session: &UdpSession,
    app_src: SocketAddr,
    app_dst: SocketAddr,
    reply_tx: &mpsc::Sender<UdpDatagram>,
) {
    let forward = |payload| {
        // Replies are activity too: refresh the NAT sweeper's idle clock.
        session.touch();
        reply_tx
            .try_send(UdpDatagram {
                payload,
                src: app_dst,
                dst: app_src,
            })
            .is_ok()
    };
    if let Some(conn) = session.conn.poll_packet_conn_ref() {
        while let Ok(payload) = std::future::poll_fn(|cx| {
            poll_native_udp_payload(cx, |cx, buf| conn.poll_read_packet(cx, buf))
        })
        .await
        {
            if !forward(payload) {
                break;
            }
        }
    } else {
        // An asynchronous stream-framed read may keep partial state and
        // borrow its own buffer across await. Keep it in place and sized
        // for the full UDP payload, as on the native path.
        let mut buf = vec![0; UDP_REPLY_CAPACITY];
        while let Ok((n, _)) = session.conn.read_packet(&mut buf).await {
            if !forward(buf[..n].to_vec()) {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// UDP / IP packet helpers
// ---------------------------------------------------------------------------

struct ParsedUdp<'a> {
    src: SocketAddr,
    dst: SocketAddr,
    payload: &'a [u8],
}

fn parse_udp_packet(ip_data: &[u8]) -> Option<ParsedUdp<'_>> {
    if ip_data.len() < 28 {
        return None;
    }
    if (ip_data[0] >> 4) != 4 {
        return None;
    }
    if ip_data[9] != 17 {
        return None;
    }
    let ihl = (ip_data[0] & 0x0F) as usize * 4;
    let flags = u16::from_be_bytes([ip_data[6], ip_data[7]]);
    if ihl < 20 || ip_data.len() < ihl + 8 || (flags & 0x3fff) != 0 {
        return None;
    }
    let src_port = u16::from_be_bytes([ip_data[ihl], ip_data[ihl + 1]]);
    let dst_port = u16::from_be_bytes([ip_data[ihl + 2], ip_data[ihl + 3]]);
    let udp_len = u16::from_be_bytes([ip_data[ihl + 4], ip_data[ihl + 5]]) as usize;
    let start = ihl + 8;
    let end = (ihl + udp_len).min(ip_data.len());
    if start > end {
        return None;
    }
    let src = Ipv4Addr::new(ip_data[12], ip_data[13], ip_data[14], ip_data[15]);
    let dst = Ipv4Addr::new(ip_data[16], ip_data[17], ip_data[18], ip_data[19]);
    Some(ParsedUdp {
        src: (src, src_port).into(),
        dst: (dst, dst_port).into(),
        payload: &ip_data[start..end],
    })
}

#[cfg(test)]
mod app_gate_tests {
    use super::*;

    #[tokio::test]
    #[cfg(all(feature = "zerotier", not(target_os = "android")))]
    async fn a_missing_owner_never_reaches_a_restricted_clash_egress() {
        let local = "172.19.0.1:54321".parse().unwrap();
        let remote = "172.19.0.2:53".parse().unwrap();
        assert_eq!(
            flow_exit(None, owner::IPPROTO_UDP, local, remote).await,
            FlowExit::Clash
        );
        let gate = AppFilter::Exclude(["com.example.overlay".to_owned()].into());
        for protocol in [owner::IPPROTO_UDP, owner::IPPROTO_TCP] {
            assert_eq!(
                flow_exit(Some(&gate), protocol, local, remote).await,
                FlowExit::Drop
            );
        }
        assert_eq!(
            owner_exit(&gate, &["com.example.overlay"]),
            FlowExit::Direct(vec!["com.example.overlay".into()])
        );
        assert_eq!(
            owner_exit(&gate, &["com.example.overlay", "other"]),
            FlowExit::Drop
        );
        assert_eq!(owner_exit(&gate, &["other"]), FlowExit::Clash);
    }

    #[test]
    fn parses_dns_owner_tuple_and_refuses_fragments() {
        let mut packet = vec![0u8; 29];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&29u16.to_be_bytes());
        packet[9] = 17;
        packet[12..20].copy_from_slice(&[172, 19, 0, 1, 172, 19, 0, 2]);
        packet[20..26].copy_from_slice(&[0xd4, 0x31, 0, 53, 0, 9]);
        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.src, "172.19.0.1:54321".parse().unwrap());
        assert_eq!(parsed.dst, "172.19.0.2:53".parse().unwrap());
        packet[6] = 0x20;
        assert!(parse_udp_packet(&packet).is_none());
    }
}

fn build_udp_reply(orig_ip_data: &[u8], reply_payload: &[u8]) -> Option<Vec<u8>> {
    if orig_ip_data.len() < 28 || (orig_ip_data[0] >> 4) != 4 || orig_ip_data[9] != 17 {
        return None;
    }
    let ihl = (orig_ip_data[0] & 0x0F) as usize * 4;
    if ihl < 20 || orig_ip_data.len() < ihl + 8 {
        return None;
    }
    let total_len = 20u16
        .checked_add(8)
        .and_then(|n| n.checked_add(u16::try_from(reply_payload.len()).ok()?))?;
    let udp_len = 8u16.checked_add(u16::try_from(reply_payload.len()).ok()?)?;

    let mut pkt = Vec::with_capacity(usize::from(total_len));
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0, 0]);
    pkt.extend_from_slice(&[0x40, 0x00]);
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&[0, 0]);
    pkt.extend_from_slice(&orig_ip_data[16..20]); // src = original dst
    pkt.extend_from_slice(&orig_ip_data[12..16]); // dst = original src

    let cksum = ipv4_header_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&cksum.to_be_bytes());

    pkt.extend_from_slice(&orig_ip_data[ihl + 2..ihl + 4]); // src port = original dst port
    pkt.extend_from_slice(&orig_ip_data[ihl..ihl + 2]); // dst port = original src port
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0, 0]);
    pkt.extend_from_slice(reply_payload);

    Some(pkt)
}

fn ipv4_header_checksum(h: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for i in (0..h.len()).step_by(2) {
        s += if i + 1 < h.len() {
            ((h[i] as u32) << 8) | h[i + 1] as u32
        } else {
            (h[i] as u32) << 8
        };
    }
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !s as u16
}

#[cfg(test)]
mod tests {
    #[test]
    fn app_udp443_gate_applies_only_to_the_meow_exit_for_both_address_families() {
        for ip in ["192.0.2.1", "2001:db8::1"] {
            let ip = ip.parse().unwrap();
            for port in [53, 442, 443, 444, 8443] {
                let dst = std::net::SocketAddr::new(ip, port);
                assert_eq!(
                    super::drop_app_udp(&super::FlowExit::Clash, true, dst),
                    port == 443
                );
                assert!(!super::drop_app_udp(&super::FlowExit::Clash, false, dst));
                #[cfg(feature = "zerotier")]
                {
                    let direct = super::FlowExit::Direct(vec!["underlay".into()]);
                    assert!(!super::drop_app_udp(&direct, true, dst));
                    assert!(!super::drop_app_udp(&super::FlowExit::Drop, true, dst));
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "zerotier")]
    fn apply_deadline_and_reader_claim_are_exclusive() {
        let cancelled = CommandClaim::default();
        assert!(cancelled.cancel_before_apply());
        assert!(!cancelled.claim());
        let begun = CommandClaim::default();
        assert!(begun.claim());
        assert!(!begun.cancel_before_apply());
        assert!(!begun.claim());
    }

    #[tokio::test]
    async fn native_reply_scratch_releases_on_pending_and_copies_large_datagrams() {
        let first = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv = |socket: &tokio::net::UdpSocket, cx: &mut Context<'_>| {
            poll_native_udp_payload(cx, |cx, bytes| {
                let mut buf = ReadBuf::new(bytes);
                socket.poll_recv_from(cx, &mut buf).map(|result| {
                    result
                        .map(|addr| (buf.filled().len(), addr))
                        .map_err(Into::into)
                })
            })
        };
        // Drive one flow to Pending before a different flow uses the same
        // thread-local buffer. A legal near-maximum IPv4 UDP reply must fit.
        let mut first_read = std::future::poll_fn(|cx| recv(&first, cx));
        assert!(futures::poll!(&mut first_read).is_pending());
        let payload = vec![0xa5; 65_507];
        sender
            .send_to(&payload, second.local_addr().unwrap())
            .await
            .unwrap();
        let got = std::future::poll_fn(|cx| recv(&second, cx)).await.unwrap();
        sender
            .send_to(b"next", first.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(first_read.await.unwrap(), b"next");
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn full_ingress_queue_does_not_delay_stop() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(vec![1]).await.unwrap();
        let notify = Notify::new();
        let stopped = notify.notified();
        tokio::pin!(stopped);
        let pending = send_ingress(&tx, vec![2], &mut stopped);
        tokio::pin!(pending);
        tokio::select! {
            biased;
            _ = &mut pending => panic!("full queue must wait"),
            _ = tokio::task::yield_now() => {}
        }
        notify.notify_waiters();
        let sent = tokio::time::timeout(Duration::from_millis(100), &mut pending)
            .await
            .expect("stop must cancel a full-queue wait");
        assert!(!sent);
        assert_eq!(rx.recv().await, Some(vec![1]));
        assert!(rx.try_recv().is_err(), "cancelled frame must not be queued");
    }

    #[tokio::test]
    async fn stop_wins_over_a_ready_ingress_queue() {
        let (tx, mut rx) = mpsc::channel(1);
        let notify = Notify::new();
        let stopped = notify.notified();
        tokio::pin!(stopped);
        notify.notify_waiters();
        assert!(!send_ingress(&tx, vec![1], &mut stopped).await);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn ingress_send_preserves_packets_and_reports_closed_queue() {
        let (tx, mut rx) = mpsc::channel(1);
        let notify = Notify::new();
        let stopped = notify.notified();
        tokio::pin!(stopped);
        assert!(send_ingress(&tx, vec![1, 2, 3], &mut stopped).await);
        assert_eq!(rx.recv().await, Some(vec![1, 2, 3]));
        drop(rx);
        assert!(!send_ingress(&tx, vec![4], &mut stopped).await);
    }

    #[test]
    fn nonblocking_setup_preserves_existing_flags() {
        use std::os::fd::AsRawFd;
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd = socket.as_raw_fd();
        let before = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(before >= 0);
        set_nonblocking(fd).unwrap();
        let after = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(after, before | libc::O_NONBLOCK);
        set_nonblocking(fd).unwrap();
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, after);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn setfl_failure_does_not_publish_or_leave_active_session() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let _serial = SERIAL.lock();
        let path = std::ffi::CString::new("/dev/null").unwrap();
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        assert!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) } >= 0);
        let result = start(fd.as_raw_fd(), 1053);
        let published = TUN2SOCKS_TASK.lock().is_some();
        if result.is_ok() {
            stop();
        }
        assert!(result.is_err(), "F_SETFL failure must reach the caller");
        assert!(!published);
        assert!(!TUN2SOCKS_ACTIVE.load(Ordering::SeqCst));
    }

    #[test]
    fn invalid_tun_fd_is_reported_before_session_publication() {
        let _serial = SERIAL.lock();
        let result = start(-1, 1053);
        let published = TUN2SOCKS_TASK.lock().is_some();
        // Clean up the old implementation before asserting its failure.
        if result.is_ok() {
            stop();
        }
        assert!(
            result.is_err(),
            "invalid fd must not report startup success"
        );
        assert!(!published, "failed setup must not publish a session");
        assert!(!TUN2SOCKS_ACTIVE.load(Ordering::SeqCst));
    }

    use super::*;
    use crate::test_support::{dns_query, from_the_profile_nameserver, txt_nameserver, SERIAL};
    use std::time::Instant;

    struct ReplyConn {
        packets: Mutex<std::collections::VecDeque<Vec<u8>>>,
        reject_small_buffer: bool,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyPacketConn for ReplyConn {
        async fn read_packet(&self, buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            let packet = self.packets.lock().pop_front();
            let Some(packet) = packet else {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
            };
            if self.reject_small_buffer && packet.len() > buf.len() {
                return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
            }
            let n = packet.len().min(buf.len());
            buf[..n].copy_from_slice(&packet[..n]);
            Ok((n, "127.0.0.1:53".parse().unwrap()))
        }

        async fn write_packet(&self, _: &[u8], _: &SocketAddr) -> meow_common::Result<usize> {
            unreachable!("reply-only test connection")
        }

        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok("127.0.0.1:40000".parse().unwrap())
        }

        fn close(&self) -> meow_common::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn large_udp_replies_are_intact_and_the_flow_survives() {
        // Cover adapters that truncate and adapters that reject undersized
        // buffers. Include both IP families' maximum payloads and a later
        // small reply on the same flow; neither corruption nor teardown is OK.
        for reject_small_buffer in [false, true] {
            let packets: Vec<Vec<u8>> = [65507, 65527, 4097, 32]
                .into_iter()
                .map(|size| (0..size).map(|i| (i % 251) as u8).collect())
                .collect();
            let session = UdpSession::new(
                Box::new(ReplyConn {
                    packets: Mutex::new(packets.clone().into()),
                    reject_small_buffer,
                }),
                Arc::from("test"),
            );
            let app_src = "172.19.0.2:40000".parse().unwrap();
            let app_dst = "198.51.100.1:53".parse().unwrap();
            let (tx, mut rx) = mpsc::channel(4);
            relay_udp_replies(&session, app_src, app_dst, &tx).await;
            for payload in packets {
                let reply = rx.try_recv().expect("flow lost a reply");
                assert_eq!(reply.payload, payload);
                assert_eq!((reply.src, reply.dst), (app_dst, app_src));
            }
        }
    }

    /// `stop()` runs on JNI threads, which are outside the runtime.
    #[test]
    fn stop_from_a_non_runtime_thread_waits_for_the_session() {
        let _serial = SERIAL.lock();
        let finished = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&finished);
        let handle = crate::get_runtime().spawn(async move {
            while !TUN2SOCKS_STOP_REQUESTED.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            flag.store(true, Ordering::SeqCst);
        });
        *TUN2SOCKS_TASK.lock() = Some(handle);

        stop();

        assert!(finished.load(Ordering::SeqCst));
        TUN2SOCKS_STOP_REQUESTED.store(false, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn accepted_tcp_keeps_original_tuple_and_accepts_non_lwip_io() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (src, dst) in [
            ("192.0.2.3:41000", "198.51.100.7:443"),
            ("[2001:db8::3]:41000", "[2001:db8:1::7]:443"),
        ] {
            let (stream, mut peer) = tokio::io::duplex(16);
            let accepted = AcceptedTcp {
                conn: NetstackConn(stream),
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
            };
            let metadata = accepted.metadata();
            assert_eq!(
                (metadata.src_ip, metadata.src_port),
                (Some(accepted.src.ip()), accepted.src.port())
            );
            assert_eq!(
                (metadata.dst_ip, metadata.dst_port),
                (Some(accepted.dst.ip()), accepted.dst.port())
            );
            let mut proxy: Box<dyn ProxyConn> = Box::new(accepted.conn);
            assert!(proxy.tcp_stream().is_none());
            peer.write_all(b"up").await.unwrap();
            let mut incoming = [0; 2];
            proxy.read_exact(&mut incoming).await.unwrap();
            assert_eq!(&incoming, b"up");
            proxy.write_all(b"ok").await.unwrap();
            proxy.shutdown().await.unwrap();
            let mut reply = Vec::new();
            peer.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"ok");
        }
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn accepted_tcp_dispatch_serves_framed_dns_on_non_lwip_io() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _serial = SERIAL.lock();
        let result = crate::get_runtime().block_on(async {
            let yaml = "dns: {nameserver: ['rcode://refused']}\nrules: [MATCH,DIRECT]\n";
            let stripped = engine::strip_and_inject(yaml, engine::DnsUpstreams::Inherit).unwrap();
            let config = meow_config::load_config_from_str(&stripped).await.unwrap();
            let old = crate::DNS_RESOLVER
                .write()
                .replace(config.dns.resolver_slot);
            let (stream, mut peer) = tokio::io::duplex(512);
            let accepted = AcceptedTcp {
                conn: NetstackConn(stream),
                src: "192.0.2.3:41000".parse().unwrap(),
                dst: "198.51.100.7:53".parse().unwrap(),
            };
            let worker = tokio::spawn(dispatch_accepted_tcp(
                accepted,
                None,
                Some(TcpDnsLimits::new()),
            ));
            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let dns = dns_query("portable.invalid", 16);
                peer.write_u16(u16::try_from(dns.len()).unwrap()).await?;
                peer.write_all(&dns).await?;
                peer.shutdown().await?;
                let n = peer.read_u16().await? as usize;
                let mut reply = vec![0; n];
                peer.read_exact(&mut reply).await?;
                Ok::<_, io::Error>(reply)
            })
            .await;
            drop(peer);
            worker.abort();
            let _ = worker.await;
            *crate::DNS_RESOLVER.write() = old;
            result
        });
        let reply = result.unwrap().unwrap();
        assert_eq!(&reply[..2], &[0x12, 0x34]);
        assert_eq!(reply[3] & 0x0f, 5); // REFUSED from the configured resolver
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn accepted_udp_dns_preserves_reverse_tuple_and_disabled_policy_for_both_families() {
        let _serial = SERIAL.lock();
        let checks = crate::get_runtime().block_on(async {
            assert!(
                engine::tunnel().is_none(),
                "negative case must not dial any engine"
            );
            let yaml = "dns: {nameserver: ['rcode://refused']}\nrules: [MATCH,DIRECT]\n";
            let stripped = engine::strip_and_inject(yaml, engine::DnsUpstreams::Inherit).unwrap();
            let config = meow_config::load_config_from_str(&stripped).await.unwrap();
            let old = crate::DNS_RESOLVER
                .write()
                .replace(config.dns.resolver_slot);
            let mut checks = Vec::new();
            for (src, dst, enabled) in [
                ("192.0.2.3:41000", "198.51.100.7:53", true),
                ("192.0.2.3:41000", "198.51.100.7:53", false),
                ("[2001:db8::3]:41000", "[2001:db8:1::7]:53", true),
                ("[2001:db8::3]:41000", "[2001:db8:1::7]:53", false),
            ] {
                let src = src.parse().unwrap();
                let dst = dst.parse().unwrap();
                let (reply_tx, mut replies) = mpsc::channel(1);
                let (dns_tx, mut dns_replies) = mpsc::channel(1);
                let dns = DnsHijackPolicy::new(enabled)
                    .captures(dst)
                    .then(|| (Arc::new(Semaphore::new(1)), dns_tx));
                dispatch_accepted_udp(
                    UdpDatagram {
                        payload: dns_query("portable.invalid", 16),
                        src,
                        dst,
                    },
                    UdpDispatch {
                        gate: None,
                        block_app_udp443: false,
                        dns,
                        reply_tx,
                        readers: Arc::new(Mutex::new(HashMap::new())),
                    },
                )
                .await;
                checks.push((
                    src,
                    dst,
                    enabled,
                    dns_replies.try_recv().ok(),
                    replies.try_recv().is_err(),
                ));
            }
            *crate::DNS_RESOLVER.write() = old;
            checks
        });
        for (src, dst, enabled, reply, no_ordinary_reply) in checks {
            assert!(no_ordinary_reply);
            assert_eq!(reply.is_some(), enabled);
            if let Some(reply) = reply {
                assert_eq!((reply.packet.src, reply.packet.dst), (dst, src));
                assert_eq!(&reply.packet.payload[..2], &[0x12, 0x34]);
                assert_eq!(reply.packet.payload[3] & 0x0f, 5);
            }
        }
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn native_start_keeps_first_service_hooks_and_can_retry_failed_install() {
        let _serial = SERIAL.lock();
        let (first, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let (second, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let owner = std::cell::Cell::new(None);

        let start_with_hooks = |fd, hook| start_inner(fd, false, DnsHijackPolicy::default(), hook);
        let failure = start_with_hooks(first.as_raw_fd(), || {
            Err("injected protection failure".into())
        });
        assert_eq!(failure.unwrap_err(), "injected protection failure");
        assert!(!TUN2SOCKS_ACTIVE.load(Ordering::SeqCst));

        let start_result =
            start_inner(first.as_raw_fd(), false, DnsHijackPolicy::default(), || {
                owner.set(Some("first"));
                Ok(())
            });
        assert!(start_result.is_ok());
        let duplicate = start_inner(
            second.as_raw_fd(),
            false,
            DnsHijackPolicy::default(),
            || {
                owner.set(Some("second"));
                Ok(())
            },
        );
        let owner_after_duplicate = owner.get();
        assert!(stop());
        assert!(duplicate.is_err());
        assert_eq!(owner_after_duplicate, Some("first"));
    }

    /// A session on one end of a datagram socketpair, which keeps packet
    /// boundaries and polls like a TUN fd. Returns the other end.
    fn start_on_fake_tun() -> (RawFd, RawFd) {
        let mut fds = [0; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        start(fds[0], 0).unwrap();
        // Let the reader get as far as waiting for the fd.
        std::thread::sleep(Duration::from_millis(200));
        (fds[0], fds[1])
    }

    fn stop_and_close((tun, peer): (RawFd, RawFd)) {
        stop();
        unsafe {
            libc::close(tun);
            libc::close(peer);
        }
    }

    /// Voluntary context switches of the runtime's threads so far.
    #[cfg(target_os = "linux")]
    fn worker_wakeups() -> u64 {
        let mut total = 0;
        for task in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
            // "tokio-rt-worker", "tokio-runtime-worker" before tokio 1.50.
            let comm = std::fs::read_to_string(task.path().join("comm")).unwrap_or_default();
            if !comm.starts_with("tokio-") {
                continue;
            }
            let status = std::fs::read_to_string(task.path().join("status")).unwrap_or_default();
            total += status
                .lines()
                .find_map(|l| l.strip_prefix("voluntary_ctxt_switches:"))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0);
        }
        total
    }

    /// An idle VPN must leave the CPU asleep. Polling the fd every 200 µs
    /// cost ~1400 context switches a second here; what remains (~8) is
    /// mostly lwIP's own 250 ms timer.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_idle_session_does_not_wake_the_cpu() {
        let _serial = SERIAL.lock();
        let fds = start_on_fake_tun();

        let before = worker_wakeups();
        std::thread::sleep(Duration::from_secs(1));
        let wakeups = worker_wakeups() - before;

        stop_and_close(fds);
        assert!(wakeups < 50, "{wakeups} worker wakeups in an idle second");
    }

    /// An IPv4 TCP SYN from 172.19.0.2:40000 to 198.51.100.1:80.
    fn tcp_syn() -> Vec<u8> {
        let (src, dst) = ([172, 19, 0, 2], [198, 51, 100, 1]);
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        let sum = ipv4_header_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&sum.to_be_bytes());
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&1u32.to_be_bytes());
        pkt[32] = 0x50; // 20-byte header
        pkt[33] = 0x02; // SYN
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        let mut pseudo = [&src[..], &dst[..], &[0, 6, 0, 20]].concat();
        pseudo.extend_from_slice(&pkt[20..]);
        let sum = ipv4_header_checksum(&pseudo);
        pkt[36..38].copy_from_slice(&sum.to_be_bytes());
        pkt
    }

    /// The reader sleeps until the fd is readable, so a packet must wake it:
    /// lwIP answers the SYN.
    #[test]
    fn a_packet_wakes_the_reader() {
        let _serial = SERIAL.lock();
        let fds = start_on_fake_tun();
        let (_, peer) = fds;

        let syn = tcp_syn();
        let sent = unsafe { libc::write(peer, syn.as_ptr() as *const c_void, syn.len()) };
        assert_eq!(sent, syn.len() as isize);

        let mut pfd = libc::pollfd {
            fd: peer,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, 3000) };
        let mut reply = [0u8; 1500];
        let n = if ready == 1 {
            unsafe { libc::read(peer, reply.as_mut_ptr() as *mut c_void, reply.len()) }
        } else {
            0
        };

        stop_and_close(fds);
        assert!(n >= 40, "no reply to the SYN");
        assert_eq!(reply[9], 6, "not TCP");
        assert_eq!(
            &reply[20..24],
            &[0, 80, 0x9c, 0x40],
            "not from :80 to :40000"
        );
        assert_eq!(reply[33] & 0x12, 0x12, "not a SYN-ACK");
    }

    /// An IPv4 UDP packet from 172.19.0.1:40001 to the VPN's DNS address,
    /// asking for `name`'s records of `qtype`.
    fn dns_query_packet(name: &str, qtype: u16) -> Vec<u8> {
        let dns = dns_query(name, qtype);
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&((28 + dns.len()) as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[172, 19, 0, 1]);
        pkt[16..20].copy_from_slice(&[172, 19, 0, 2]);
        let sum = ipv4_header_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&sum.to_be_bytes());
        pkt[20..22].copy_from_slice(&40001u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&dns);
        pkt
    }

    /// A TXT query — like HTTPS, MX or PTR, not an address — is answered
    /// through the engine's resolver, so it reaches the nameserver the
    /// profile names instead of a fixed pool.
    #[test]
    fn non_address_queries_use_the_engine_upstreams() {
        let _serial = SERIAL.lock();
        let rt = crate::get_runtime();
        let nameserver = rt.block_on(txt_nameserver());
        let profile =
            format!("dns:\n  nameserver: [\"udp://{nameserver}\"]\nrules: [MATCH,DIRECT]\n");
        let stripped = engine::strip_and_inject(&profile, engine::DnsUpstreams::Profile).unwrap();
        let config = rt
            .block_on(meow_config::load_config_from_str(&stripped))
            .unwrap();
        *crate::DNS_RESOLVER.write() = Some(Arc::clone(&config.dns.resolver_slot));
        let fds = start_on_fake_tun();
        let answer = query_fake_tun(fds.1);
        stop_and_close(fds);
        *crate::DNS_RESOLVER.write() = None;
        assert!(from_the_profile_nameserver(&answer));
    }

    #[test]
    fn dns_intercept_uses_the_published_resolver_slot_without_network_io() {
        let _serial = SERIAL.lock();
        let rt = crate::get_runtime();
        let config = |code: &str| {
            let yaml = format!("dns: {{nameserver: ['rcode://{code}']}}\nrules: [MATCH,DIRECT]\n");
            let stripped = engine::strip_and_inject(&yaml, engine::DnsUpstreams::Inherit).unwrap();
            rt.block_on(meow_config::load_config_from_str(&stripped))
                .unwrap()
        };
        let initial = config("refused");
        let slot = initial.dns.resolver_slot;
        *crate::DNS_RESOLVER.write() = Some(Arc::clone(&slot));
        let fds = start_on_fake_tun();
        assert_eq!(query_fake_tun(fds.1)[3] & 0x0f, 5);
        let success = config("success");
        meow_tunnel::Tunnel::new_with_slot(slot)
            .set_resolver(success.dns.resolver, success.dns.enabled);
        assert_eq!(query_fake_tun(fds.1)[3] & 0x0f, 0);
        stop_and_close(fds);
        *crate::DNS_RESOLVER.write() = None;
    }

    fn query_fake_tun(peer: RawFd) -> Vec<u8> {
        let query = dns_query_packet("meow-test.invalid", 16);
        let sent = unsafe { libc::write(peer, query.as_ptr() as *const c_void, query.len()) };
        assert_eq!(sent, query.len() as isize);
        let mut pfd = libc::pollfd {
            fd: peer,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, 5000) };
        let mut reply = [0u8; 1500];
        let n = if ready == 1 {
            unsafe { libc::read(peer, reply.as_mut_ptr() as *mut c_void, reply.len()) }
        } else {
            0
        };

        assert!(n > 28, "no answer to the TXT query");
        let reply = &reply[..n as usize];
        assert_eq!(&reply[20..24], &[0, 53, 0x9c, 0x41]);
        reply[28..].to_vec()
    }

    #[test]
    fn a_closed_tun_peer_returns_an_error_after_cleanup() {
        use std::os::fd::AsRawFd;
        let _serial = SERIAL.lock();
        // Match start_inner's initial state; earlier tests may have called stop().
        TUN2SOCKS_STOP_REQUESTED.store(false, Ordering::SeqCst);
        let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        set_nonblocking(socket.as_raw_fd()).unwrap();
        drop(peer);
        let error = crate::get_runtime()
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(2),
                    run_tun2socks(
                        socket.into(),
                        false,
                        DnsHijackPolicy::default(),
                        #[cfg(all(target_os = "android", feature = "zerotier"))]
                        None,
                        #[cfg(all(target_os = "android", feature = "zerotier"))]
                        None,
                        #[cfg(all(target_os = "android", feature = "zerotier"))]
                        crate::tun_egress::Gate::new(true),
                    ),
                )
                .await
            })
            .expect("closed reader must not leave background tasks waiting")
            .expect_err("EOF must be observable as an error");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// With the reader asleep on an idle fd, stop() has to wake it rather
    /// than wait out TUN2SOCKS_STOP_TIMEOUT.
    #[test]
    fn packet_endpoint_releases_lwip_on_stop_before_same_fd_restart() {
        let _serial = SERIAL.lock();
        let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        for _ in 0..2 {
            start(tun.as_raw_fd(), 0).unwrap();
            assert!(stop());
            assert!(!TUN2SOCKS_ACTIVE.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn stop_wakes_an_idle_reader() {
        let _serial = SERIAL.lock();
        let fds = start_on_fake_tun();

        let started = Instant::now();
        stop_and_close(fds);

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stop took {:?}",
            started.elapsed()
        );
        assert!(!TUN2SOCKS_ACTIVE.load(Ordering::SeqCst));
    }

    #[test]
    fn owner_tags_uid_and_package() {
        let mut metadata = Metadata::default();
        apply_owner(
            &mut metadata,
            Some(owner::Owner {
                uid: 10_123,
                package: Some("com.example.app".into()),
            }),
        );
        assert_eq!(metadata.uid, Some(10_123));
        assert_eq!(metadata.process, "com.example.app");
    }

    #[tokio::test]
    async fn process_mode_controls_owner_lookup_and_rule_results() {
        use meow_common::ProcessLookupMode::{Always, Off};

        let yaml = "mode: rule\nrules: ['PROCESS-NAME,com.example.app,REJECT', 'UID,10123,REJECT', 'MATCH,DIRECT']\n";
        let stripped = engine::strip_and_inject(yaml, engine::DnsUpstreams::Builtin).unwrap();
        let config = meow_config::load_config_from_str(&stripped).await.unwrap();
        let tunnel = meow_tunnel::Tunnel::new(config.dns.resolver);
        tunnel.set_mode(config.general.mode);
        tunnel.update_routing(
            config.proxies,
            config.rules,
            config.sub_rules,
            config.dialer_registry,
        );

        for network in [Network::Tcp, Network::Udp] {
            for (mode, owner, expected) in [
                (Off, Some((10_123, Some("com.example.app"))), "DIRECT"),
                (Always, Some((10_124, Some("com.example.app"))), "REJECT"),
                (Always, Some((10_123, None)), "REJECT"),
                (Always, None, "DIRECT"),
            ] {
                tunnel.set_process_lookup_mode(mode);
                let mut metadata = Metadata {
                    network,
                    dst_ip: Some("192.0.2.53".parse().unwrap()),
                    dst_port: 443,
                    ..Default::default()
                };
                let mut calls = 0;
                apply_flow_owner(tunnel.process_lookup_mode(), &mut metadata, || {
                    calls += 1;
                    std::future::ready(owner.map(|(uid, package)| owner::Owner {
                        uid,
                        package: package.map(Into::into),
                    }))
                })
                .await;
                let selected = tunnel
                    .inner()
                    .resolve_proxy_flow(&mut metadata)
                    .await
                    .unwrap();
                assert_eq!(selected.adapter.name(), expected);
                assert_eq!(calls, usize::from(mode == Always));
            }
        }
    }

    #[test]
    fn owner_without_package_tags_only_uid() {
        let mut metadata = Metadata::default();
        apply_owner(
            &mut metadata,
            Some(owner::Owner {
                uid: 1051,
                package: None,
            }),
        );
        assert_eq!(metadata.uid, Some(1051));
        assert!(metadata.process.is_empty());

        let mut untouched = Metadata::default();
        apply_owner(&mut untouched, None);
        assert_eq!(untouched.uid, None);
        assert!(untouched.process.is_empty());
    }
}
