//! Runs one native node on a dedicated thread for the lifetime of one VPN.
use crate::{
    zerotier::{Client, Frame},
    zerotier_config::Config,
};
use meow_overlay_policy::{
    Destination, Prefix,
    bridge::{Bridge, Ethernet},
    routes::{NextHop, next_hop},
    wire,
};
use serde::Serialize;
use std::{
    fs,
    io::Read,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const TUN_IP: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 1);
// ZT_VirtualNetworkStatus::ZT_NETWORK_STATUS_OK in the pinned SDK.
const NETWORK_STATUS_OK: i32 = 1;
const IDLE_WAKE: Duration = Duration::from_millis(60);
const MAX_FRAME_BATCH: usize = 128;

#[derive(Clone, Serialize, PartialEq, Eq)]
struct MoonRootStatus {
    address: String,
    recent_rx: bool,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
struct MoonStatus {
    world: String,
    roots: Vec<MoonRootStatus>,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
struct Status {
    phase: &'static str,
    network: String,
    node: Option<String>,
    ip: Option<Ipv4Addr>,
    sdk_status: Option<i32>,
    error: Option<&'static str>,
    moons: Vec<MoonStatus>,
}

pub(crate) struct Worker {
    pub config: Arc<Config>,
    ready: Arc<AtomicBool>,
    quit: Arc<AtomicBool>,
    packets: SyncSender<Vec<u8>>,
    task: Option<JoinHandle<()>>,
}

impl Worker {
    pub(crate) fn start(
        config: Config,
        root: PathBuf,
        tun_out: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> std::io::Result<Self> {
        let config = Arc::new(config);
        let ready = Arc::new(AtomicBool::new(false));
        let quit = Arc::new(AtomicBool::new(false));
        let (packets, incoming) = mpsc::sync_channel(128);
        let thread_state = (config.clone(), ready.clone(), quit.clone());
        let task = thread::Builder::new()
            .name("meowz-zerotier".into())
            .spawn(move || {
                run(thread_state, &root, incoming, &tun_out);
            })?;
        Ok(Self {
            config,
            ready,
            quit,
            packets,
            task: Some(task),
        })
    }

    pub(crate) fn classify(&self, packet: &[u8]) -> Destination {
        self.config
            .policy
            .classify_packet(packet, self.ready.load(Ordering::Acquire))
            .unwrap_or(Destination::DropOverlayUnavailable)
    }

    pub(crate) async fn permits(&self, packet: &[u8]) -> bool {
        use std::net::{SocketAddr, SocketAddrV4};
        let Ok(flow) = wire::flow(packet) else {
            return false;
        };
        if self.config.filter.permits_owner(&[]) {
            return true;
        }
        let protocol = match flow.protocol {
            wire::Transport::Tcp => crate::owner::IPPROTO_TCP,
            wire::Transport::Udp => crate::owner::IPPROTO_UDP,
            wire::Transport::Echo => return false,
        };
        let packages = crate::owner::overlay_packages(
            protocol,
            SocketAddr::V4(SocketAddrV4::new(flow.src, flow.src_port)),
            SocketAddr::V4(SocketAddrV4::new(flow.dst, flow.dst_port)),
        )
        .await;
        let refs: Vec<_> = packages.iter().map(String::as_str).collect();
        self.config.filter.permits_owner(&refs)
    }

    pub(crate) fn transmit(&self, packet: Vec<u8>) {
        let _ = self.packets.try_send(packet);
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.ready.store(false, Ordering::Release);
        self.quit.store(true, Ordering::Release);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn publish(path: &Path, last: &mut Option<Status>, status: &Status) {
    if last.as_ref() == Some(status) {
        return;
    }
    let temp = path.with_extension("tmp");
    if let Ok(bytes) = serde_json::to_vec(status) {
        if fs::write(&temp, bytes).is_ok() && fs::rename(&temp, path).is_ok() {
            *last = Some(status.clone());
        }
    }
}

fn read_moon(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(16_385).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn remove_moon_file(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path).or_else(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(err)
        }
    })
}

fn run(
    (config, ready, quit): (Arc<Config>, Arc<AtomicBool>, Arc<AtomicBool>),
    root: &Path,
    incoming: mpsc::Receiver<Vec<u8>>,
    tun_out: &tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let state_path = root.join("state");
    let status_path = root.join("status.json");
    let mut status = Status {
        phase: "starting",
        network: config.network.to_string(),
        node: None,
        ip: None,
        sdk_status: None,
        error: None,
        moons: Vec::new(),
    };
    let mut last = None;
    publish(&status_path, &mut last, &status);
    let result = (|| -> Result<(), &'static str> {
        fs::create_dir_all(&state_path).map_err(|_| "could not create node state")?;
        let mut client = Client::open(&state_path)?;
        status.node = Some(format!("{:010x}", client.address()));
        let network = config.network.sdk_value();
        let status_code = client.join(network);
        if status_code != 0 {
            return Err("native join request failed");
        }
        let desired: std::collections::BTreeSet<_> =
            config.moons.iter().map(|moon| moon.sdk_args().0).collect();
        for entry in fs::read_dir(&state_path)
            .map_err(|_| "could not read node state")?
            .flatten()
        {
            let name = entry.file_name();
            let retired = name
                .to_str()
                .and_then(|name| name.strip_prefix("moon-"))
                .filter(|raw| raw.len() == 16)
                .and_then(|raw| u64::from_str_radix(raw, 16).ok())
                .filter(|world| *world != 0 && !desired.contains(world));
            if let Some(world) = retired {
                if client.deorbit(world) != 0 {
                    return Err("could not retire cached Moon");
                }
                remove_moon_file(&state_path.join(format!("import-anchor-{world:016x}")))
                    .map_err(|_| "could not retire Moon trust anchor")?;
            }
        }
        for moon in &config.moons {
            let (world, seed) = moon.sdk_args();
            let anchor = state_path.join(format!("import-anchor-{world:016x}"));
            if seed == 0 {
                let path = root.join(format!("imported-{world:016x}.moon"));
                let bytes = read_moon(&path).map_err(|_| "could not read imported Moon")?;
                let changed = read_moon(&anchor).ok().as_ref() != Some(&bytes);
                // A newly approved import must not reuse a cache rooted in an
                // earlier definition with the same ID. Unchanged anchors keep
                // the SDK's authenticated updates instead of resetting to the file.
                if changed && client.deorbit(world) != 0 {
                    return Err("could not replace stale Moon definition");
                }
                if !client.install_moon(world, &bytes) {
                    return Err("imported Moon is not valid for this World ID");
                }
                if changed {
                    let temp = anchor.with_extension("tmp");
                    fs::write(&temp, &bytes)
                        .and_then(|_| fs::rename(&temp, &anchor))
                        .map_err(|_| "could not remember approved Moon definition")?;
                }
            } else if anchor.is_file() {
                if client.deorbit(world) != 0 {
                    return Err("could not retire imported Moon");
                }
                remove_moon_file(&anchor).map_err(|_| "could not retire Moon trust anchor")?;
            }
            if client.orbit(world, seed) != 0 {
                return Err("native Moon orbit request failed");
            }
        }
        let mut bridge = None;
        let mut current = None;
        let mut last_expire = Instant::now();
        let mut routes = Vec::new();
        let mut last_routes = None;
        let mut last_moons = None;
        while !quit.load(Ordering::Acquire) {
            if client.step() != 0 {
                return Err("native ZeroTier transport stopped");
            }
            let view = client.network(network);
            let online = client.online();
            let usable =
                view.filter(|v| online && v.status == NETWORK_STATUS_OK && v.first_ipv4 != 0);
            let next = usable.and_then(|v| {
                let ip = Ipv4Addr::from(v.first_ipv4);
                let subnet = Prefix::new(ip, v.first_ipv4_prefix.try_into().ok()?)?;
                Some((ip, subnet, v.mac, v.mtu as usize))
            });
            let clock = Instant::now();
            let mut routing_changed = false;
            if next.is_none() {
                routes.clear();
                last_routes = None;
            } else if next != current
                || last_routes.is_none_or(|t| clock.duration_since(t) >= Duration::from_secs(1))
            {
                let updated = client.routes(network);
                routing_changed = updated != routes;
                routes = updated;
                last_routes = Some(clock);
            }
            if next != current || routing_changed {
                bridge = next.and_then(|(ip, _, mac, mtu)| {
                    if client.subscribe_arp(network, u32::from(ip)) != 0 {
                        None
                    } else {
                        Bridge::new(TUN_IP, ip, mac, mtu)
                    }
                });
                current = next;
            }
            ready.store(bridge.is_some(), Ordering::Release);
            if last_moons.is_none_or(|then| clock.duration_since(then) >= Duration::from_secs(5)) {
                let wall = crate::zerotier::now() as u64;
                status.moons = config
                    .moons
                    .iter()
                    .map(|moon| {
                        let (world, _) = moon.sdk_args();
                        let roots = client
                            .moon_roots(world)
                            .iter()
                            .map(|root| MoonRootStatus {
                                address: format!("{:010x}", root.address),
                                recent_rx: root.last_receive_ms != 0
                                    && root.last_receive_ms <= wall
                                    && wall - root.last_receive_ms <= 120_000,
                            })
                            .collect();
                        MoonStatus {
                            world: format!("{world:016x}"),
                            roots,
                        }
                    })
                    .collect();
                last_moons = Some(clock);
            }
            status.phase = if bridge.is_some() { "ready" } else { "waiting" };
            status.ip = usable.map(|v| Ipv4Addr::from(v.first_ipv4));
            status.sdk_status = view.map(|v| v.status);
            publish(&status_path, &mut last, &status);

            if let Some(bridge) = bridge.as_mut() {
                let now = Instant::now();
                if now.duration_since(last_expire) >= Duration::from_secs(1) {
                    bridge.expire(now);
                    last_expire = now;
                }
                for request in bridge.retry_arp(now) {
                    send(&mut client, network, request);
                }
                for _ in 0..MAX_FRAME_BATCH {
                    let Ok(frame) = client.receive() else { break };
                    if frame.network != network {
                        continue;
                    }
                    let incoming = bridge.receive(
                        Ethernet {
                            from: frame.from,
                            to: frame.to,
                            kind: frame.kind,
                            payload: frame.data,
                        },
                        now,
                    );
                    if let Some(pkt) = incoming.tun {
                        let _ = tun_out.try_send(pkt);
                    }
                    for reply in incoming.frames {
                        send(&mut client, network, reply);
                    }
                }
            } else {
                // No stale frame may cross an authorization or config boundary.
                while client.receive().is_ok() {}
            }

            match incoming.recv_timeout(IDLE_WAKE) {
                Ok(packet) => {
                    let Some(bridge) = bridge.as_mut() else {
                        continue;
                    };
                    if !config
                        .policy
                        .classify_packet(&packet, true)
                        .is_ok_and(|d| d == Destination::ZeroTier)
                    {
                        continue;
                    }
                    let (Some((local, subnet, _, _)), Ok(flow)) = (current, wire::flow(&packet))
                    else {
                        continue;
                    };
                    let gateway = match next_hop(local, subnet, &routes, flow.dst) {
                        Some(NextHop::OnLink) => None,
                        Some(NextHop::Gateway(ip)) => Some(ip),
                        None => continue,
                    };
                    if let Some(frame) = bridge.transmit(packet, gateway, Instant::now()) {
                        send(&mut client, network, frame);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        Ok(())
    })();
    ready.store(false, Ordering::Release);
    status.phase = if result.is_ok() { "stopped" } else { "failed" };
    status.ip = None;
    status.moons.clear();
    status.error = result.err();
    publish(&status_path, &mut last, &status);
}

fn send(client: &mut Client, network: u64, frame: Ethernet) {
    let _ = client.send(&Frame {
        network,
        from: frame.from,
        to: frame.to,
        kind: frame.kind,
        data: frame.payload,
    });
}
