//! Runs one native node on a dedicated thread for the lifetime of one VPN.
use crate::{
    zerotier::{Client, Frame},
    zerotier_config::{Config, DnsMode},
    zerotier_wake::Wake,
};
use meow_overlay_policy::{
    bridge::{Bridge, Ethernet},
    routes::{next_hop_with_default, NextHop},
    wire, Destination, OverlayPolicy, Prefix,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs,
    io::Read,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender, TryRecvError},
        Arc, RwLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const DNS_STUB: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 2);
const MAX_DNS_FLOWS: usize = 128;
const TUN_IP: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 1);
// ZT_VirtualNetworkStatus::ZT_NETWORK_STATUS_OK in the pinned SDK.
const NETWORK_STATUS_OK: i32 = 1;
const MAINTENANCE: Duration = Duration::from_secs(1);
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
struct PeerStatus {
    address: String,
    role: &'static str,
    latency_ms: Option<i32>,
    recent_rx: bool,
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
    managed_routes: Vec<String>,
    effective_routes: Vec<String>,
    mac: Option<String>,
    mtu: Option<u32>,
    nameservers: Vec<Ipv4Addr>,
    name: Option<String>,
    public: Option<bool>,
    broadcast: Option<bool>,
    bridging: Option<bool>,
    peers: Vec<PeerStatus>,
}

type ManagedPolicy = Arc<RwLock<OverlayPolicy>>;

pub(crate) struct Worker {
    pub config: Arc<Config>,
    ready: Arc<AtomicBool>,
    managed: ManagedPolicy,
    quit: Arc<AtomicBool>,
    packets: SyncSender<Vec<u8>>,
    wake: Arc<Wake>,
    task: Option<JoinHandle<()>>,
}

impl Worker {
    pub(crate) fn start(
        config: Config,
        root: PathBuf,
        tun_out: crate::tun_egress::Tx,
    ) -> std::io::Result<Self> {
        let config = Arc::new(config);
        let ready = Arc::new(AtomicBool::new(false));
        let quit = Arc::new(AtomicBool::new(false));
        let managed = Arc::new(RwLock::new(OverlayPolicy::membership_only()));
        let (packets, incoming) = mpsc::sync_channel(128);
        let wake = Arc::new(Wake::new()?);
        let worker_wake = Arc::clone(&wake);
        let thread_state = (config.clone(), ready.clone(), quit.clone(), managed.clone());
        let task = thread::Builder::new()
            .name("meowz-zerotier".into())
            .spawn(move || {
                run(thread_state, &root, incoming, &tun_out, &worker_wake);
            })?;
        Ok(Self {
            config,
            ready,
            managed,
            quit,
            packets,
            wake,
            task: Some(task),
        })
    }

    pub(crate) fn classify(&self, packet: &[u8]) -> Destination {
        let ready = self.ready.load(Ordering::Acquire);
        let route = if self.config.use_managed {
            self.managed
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .classify_packet(packet, ready)
        } else {
            self.config.policy.classify_packet(packet, ready)
        }
        .unwrap_or(Destination::DropOverlayUnavailable);
        if route == Destination::Clash && self.config.default_candidate(packet) {
            Destination::ZeroTierDefault
        } else {
            route
        }
    }

    pub(crate) fn wants_dns(&self, packet: &[u8]) -> bool {
        self.config.dns_mode != DnsMode::Off && system_dns(packet).is_some()
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
        if self.packets.try_send(packet).is_ok() {
            self.wake.signal();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.ready.store(false, Ordering::Release);
        self.quit.store(true, Ordering::Release);
        self.wake.signal();
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn system_dns(packet: &[u8]) -> Option<wire::Flow> {
    let f = wire::flow(packet).ok()?;
    (f.dst == DNS_STUB
        && f.dst_port == 53
        && matches!(f.protocol, wire::Transport::Tcp | wire::Transport::Udp))
    .then_some(f)
}

fn route_dns(
    mut packet: Vec<u8>,
    query: wire::Flow,
    servers: &[Ipv4Addr],
    flows: &mut HashMap<wire::Flow, Instant>,
    now: Instant,
    next_hop: impl Fn(Ipv4Addr) -> Option<NextHop>,
) -> Option<(Vec<u8>, Option<Ipv4Addr>)> {
    let key = |server| {
        wire::Flow {
            dst: server,
            ..query
        }
        .reverse()
    };
    let existing = servers
        .iter()
        .copied()
        .find(|server| flows.get(&key(*server)).is_some_and(|until| *until > now));
    let server = existing.or_else(|| servers.iter().copied().find(|ip| next_hop(*ip).is_some()))?;
    if flows.len() >= MAX_DNS_FLOWS && existing.is_none() {
        return None;
    }
    let gateway = match next_hop(server)? {
        NextHop::OnLink => None,
        NextHop::Gateway(ip) => Some(ip),
    };
    wire::translate(&mut packet, false, DNS_STUB, server).ok()?;
    flows.insert(key(server), now + Duration::from_secs(60));
    Some((packet, gateway))
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
    (config, ready, quit, managed): (Arc<Config>, Arc<AtomicBool>, Arc<AtomicBool>, ManagedPolicy),
    root: &Path,
    incoming: mpsc::Receiver<Vec<u8>>,
    tun_out: &crate::tun_egress::Tx,
    wake: &Wake,
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
        managed_routes: Vec::new(),
        effective_routes: Vec::new(),
        mac: None,
        mtu: None,
        nameservers: Vec::new(),
        name: None,
        public: None,
        broadcast: None,
        bridging: None,
        peers: Vec::new(),
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
        let mut dns = Vec::new();
        let mut dns_flows = HashMap::new();
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
                dns.clear();
                status.nameservers.clear();
                last_routes = None;
            } else if next != current
                || last_routes.is_none_or(|t| clock.duration_since(t) >= Duration::from_secs(1))
            {
                let updated = client.routes(network);
                routing_changed = updated != routes;
                routes = updated;
                let new_dns = match config.dns_mode {
                    DnsMode::Off => Vec::new(),
                    DnsMode::Network => client.dns_ipv4(network),
                    DnsMode::Custom => config.dns_servers.clone(),
                };
                dns = new_dns
                    .into_iter()
                    .filter(|server| config.acceptable_address(*server))
                    .collect();
                status.nameservers.clone_from(&dns);
                last_routes = Some(clock);
            }
            if next != current || routing_changed {
                ready.store(false, Ordering::Release);
                dns_flows.clear();
                if let Some((_, subnet, _, _)) = next {
                    status.managed_routes = std::iter::once(subnet)
                        .chain(routes.iter().map(|r| r.target))
                        .map(|p| p.to_string())
                        .collect();
                    let policy = if config.use_managed {
                        let computed = config.managed_policy(subnet, &routes);
                        let shown = computed
                            .prefixes()
                            .iter()
                            .map(ToString::to_string)
                            .collect();
                        *managed.write().unwrap_or_else(|p| p.into_inner()) = computed;
                        shown
                    } else {
                        config
                            .policy
                            .prefixes()
                            .iter()
                            .map(ToString::to_string)
                            .collect()
                    };
                    status.effective_routes = policy;
                } else {
                    status.effective_routes.clear();
                }
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
                status.peers = client
                    .peers()
                    .into_iter()
                    .map(|p| PeerStatus {
                        address: format!("{:010x}", p.address),
                        role: match p.role {
                            2 => "PLANET",
                            1 => "MOON",
                            _ => "LEAF",
                        },
                        latency_ms: (p.latency_ms >= 0).then_some(p.latency_ms),
                        recent_rx: p.last_receive_ms != 0
                            && p.last_receive_ms <= wall
                            && wall - p.last_receive_ms <= 120_000,
                    })
                    .collect();
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
            status.mac = view.map(|v| {
                let bytes = v.mac.to_be_bytes();
                bytes[2..]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            });
            status.mtu = view.map(|v| v.mtu).filter(|mtu| *mtu != 0);
            status.name = view.and_then(|v| {
                let len = v.name.iter().position(|x| *x == 0).unwrap_or(v.name.len());
                (len != 0).then(|| String::from_utf8_lossy(&v.name[..len]).into_owned())
            });
            let confirmed = view.filter(|v| v.status == NETWORK_STATUS_OK);
            status.public = confirmed.map(|v| v.flags & 1 != 0);
            status.broadcast = confirmed.map(|v| v.flags & 2 != 0);
            status.bridging = confirmed.map(|v| v.flags & 4 != 0);

            publish(&status_path, &mut last, &status);

            let mut more_frames = false;
            if let Some(bridge) = bridge.as_mut() {
                let now = Instant::now();
                if now.duration_since(last_expire) >= Duration::from_secs(1) {
                    bridge.expire(now);
                    dns_flows.retain(|_, expiry| *expiry > now);
                    last_expire = now;
                }
                for request in bridge.retry_arp(now) {
                    send(&mut client, network, request);
                }
                for i in 0..MAX_FRAME_BATCH {
                    let Ok(frame) = client.receive() else { break };
                    more_frames = i + 1 == MAX_FRAME_BATCH;
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
                    if let Some(mut pkt) = incoming.tun {
                        if wire::flow(&pkt).is_ok_and(|flow| {
                            dns_flows.get(&flow).is_some_and(|expiry| *expiry > now)
                                && wire::translate(&mut pkt, true, flow.src, DNS_STUB).is_err()
                        }) {
                            continue;
                        }
                        tun_out.enqueue(pkt);
                    }
                    for reply in incoming.frames {
                        send(&mut client, network, reply);
                    }
                }
            } else {
                // No stale frame may cross an authorization or config boundary.
                while client.receive().is_ok() {}
            }

            if quit.load(Ordering::Acquire) {
                break;
            }
            let mut message = incoming.try_recv();
            if matches!(message, Err(TryRecvError::Empty)) && !more_frames {
                // No syscalls while draining a burst. Rearm and recheck
                // before poll so enqueue or shutdown cannot be lost.
                wake.clear()
                    .map_err(|_| "could not clear ZeroTier wake signal")?;
                if quit.load(Ordering::Acquire) {
                    break;
                }
                message = incoming.try_recv();
            }
            match message {
                Ok(packet) => {
                    let Some(bridge) = bridge.as_mut() else {
                        continue;
                    };
                    let Some((local, subnet, _, _)) = current else {
                        continue;
                    };
                    let next_hop = |ip| {
                        next_hop_with_default(local, subnet, &routes, ip, config.allow_default)
                    };
                    if let Some(query) =
                        system_dns(&packet).filter(|_| config.dns_mode != DnsMode::Off)
                    {
                        let now = Instant::now();
                        if let Some(frame) =
                            route_dns(packet, query, &dns, &mut dns_flows, now, next_hop)
                                .and_then(|(packet, gateway)| bridge.transmit(packet, gateway, now))
                        {
                            send(&mut client, network, frame);
                        }
                        continue;
                    }
                    let target = if config.use_managed {
                        managed
                            .read()
                            .unwrap_or_else(|p| p.into_inner())
                            .classify_packet(&packet, true)
                    } else {
                        config.policy.classify_packet(&packet, true)
                    };
                    if target != Ok(Destination::ZeroTier)
                        && (target != Ok(Destination::Clash) || !config.default_candidate(&packet))
                    {
                        continue;
                    }
                    let Ok(flow) = wire::flow(&packet) else {
                        continue;
                    };
                    let gateway = match next_hop(flow.dst) {
                        Some(NextHop::OnLink) => None,
                        Some(NextHop::Gateway(ip)) => Some(ip),
                        None => continue,
                    };
                    if let Some(frame) = bridge.transmit(packet, gateway, Instant::now()) {
                        send(&mut client, network, frame);
                    }
                }
                Err(TryRecvError::Empty) if !more_frames => {
                    let (sockets, sdk_wait) = client.poll_state();
                    let bridge_wait = bridge
                        .as_ref()
                        .and_then(|bridge| bridge.next_arp_retry(Instant::now()))
                        .map_or(MAINTENANCE, |at| {
                            at.saturating_duration_since(Instant::now())
                        });
                    wake.wait(sockets, sdk_wait.min(MAINTENANCE).min(bridge_wait))
                        .map_err(|_| "could not wait for ZeroTier socket readiness")?;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => break,
            }
        }
        Ok(())
    })();
    ready.store(false, Ordering::Release);
    status.phase = if result.is_ok() { "stopped" } else { "failed" };
    status.ip = None;
    status.moons.clear();
    status.peers.clear();
    status.effective_routes.clear();
    status.nameservers.clear();
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
