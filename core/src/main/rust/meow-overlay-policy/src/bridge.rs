//! Bounded IPv4/Ethernet bridge for one authenticated ZeroTier network.
use crate::wire::{self, Arp, Flow, BROADCAST_MAC, ETHER_ARP, ETHER_IPV4};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

const MAX_NEIGHBORS: usize = 256;
const MAX_FLOWS: usize = 4096;
const MAX_PENDING: usize = 128;
const NEIGHBOR_TTL: Duration = Duration::from_secs(60);
const FLOW_TTL: Duration = Duration::from_secs(180);
const ARP_RETRY: Duration = Duration::from_millis(500);
const ARP_WAIT: Duration = Duration::from_millis(2500);
const ARP_RETRY_BATCH: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub struct Ethernet {
    pub from: u64,
    pub to: u64,
    pub kind: u32,
    pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct Inbound {
    pub tun: Option<Vec<u8>>,
    pub frames: Vec<Ethernet>,
}

struct Pending {
    created: Instant,
    last_request: Instant,
    packets: Vec<Vec<u8>>,
}

/// Construct only after the worker knows its assigned IPv4 address and sender
/// MAC. The caller destroys the bridge when authorization or addressing changes.
pub struct Bridge {
    tun: Ipv4Addr,
    assigned: Ipv4Addr,
    local_mac: u64,
    mtu: usize,
    neighbors: HashMap<Ipv4Addr, (u64, Instant)>,
    flows: HashMap<Flow, Instant>,
    pending: HashMap<Ipv4Addr, Pending>,
}

impl Bridge {
    pub fn new(tun: Ipv4Addr, assigned: Ipv4Addr, local_mac: u64, mtu: usize) -> Option<Self> {
        if !unicast(tun)
            || !unicast(assigned)
            || tun == assigned
            || !valid_mac(local_mac)
            || mtu < 68
        {
            return None;
        }
        Some(Self {
            tun,
            assigned,
            local_mac,
            mtu: mtu.min(1500),
            neighbors: HashMap::new(),
            flows: HashMap::new(),
            pending: HashMap::new(),
        })
    }

    pub fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, v| now.duration_since(v.created) < ARP_WAIT);
        self.neighbors
            .retain(|_, (_, at)| now.duration_since(*at) < NEIGHBOR_TTL);
        self.flows
            .retain(|_, at| now.duration_since(*at) < FLOW_TTL);
    }

    /// The caller checks source owner, route and ACL before invoking this.
    pub fn transmit(
        &mut self,
        mut packet: Vec<u8>,
        gateway: Option<Ipv4Addr>,
        now: Instant,
    ) -> Option<Ethernet> {
        let flow = wire::flow(&packet).ok()?;
        let next_hop = gateway.unwrap_or(flow.dst);
        if packet.len() > self.mtu
            || flow.src != self.tun
            || !unicast(flow.dst)
            || !unicast(next_hop)
            || next_hop == self.assigned
        {
            return None;
        }
        let len = wire::translate(&mut packet, true, self.tun, self.assigned).ok()?;
        packet.truncate(len);
        if let Some(&(peer, at)) = self.neighbors.get(&next_hop) {
            if now.duration_since(at) < NEIGHBOR_TTL {
                return self.track_outbound(packet, peer, now);
            }
        }

        // In-flight ARP is rate-limited per next-hop, queue is globally bounded.
        if let Some(pending) = self.pending.get_mut(&next_hop) {
            if now.duration_since(pending.created) < ARP_WAIT {
                if pending.packets.len() < 3 {
                    pending.packets.push(packet);
                }
                return None;
            }
            self.pending.remove(&next_hop);
        }
        if self.pending.len() >= MAX_PENDING {
            return None;
        }
        self.pending.insert(
            next_hop,
            Pending {
                created: now,
                last_request: now,
                packets: vec![packet],
            },
        );
        Some(self.arp_request(next_hop))
    }

    /// Earliest useful retry, excluding entries that expire before it.
    pub fn next_arp_retry(&self, now: Instant) -> Option<Instant> {
        self.pending
            .values()
            .filter_map(|pending| {
                let retry = pending.last_request + ARP_RETRY;
                (retry < pending.created + ARP_WAIT && now < pending.created + ARP_WAIT)
                    .then_some(retry)
            })
            .min()
    }

    /// Retry discovery without depending on the application to send again.
    pub fn retry_arp(&mut self, now: Instant) -> Vec<Ethernet> {
        let targets: Vec<_> = self
            .pending
            .iter_mut()
            .filter_map(|(&target, pending)| {
                if now.duration_since(pending.created) < ARP_WAIT
                    && now.duration_since(pending.last_request) >= ARP_RETRY
                {
                    pending.last_request = now;
                    Some(target)
                } else {
                    None
                }
            })
            .take(ARP_RETRY_BATCH)
            .collect();
        targets
            .into_iter()
            .map(|target| self.arp_request(target))
            .collect()
    }

    fn arp_request(&self, next_hop: Ipv4Addr) -> Ethernet {
        self.arp_to(
            BROADCAST_MAC,
            Arp {
                reply: false,
                sender_mac: self.local_mac,
                sender: self.assigned,
                target_mac: 0,
                target: next_hop,
            },
        )
    }

    pub fn receive(&mut self, frame: Ethernet, now: Instant) -> Inbound {
        if frame.from == self.local_mac || !valid_mac(frame.from) {
            return Inbound::default();
        }
        match frame.kind {
            ETHER_ARP if frame.to == self.local_mac || frame.to == BROADCAST_MAC => {
                self.receive_arp(frame, now)
            }
            ETHER_IPV4 if frame.to == self.local_mac => {
                let Ok(flow) = wire::flow(&frame.payload) else {
                    return Inbound::default();
                };
                if flow.dst != self.assigned
                    || !self
                        .flows
                        .get(&flow)
                        .is_some_and(|seen| now.duration_since(*seen) < FLOW_TTL)
                {
                    return Inbound::default();
                }
                let mut packet = frame.payload;
                let Ok(len) = wire::translate(&mut packet, false, self.assigned, self.tun) else {
                    return Inbound::default();
                };
                packet.truncate(len);
                Inbound {
                    tun: Some(packet),
                    frames: Vec::new(),
                }
            }
            _ => Inbound::default(),
        }
    }

    fn receive_arp(&mut self, frame: Ethernet, now: Instant) -> Inbound {
        let Some(arp) = Arp::parse(&frame.payload) else {
            return Inbound::default();
        };
        if arp.target != self.assigned
            || arp.sender_mac != frame.from
            || !unicast(arp.sender)
            || arp.sender == self.assigned
        {
            return Inbound::default();
        }
        if !arp.reply {
            return Inbound {
                tun: None,
                frames: vec![self.arp_to(
                    arp.sender_mac,
                    Arp {
                        reply: true,
                        sender_mac: self.local_mac,
                        sender: self.assigned,
                        target_mac: arp.sender_mac,
                        target: arp.sender,
                    },
                )],
            };
        }
        if arp.target_mac != self.local_mac || frame.to != self.local_mac {
            return Inbound::default();
        }
        let Some(pending) = self.pending.remove(&arp.sender) else {
            return Inbound::default();
        };
        if now.duration_since(pending.created) >= ARP_WAIT {
            return Inbound::default();
        }
        if self.neighbors.len() >= MAX_NEIGHBORS && !self.neighbors.contains_key(&arp.sender) {
            self.neighbors.clear();
        }
        self.neighbors.insert(arp.sender, (arp.sender_mac, now));
        Inbound {
            tun: None,
            frames: pending
                .packets
                .into_iter()
                .filter_map(|packet| self.track_outbound(packet, arp.sender_mac, now))
                .collect(),
        }
    }

    fn arp_to(&self, to: u64, packet: Arp) -> Ethernet {
        Ethernet {
            from: self.local_mac,
            to,
            kind: ETHER_ARP,
            payload: packet.encode().to_vec(),
        }
    }

    fn track_outbound(&mut self, packet: Vec<u8>, to: u64, now: Instant) -> Option<Ethernet> {
        let return_flow = wire::flow(&packet).ok()?.reverse();
        if !self.flows.contains_key(&return_flow) && self.flows.len() >= MAX_FLOWS {
            return None;
        }
        self.flows.insert(return_flow, now);
        Some(Ethernet {
            from: self.local_mac,
            to,
            kind: ETHER_IPV4,
            payload: packet,
        })
    }
}

fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && ip.octets()[0] < 224
}

fn valid_mac(mac: u64) -> bool {
    mac != 0 && mac < (1 << 48) && mac & (1 << 40) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const TUN: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 1);
    const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 4);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 5);
    const LOCAL_MAC: u64 = 0x021122334455;
    const PEER_MAC: u64 = 0x02aabbccddee;

    fn udp(a: Ipv4Addr, b: Ipv4Addr, ports: [u16; 2]) -> Vec<u8> {
        let mut bytes = vec![0u8; 28];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&a.octets());
        bytes[16..20].copy_from_slice(&b.octets());
        bytes[20..22].copy_from_slice(&ports[0].to_be_bytes());
        bytes[22..24].copy_from_slice(&ports[1].to_be_bytes());
        bytes[24..26].copy_from_slice(&8u16.to_be_bytes());
        bytes
    }

    fn reply(from: u64, payload: Vec<u8>, kind: u32) -> Ethernet {
        Ethernet {
            from,
            to: LOCAL_MAC,
            kind,
            payload,
        }
    }

    #[test]
    fn late_arp_preserves_the_first_datagram_and_retries_without_app_traffic() {
        let now = Instant::now();
        let mut bridge = Bridge::new(TUN, LOCAL, LOCAL_MAC, 1500).unwrap();
        assert!(bridge
            .transmit(udp(TUN, PEER, [1234, 443]), None, now)
            .is_some());
        assert!(bridge.retry_arp(now).is_empty());
        assert_eq!(bridge.next_arp_retry(now), Some(now + ARP_RETRY));
        assert!(bridge.next_arp_retry(now + ARP_WAIT).is_none());
        let retry = bridge.retry_arp(now + ARP_RETRY);
        assert_eq!(retry.len(), 1);
        assert_eq!(Arp::parse(&retry[0].payload).unwrap().target, PEER);
        assert!(bridge.retry_arp(now + ARP_RETRY).is_empty());
        let late = now + ARP_RETRY * 3;
        bridge.expire(late);
        let arp = Arp {
            reply: true,
            sender_mac: PEER_MAC,
            sender: PEER,
            target_mac: LOCAL_MAC,
            target: LOCAL,
        };
        let out = bridge.receive(reply(PEER_MAC, arp.encode().to_vec(), ETHER_ARP), late);
        assert_eq!(out.frames.len(), 1);
        assert_eq!(wire::flow(&out.frames[0].payload).unwrap().src_port, 1234);
        assert!(bridge.retry_arp(late + ARP_RETRY).is_empty());

        let mut bridge = Bridge::new(TUN, LOCAL, LOCAL_MAC, 1500).unwrap();
        assert!(bridge
            .transmit(udp(TUN, PEER, [1234, 443]), None, now)
            .is_some());
        assert!(bridge.retry_arp(now + ARP_WAIT).is_empty());
        let expired = bridge.receive(
            reply(PEER_MAC, arp.encode().to_vec(), ETHER_ARP),
            now + ARP_WAIT,
        );
        assert!(expired.frames.is_empty());
    }

    #[test]
    fn gates_peer_replies_and_routes_a_udp_round_trip() {
        let now = Instant::now();
        let mut bridge = Bridge::new(TUN, LOCAL, LOCAL_MAC, 1500).unwrap();
        let incoming = udp(PEER, LOCAL, [443, 1234]);
        assert!(bridge
            .receive(reply(PEER_MAC, incoming.clone(), ETHER_IPV4), now)
            .tun
            .is_none());
        let arp = bridge
            .transmit(udp(TUN, PEER, [1234, 443]), None, now)
            .unwrap();
        assert_eq!(arp.to, BROADCAST_MAC);
        assert_eq!(Arp::parse(&arp.payload).unwrap().target, PEER);
        assert!(bridge
            .transmit(udp(TUN, PEER, [5678, 443]), None, now)
            .is_none());
        let arp = Arp {
            reply: true,
            sender_mac: PEER_MAC,
            sender: PEER,
            target_mac: LOCAL_MAC,
            target: LOCAL,
        }
        .encode()
        .to_vec();
        assert!(bridge
            .receive(reply(LOCAL_MAC + 2, arp.clone(), ETHER_ARP), now)
            .frames
            .is_empty());
        let out = bridge.receive(reply(PEER_MAC, arp, ETHER_ARP), now);
        assert_eq!(out.frames.len(), 2);
        assert_eq!(wire::flow(&out.frames[0].payload).unwrap().src, LOCAL);
        let received = bridge
            .receive(reply(PEER_MAC, incoming.clone(), ETHER_IPV4), now)
            .tun
            .unwrap();
        assert_eq!(wire::flow(&received).unwrap().dst, TUN);
        let future = now + FLOW_TTL + Duration::from_secs(1);
        bridge.expire(future);
        assert!(bridge
            .receive(reply(PEER_MAC, incoming, ETHER_IPV4), future)
            .tun
            .is_none());
    }
}
