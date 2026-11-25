//! IPv4 at the shared TUN/Ethernet boundary. Validated packets are translated
//! only after policy selects the ZeroTier channel. Do not route a fragment
//! via Clash just because the overlay cannot inspect its flow.
use std::net::Ipv4Addr;

pub const ETHER_IPV4: u32 = 0x0800;
pub const ETHER_ARP: u32 = 0x0806;
pub const BROADCAST_MAC: u64 = 0xffffffffffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
    Echo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flow {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: Transport,
    pub src_port: u16,
    pub dst_port: u16,
}

impl Flow {
    pub fn reverse(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            protocol: self.protocol,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidPacket {
    Header,
    Fragment,
    Transport,
    Address,
}

fn word(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

fn ip(data: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(data[0], data[1], data[2], data[3])
}

struct Packet {
    flow: Flow,
    header: usize,
    total: usize,
    checksum_offset: Option<usize>,
}

fn packet(data: &[u8]) -> Result<Packet, InvalidPacket> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return Err(InvalidPacket::Header);
    }
    let header = (data[0] as usize & 15) * 4;
    let total = usize::from(word(&data[2..4]));
    if header < 20 || total < header || total > data.len() {
        return Err(InvalidPacket::Header);
    }
    if word(&data[6..8]) & 0xbfff != 0 {
        return Err(InvalidPacket::Fragment);
    }
    let segment = &data[header..total];
    let (protocol, src_port, dst_port, checksum) = match data[9] {
        6 if segment.len() >= 20
            && (20..=segment.len()).contains(&(usize::from(segment[12] >> 4) * 4)) =>
        {
            (
                Transport::Tcp,
                word(segment),
                word(&segment[2..]),
                Some(header + 16),
            )
        }
        17 if segment.len() >= 8 && usize::from(word(&segment[4..])) == segment.len() => (
            Transport::Udp,
            word(segment),
            word(&segment[2..]),
            Some(header + 6),
        ),
        1 if segment.len() >= 8 && segment[1] == 0 && matches!(segment[0], 0 | 8) => {
            let id = word(&segment[4..]);
            (Transport::Echo, id, id, None)
        }
        _ => return Err(InvalidPacket::Transport),
    };
    Ok(Packet {
        flow: Flow {
            src: ip(&data[12..16]),
            dst: ip(&data[16..20]),
            protocol,
            src_port,
            dst_port,
        },
        header,
        total,
        checksum_offset: checksum,
    })
}

pub fn flow(data: &[u8]) -> Result<Flow, InvalidPacket> {
    Ok(packet(data)?.flow)
}

pub fn translate(
    data: &mut [u8],
    source_side: bool,
    expected: Ipv4Addr,
    replacement: Ipv4Addr,
) -> Result<usize, InvalidPacket> {
    let parsed = packet(data)?;
    let offset = if source_side { 12 } else { 16 };
    if ip(&data[offset..offset + 4]) != expected {
        return Err(InvalidPacket::Address);
    }

    let old = expected.octets();
    let new = replacement.octets();
    data[offset..offset + 4].copy_from_slice(&new);
    data[10..12].fill(0);
    let result = checksum(&data[..parsed.header]);
    data[10..12].copy_from_slice(&result.to_be_bytes());
    if let Some(pos) = parsed.checksum_offset {
        let old_checksum = word(&data[pos..]);
        if parsed.flow.protocol != Transport::Udp || old_checksum != 0 {
            let value = u32::from(!old_checksum)
                + u32::from(!word(&old))
                + u32::from(!word(&old[2..]))
                + u32::from(word(&new))
                + u32::from(word(&new[2..]));
            let mut result = !fold(value);
            if result == 0 && parsed.flow.protocol == Transport::Udp {
                // Zero denotes a disabled IPv4 UDP checksum, not computed zero.
                result = 0xffff;
            }
            data[pos..pos + 2].copy_from_slice(&result.to_be_bytes());
        }
    }
    Ok(parsed.total)
}

fn fold(mut n: u32) -> u16 {
    while n >> 16 != 0 {
        n = (n & 0xffff) + (n >> 16);
    }
    n as u16
}

fn checksum(data: &[u8]) -> u16 {
    let (pairs, tail) = data.as_chunks::<2>();
    let sum: u32 = pairs
        .iter()
        .map(|&p| u32::from(u16::from_be_bytes(p)))
        .sum();
    !fold(sum + tail.first().map_or(0, |&p| u32::from(p) << 8))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arp {
    pub reply: bool,
    pub sender_mac: u64,
    pub sender: Ipv4Addr,
    pub target_mac: u64,
    pub target: Ipv4Addr,
}

impl Arp {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 || data[..6] != [0, 1, 8, 0, 6, 4] {
            return None;
        }
        let reply = match word(&data[6..]) {
            1 => false,
            2 => true,
            _ => return None,
        };
        let read_mac = |bytes: &[u8]| bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        let sender_mac = read_mac(&data[8..14]);
        if sender_mac == 0 || sender_mac & (1 << 40) != 0 {
            return None;
        }
        Some(Self {
            reply,
            sender_mac,
            sender: ip(&data[14..18]),
            target_mac: read_mac(&data[18..24]),
            target: ip(&data[24..28]),
        })
    }

    pub fn encode(self) -> [u8; 28] {
        let mut out = [0; 28];
        out[..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, if self.reply { 2 } else { 1 }]);
        out[8..14].copy_from_slice(&self.sender_mac.to_be_bytes()[2..]);
        out[14..18].copy_from_slice(&self.sender.octets());
        out[18..24].copy_from_slice(&self.target_mac.to_be_bytes()[2..]);
        out[24..28].copy_from_slice(&self.target.octets());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TUN: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 1);
    const ASSIGNED: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 4);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 5);

    fn pseudo_checksum(pkt: &[u8]) -> u16 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&pkt[12..20]);
        bytes.extend_from_slice(&[0, pkt[9]]);
        bytes.extend_from_slice(&((pkt.len() - 20) as u16).to_be_bytes());
        bytes.extend_from_slice(&pkt[20..]);
        checksum(&bytes)
    }

    fn fixture(tcp: bool) -> Vec<u8> {
        let mut out = vec![0u8; if tcp { 41 } else { 29 }];
        let len = out.len() as u16;
        out[0] = 0x45;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out[8] = 64;
        out[9] = if tcp { 6 } else { 17 };
        out[12..16].copy_from_slice(&TUN.octets());
        out[16..20].copy_from_slice(&PEER.octets());
        out[20..22].copy_from_slice(&1234u16.to_be_bytes());
        out[22..24].copy_from_slice(&443u16.to_be_bytes());
        if tcp {
            out[32] = 0x50;
        } else {
            out[24..26].copy_from_slice(&9u16.to_be_bytes());
        }
        let sum = checksum(&out[..20]);
        out[10..12].copy_from_slice(&sum.to_be_bytes());
        let sum = pseudo_checksum(&out);
        let off = if tcp { 36 } else { 26 };
        out[off..off + 2].copy_from_slice(&sum.to_be_bytes());
        out
    }

    #[test]
    fn ipv4_translation_keeps_tcp_and_udp_checksums_valid() {
        for tcp in [true, false] {
            let original = fixture(tcp);
            let mut data = original.clone();
            assert_eq!(pseudo_checksum(&data), 0);
            assert_eq!(
                translate(&mut data, true, TUN, ASSIGNED),
                Ok(original.len())
            );
            assert_eq!(flow(&data).unwrap().src, ASSIGNED);
            assert_eq!(checksum(&data[..20]), 0);
            assert_eq!(pseudo_checksum(&data), 0);
            translate(&mut data, true, ASSIGNED, TUN).unwrap();
            assert_eq!(data, original);

            // Simulate a peer→assigned datagram, then translate destination.
            let mut data = original.clone();
            translate(&mut data, true, TUN, PEER).unwrap();
            translate(&mut data, false, PEER, ASSIGNED).unwrap();
            translate(&mut data, false, ASSIGNED, TUN).unwrap();
            assert_eq!(flow(&data).unwrap().dst, TUN);
            assert_eq!(pseudo_checksum(&data), 0);
        }
    }

    #[test]
    fn ipv4_translation_does_not_enable_disabled_udp_checksums_or_mutate_invalid_frames() {
        let mut pkt = fixture(false);
        pkt[26..28].fill(0);
        translate(&mut pkt, true, TUN, ASSIGNED).unwrap();
        assert_eq!(&pkt[26..28], &[0, 0]);
        pkt[6] = 0x20;
        let before = pkt.clone();
        assert_eq!(
            translate(&mut pkt, true, ASSIGNED, TUN),
            Err(InvalidPacket::Fragment)
        );
        assert_eq!(pkt, before);
        pkt[6] = 0;
        assert_eq!(
            translate(&mut pkt, true, TUN, ASSIGNED),
            Err(InvalidPacket::Address)
        );
    }

    #[test]
    fn arp_round_trips_and_rejects_multicast_sender() {
        let arp = Arp {
            reply: true,
            sender_mac: 0x021234567890,
            sender: ASSIGNED,
            target_mac: 0xaa0123456789,
            target: PEER,
        };
        assert_eq!(Arp::parse(&arp.encode()), Some(arp));
        let mut malformed = arp.encode();
        malformed[8] |= 1;
        assert_eq!(Arp::parse(&malformed), None);
        assert_eq!(Arp::parse(&malformed[..27]), None);
    }
}
