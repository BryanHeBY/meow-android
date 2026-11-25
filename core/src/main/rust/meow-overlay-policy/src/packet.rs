use super::{Destination, OverlayPolicy};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    TruncatedOrInconsistentLength,
    UnsupportedVersion,
}

impl OverlayPolicy {
    /// Classify one raw IP packet from Android TUN without decoding TCP/UDP.
    /// Malformed packets must not fall back to a different egress.
    pub fn classify_packet(&self, packet: &[u8], ready: bool) -> Result<Destination, PacketError> {
        use PacketError::{TruncatedOrInconsistentLength as InvalidLength, UnsupportedVersion};
        let first = *packet.first().ok_or(InvalidLength)?;
        match first >> 4 {
            4 => {
                let fixed = packet.get(..20).ok_or(InvalidLength)?;
                let header_len = usize::from(first & 0x0f) * 4;
                let packet_len = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
                if header_len < 20 || header_len > packet_len || packet_len != packet.len() {
                    return Err(InvalidLength);
                }
                let address = Ipv4Addr::new(fixed[16], fixed[17], fixed[18], fixed[19]);
                Ok(self.classify(IpAddr::V4(address), ready))
            }
            // IPv6 routing and parsing remain the existing Clash path.
            6 => Ok(Destination::Clash),
            _ => Err(UnsupportedVersion),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Prefix;

    fn policy() -> OverlayPolicy {
        OverlayPolicy::new(
            vec![Prefix::new(Ipv4Addr::new(10, 77, 0, 0), 16).unwrap()],
            &[],
        )
        .unwrap()
    }

    fn ipv4(dst: [u8; 4], size: u8) -> Vec<u8> {
        let mut packet = vec![0; usize::from(size)];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&u16::from(size).to_be_bytes());
        packet[16..20].copy_from_slice(&dst);
        packet
    }

    #[test]
    fn classifies_by_destination_even_for_non_initial_fragments() {
        let mut fragment = ipv4([10, 77, 0, 12], 28);
        fragment[6..8].copy_from_slice(&[0, 1]);
        fragment[12..16].copy_from_slice(&[203, 0, 113, 2]);
        assert_eq!(
            policy().classify_packet(&fragment, true),
            Ok(Destination::ZeroTier)
        );
        assert_eq!(
            policy().classify_packet(&fragment, false),
            Ok(Destination::DropOverlayUnavailable)
        );
        fragment[12..16].copy_from_slice(&[10, 77, 0, 2]);
        fragment[16..20].copy_from_slice(&[203, 0, 113, 2]);
        assert_eq!(
            policy().classify_packet(&fragment, true),
            Ok(Destination::Clash)
        );
    }

    #[test]
    fn supports_options_but_rejects_invalid_header_or_total_length() {
        let mut packet = ipv4([10, 77, 0, 12], 28);
        packet[0] = 0x46;
        assert_eq!(
            policy().classify_packet(&packet, true),
            Ok(Destination::ZeroTier)
        );
        assert_eq!(
            policy().classify_packet(&packet[..20], true),
            Err(PacketError::TruncatedOrInconsistentLength)
        );
        packet[0] = 0x44;
        assert_eq!(
            policy().classify_packet(&packet, true),
            Err(PacketError::TruncatedOrInconsistentLength)
        );
        packet[0] = 0x47;
        packet[3] = 24;
        assert_eq!(
            policy().classify_packet(&packet, true),
            Err(PacketError::TruncatedOrInconsistentLength)
        );
    }

    #[test]
    fn keeps_ipv6_with_existing_path_and_drops_non_ip() {
        assert_eq!(
            policy().classify_packet(&[0x60; 40], true),
            Ok(Destination::Clash)
        );
        assert_eq!(
            policy().classify_packet(&[0x20; 40], true),
            Err(PacketError::UnsupportedVersion)
        );
        assert_eq!(
            policy().classify_packet(&[], true),
            Err(PacketError::TruncatedOrInconsistentLength)
        );
    }
}
