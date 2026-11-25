//! Typed ZeroTier client intent. The Android adapter must execute these operations
//! on its node worker; parsing and a successful SDK request are not connectivity.

use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidId;

fn parse_id(input: &str, digits: usize) -> Result<NonZeroU64, InvalidId> {
    let input = input.trim();
    if input.len() != digits || !input.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(InvalidId);
    }
    u64::from_str_radix(input, 16)
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(InvalidId)
}

macro_rules! hex_id {
    ($name:ident, $digits:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(NonZeroU64);

        impl $name {
            pub const fn sdk_value(self) -> u64 {
                self.0.get()
            }
        }

        impl FromStr for $name {
            type Err = InvalidId;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_id(s, $digits).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:0width$x}", self.sdk_value(), width = $digits)
            }
        }
    };
}

hex_id!(NetworkId, 16);
hex_id!(NodeAddress, 10);
hex_id!(MoonWorldId, 16);

impl MoonWorldId {
    /// Accept the short, seed-address-shaped World ID shown by ZeroTier Fix.
    /// A full-width World ID remains distinct from any 40-bit seed address.
    pub fn from_manual_input(input: &str) -> Result<Self, InvalidId> {
        let input = input.trim();
        if input.len() <= 10 {
            parse_id(input, input.len()).map(Self)
        } else {
            input.parse()
        }
    }

    /// The SDK state-store key uses the full World ID, not the seed.
    pub fn state_key(self) -> String {
        format!("moons.d/{self}.moon")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrbitSource {
    Seed(NodeAddress),
    /// A separately verified import must already be staged in the SDK state store.
    ImportedFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoonOrbit {
    pub world: MoonWorldId,
    pub source: OrbitSource,
}

impl MoonOrbit {
    pub fn sdk_args(self) -> (u64, u64) {
        let seed = match self.source {
            OrbitSource::Seed(seed) => seed.sdk_value(),
            OrbitSource::ImportedFile => 0,
        };
        (self.world.sdk_value(), seed)
    }
}

/// Node membership and link usability are deliberately separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkStatus {
    RequestingConfiguration,
    AccessDenied,
    NotFound,
    ClientTooOld,
    AuthenticationRequired,
    Ready,
    Failed,
}

pub fn overlay_ready(
    node_online: bool,
    status: NetworkStatus,
    has_ipv4: bool,
    has_effective_route: bool,
) -> bool {
    node_online && status == NetworkStatus::Ready && has_ipv4 && has_effective_route
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_ids_are_unsigned_exact_width_and_canonical() {
        let network = "  F123456789ABCDEF\n".parse::<NetworkId>().unwrap();
        assert_eq!(network.sdk_value(), 0xf123456789abcdef);
        assert_eq!(network.to_string(), "f123456789abcdef");
        for invalid in [
            "0000000000000000",
            "123456789a",
            "+123456789abcde",
            "０123456789abcde",
        ] {
            assert!(invalid.parse::<NetworkId>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn a_moon_world_and_its_seed_are_independent() {
        let world = MoonWorldId::from_manual_input(" 12ABcd ").unwrap();
        let seed = "aabbccddee".parse::<NodeAddress>().unwrap();
        assert_eq!(world.state_key(), "moons.d/000000000012abcd.moon");
        assert_eq!(
            MoonOrbit {
                world,
                source: OrbitSource::Seed(seed)
            }
            .sdk_args(),
            (0x12abcd, 0xaabbccddee),
        );
        let world = MoonWorldId::from_manual_input("f123456789abcdef").unwrap();
        assert_eq!(
            MoonOrbit {
                world,
                source: OrbitSource::ImportedFile
            }
            .sdk_args(),
            (0xf123456789abcdef, 0),
        );
        for invalid in [
            "",
            "0",
            "123456789ab",
            "0x12345678",
            "../world",
            "fffffffffffffffff",
        ] {
            assert!(
                MoonWorldId::from_manual_input(invalid).is_err(),
                "{invalid}"
            );
        }
        assert!("0000000000".parse::<NodeAddress>().is_err());
        assert!("0000aabbccddee".parse::<NodeAddress>().is_err());
    }

    #[test]
    fn requests_and_authorization_errors_never_enable_forwarding() {
        for status in [
            NetworkStatus::RequestingConfiguration,
            NetworkStatus::AccessDenied,
            NetworkStatus::NotFound,
            NetworkStatus::ClientTooOld,
            NetworkStatus::AuthenticationRequired,
            NetworkStatus::Failed,
        ] {
            assert!(!overlay_ready(true, status, true, true));
        }
        assert!(!overlay_ready(false, NetworkStatus::Ready, true, true));
        assert!(!overlay_ready(true, NetworkStatus::Ready, false, true));
        assert!(!overlay_ready(true, NetworkStatus::Ready, true, false));
        assert!(overlay_ready(true, NetworkStatus::Ready, true, true));
    }
}
