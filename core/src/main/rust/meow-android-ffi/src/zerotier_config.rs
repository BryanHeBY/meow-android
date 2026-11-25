//! The VPN takes an immutable validated configuration snapshot on start.
use meow_overlay_policy::{
    apps::AppFilter,
    membership::{MoonOrbit, MoonWorldId, NetworkId, NodeAddress, OrbitSource},
    OverlayPolicy, Prefix,
};
use serde::Deserialize;
use std::{collections::BTreeSet, net::Ipv4Addr};

const MAX_ROUTES: usize = 128;
const MAX_MOONS: usize = 32;
const MAX_PACKAGES: usize = 4096;
const MAX_JSON: usize = 256 * 1024;

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    All,
    #[default]
    Allow,
    Exclude,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMoon {
    world: String,
    seed: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    enabled: bool,
    network: String,
    routes: Vec<String>,
    /// Active local LAN routes as observed by the Android VPN owner.
    local_cidrs: Vec<String>,
    app_mode: Mode,
    packages: BTreeSet<String>,
    moons: Vec<RawMoon>,
}

// This type is independent of Android, for host-side validation of the IPC
// input before the native TUN worker opens a UDP socket.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) struct Config {
    pub network: NetworkId,
    pub policy: OverlayPolicy,
    pub filter: AppFilter,
    pub moons: Vec<MoonOrbit>,
}

fn prefix(raw: &str) -> Result<Prefix, &'static str> {
    let (ip, length) = raw.trim().split_once('/').ok_or("expected IPv4 CIDR")?;
    Prefix::new(
        ip.parse().map_err(|_| "invalid IPv4 address")?,
        length.parse().map_err(|_| "invalid prefix length")?,
    )
    .ok_or("prefix length must be 0 to 32")
}

pub(crate) fn parse(json: &[u8]) -> Result<Option<Config>, &'static str> {
    if json.len() > MAX_JSON {
        return Err("ZeroTier settings exceed the size limit");
    }
    let raw: RawConfig = serde_json::from_slice(json).map_err(|_| "invalid ZeroTier settings")?;
    if !raw.enabled {
        return Ok(None);
    }
    if raw.routes.len() > MAX_ROUTES
        || raw.local_cidrs.len() > MAX_ROUTES
        || raw.packages.len() > MAX_PACKAGES
        || raw.moons.len() > MAX_MOONS
    {
        return Err("too many ZeroTier settings entries");
    }
    let network = raw.network.parse().map_err(|_| "invalid network ID")?;
    let authorized = raw
        .routes
        .iter()
        .map(|s| prefix(s))
        .collect::<Result<_, _>>()?;
    let mut conflicts = vec![
        Prefix::new(Ipv4Addr::new(172, 19, 0, 0), 30).expect("valid TUN prefix"),
        Prefix::new(Ipv4Addr::new(28, 0, 0, 0), 8).expect("valid fake-IP prefix"),
    ];
    for route in &raw.local_cidrs {
        conflicts.push(prefix(route)?);
    }
    let policy = OverlayPolicy::new(authorized, &conflicts)
        .map_err(|_| "ZeroTier route is empty, reserved, default, or overlaps a local route")?;
    if !raw.packages.iter().all(|name| {
        !name.is_empty()
            && name.len() <= 255
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
    }) {
        return Err("invalid package in ZeroTier app rules");
    }
    let filter = match raw.app_mode {
        Mode::All => AppFilter::All,
        Mode::Allow => AppFilter::Allow(raw.packages),
        Mode::Exclude => AppFilter::Exclude(raw.packages),
    };
    let mut worlds = BTreeSet::new();
    let mut moons = Vec::with_capacity(raw.moons.len());
    for moon in raw.moons {
        let world =
            MoonWorldId::from_manual_input(&moon.world).map_err(|_| "invalid Moon world ID")?;
        if !worlds.insert(world) {
            return Err("duplicate Moon world ID");
        }
        let source = match moon.seed {
            Some(seed) => OrbitSource::Seed(
                seed.parse::<NodeAddress>()
                    .map_err(|_| "invalid Moon seed")?,
            ),
            None => OrbitSource::ImportedFile,
        };
        moons.push(MoonOrbit { world, source });
    }
    Ok(Some(Config {
        network,
        policy,
        filter,
        moons,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_overlay_policy::Destination;
    use serde_json::json;

    fn settings(routes: &[&str], local: &[&str]) -> serde_json::Value {
        json!({ "enabled": true, "network": "f123456789abcdef", "routes": routes,
            "local_cidrs": local, "app_mode": "allow", "packages": ["com.example.app"],
            "moons": [{"world": "abcdef1234", "seed": "acddedabcd"}] })
    }

    #[test]
    fn validates_enabled_policy_without_expanding_access() {
        assert!(parse(br#"{"enabled":false}"#).unwrap().is_none());
        let config = parse(settings(&["10.8.0.0/24"], &[]).to_string().as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(config.network.sdk_value(), 0xf123456789abcdef);
        assert_eq!(config.moons[0].sdk_args(), (0xabcdef1234, 0xacddedabcd));
        assert!(config.filter.permits_owner(&["com.example.app"]));
        assert!(!config
            .filter
            .permits_owner(&["com.example.app", "com.some.other"]));
        assert_eq!(
            config.policy.classify("10.8.0.7".parse().unwrap(), false),
            Destination::DropOverlayUnavailable
        );
        assert_eq!(
            config.policy.classify("1.1.1.1".parse().unwrap(), false),
            Destination::Clash
        );
    }

    #[test]
    fn rejects_collisions_and_default_routes_before_native_use() {
        for bad in [
            "0.0.0.0/0",
            "28.2.0.0/16",
            "172.19.0.1/32",
            "bad",
            "10.8.1.0/24",
        ] {
            assert!(
                parse(settings(&[bad], &["10.8.0.0/16"]).to_string().as_bytes()).is_err(),
                "{bad}"
            );
        }
        assert!(parse(br#"{"enabled":true}"#).is_err());
    }
}
