//! The VPN takes an immutable validated configuration snapshot on start.
use meow_overlay_policy::{
    apps::AppFilter,
    membership::{MoonOrbit, MoonWorldId, NetworkId, NodeAddress, OrbitSource},
    routes::ManagedRoute,
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

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DnsMode {
    #[default]
    Off,
    Network,
    Custom,
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
    allow_default: bool,
    dns_mode: DnsMode,
    dns_servers: Vec<Ipv4Addr>,
    /// Active local LAN routes as observed by the Android VPN owner.
    local_cidrs: Vec<String>,
    app_mode: Mode,
    packages: BTreeSet<String>,
    clash_app_mode: Option<Mode>,
    clash_packages: BTreeSet<String>,
    moons: Vec<RawMoon>,
}

// This type is independent of Android, for host-side validation of the IPC
// input before the native TUN worker opens a UDP socket.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) struct Config {
    pub network: NetworkId,
    pub policy: OverlayPolicy,
    pub use_managed: bool,
    pub allow_default: bool,
    pub dns_mode: DnsMode,
    pub dns_servers: Vec<Ipv4Addr>,
    conflicts: Vec<Prefix>,
    pub filter: AppFilter,
    pub clash_filter: AppFilter,
    pub moons: Vec<MoonOrbit>,
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
impl Config {
    pub fn acceptable_address(&self, address: Ipv4Addr) -> bool {
        OverlayPolicy::allows_prefix(
            Prefix::new(address, 32).expect("valid host route"),
            &self.conflicts,
        )
    }
    pub fn default_candidate(&self, packet: &[u8]) -> bool {
        self.allow_default
            && packet.first().is_some_and(|v| *v >> 4 == 4)
            && packet
                .get(16..20)
                .is_some_and(|a| self.acceptable_address(Ipv4Addr::new(a[0], a[1], a[2], a[3])))
    }

    /// Controller-assigned on-link prefix and non-default advertised routes.
    /// Conflicting/reserved routes are skipped individually; the network can
    /// still be joined and its eligible routes continue to work.
    pub fn managed_policy(&self, attached: Prefix, routes: &[ManagedRoute]) -> OverlayPolicy {
        let mut accepted = Vec::new();
        for target in std::iter::once(attached).chain(routes.iter().map(|route| route.target)) {
            if !accepted.contains(&target) && OverlayPolicy::allows_prefix(target, &self.conflicts)
            {
                accepted.push(target);
            }
        }
        OverlayPolicy::new(accepted, &self.conflicts)
            .unwrap_or_else(|_| OverlayPolicy::membership_only())
    }
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
        || raw.clash_packages.len() > MAX_PACKAGES
        || raw.moons.len() > MAX_MOONS
        || raw.dns_servers.len() > 2
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
    let use_managed = raw.routes.is_empty();
    let policy = if use_managed {
        OverlayPolicy::membership_only()
    } else {
        OverlayPolicy::new(authorized, &conflicts)
            .map_err(|_| "ZeroTier route is reserved, default, or overlaps a local route")?
    };
    if !raw.packages.iter().chain(&raw.clash_packages).all(|name| {
        !name.is_empty()
            && name.len() <= 255
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
    }) {
        return Err("invalid package in VPN app rules");
    }
    let filter = match raw.app_mode {
        Mode::All => AppFilter::All,
        Mode::Allow => AppFilter::Allow(raw.packages),
        Mode::Exclude => AppFilter::Exclude(raw.packages),
    };
    let clash_filter = match raw.clash_app_mode {
        None | Some(Mode::All) => AppFilter::All,
        Some(Mode::Allow) => AppFilter::Allow(raw.clash_packages),
        Some(Mode::Exclude) => AppFilter::Exclude(raw.clash_packages),
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
        use_managed,
        allow_default: raw.allow_default,
        dns_mode: raw.dns_mode,
        dns_servers: raw.dns_servers,
        conflicts,
        filter,
        clash_filter,
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
    fn decodes_the_two_app_policies_without_granting_crossover() {
        let mut input = settings(&["10.8.0.0/24"], &[]);
        input["clash_app_mode"] = json!("exclude");
        input["clash_packages"] = json!(["com.example.app"]);
        let config = parse(input.to_string().as_bytes()).unwrap().unwrap();
        assert!(config.filter.permits_owner(&["com.example.app"]));
        assert!(!config.clash_filter.permits_owner(&["com.example.app"]));
        assert!(!config
            .clash_filter
            .permits_owner(&["com.example.app", "other"]));
        assert!(!config.clash_filter.permits_owner(&[]));
        assert!(config.clash_filter.permits_owner(&["other"]));
        input["clash_packages"] = json!(["/invalid"]);
        assert!(parse(input.to_string().as_bytes()).is_err());
    }

    #[test]
    fn joins_by_id_and_adopts_only_safe_controller_routes() {
        let config = parse(settings(&[], &["192.168.1.0/24"]).to_string().as_bytes())
            .unwrap()
            .unwrap();
        assert!(config.use_managed);
        assert!(config.policy.prefixes().is_empty());
        let routes = ["0.0.0.0/0", "10.20.0.0/16", "192.168.1.0/24", "28.0.0.0/8"].map(|cidr| {
            ManagedRoute {
                target: prefix(cidr).unwrap(),
                via: None,
            }
        });
        let policy = config.managed_policy(prefix("10.8.0.2/24").unwrap(), &routes);
        let actual: Vec<_> = policy.prefixes().iter().map(ToString::to_string).collect();
        assert_eq!(actual, ["10.8.0.0/24", "10.20.0.0/16"]);
        assert_eq!(
            policy.classify("10.20.0.2".parse().unwrap(), false),
            Destination::DropOverlayUnavailable
        );
        assert_eq!(
            policy.classify("1.1.1.1".parse().unwrap(), true),
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
