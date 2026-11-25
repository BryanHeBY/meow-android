//! Logical per-channel policies, separate from the single Android VPN allowlist.

use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppFilter {
    All,
    Allow(BTreeSet<String>),
    Exclude(BTreeSet<String>),
}

impl AppFilter {
    pub fn permits(&self, package: &str) -> bool {
        match self {
            Self::All => true,
            Self::Allow(packages) => packages.contains(package),
            Self::Exclude(packages) => !packages.contains(package),
        }
    }

    /// Permission is enforced by UID. A shared UID must not inherit a grant
    /// merely because one of its packages is allowed.
    pub fn permits_owner(&self, packages: &[&str]) -> bool {
        if packages.is_empty() {
            return matches!(self, Self::All)
                || matches!(self, Self::Exclude(list) if list.is_empty());
        }
        packages.iter().all(|package| self.permits(package))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VpnCapture {
    None,
    All,
    Allow(BTreeSet<String>),
    Exclude(BTreeSet<String>),
}

/// Compute the union for Android's one application filter. A missing channel
/// is disabled, not unrestricted. None means do not establish a full VPN.
pub fn capture(clash: Option<&AppFilter>, overlay: Option<&AppFilter>) -> VpnCapture {
    use AppFilter::{All, Allow, Exclude};
    let raw = match (clash, overlay) {
        (None, None) => return VpnCapture::None,
        (Some(All), _) | (_, Some(All)) => return VpnCapture::All,
        (Some(Allow(list)), None) | (None, Some(Allow(list))) => VpnCapture::Allow(list.clone()),
        (Some(Exclude(list)), None) | (None, Some(Exclude(list))) => {
            VpnCapture::Exclude(list.clone())
        }
        (Some(Allow(a)), Some(Allow(b))) => VpnCapture::Allow(a.union(b).cloned().collect()),
        (Some(Exclude(a)), Some(Exclude(b))) => {
            VpnCapture::Exclude(a.intersection(b).cloned().collect())
        }
        (Some(Allow(a)), Some(Exclude(b))) | (Some(Exclude(b)), Some(Allow(a))) => {
            VpnCapture::Exclude(b.difference(a).cloned().collect())
        }
    };
    match raw {
        VpnCapture::Allow(list) if list.is_empty() => VpnCapture::None,
        VpnCapture::Exclude(list) if list.is_empty() => VpnCapture::All,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(packages: &[&str]) -> BTreeSet<String> {
        packages.iter().map(|p| (*p).to_owned()).collect()
    }

    fn captures(capture: &VpnCapture, package: &str) -> bool {
        match capture {
            VpnCapture::None => false,
            VpnCapture::All => true,
            VpnCapture::Allow(list) => list.contains(package),
            VpnCapture::Exclude(list) => !list.contains(package),
        }
    }

    #[test]
    fn verifies_union_for_all_whitelist_blacklist_and_disabled_combinations() {
        let configs = [
            None,
            Some(AppFilter::All),
            Some(AppFilter::Allow(names(&[]))),
            Some(AppFilter::Exclude(names(&[]))),
            Some(AppFilter::Allow(names(&["terminal", "ssh"]))),
            Some(AppFilter::Exclude(names(&["terminal", "bank"]))),
            Some(AppFilter::Allow(names(&["bank"]))),
            Some(AppFilter::Exclude(names(&["bank", "browser"]))),
        ];
        for a in &configs {
            for b in &configs {
                let actual = capture(a.as_ref(), b.as_ref());
                for pkg in ["terminal", "ssh", "bank", "browser", "new"] {
                    let expected = a.as_ref().is_some_and(|filter| filter.permits(pkg))
                        || b.as_ref().is_some_and(|filter| filter.permits(pkg));
                    assert_eq!(captures(&actual, pkg), expected, "{a:?} + {b:?}: {pkg}");
                }
            }
        }
    }

    #[test]
    fn empty_whitelist_does_not_become_an_unrestricted_system_vpn() {
        assert_eq!(
            capture(Some(&AppFilter::Allow(names(&[]))), None),
            VpnCapture::None
        );
        assert_eq!(
            capture(None, Some(&AppFilter::Exclude(names(&[])))),
            VpnCapture::All
        );
        assert_eq!(capture(None, None), VpnCapture::None);
    }

    #[test]
    fn union_does_not_grant_an_app_permission_to_both_channels() {
        let clash = AppFilter::Exclude(names(&["terminal", "bank"]));
        let overlay = AppFilter::Allow(names(&["terminal"]));
        assert_eq!(
            capture(Some(&clash), Some(&overlay)),
            VpnCapture::Exclude(names(&["bank"]))
        );
        assert!(!clash.permits_owner(&["terminal"]));
        assert!(overlay.permits_owner(&["terminal"]));
        assert!(clash.permits_owner(&["browser"]));
        assert!(!overlay.permits_owner(&["browser"]));
    }

    #[test]
    fn unknown_and_shared_owners_cannot_inherit_restricted_permissions() {
        let allow = AppFilter::Allow(names(&["terminal"]));
        let exclude = AppFilter::Exclude(names(&["bank"]));
        assert!(!allow.permits_owner(&[]));
        assert!(!exclude.permits_owner(&[]));
        assert!(AppFilter::All.permits_owner(&[]));
        assert!(AppFilter::Exclude(names(&[])).permits_owner(&[]));
        assert!(!allow.permits_owner(&["terminal", "browser"]));
        assert!(!exclude.permits_owner(&["terminal", "bank"]));
        assert!(exclude.permits_owner(&["terminal", "browser"]));
    }
}
