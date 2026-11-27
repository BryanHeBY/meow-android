//! A private prepared Country reader owned by one Android DNS generation.
use crate::dns_override::DnsIssue;
use meow_config::PreparedFallbackGeoIp;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_BYTES: u64 = 128 * 1024 * 1024;

fn read_country(home: &Path) -> anyhow::Result<PreparedFallbackGeoIp> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(home.join("Country.mmdb"))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && (1..=MAX_BYTES).contains(&metadata.len()),
        "invalid bundled Country database size or type"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 == metadata.len(),
        "bundled Country database changed while reading"
    );
    PreparedFallbackGeoIp::from_bytes(bytes)
}

pub(crate) async fn prepare() -> Result<PreparedFallbackGeoIp, DnsIssue> {
    let home = crate::HOME_DIR
        .lock()
        .as_ref()
        .map(PathBuf::from)
        .ok_or(DnsIssue::GeoIpUnavailable)?;
    tokio::task::spawn_blocking(move || read_country(&home))
        .await
        .map_err(|_| DnsIssue::GeoIpUnavailable)?
        .map_err(|_| DnsIssue::GeoIpUnavailable)
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ActivationKey {
    pub profile: i64,
    pub mode: crate::dns_override::DnsUpstreams,
    pub policy: crate::nameserver_policy_override::NameserverPolicyOverride,
}

type Entry = (ActivationKey, PreparedFallbackGeoIp);

struct Transition {
    token: i64,
    candidate: Option<Entry>,
    previous: Option<Entry>,
}

static NEXT_TRANSITION: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1);
static TRANSITION: parking_lot::Mutex<Option<Transition>> = parking_lot::Mutex::new(None);

pub(crate) fn begin() -> i64 {
    let token = NEXT_TRANSITION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    *TRANSITION.lock() = Some(Transition {
        token,
        candidate: None,
        previous: None,
    });
    token
}

pub(crate) fn stage(
    token: i64,
    candidate: Option<Entry>,
    previous: Option<Entry>,
) -> Result<(), DnsIssue> {
    let mut pending = TRANSITION.lock();
    let pending = pending
        .as_mut()
        .filter(|current| current.token == token)
        .ok_or(DnsIssue::ProfileChanged)?;
    pending.candidate = candidate;
    pending.previous = previous;
    Ok(())
}

pub(crate) fn discard(token: i64) {
    let mut pending = TRANSITION.lock();
    if pending
        .as_ref()
        .is_some_and(|current| current.token == token)
    {
        *pending = None;
    }
}

pub(crate) fn transition_reader(
    token: i64,
    key: &ActivationKey,
    recovery: bool,
    consume: bool,
) -> Result<PreparedFallbackGeoIp, DnsIssue> {
    let mut pending = TRANSITION.lock();
    let pending = pending
        .as_mut()
        .filter(|current| current.token == token)
        .ok_or(DnsIssue::ProfileChanged)?;
    let entry = if recovery {
        &mut pending.previous
    } else {
        &mut pending.candidate
    };
    if !entry.as_ref().is_some_and(|(expected, _)| expected == key) {
        // This role can no longer be used after a mismatched attempted
        // activation. The other role still authorizes its exact recovery.
        *entry = None;
        return Err(DnsIssue::ProfileChanged);
    }
    if consume {
        Ok(entry.take().expect("matched pending reader").1)
    } else {
        Ok(entry.as_ref().expect("matched pending reader").1.clone())
    }
}

#[cfg(test)]
#[path = "fallback_geoip_fixture.rs"]
mod fixture;
#[cfg(test)]
pub(crate) use fixture::fixture as test_fixture;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_readers_are_exact_single_use_per_role_and_cancelled_on_supersession() {
        let _serial = crate::test_support::SERIAL.lock();
        let reader = PreparedFallbackGeoIp::from_bytes(test_fixture(true)).unwrap();
        let key = |profile, mode| ActivationKey {
            profile,
            mode,
            policy: Default::default(),
        };
        let first = key(1, crate::dns_override::DnsUpstreams::Profile);
        let next = key(2, crate::dns_override::DnsUpstreams::Builtin);
        let old = begin();
        let token = begin();
        assert!(stage(old, None, None).is_err());
        stage(
            token,
            Some((next.clone(), reader.clone())),
            Some((first.clone(), reader.clone())),
        )
        .unwrap();
        assert!(transition_reader(token, &next, false, false).is_ok()); // preflight
        assert!(transition_reader(token, &next, false, true).is_ok()); // startup
        assert!(transition_reader(token, &next, false, true).is_err());
        assert!(transition_reader(token, &first, true, true).is_ok()); // recovery
        assert!(transition_reader(token, &first, true, true).is_err());
        discard(token);
        assert!(stage(token, None, None).is_err());

        let token = begin();
        stage(
            token,
            Some((next.clone(), reader.clone())),
            Some((first.clone(), reader)),
        )
        .unwrap();
        assert!(transition_reader(token, &first, false, false).is_err()); // cannot spend other role
        assert!(transition_reader(token, &next, false, true).is_err()); // mismatched role invalidated
        assert!(transition_reader(token, &first, true, true).is_ok()); // exact recovery remains
        discard(token);
    }

    // Locally verify an explicitly selected, previously packaged public asset;
    // never reads product home or opens the network.
    #[test]
    #[ignore = "requires previously packaged public Country.mmdb fixture"]
    fn verifies_packaged_country_geoip_fixture() {
        let path = std::env::var_os("MEOWZ_PACKAGED_COUNTRY_FIXTURE").expect("fixture path");
        let bytes = std::fs::read(path).expect("packaged Country DB");
        assert!((1..=MAX_BYTES as usize).contains(&bytes.len()));
        assert!(PreparedFallbackGeoIp::from_bytes(bytes).is_ok());
    }

    #[test]
    fn valid_synthetic_country_reader_can_be_prepared() {
        let home =
            std::env::temp_dir().join(format!("meow-geoip-synthetic-{}", std::process::id()));
        std::fs::create_dir(&home).unwrap();
        let db = home.join("Country.mmdb");
        std::fs::write(&db, test_fixture(false)).unwrap();
        assert!(read_country(&home).is_err());
        std::fs::write(&db, test_fixture(true)).unwrap();
        assert!(read_country(&home).is_ok());
        std::fs::remove_file(db).unwrap();
        std::fs::remove_dir(&home).unwrap();
    }

    #[test]
    fn fails_closed_for_missing_empty_corrupt_or_nonregular_app_owned_data() {
        let home =
            std::env::temp_dir().join(format!("meow-geoip-malformed-{}", std::process::id()));
        std::fs::create_dir(&home).unwrap();
        assert!(read_country(&home).is_err());
        let db = home.join("Country.mmdb");
        std::fs::write(&db, []).unwrap();
        assert!(read_country(&home).is_err());
        std::fs::write(&db, b"not a database").unwrap();
        assert!(read_country(&home).is_err());
        std::fs::remove_file(&db).unwrap();
        std::fs::create_dir(&db).unwrap();
        assert!(read_country(&home).is_err());
        std::fs::remove_dir(&db).unwrap();
        #[cfg(unix)]
        {
            let other = home.join("not-the-fixed-country-file.mmdb");
            std::fs::write(&other, test_fixture(true)).unwrap();
            std::os::unix::fs::symlink(&other, &db).unwrap();
            assert!(read_country(&home).is_err());
            std::fs::remove_file(db).unwrap();
            std::fs::remove_file(other).unwrap();
        }
        std::fs::remove_dir(&home).unwrap();
    }
}
