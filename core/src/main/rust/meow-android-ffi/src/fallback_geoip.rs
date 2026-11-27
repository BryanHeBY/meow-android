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

#[cfg(test)]
#[path = "fallback_geoip_fixture.rs"]
mod fixture;
#[cfg(test)]
pub(crate) use fixture::fixture as test_fixture;

#[cfg(test)]
mod tests {
    use super::*;

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
