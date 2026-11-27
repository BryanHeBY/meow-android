use meow_api::log_stream::{LogBroadcastLayer, LogLevel, LogMessage};
use std::sync::OnceLock;
use tokio::sync::broadcast;
use tracing_subscriber::{filter::LevelFilter, prelude::*, reload, Registry};

type FilterHandle = reload::Handle<LevelFilter, Registry>;
static FILTER: OnceLock<Option<FilterHandle>> = OnceLock::new();

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LogLevelOverride {
    Debug,
    Info,
    Warning,
    Error,
    Silent,
}

impl LogLevelOverride {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Silent => "silent",
        }
    }
}

pub(crate) fn effective(value: Option<&str>) -> LogLevel {
    value.map_or(LogLevel::Info, meow_api::log_stream::parse_log_level)
}

fn filter(value: Option<&str>) -> LevelFilter {
    match effective(value) {
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warning => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Silent => LevelFilter::OFF,
    }
}

pub(crate) fn install(tx: &broadcast::Sender<LogMessage>) {
    FILTER.get_or_init(|| {
        let (layer, handle) = reload::Layer::new(LevelFilter::INFO);
        tracing_subscriber::registry()
            .with(LogBroadcastLayer { tx: tx.clone() }.with_filter(layer))
            .try_init()
            .ok()
            .map(|()| handle)
    });
}

pub(crate) fn reset() {
    if let Some(handle) = FILTER.get().and_then(Option::as_ref) {
        let _ = handle.reload(LevelFilter::INFO);
    }
}

/// Start owns ENGINE while applying or restoring the broadcast-only filter.
pub(crate) struct StartupLogLevel<'a> {
    handle: Option<&'a FilterHandle>,
    previous: Option<LevelFilter>,
}

impl StartupLogLevel<'static> {
    pub(crate) fn new() -> Self {
        Self::capture(FILTER.get().and_then(Option::as_ref))
    }
}

impl<'a> StartupLogLevel<'a> {
    fn capture(handle: Option<&'a FilterHandle>) -> Self {
        Self {
            handle,
            previous: handle.and_then(|filter| filter.with_current(|level| *level).ok()),
        }
    }

    pub(crate) fn apply(&mut self, value: Option<&str>) {
        if let Some(handle) = self.handle {
            let _ = handle.reload(filter(value));
        }
    }

    pub(crate) fn commit(mut self) {
        self.previous = None;
    }
}

impl Drop for StartupLogLevel<'_> {
    fn drop(&mut self) {
        if let (Some(handle), Some(previous)) = (self.handle, self.previous) {
            let _ = handle.reload(previous);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_obeys_commit_and_failed_start_rollback() {
        let (tx, mut rx) = broadcast::channel(16);
        let (layer, handle) = reload::Layer::new(LevelFilter::INFO);
        let subscriber =
            tracing_subscriber::registry().with(LogBroadcastLayer { tx }.with_filter(layer));
        tracing::subscriber::with_default(subscriber, || {
            fn messages() {
                tracing::debug!("fixture debug");
                tracing::info!("fixture info");
                tracing::warn!("fixture warning");
                tracing::error!("fixture error");
            }
            let mut expect = |levels: &[LogLevel]| {
                assert_eq!(
                    std::iter::from_fn(|| rx.try_recv().ok())
                        .map(|m| m.level)
                        .collect::<Vec<_>>(),
                    levels,
                );
            };
            messages();
            expect(&[LogLevel::Info, LogLevel::Warning, LogLevel::Error]);
            {
                let mut failed_start = StartupLogLevel::capture(Some(&handle));
                failed_start.apply(Some("silent"));
                messages();
                expect(&[]);
            }
            messages();
            expect(&[LogLevel::Info, LogLevel::Warning, LogLevel::Error]);
            let mut successful_start = StartupLogLevel::capture(Some(&handle));
            successful_start.apply(Some("warn"));
            successful_start.commit();
            messages();
            expect(&[LogLevel::Warning, LogLevel::Error]);
            let mut next = StartupLogLevel::capture(Some(&handle));
            next.apply(Some("debug"));
            messages();
            expect(&[
                LogLevel::Debug,
                LogLevel::Info,
                LogLevel::Warning,
                LogLevel::Error,
            ]);
        });
    }
}
