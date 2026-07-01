//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! pastefire/keystone/watchtower. Production overrides each via the environment.

use std::time::Duration;

/// Default listen address (all interfaces, internal-only port 8970).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8970";

/// How many unread items the unified river shows at once (newest-first across all feeds).
pub const RIVER_LIMIT: i64 = 200;

/// How many feeds one owner may subscribe to (a friendly bound; the river join stays cheap).
pub const MAX_FEEDS_PER_OWNER: usize = 500;

/// Hard cap on the entries parsed out of a single fetched feed body (bounds memory + churn).
pub const MAX_ITEMS_PER_FETCH: usize = 200;

/// Hard cap on a fetched feed body, in bytes (a misbehaving server can't exhaust memory).
pub const MAX_FEED_BYTES: usize = 5 * 1024 * 1024;

/// Hard cap on a stored item summary, in characters (post sanitize-to-text).
pub const MAX_SUMMARY_CHARS: usize = 600;

/// Hard cap on a stored item / feed title, in characters.
pub const MAX_TITLE_CHARS: usize = 500;

/// Hard cap on a stored item guid (the dedup key), in characters.
pub const MAX_GUID_CHARS: usize = 512;

/// Hard cap on a submitted feed URL, in characters.
pub const MAX_URL_CHARS: usize = 2048;

/// Hard cap on the `<outline>` feed URLs parsed out of a single imported OPML body (bounds the
/// import work regardless of the per-owner feed cap).
pub const MAX_OPML_OUTLINES: usize = 1000;

/// Number of sentences in an extractive item summary (the inline TL;DR + the summary API).
pub const SUMMARY_SENTENCES: usize = 2;

/// In-app reader: at or below this many characters of stored summary, the reader view treats the
/// item as having "no/short content" and attempts a one-off fetch of the article link to extract
/// the full readable text (cached thereafter).
pub const READER_SHORT_CONTENT_CHARS: usize = 400;

/// In-app reader: hard cap on a fetched article body, in bytes (a misbehaving server can't
/// exhaust memory). Separate from the feed-body cap since article pages are the fetch target.
pub const MAX_ARTICLE_BYTES: usize = 3 * 1024 * 1024;

/// In-app reader: hard cap on the extracted+cached full text, in characters.
pub const MAX_FULLTEXT_CHARS: usize = 40_000;

/// In-app reader: maximum HTTP redirects followed (each hop re-validated by the SSRF guard).
pub const MAX_ARTICLE_REDIRECTS: usize = 5;

/// Cross-source story clustering: overlap-coefficient threshold (0..1) above which two items'
/// title+summary token sets are treated as the same story.
pub const CLUSTER_SIMILARITY: f64 = 0.5;

/// Cross-source story clustering: minimum shared significant tokens required before the overlap
/// coefficient is even considered (guards against a single-word coincidence collapsing items).
pub const CLUSTER_MIN_SHARED: usize = 2;

/// Default poller cadence: how often the background task re-fetches every feed.
pub const DEFAULT_FETCH_INTERVAL_SECS: u64 = 900;

/// Default per-request outbound fetch timeout (connect + read), seconds.
pub const DEFAULT_FETCH_TIMEOUT_SECS: u64 = 15;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Poller cadence (`FETCH_INTERVAL`, seconds).
    pub fetch_interval: Duration,
    /// Per-request outbound fetch timeout (`FETCH_TIMEOUT`, seconds).
    pub fetch_timeout: Duration,
}

impl Config {
    /// Default development configuration (in-memory, no database, no persistence).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            fetch_interval: Duration::from_secs(DEFAULT_FETCH_INTERVAL_SECS),
            fetch_timeout: Duration::from_secs(DEFAULT_FETCH_TIMEOUT_SECS),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(secs) = env_nonempty("FETCH_INTERVAL").and_then(|v| v.parse::<u64>().ok()) {
            if secs > 0 {
                config.fetch_interval = Duration::from_secs(secs);
            }
        }
        if let Some(secs) = env_nonempty("FETCH_TIMEOUT").and_then(|v| v.parse::<u64>().ok()) {
            if secs > 0 {
                config.fetch_timeout = Duration::from_secs(secs);
            }
        }
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
