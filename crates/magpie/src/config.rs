//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! pastefire/cortex. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 8980).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8980";

/// Public base URL of this service (used to render the draggable bookmarklet target). The
/// bookmarklet opens `<PUBLIC_BASE_URL>/clip?u=<page>` as a top-level GET so the SameSite=Lax
/// gateway SSO cookie is carried (a cross-site POST would not be authenticated).
pub const DEFAULT_PUBLIC_BASE_URL: &str = "https://clip.w33d.xyz";

/// How many of an owner's clips a reading-list view shows.
pub const LIST_LIMIT: usize = 200;

/// Hard cap on bytes read from a fetched page (the streaming reader stops here). Keeps a single
/// clip bounded regardless of the remote `Content-Length`.
pub const MAX_FETCH_BYTES: usize = 3 * 1024 * 1024;

/// Hard cap on the extracted `content_text`, in characters (post-extraction).
pub const MAX_CONTENT_CHARS: usize = 120_000;

/// Excerpt length, in characters.
pub const EXCERPT_CHARS: usize = 280;

/// Hard cap on a submitted URL, in characters.
pub const MAX_URL_CHARS: usize = 4000;

/// Hard cap on a stored title, in characters.
pub const MAX_TITLE_CHARS: usize = 300;

/// Overall per-request fetch timeout (connect + read), seconds.
pub const FETCH_TIMEOUT_SECS: u64 = 12;

/// Max redirect hops the manual (SSRF-rechecked) redirect loop will follow.
pub const MAX_REDIRECTS: usize = 5;

/// User-Agent the clipper presents to remote servers.
pub const USER_AGENT: &str = "MagpieClipper/0.1 (+https://clip.w33d.xyz)";

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Public base URL (`PUBLIC_BASE_URL`) baked into the bookmarklet.
    pub public_base_url: String,
}

impl Config {
    /// Default development configuration (in-memory, no database, no persistence).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            public_base_url: DEFAULT_PUBLIC_BASE_URL.to_string(),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("PUBLIC_BASE_URL") {
            // Trim a trailing slash so `{base}/clip` never doubles up.
            config.public_base_url = v.trim_end_matches('/').to_string();
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
