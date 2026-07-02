//! Current — enterprise RSS/Atom feed reader for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], provides [`build_dev_state`]
//! (in-memory store) and [`build_state_from_env`] (env-selected store), and the background feed
//! [`spawn_poller`]. Integration tests consume [`app`] directly via `tower::oneshot`, exactly
//! like the rest of the estate.
//!
//! Endpoints (served at the subdomain ROOT — Sluice forwards the path unmodified):
//! - `GET /healthz` — liveness (public)
//! - `GET /` — the unified river; `?filter=unread|starred|all` toggles the view
//! - `POST /read-all` — mark all read -> 303 `/` (CSRF)
//! - `GET /i/{id}` — open: mark read -> 302 to the article link
//! - `GET /read/{id}` — in-app reader: fetch+extract (SSRF-guarded) + cache full text, mark read
//! - `POST /i/{id}/read` — mark one read -> 303 `/` (CSRF)
//! - `POST /i/{id}/star` — toggle the star/save flag -> 303 `/?filter=…` (CSRF)
//! - `GET /api/item/{id}/summary` — extractive 1–2 sentence summary of an item (JSON)
//! - `GET /feeds` — manage feeds (add form + categories + subscriptions grouped by category)
//! - `POST /feeds` — add a feed by URL -> 303 `/feeds` (CSRF)
//! - `POST /feeds/{id}/delete` — remove a feed -> 303 `/feeds` (CSRF)
//! - `POST /feeds/{id}/category` — assign a feed to a category (or clear) -> 303 `/feeds` (CSRF)
//! - `POST /feeds/{id}/full-content` — toggle per-feed full-content fetch -> 303 `/feeds` (CSRF)
//! - `POST /categories` — create a category -> 303 `/feeds` (CSRF)
//! - `POST /categories/{id}/rename` — rename a category -> 303 `/feeds` (CSRF)
//! - `POST /categories/{id}/delete` — delete a category (feeds uncategorized) -> 303 `/feeds` (CSRF)
//! - `POST /categories/{id}/move` — reorder a category up/down -> 303 `/feeds` (CSRF)
//! - `GET /opml` — export all subscriptions as an OPML document (download)
//! - `POST /opml` — import subscriptions from a pasted OPML document -> 303 `/feeds` (CSRF)

pub mod article;
pub mod auth;
pub mod config;
pub mod error;
pub mod feed;
pub mod handlers;
pub mod model;
pub mod nlp;
pub mod store;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::config::Config;
use crate::store::{InMemoryStore, PgStore, Store};

/// Length of a random feed id (62-symbol alphabet).
pub const FEED_ID_LEN: usize = 12;
/// Length of a random item id (62-symbol alphabet).
pub const ITEM_ID_LEN: usize = 16;

/// Shared application state. Cheap to clone (everything behind `Arc`, and `reqwest::Client` is
/// itself an `Arc` internally).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    /// Outbound HTTP client for the feed poller + the on-add immediate fetch.
    pub http: reqwest::Client,
}

/// Build the router wiring all endpoints onto `state`. Routes are explicit (no fallback): the
/// service owns its subdomain, so Sluice forwards these exact paths.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::river::index))
        .route("/read-all", post(handlers::river::mark_all))
        .route(
            "/i/{id}",
            get(handlers::river::open),
        )
        .route("/i/{id}/read", post(handlers::river::mark_read))
        .route("/i/{id}/star", post(handlers::river::star))
        .route("/read/{id}", get(handlers::reader::read))
        .route(
            "/api/item/{id}/summary",
            get(handlers::river::item_summary),
        )
        .route(
            "/feeds",
            get(handlers::feeds::list).post(handlers::feeds::add),
        )
        .route("/feeds/{id}/delete", post(handlers::feeds::remove))
        .route("/feeds/{id}/category", post(handlers::feeds::assign_category))
        .route(
            "/feeds/{id}/full-content",
            post(handlers::feeds::toggle_full_content),
        )
        .route("/categories", post(handlers::feeds::create_category))
        .route(
            "/categories/{id}/rename",
            post(handlers::feeds::rename_category),
        )
        .route(
            "/categories/{id}/delete",
            post(handlers::feeds::delete_category),
        )
        .route("/categories/{id}/move", post(handlers::feeds::move_category))
        .route(
            "/opml",
            get(handlers::feeds::export_opml).post(handlers::feeds::import_opml),
        )
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (health / dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
}

/// Middleware enforcing [`auth::gateway_identity_ok`] — 401 on a missing/invalid signature.
async fn require_gateway_sig(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if auth::gateway_identity_ok(req.headers()) {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid or missing gateway identity signature",
        )
            .into_response()
    }
}

/// Build the outbound HTTP client. Installs the `ring` rustls CryptoProvider process-wide
/// (idempotent) so reqwest's provider-less rustls connector has a backend — matching the
/// corvid/sqlx crypto stack (no openssl, no aws-lc-rs).
fn build_http_client(timeout: Duration) -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .user_agent("HOLDFAST-Current/0.1 (+https://rss.w33d.xyz)")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("build reqwest client")
}

/// Construct dev state: dev [`Config`] + an empty [`InMemoryStore`] + an HTTP client. Used by
/// `main`'s memory mode and by the integration tests, so they need no database.
pub fn build_dev_state() -> AppState {
    let config = Config::dev();
    let http = build_http_client(config.fetch_timeout);
    AppState {
        config: Arc::new(config),
        store: Arc::new(InMemoryStore::new()),
        http,
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `CURRENT_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();
    let http = build_http_client(config.fetch_timeout);

    let store_kind = std::env::var("CURRENT_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "CURRENT_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("CURRENT_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => return Err(format!("unknown CURRENT_STORE={other} (use memory|postgres)")),
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
        http,
    })
}

/// Spawn the background poller: every `config.fetch_interval`, re-fetch every feed and upsert
/// its new items. A bad/unreachable feed is logged and skipped — it never breaks the loop or a
/// page. The task is detached; it lives for the process lifetime.
pub fn spawn_poller(state: AppState) {
    tokio::spawn(async move {
        let interval = state.config.fetch_interval;
        tracing::info!(secs = interval.as_secs(), "feed poller started");
        loop {
            poll_once(&state).await;
            tokio::time::sleep(interval).await;
        }
    });
}

/// One poll pass over every feed (all owners). Errors per-feed are logged and skipped.
async fn poll_once(state: &AppState) {
    let feeds = match state.store.all_feeds().await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "poller: could not list feeds");
            return;
        }
    };
    for feed in feeds {
        match feed::fetch_and_store(&state.http, state.store.as_ref(), &feed, now_secs()).await {
            Ok(n) if n > 0 => tracing::info!(url = feed.url, new = n, "poller: fetched new items"),
            Ok(_) => {}
            Err(e) => tracing::warn!(url = feed.url, error = %e, "poller: fetch failed (skipped)"),
        }
    }
}

/// Current wall-clock time in epoch seconds (the timestamp granularity for feeds + items).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Generate a random URL-safe alphanumeric string of `len` characters from a 62-symbol
/// alphabet, via the OS CSPRNG. Used for feed/item ids and the CSRF token. The modulo over 62
/// introduces a negligible bias that is irrelevant for ids/tokens of this size.
pub fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}
