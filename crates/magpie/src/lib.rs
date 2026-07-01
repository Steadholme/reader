//! Magpie — read-later / web clipper for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store + real HTTP fetcher) and [`build_state_from_env`]
//! (env-selected store). Integration tests consume [`app`] directly via `tower::oneshot` and
//! swap in a fake [`fetch::Fetcher`], exactly like the rest of the estate.
//!
//! Endpoints (served at the subdomain ROOT — Sluice forwards the path unmodified):
//! - `GET  /healthz` — liveness (public)
//! - `GET  /` — reading list (filters: all / unread / archived) + save form + bookmarklet
//! - `GET  /clip?u=` — bookmarklet landing: SSO confirm page that POSTs to `/clip`
//! - `POST /clip` — fetch the URL, extract, save -> 302 `/` (CSRF-checked)
//! - `GET  /r/{id}` — clean reader view of the saved text; marks the clip read
//! - `POST /archive/{id}` — toggle archived -> 302 back (CSRF-checked)
//! - `POST /delete/{id}` — delete your own clip -> 302 back (CSRF-checked)

pub mod auth;
pub mod config;
pub mod error;
pub mod extract;
pub mod fetch;
pub mod handlers;
pub mod model;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::config::Config;
use crate::fetch::{Fetcher, HttpFetcher};
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub fetcher: Arc<dyn Fetcher>,
}

/// Build the router wiring all endpoints onto `state`. Routes are explicit (no fallback): the
/// service owns its subdomain, so Sluice forwards these exact paths.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::clips::index))
        .route(
            "/clip",
            get(handlers::clips::clip_form).post(handlers::clips::clip_create),
        )
        .route("/r/{id}", get(handlers::clips::reader))
        .route("/archive/{id}", post(handlers::clips::archive))
        .route("/delete/{id}", post(handlers::clips::delete))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (health/dev).
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

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], and the real [`HttpFetcher`]
/// (so a local `cargo run` can actually clip). Tests reuse this and then swap `store`/`fetcher`.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        fetcher: Arc::new(HttpFetcher::new()),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `MAGPIE_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// The fetcher is always the real [`HttpFetcher`]. Returns an error string on misconfiguration so
/// `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = std::env::var("MAGPIE_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "MAGPIE_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("MAGPIE_STORE=postgres — connecting to database");
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
        other => return Err(format!("unknown MAGPIE_STORE={other} (use memory|postgres)")),
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
        fetcher: Arc::new(HttpFetcher::new()),
    })
}

/// Current wall-clock time in epoch seconds (clip `saved_at` granularity).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Generate a random URL-safe alphanumeric string of `len` characters from a 62-symbol alphabet,
/// via the OS CSPRNG. Used for the short clip id and the CSRF token. The modulo over 62 introduces
/// a negligible bias that is irrelevant for ids/tokens of this size.
pub fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}
