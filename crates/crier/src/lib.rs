//! Crier — single-user ActivityPub microblog (sovereign fediverse identity) for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides [`build_dev_state`]
//! (in-memory store, audit off) and [`build_state_from_env`] (env-selected store + Watchtower audit).
//! Integration tests consume [`app`] directly via `tower::oneshot`, exactly like the rest of the
//! estate.
//!
//! Crier serves TWO surfaces on one subdomain (`social.w33d.xyz`), split at the Sluice gateway (the
//! cellar/relay precedent — longer/explicit prefixes win):
//!
//! - The WEB surface at `/` is `auth=sso` (gateway-injected `X-Auth-*`): the timeline + a composer.
//!   Crier is internal-only here and trusts the injected identity; it runs no login of its own.
//! - The ActivityPub + WebFinger surface is `auth=public` at the gateway, because remote fediverse
//!   servers (and `webfinger` clients) cannot speak the browser OIDC/cookie SSO. These endpoints
//!   read NO identity headers and are safe to expose:
//!     * `GET  /.well-known/webfinger`        — resolve the `acct:` handle to the actor
//!     * `GET  /users/{name}`                 — the Actor (Person) document
//!     * `GET  /users/{name}/outbox`          — OrderedCollection of public notes
//!     * `GET  /users/{name}/followers`       — followers OrderedCollection
//!     * `GET  /users/{name}/notes/{id}`      — a dereferenceable Note object
//!     * `POST /users/{name}/inbox`           — accept Follow/Create/Undo (best-effort)
//!     * `POST /inbox`                        — instance shared inbox (same handler)
//!     * `GET  /outbox`                       — alias of the single user's outbox
//!
//! Outbound federation delivery (Accept on Follow, Create fan-out) is best-effort and UNSIGNED so it
//! never pulls OpenSSL; the local microblog + actor/outbox JSON are correct regardless of whether
//! any remote ever talks to Crier.

pub mod activitypub;
pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod federation;
pub mod handlers;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / cloneable handles).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub http: reqwest::Client,
    pub audit: AuditSink,
}

/// Build the router wiring both surfaces onto `state`.
///
/// The web routes sit at the service root (Sluice forwards them unmodified under `auth=sso`); the
/// `.well-known` / `/users` / `/inbox` / `/outbox` subtrees are the public ActivityPub surface.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        // --- SSO web surface ---
        .route("/", get(handlers::web::index))
        .route("/api/notes", post(handlers::web::create_note))
        // --- public ActivityPub + WebFinger surface ---
        .route("/.well-known/webfinger", get(handlers::ap::webfinger))
        .route("/users/{name}", get(handlers::ap::actor))
        .route("/users/{name}/outbox", get(handlers::ap::outbox))
        .route("/users/{name}/followers", get(handlers::ap::followers))
        .route("/users/{name}/notes/{id}", get(handlers::ap::note_object))
        .route("/users/{name}/inbox", post(handlers::ap::inbox))
        // Instance shared inbox + a top-level outbox alias (match the public gateway prefixes).
        .route("/inbox", post(handlers::ap::shared_inbox))
        .route("/outbox", get(handlers::ap::outbox_alias))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (public ActivityPub / dev).
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

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], a reqwest client, and a disabled
/// audit sink (no network). Used by `main`'s memory mode and the integration tests, so they need NO
/// database and NO external services.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        http: federation::build_http_client(),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `CRIER_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`. Returns
/// an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = env_nonempty("CRIER_STORE").unwrap_or_else(|| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("DATABASE_URL")
                .ok_or_else(|| "CRIER_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("CRIER_STORE=postgres — connecting to database");
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
        other => return Err(format!("unknown CRIER_STORE={other} (use memory|postgres)")),
    };

    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    tracing::info!(
        actor = %config.actor,
        domain = %config.domain,
        federate = config.federate,
        "crier configured (actor handle {})",
        config.handle()
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        http: federation::build_http_client(),
        audit,
    })
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive).
fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "on" | "true" | "1" | "yes"
    )
}

/// Current wall-clock time in epoch seconds (the note `created_at`).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Monotonic-ish nanosecond counter for note ids + activity-id uniqueness.
pub fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos()
}

/// Format epoch seconds as an RFC3339 / ISO-8601 UTC timestamp (the ActivityPub `published` form,
/// e.g. `2026-06-30T12:00:00Z`). Falls back to the epoch UNIX time on the (impossible) error.
pub fn rfc3339(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| OffsetDateTime::UNIX_EPOCH.format(&Rfc3339).unwrap())
}
