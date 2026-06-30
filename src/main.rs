//! Reader — one container hosting the HOLDFAST reading surfaces (read-later / RSS).
//!
//! Each surface is its OWN library crate (Magpie/Current), reused verbatim: same schema, same
//! routes, same templates, same OWN database, same subdomain. This binary only adds a **Host-based
//! vhost demux** so the estate runs ONE deployable instead of two. Sluice points `clip.w33d.xyz`
//! and `rss.w33d.xyz` both at this container; each request is dispatched to the matching surface's
//! router by its `Host` header. Because the surfaces keep their exact paths and separate databases,
//! Magpie still clips into its own store and Current still polls feeds into its own — zero behavior
//! change.
//!
//! Both surfaces read `DATABASE_URL` in their own `build_state_from_env`; in ONE process that would
//! collide, so (exactly like Scriptoria) the demux constructs each state EXPLICITLY with its OWN
//! DSN env var: `MAGPIE_DATABASE_URL` for clip, `CURRENT_DATABASE_URL` for rss.
//!
//! `healthcheck` subcommand: a dependency-free loopback `GET /healthz` (host-agnostic) used as the
//! container HEALTHCHECK, so the image needs no curl.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

/// Default listen address — internal-only; Sluice fronts the two subdomains at this upstream.
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8980";

/// The two composed per-surface routers, dispatched by Host. Cheap to clone (each `Router` is
/// `Arc`-backed internally).
#[derive(Clone)]
struct Vhosts {
    clip: Router,
    rss: Router,
}

#[tokio::main]
async fn main() {
    // Container HEALTHCHECK path — handled before any setup, exits the process.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(run_healthcheck());
    }

    tracing_subscriber::fmt::init();

    // Install the ring CryptoProvider process-wide BEFORE building either surface's reqwest client.
    // Current builds its client with reqwest's `-no-provider` feature and relies on this default;
    // installing it up front (idempotent) guarantees both surfaces' outbound HTTPS works regardless
    // of cargo feature unification. Matches the corvid/sqlx/reqwest crypto stack (no openssl).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());

    // Each surface connects to its OWN database and migrates idempotently — exactly what the
    // standalone service did. A failure here is fatal (the surface cannot serve without its DB).
    let clip = build_clip().await.unwrap_or_else(|e| fatal("clip (magpie)", e));
    let rss = build_rss().await.unwrap_or_else(|e| fatal("rss (current)", e));

    let app = Router::new()
        // Host-agnostic liveness for the container HEALTHCHECK + estate probes.
        .route("/healthz", get(|| async { "ok" }))
        .fallback(dispatch)
        .with_state(Vhosts { clip, rss });

    let addr: SocketAddr = bind_addr.parse().expect("invalid BIND_ADDR");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    tracing::info!(%addr, "Reader listening (clip/rss vhost demux)");
    axum::serve(listener, app).await.expect("server error");
}

/// Dispatch one request to the surface matching its `Host` header. An unknown reading host is a
/// 404 — we never silently serve one surface's content under another's vhost.
async fn dispatch(State(v): State<Vhosts>, req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // Match on the leading label (`clip`/`rss`), ignoring any port.
    let label = host
        .split(':')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    let router = match label {
        "clip" => v.clip,
        "rss" => v.rss,
        _ => return (StatusCode::NOT_FOUND, "unknown reading host").into_response(),
    };
    // `Router` is a tower `Service` (the exact `app(state).oneshot(req)` path the surfaces' own
    // tests use); its error type is `Infallible`.
    match router.oneshot(req).await {
        Ok(resp) => resp,
        Err(e) => match e {},
    }
}

/// Build the clip (Magpie) surface router against `MAGPIE_DATABASE_URL`. The fetcher is the real
/// `HttpFetcher` exactly as Magpie's own `build_state_from_env` wires it.
async fn build_clip() -> Result<Router, String> {
    let dsn = require_env("MAGPIE_DATABASE_URL")?;
    let pg = magpie::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("clip (magpie) store ready");
    let state = magpie::AppState {
        config: Arc::new(magpie::config::Config::from_env()),
        store: Arc::new(pg),
        fetcher: Arc::new(magpie::fetch::HttpFetcher::new()),
    };
    Ok(magpie::app(state))
}

/// Build the rss (Current) surface router against `CURRENT_DATABASE_URL`, then spawn its background
/// feed poller (every `FETCH_INTERVAL`) so the merged deployable keeps Current's exact behavior.
/// The `http` client is built exactly as Current's own `build_state_from_env` does.
async fn build_rss() -> Result<Router, String> {
    let dsn = require_env("CURRENT_DATABASE_URL")?;
    let pg = current::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("rss (current) store ready");
    let config = current::config::Config::from_env();
    let http = build_current_http_client(config.fetch_timeout);
    let state = current::AppState {
        config: Arc::new(config),
        store: Arc::new(pg),
        http,
    };
    // Background feed poller (detached; lives for the process lifetime) — exactly as Current's
    // standalone `main` starts it.
    current::spawn_poller(state.clone());
    Ok(current::app(state))
}

/// Build Current's outbound HTTP client — a verbatim copy of Current's private `build_http_client`.
/// Installs the `ring` rustls CryptoProvider process-wide (idempotent) so reqwest's provider-less
/// rustls connector has a backend, then builds the client with Current's exact settings.
fn build_current_http_client(timeout: Duration) -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .user_agent("HOLDFAST-Current/0.1 (+https://rss.w33d.xyz)")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("build reqwest client")
}

/// Read a required env var, returning a descriptive error when unset/empty.
fn require_env(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} is required")),
    }
}

/// Log a fatal startup error for one surface and exit.
fn fatal(surface: &str, err: String) -> ! {
    tracing::error!(surface, error = %err, "failed to build reading surface");
    std::process::exit(1);
}

/// GET `/healthz` over a raw TCP socket on the loopback. Returns the process exit code.
fn run_healthcheck() -> i32 {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let port = bind_addr.rsplit(':').next().unwrap_or("8980");
    let target = format!("127.0.0.1:{port}");
    match healthcheck_once(&target) {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("healthcheck: {target} did not return 200");
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {target} error: {e}");
            1
        }
    }
}

fn healthcheck_once(target: &str) -> std::io::Result<bool> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf.lines().next().unwrap_or("").contains("200"))
}
