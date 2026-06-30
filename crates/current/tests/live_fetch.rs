//! Live outbound fetch smoke test (real HTTPS + RSS/Atom parse).
//!
//! Runs ONLY when `LIVE_FETCH=1` (it needs outbound internet). When unset it prints a note and
//! returns early, so the default `cargo test` stays network-free + deterministic. This is the
//! one place that exercises the real reqwest + rustls(ring) TLS connector against a live feed:
//!
//! ```text
//! LIVE_FETCH=1 cargo test --test live_fetch -- --nocapture
//! ```

use current::feed::fetch_and_store;
use current::model::Feed;
use current::store::InMemoryStore;
use current::{build_dev_state, now_secs};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetches_and_parses_a_live_feed() {
    if std::env::var("LIVE_FETCH").ok().as_deref() != Some("1") {
        eprintln!("NOTE: LIVE_FETCH != 1 — skipping live network fetch smoke (expected default).");
        return;
    }

    let state = build_dev_state();
    let store = InMemoryStore::new();
    // A couple of stable public feeds; the first that yields items wins (resilient to any one
    // being briefly down).
    let candidates = [
        "https://blog.rust-lang.org/feed.xml",
        "https://hnrss.org/frontpage",
        "https://www.theverge.com/rss/index.xml",
    ];

    let mut total = 0usize;
    for url in candidates {
        let feed = Feed {
            id: "live".into(),
            owner_sub: "u_live".into(),
            url: url.into(),
            title: url.into(),
            last_fetched: None,
            created_at: now_secs(),
        };
        match fetch_and_store(&state.http, &store, &feed, now_secs()).await {
            Ok(n) => {
                eprintln!("fetched {n} items from {url}");
                total = n;
                if n > 0 {
                    break;
                }
            }
            Err(e) => eprintln!("fetch {url} failed: {e}"),
        }
    }
    assert!(total > 0, "expected at least one item from a live feed");
}
