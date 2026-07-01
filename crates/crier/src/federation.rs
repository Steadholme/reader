//! Best-effort outbound federation delivery (reqwest + rustls).
//!
//! Everything here is fire-and-forget: handlers spawn these tasks and return immediately, so a slow
//! or unreachable remote NEVER blocks a request and a federation failure NEVER fails the local
//! action that triggered it. Deliveries are UNSIGNED (no HTTP Signatures — that would risk pulling
//! OpenSSL); remotes that demand signed delivery will reject us, which is the documented degraded
//! behaviour. The local microblog + actor/outbox JSON stay fully correct regardless.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::activitypub::{
    accept_activity, create_activity, delete_activity, update_activity, ACTIVITY_JSON,
};
use crate::config::Config;
use crate::store::{Follower, Note, Store};

/// Per-request budget for an outbound delivery / actor fetch.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the shared reqwest client used for all outbound federation (rustls, bounded timeouts so a
/// slow remote can never hang a task indefinitely).
pub fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .user_agent("crier/0.1 (+https://social.w33d.xyz)")
        .build()
        .expect("failed to build reqwest client")
}

/// POST an activity JSON to a remote inbox. Best-effort: returns `Err` on any failure but the caller
/// only logs it. Unsigned (`Content-Type: application/activity+json`).
pub async fn post_activity(
    client: &reqwest::Client,
    inbox_url: &str,
    body: &Value,
) -> Result<(), String> {
    let resp = client
        .post(inbox_url)
        .header(reqwest::header::CONTENT_TYPE, ACTIVITY_JSON)
        .header(reqwest::header::ACCEPT, ACTIVITY_JSON)
        .json(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("remote inbox returned {status}"))
    }
}

/// Dereference a remote actor document and pull out its inbox URL (preferring `endpoints.sharedInbox`
/// is intentionally NOT done — we deliver to the personal inbox for correctness). Best-effort.
pub async fn resolve_inbox(client: &reqwest::Client, actor_url: &str) -> Option<String> {
    let resp = client
        .get(actor_url)
        .header(reqwest::header::ACCEPT, ACTIVITY_JSON)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let doc: Value = resp.json().await.ok()?;
    doc.get("inbox")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Handle an inbound `Follow`: resolve the follower's inbox, persist it, and deliver an `Accept`.
/// Spawned by the inbox handler; all failures are logged only. The follower row was already
/// recorded (with an empty inbox) by the handler, so the followers collection is correct even if
/// this delivery never lands.
pub async fn accept_follow(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    follower_actor: String,
    follow_activity: Value,
    stamp: String,
) {
    let Some(inbox) = resolve_inbox(&client, &follower_actor).await else {
        tracing::warn!(actor = %follower_actor, "could not resolve follower inbox — Accept skipped");
        return;
    };

    // Persist the resolved inbox so future note fan-out can reach this follower.
    let now = crate::now_secs();
    if let Err(e) = store
        .add_follower(&Follower {
            actor: follower_actor.clone(),
            inbox_url: inbox.clone(),
            created_at: now,
        })
        .await
    {
        tracing::warn!(actor = %follower_actor, error = %e, "failed to persist follower inbox");
    }

    let accept = accept_activity(&cfg, &follow_activity, &stamp);
    match post_activity(&client, &inbox, &accept).await {
        Ok(()) => tracing::info!(actor = %follower_actor, "Accept delivered to follower"),
        Err(e) => tracing::warn!(actor = %follower_actor, error = %e, "Accept delivery failed (best-effort)"),
    }
}

/// Fan one already-built activity out to every follower with a known inbox. Per-follower failures
/// are logged only and never affect the local action; `label` names the activity for the logs.
async fn fan_out(client: &reqwest::Client, store: &Arc<dyn Store>, activity: &Value, label: &str) {
    let followers = store.list_followers().await;
    for f in followers {
        if f.inbox_url.is_empty() {
            continue;
        }
        match post_activity(client, &f.inbox_url, activity).await {
            Ok(()) => tracing::debug!(actor = %f.actor, label, "activity delivered"),
            Err(e) => {
                tracing::warn!(actor = %f.actor, error = %e, label, "delivery failed (best-effort)")
            }
        }
    }
}

/// Fan a freshly-created note out to every follower with a known inbox. Spawned by the compose
/// handler; per-follower failures are logged only and never affect the local post.
pub async fn deliver_note(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    note: Note,
) {
    let activity = create_activity(&cfg, &note);
    fan_out(&client, &store, &activity, "Create").await;
}

/// Fan an owner edit out to every follower as an `Update`. Spawned by the edit handler.
pub async fn deliver_update(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    note: Note,
) {
    let stamp = crate::now_nanos().to_string();
    let activity = update_activity(&cfg, &note, &stamp);
    fan_out(&client, &store, &activity, "Update").await;
}

/// Fan an owner delete out to every follower as a `Delete` of a `Tombstone`. Spawned by the delete
/// handler; takes the note id only, since the row is already gone from the store.
pub async fn deliver_delete(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    note_id: String,
) {
    let stamp = crate::now_nanos().to_string();
    let activity = delete_activity(&cfg, &note_id, &stamp);
    fan_out(&client, &store, &activity, "Delete").await;
}
