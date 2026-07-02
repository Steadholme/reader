//! Best-effort outbound federation delivery (reqwest + rustls).
//!
//! Everything here is fire-and-forget: handlers spawn these tasks and return immediately, so a slow
//! or unreachable remote NEVER blocks a request and a federation failure NEVER fails the local
//! action that triggered it. Every delivery is SIGNED with the actor's RSA key (draft-cavage HTTP
//! Signatures, as Mastodon expects): the body's `Digest`, a `Date`, and the `Signature` over
//! `(request-target) host date digest` ride each POST. The local microblog + actor/outbox JSON stay
//! fully correct regardless of whether any remote ever accepts a delivery.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::activitypub::{
    accept_activity, announce_activity, create_activity, delete_activity, undo_announce_activity,
    update_activity, ACTIVITY_JSON,
};
use crate::config::Config;
use crate::httpsig::{self, Signer};
use crate::store::{Follower, Following, Note, Store};

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

/// POST a SIGNED activity JSON to a remote inbox. Builds the `Digest` (SHA-256 of the exact body
/// bytes) + `Date` headers, signs `(request-target) host date digest` with the actor key, and sets
/// the draft-cavage `Signature` header. Best-effort: returns `Err` on any failure, which the caller
/// only logs.
pub async fn post_activity(
    client: &reqwest::Client,
    signer: &Signer,
    inbox_url: &str,
    body: &Value,
) -> Result<(), String> {
    // Serialize ONCE: the exact bytes hashed for the digest must be the exact bytes sent.
    let body_bytes = serde_json::to_vec(body).map_err(|e| format!("serialize activity: {e}"))?;
    let url = reqwest::Url::parse(inbox_url).map_err(|e| format!("bad inbox url {inbox_url}: {e}"))?;
    let host = url.host_str().ok_or_else(|| format!("inbox url has no host: {inbox_url}"))?;
    // The request-target path includes the query string when present.
    let target = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };

    let digest = httpsig::compute_digest(&body_bytes);
    let date = httpsig::http_date(crate::now_secs());
    let signature = signer.sign_post(&target, host, &date, &digest);

    let resp = client
        .post(inbox_url)
        .header(reqwest::header::CONTENT_TYPE, ACTIVITY_JSON)
        .header(reqwest::header::ACCEPT, ACTIVITY_JSON)
        .header(reqwest::header::HOST, host)
        .header(reqwest::header::DATE, &date)
        .header("Digest", &digest)
        .header("Signature", &signature)
        .body(body_bytes)
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
    signer: Arc<Signer>,
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
    match post_activity(&client, &signer, &inbox, &accept).await {
        Ok(()) => tracing::info!(actor = %follower_actor, "Accept delivered to follower"),
        Err(e) => tracing::warn!(actor = %follower_actor, error = %e, "Accept delivery failed (best-effort)"),
    }
}

/// Follow a REMOTE actor: resolve its inbox, persist it in `following`, and deliver a SIGNED
/// `Follow`. Spawned by the web follow handler; the `following` row is recorded by the handler
/// first, so the relationship survives even if this delivery never lands.
pub async fn deliver_follow(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    signer: Arc<Signer>,
    remote_actor: String,
) {
    let Some(inbox) = resolve_inbox(&client, &remote_actor).await else {
        tracing::warn!(actor = %remote_actor, "could not resolve remote inbox — Follow skipped");
        return;
    };
    // Persist the resolved inbox for the follow relationship.
    if let Err(e) = store
        .add_following(&Following {
            actor: remote_actor.clone(),
            inbox_url: inbox.clone(),
            created_at: crate::now_secs(),
        })
        .await
    {
        tracing::warn!(actor = %remote_actor, error = %e, "failed to persist following inbox");
    }

    let follow = crate::activitypub::follow_activity(&cfg, &remote_actor, &crate::now_nanos().to_string());
    match post_activity(&client, &signer, &inbox, &follow).await {
        Ok(()) => tracing::info!(actor = %remote_actor, "Follow delivered to remote"),
        Err(e) => tracing::warn!(actor = %remote_actor, error = %e, "Follow delivery failed (best-effort)"),
    }
}

/// Resolve a follow target (either a direct actor URL or an `acct` handle) to an actor URL, then
/// deliver a signed `Follow`. Spawned by the web follow handler.
pub async fn follow_target(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    signer: Arc<Signer>,
    target: String,
) {
    let actor_url = if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else {
        match resolve_actor_url(&client, &target).await {
            Some(url) => url,
            None => {
                tracing::warn!(target = %target, "could not resolve follow handle via WebFinger");
                return;
            }
        }
    };
    deliver_follow(client, cfg, store, signer, actor_url).await;
}

/// Resolve an `acct` handle (`user@domain`, optionally `@`-prefixed) to its actor id URL via the
/// remote's WebFinger endpoint. Best-effort: `None` on any failure.
pub async fn resolve_actor_url(client: &reqwest::Client, handle: &str) -> Option<String> {
    let handle = handle.trim().trim_start_matches('@');
    let domain = handle.rsplit('@').next().filter(|d| !d.is_empty())?;
    if domain == handle {
        return None; // no '@' — not a handle
    }
    let url = format!("https://{domain}/.well-known/webfinger?resource=acct:{handle}");
    let resp = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/jrd+json")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let doc: Value = resp.json().await.ok()?;
    let links = doc.get("links")?.as_array()?;
    links
        .iter()
        .find(|l| {
            l.get("rel").and_then(Value::as_str) == Some("self")
                && l.get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| t.contains("activity+json") || t.contains("ld+json"))
        })
        .and_then(|l| l.get("href").and_then(Value::as_str))
        .map(str::to_string)
}

/// Fan one already-built activity out to every follower with a known inbox. Per-follower failures
/// are logged only and never affect the local action; `label` names the activity for the logs.
async fn fan_out(
    client: &reqwest::Client,
    store: &Arc<dyn Store>,
    signer: &Signer,
    activity: &Value,
    label: &str,
) {
    let followers = store.list_followers().await;
    for f in followers {
        if f.inbox_url.is_empty() {
            continue;
        }
        match post_activity(client, signer, &f.inbox_url, activity).await {
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
    signer: Arc<Signer>,
    note: Note,
) {
    let activity = create_activity(&cfg, &note);
    fan_out(&client, &store, &signer, &activity, "Create").await;
}

/// Fan an owner edit out to every follower as an `Update`. Spawned by the edit handler.
pub async fn deliver_update(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    signer: Arc<Signer>,
    note: Note,
) {
    let stamp = crate::now_nanos().to_string();
    let activity = update_activity(&cfg, &note, &stamp);
    fan_out(&client, &store, &signer, &activity, "Update").await;
}

/// Fan an owner delete out to every follower as a `Delete` of a `Tombstone`. Spawned by the delete
/// handler; takes the note id only, since the row is already gone from the store.
pub async fn deliver_delete(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    signer: Arc<Signer>,
    note_id: String,
) {
    let stamp = crate::now_nanos().to_string();
    let activity = delete_activity(&cfg, &note_id, &stamp);
    fan_out(&client, &store, &signer, &activity, "Delete").await;
}

/// Fan a boost out to every follower as an `Announce` of the remote `note_uri`. Spawned by the boost
/// handler; the local boost row is already stored, so the timeline is correct even if delivery fails.
pub async fn deliver_announce(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    signer: Arc<Signer>,
    note_uri: String,
    note_actor: String,
) {
    let stamp = crate::now_nanos().to_string();
    let activity = announce_activity(&cfg, &note_uri, &note_actor, &stamp);
    fan_out(&client, &store, &signer, &activity, "Announce").await;
}

/// Fan an un-boost out to every follower as an `Undo` of the prior `Announce`. Spawned by the
/// un-boost handler; the local boost row is already gone.
pub async fn deliver_undo_announce(
    client: reqwest::Client,
    cfg: Arc<Config>,
    store: Arc<dyn Store>,
    signer: Arc<Signer>,
    note_uri: String,
) {
    let stamp = crate::now_nanos().to_string();
    let activity = undo_announce_activity(&cfg, &note_uri, &stamp);
    fan_out(&client, &store, &signer, &activity, "Undo(Announce)").await;
}
