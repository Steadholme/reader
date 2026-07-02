//! The public ActivityPub + WebFinger surface.
//!
//! These handlers read NO identity headers (they are `auth=public` at the gateway) and serve
//! `application/activity+json` documents derived from [`crate::activitypub`]. The inbox accepts
//! Follow / Undo(Follow) / Create best-effort and always answers `202 Accepted`; outbound side
//! effects (resolving a follower inbox, delivering an Accept) are spawned so a slow/unreachable
//! remote never blocks the response.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::activitypub::{self, ACTIVITY_JSON};
use crate::audit::AuditEvent;
use crate::store::{Follower, HomeNote, Notification};
use crate::{federation, httpsig, now_nanos, now_secs, AppState};

/// Build an `application/activity+json` 200 response from a JSON value.
fn activity_json(value: Value) -> Response {
    let body = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, ACTIVITY_JSON)],
        body,
    )
        .into_response()
}

/// A plain-text error response with an explicit status (the AP surface has no HTML chrome).
fn plain(status: StatusCode, msg: &'static str) -> Response {
    (status, msg).into_response()
}

/// True when `name` is the single configured actor for this instance.
fn is_our_actor(state: &AppState, name: &str) -> bool {
    name == state.config.actor
}

/// `GET /.well-known/webfinger?resource=acct:<actor>@<domain>` — resolve the handle to the actor.
pub async fn webfinger(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(resource) = q.get("resource") else {
        return plain(StatusCode::BAD_REQUEST, "missing resource parameter");
    };
    // Accept `acct:user@domain` (optionally without the scheme); match the local part to our actor.
    let acct = resource.strip_prefix("acct:").unwrap_or(resource);
    let user = acct.split('@').next().unwrap_or("");
    if !is_our_actor(&state, user) {
        return plain(StatusCode::NOT_FOUND, "no such resource");
    }
    activity_json(activitypub::webfinger(&state.config))
}

/// `GET /users/{name}` — the Actor (Person) document.
pub async fn actor(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    if !is_our_actor(&state, &name) {
        return plain(StatusCode::NOT_FOUND, "no such actor");
    }
    let profile = state.store.get_profile().await;
    activity_json(activitypub::actor(
        &state.config,
        &state.signer.public_pem,
        &profile,
    ))
}

/// `GET /users/{name}/outbox` — OrderedCollection of public notes (Create activities).
pub async fn outbox(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    if !is_our_actor(&state, &name) {
        return plain(StatusCode::NOT_FOUND, "no such actor");
    }
    render_outbox(&state).await
}

/// `GET /outbox` — top-level alias of the single user's outbox (matches the public gateway prefix).
pub async fn outbox_alias(State(state): State<AppState>) -> Response {
    render_outbox(&state).await
}

async fn render_outbox(state: &AppState) -> Response {
    let notes = state.store.list_notes().await;
    let total = state.store.count_notes().await;
    activity_json(activitypub::outbox(&state.config, &notes, total))
}

/// `GET /users/{name}/followers` — the followers OrderedCollection.
pub async fn followers(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    if !is_our_actor(&state, &name) {
        return plain(StatusCode::NOT_FOUND, "no such actor");
    }
    let list = state.store.list_followers().await;
    let total = state.store.count_followers().await;
    activity_json(activitypub::followers_collection(
        &state.config,
        &list,
        total,
    ))
}

/// `GET /users/{name}/notes/{id}` — a dereferenceable Note object.
pub async fn note_object(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    if !is_our_actor(&state, &name) {
        return plain(StatusCode::NOT_FOUND, "no such actor");
    }
    match state.store.get_note(&id).await {
        Some(note) if note.visibility == "public" => {
            // A standalone Note object carries its own @context.
            let mut obj = activitypub::note_object(&state.config, &note);
            obj["@context"] = serde_json::json!("https://www.w3.org/ns/activitystreams");
            activity_json(obj)
        }
        _ => plain(StatusCode::NOT_FOUND, "no such note"),
    }
}

/// `POST /users/{name}/inbox` — accept Follow / Undo(Follow) / Create best-effort.
pub async fn inbox(
    State(state): State<AppState>,
    Path(name): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_our_actor(&state, &name) {
        return plain(StatusCode::NOT_FOUND, "no such actor");
    }
    handle_inbox(state, uri.path().to_string(), headers, body).await
}

/// `POST /inbox` — the instance shared inbox (same processing as the actor inbox).
pub async fn shared_inbox(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_inbox(state, uri.path().to_string(), headers, body).await
}

/// Core inbox processing. When `verify_inbox` is on, the request MUST carry a valid HTTP Signature
/// (verified against the sender's fetched public key) or it is rejected `401`. Otherwise always
/// answers `202 Accepted` for well-formed activities; `400` only when the body is not parseable
/// JSON. Side effects (Accept delivery) are spawned, never awaited.
async fn handle_inbox(
    state: AppState,
    target: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The federation gate: verify the draft-cavage HTTP Signature before trusting the activity.
    if state.config.verify_inbox {
        if let Err(reason) =
            httpsig::verify_inbound(&state.http, &headers, "post", &target, &body).await
        {
            tracing::warn!(%reason, "inbox signature verification failed — rejecting 401");
            return plain(StatusCode::UNAUTHORIZED, "invalid HTTP signature");
        }
    }

    let Ok(activity) = serde_json::from_slice::<Value>(&body) else {
        return plain(StatusCode::BAD_REQUEST, "invalid JSON body");
    };
    let kind = activity.get("type").and_then(Value::as_str).unwrap_or("");

    // Admin blocklist gate: a blocked actor id (or any actor on a blocked domain) is rejected at
    // the inbox — it cannot follow us and cannot deliver a note. Checked before any side effect.
    if let Some(sender) = actor_id(&activity) {
        if state.store.is_blocked(&sender).await {
            tracing::info!(%sender, "inbox rejected — sender is blocklisted");
            return plain(StatusCode::FORBIDDEN, "sender is blocked");
        }
    }

    match kind {
        "Follow" => {
            let Some(follower) = actor_id(&activity) else {
                return plain(StatusCode::BAD_REQUEST, "Follow missing actor");
            };
            // Record the follower immediately (empty inbox), so the collection is correct even if
            // delivery of the Accept never lands.
            let _ = state
                .store
                .add_follower(&Follower {
                    actor: follower.clone(),
                    inbox_url: String::new(),
                    created_at: now_secs(),
                })
                .await;
            state.audit.emit(AuditEvent::notice(
                "crier.follower.add",
                &follower,
                &state.config.actor_url(),
                "follow",
            ));
            notify_known_owners(
                &state,
                "follow",
                &follower,
                "",
                "",
                &actor_profile_url(&follower),
            )
            .await;
            if state.config.federate {
                tokio::spawn(federation::accept_follow(
                    state.http.clone(),
                    state.config.clone(),
                    state.store.clone(),
                    state.signer.clone(),
                    follower,
                    activity,
                    format!("follows/{}", now_nanos()),
                ));
            }
            accepted()
        }
        "Undo" => {
            // Undo of a Follow -> drop the follower. We key off the outer actor (the follower).
            if let Some(follower) = actor_id(&activity) {
                let _ = state.store.remove_follower(&follower).await;
                state.audit.emit(AuditEvent::notice(
                    "crier.follower.remove",
                    &follower,
                    &state.config.actor_url(),
                    "undo",
                ));
            }
            accepted()
        }
        "Create" => {
            // A Note delivered by a remote WE follow lands in the home timeline. Notes from anyone
            // else are accepted (per spec) but not recorded — the home view is our follows only.
            if let Some(sender) = actor_id(&activity) {
                let parsed = home_note_from_create(&sender, &activity);
                if let Some(home) = &parsed {
                    notify_for_create(&state, &sender, home, &activity).await;
                }
                if state.store.is_following(&sender).await {
                    if let Some(home) = parsed {
                        let id = home.id.clone();
                        if let Err(e) = state.store.add_home_note(&home).await {
                            tracing::warn!(error = %e, "failed to record home note");
                        } else {
                            state.audit.emit(AuditEvent::info(
                                "crier.home.note",
                                &sender,
                                &id,
                                "delivered",
                            ));
                        }
                    }
                }
            }
            accepted()
        }
        "Announce" => {
            if let Some(sender) = actor_id(&activity) {
                if let Some(note_uri) = object_id(activity.get("object")) {
                    if let Some(local_id) = local_note_id(&state, &note_uri) {
                        if let Some(note) = state.store.get_note(&local_id).await {
                            let url = local_thread_url(&state, &local_id);
                            add_notification(
                                &state,
                                &note.author_sub,
                                "boost",
                                &sender,
                                &note_uri,
                                &notification_body_summary(&note.content),
                                &url,
                            )
                            .await;
                        }
                    }
                }
            }
            accepted()
        }
        // Like / … are accepted best-effort but not stored in v1.
        _ => accepted(),
    }
}

/// Extract a home-timeline [`HomeNote`] from an inbound `Create` activity's embedded `Note` object.
/// Returns `None` when the object is not a Note or carries no id. The content is taken verbatim
/// (the remote already HTML-escaped it) and rendered escaped in the UI regardless.
fn home_note_from_create(sender: &str, activity: &Value) -> Option<HomeNote> {
    let obj = activity.get("object")?;
    if obj.get("type").and_then(Value::as_str) != Some("Note") {
        return None;
    }
    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let content = obj
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let url = obj
        .get("url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(id)
        .to_string();
    // Best-effort parse of the RFC3339 `published` into epoch seconds (0 when absent/unparseable).
    let published = obj
        .get("published")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_secs)
        .unwrap_or(0);
    let in_reply_to = object_id(obj.get("inReplyTo")).unwrap_or_default();
    Some(HomeNote {
        id: id.to_string(),
        actor: sender.to_string(),
        content,
        url,
        published,
        in_reply_to,
        received_at: now_secs(),
    })
}

async fn notify_for_create(state: &AppState, sender: &str, home: &HomeNote, activity: &Value) {
    let mut notified: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if let Some(local_id) = local_note_id(state, &home.in_reply_to) {
        if let Some(note) = state.store.get_note(&local_id).await {
            let url = local_thread_url(state, &local_id);
            add_notification(
                state,
                &note.author_sub,
                "reply",
                sender,
                &home.id,
                &notification_body_summary(&home.content),
                &url,
            )
            .await;
            notified.insert(note.author_sub);
        }
    }
    if mentions_local_actor(state, activity) {
        let body = notification_body_summary(&home.content);
        let url = note_permalink_url(home);
        for owner in state.store.known_owner_subs().await {
            if notified.insert(owner.clone()) {
                add_notification(state, &owner, "mention", sender, &home.id, &body, &url).await;
            }
        }
    }
}

async fn notify_known_owners(
    state: &AppState,
    kind: &str,
    actor: &str,
    note_uri: &str,
    body: &str,
    url: &str,
) {
    for owner in state.store.known_owner_subs().await {
        add_notification(state, &owner, kind, actor, note_uri, body, url).await;
    }
}

async fn add_notification(
    state: &AppState,
    owner_sub: &str,
    kind: &str,
    actor: &str,
    note_uri: &str,
    body: &str,
    url: &str,
) {
    if owner_sub.is_empty() {
        return;
    }
    let notification = Notification {
        id: format!("notif_{}", now_nanos()),
        owner_sub: owner_sub.to_string(),
        kind: kind.to_string(),
        actor: actor.to_string(),
        note_uri: note_uri.to_string(),
        created_at: now_secs(),
        read: false,
    };
    if let Err(e) = state.store.add_notification(&notification).await {
        tracing::warn!(owner = %owner_sub, kind, error = %e, "failed to record notification");
        return;
    }
    state.audit.emit(AuditEvent::info(
        "crier.notification.add",
        actor,
        owner_sub,
        kind,
    ));
    notify_klaxon(state, owner_sub, kind, actor, body, url);
}

fn notify_klaxon(
    state: &AppState,
    owner_sub: &str,
    kind: &str,
    actor: &str,
    body: &str,
    url: &str,
) {
    if owner_sub == actor || actor == state.config.actor_url() {
        return;
    }
    let Some(klaxon) = &state.klaxon else {
        return;
    };
    let title = klaxon_title(kind, actor);
    klaxon.notify("crier", owner_sub, &title, body, url);
}

fn klaxon_title(kind: &str, actor: &str) -> String {
    match kind {
        "boost" => format!("{actor} 转发了你的帖子"),
        "follow" => format!("{actor} 关注了你"),
        "reply" => format!("{actor} 回复了你"),
        "mention" => format!("{actor} 提到了你"),
        _ => format!("{actor} 通知了你"),
    }
}

fn notification_body_summary(content: &str) -> String {
    const LIMIT: usize = 180;
    let compact = content.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= LIMIT {
        return compact;
    }
    let mut out: String = compact.chars().take(LIMIT - 3).collect();
    out.push_str("...");
    out
}

fn local_thread_url(state: &AppState, local_id: &str) -> String {
    format!("{}/thread/{}", state.config.base_url(), local_id)
}

fn note_permalink_url(home: &HomeNote) -> String {
    if is_http_url(&home.url) {
        home.url.clone()
    } else if is_http_url(&home.id) {
        home.id.clone()
    } else {
        String::new()
    }
}

fn actor_profile_url(actor: &str) -> String {
    if is_http_url(actor) {
        actor.to_string()
    } else {
        String::new()
    }
}

fn is_http_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn mentions_local_actor(state: &AppState, activity: &Value) -> bool {
    let Some(obj) = activity.get("object") else {
        return false;
    };
    let actor_url = state.config.actor_url();
    let handle = format!("@{}", state.config.handle());
    if let Some(tags) = obj.get("tag").and_then(Value::as_array) {
        for tag in tags {
            let is_mention = tag.get("type").and_then(Value::as_str) == Some("Mention");
            if !is_mention {
                continue;
            }
            let href_match = tag
                .get("href")
                .or_else(|| tag.get("id"))
                .and_then(Value::as_str)
                .is_some_and(|s| s == actor_url);
            let name_match = tag
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case(&handle));
            if href_match || name_match {
                return true;
            }
        }
    }
    obj.get("content")
        .and_then(Value::as_str)
        .is_some_and(|s| s.contains(&actor_url) || s.contains(&handle))
}

fn local_note_id(state: &AppState, uri: &str) -> Option<String> {
    let prefix = format!(
        "{}/users/{}/notes/",
        state.config.base_url(),
        state.config.actor
    );
    uri.strip_prefix(&prefix)
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.contains('/'))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_body_summary_compacts_and_truncates() {
        let body = notification_body_summary("hello\n\nworld\tfrom crier");
        assert_eq!(body, "hello world from crier");

        let long = "a".repeat(200);
        let body = notification_body_summary(&long);
        assert_eq!(body.chars().count(), 180);
        assert!(body.ends_with("..."));
    }

    #[test]
    fn klaxon_title_uses_event_shape() {
        assert_eq!(
            klaxon_title("boost", "https://remote.example/users/alice"),
            "https://remote.example/users/alice 转发了你的帖子"
        );
        assert_eq!(
            klaxon_title("follow", "https://remote.example/users/alice"),
            "https://remote.example/users/alice 关注了你"
        );
    }
}

fn object_id(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Object(o)) => o.get("id").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

/// Parse an RFC3339 timestamp into epoch seconds (best-effort; `None` on any error).
fn parse_rfc3339_secs(s: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .map(|dt| dt.unix_timestamp())
}

/// `202 Accepted` with an empty body — the standard ActivityPub inbox acknowledgement.
fn accepted() -> Response {
    StatusCode::ACCEPTED.into_response()
}

/// Extract the `actor` id from an activity: a bare string, or an embedded object's `id`.
fn actor_id(activity: &Value) -> Option<String> {
    match activity.get("actor") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Object(o)) => o.get("id").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}
