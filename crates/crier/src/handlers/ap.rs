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
use crate::store::{Follower, HomeNote};
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
pub async fn webfinger(State(state): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Response {
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
    activity_json(activitypub::actor(&state.config, &state.signer.public_pem))
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
    activity_json(activitypub::followers_collection(&state.config, &list, total))
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
async fn handle_inbox(state: AppState, target: String, headers: HeaderMap, body: Bytes) -> Response {
    // The federation gate: verify the draft-cavage HTTP Signature before trusting the activity.
    if state.config.verify_inbox {
        if let Err(reason) = httpsig::verify_inbound(&state.http, &headers, "post", &target, &body).await {
            tracing::warn!(%reason, "inbox signature verification failed — rejecting 401");
            return plain(StatusCode::UNAUTHORIZED, "invalid HTTP signature");
        }
    }

    let Ok(activity) = serde_json::from_slice::<Value>(&body) else {
        return plain(StatusCode::BAD_REQUEST, "invalid JSON body");
    };
    let kind = activity.get("type").and_then(Value::as_str).unwrap_or("");

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
                if state.store.is_following(&sender).await {
                    if let Some(home) = home_note_from_create(&sender, &activity) {
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
        // Like / Announce / … are accepted best-effort but not stored in v1.
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
    let id = obj.get("id").and_then(Value::as_str).filter(|s| !s.is_empty())?;
    let content = obj.get("content").and_then(Value::as_str).unwrap_or("").to_string();
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
    Some(HomeNote {
        id: id.to_string(),
        actor: sender.to_string(),
        content,
        url,
        published,
        received_at: now_secs(),
    })
}

/// Parse an RFC3339 timestamp into epoch seconds (best-effort; `None` on any error).
fn parse_rfc3339_secs(s: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(s, &Rfc3339).ok().map(|dt| dt.unix_timestamp())
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
