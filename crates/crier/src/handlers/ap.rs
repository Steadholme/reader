//! The public ActivityPub + WebFinger surface.
//!
//! These handlers read NO identity headers (they are `auth=public` at the gateway) and serve
//! `application/activity+json` documents derived from [`crate::activitypub`]. The inbox accepts
//! Follow / Undo(Follow) / Create best-effort and always answers `202 Accepted`; outbound side
//! effects (resolving a follower inbox, delivering an Accept) are spawned so a slow/unreachable
//! remote never blocks the response.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::activitypub::{self, ACTIVITY_JSON};
use crate::audit::AuditEvent;
use crate::store::Follower;
use crate::{federation, now_nanos, now_secs, AppState};

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
    activity_json(activitypub::actor(&state.config))
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
pub async fn inbox(State(state): State<AppState>, Path(name): Path<String>, body: Bytes) -> Response {
    if !is_our_actor(&state, &name) {
        return plain(StatusCode::NOT_FOUND, "no such actor");
    }
    handle_inbox(state, body).await
}

/// `POST /inbox` — the instance shared inbox (same processing as the actor inbox).
pub async fn shared_inbox(State(state): State<AppState>, body: Bytes) -> Response {
    handle_inbox(state, body).await
}

/// Core inbox processing. Always answers `202 Accepted` for well-formed activities; `400` only when
/// the body is not parseable JSON. Side effects (Accept delivery) are spawned, never awaited.
async fn handle_inbox(state: AppState, body: Bytes) -> Response {
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
        // Create / Like / Announce / … are accepted best-effort but not stored in v1.
        _ => accepted(),
    }
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
