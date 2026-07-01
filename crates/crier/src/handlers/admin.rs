//! The admin panel (`/admin`) — inbox/follower moderation, gated on admin group membership.
//!
//! Every route in the `/admin` subtree is gated by [`auth::require_admin`]: a merely signed-in user
//! gets `403`, only members of `admins` / `infra-admins` see the panel. The panel offers three
//! tools:
//!
//! - a **blocklist** to block a remote DOMAIN or a single actor id — a blocked sender is rejected at
//!   the inbox (see [`crate::handlers::ap`]) and can no longer follow;
//! - a **followers list** with a remove-follower action;
//! - **delete-any-note**, removing any note regardless of author.
//!
//! Each state-changing POST is double-submit CSRF protected and emits an [`AuditEvent`] (`notice`
//! for the destructive removals) after the mutation. All interpolated user input is HTML-escaped.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::error::AppError;
use crate::handlers::{esc, fmt_date, render_note_html, topbar, APP_CSS};
use crate::store::{actor_domain, Blocked};
use crate::{federation, now_secs, AppState};

const ADMIN_HTML: &str = include_str!("../../templates/admin.html");

/// `GET /admin` — the admin panel. Gated on admin group membership (`403` otherwise).
pub async fn panel(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    auth::require_admin(&headers)?;

    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let blocks = state.store.list_blocks().await;
    let followers = state.store.list_followers().await;
    let notes = state.store.list_notes().await;

    let blocks_html = if blocks.is_empty() {
        empty("Nothing is blocked.")
    } else {
        blocks.iter().map(|b| render_block(b, &csrf)).collect()
    };
    let followers_html = if followers.is_empty() {
        empty("No followers yet.")
    } else {
        followers
            .iter()
            .map(|f| render_follower(&f.actor, &csrf))
            .collect()
    };
    let notes_html = if notes.is_empty() {
        empty("No notes.")
    } else {
        notes.iter().map(|n| render_note_row(n, &csrf)).collect()
    };

    let page = ADMIN_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Admin", &email))
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{BLOCKS}}", &blocks_html)
        .replace("{{FOLLOWERS}}", &followers_html)
        .replace("{{NOTES}}", &notes_html);

    Ok(html_with_cookie(page, set_cookie))
}

/// Block form body for `POST /admin/block`. Identity is NEVER taken from the form.
#[derive(Debug, Deserialize)]
pub struct BlockForm {
    /// The value to block: a bare host or an actor id URL.
    #[serde(default)]
    pub target: String,
    /// `"domain"` | `"actor"` (defaults to `"actor"` when omitted/unknown).
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/block` — add a blocklist entry (domain or actor id), then bounce to `/admin`.
pub async fn add_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BlockForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    auth::require_admin(&headers)?;

    // A `domain` block is normalized to a bare lower-cased host so the inbox gate matches it against
    // the sender's host; an `actor` block is stored as the exact (trimmed) actor id.
    let (kind, target) = match form.kind.trim() {
        "domain" => ("domain", actor_domain(form.target.trim())),
        _ => ("actor", form.target.trim().to_string()),
    };
    if target.is_empty() {
        return Err(AppError::InvalidRequest("a block target is required".to_string()));
    }

    state
        .store
        .add_block(&Blocked {
            target: target.clone(),
            kind: kind.to_string(),
            created_at: now_secs(),
        })
        .await?;
    tracing::info!(%target, kind, "block added");

    let actor = if email.is_empty() { &sub } else { &email };
    state
        .audit
        .emit(AuditEvent::notice("crier.admin.block", actor, &target, kind));

    Ok(redirect("/admin"))
}

/// Unblock form body for `POST /admin/unblock`.
#[derive(Debug, Deserialize)]
pub struct UnblockForm {
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/unblock` — remove a blocklist entry, then bounce to `/admin`.
pub async fn remove_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UnblockForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    auth::require_admin(&headers)?;

    let target = form.target.trim();
    if target.is_empty() {
        return Err(AppError::InvalidRequest("a block target is required".to_string()));
    }
    state.store.remove_block(target).await?;
    tracing::info!(%target, "block removed");

    let actor = if email.is_empty() { &sub } else { &email };
    state
        .audit
        .emit(AuditEvent::notice("crier.admin.unblock", actor, target, "unblock"));

    Ok(redirect("/admin"))
}

/// Remove-follower form body for `POST /admin/followers/remove`.
#[derive(Debug, Deserialize)]
pub struct RemoveFollowerForm {
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/followers/remove` — drop a follower by actor id, then bounce to `/admin`.
pub async fn remove_follower(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RemoveFollowerForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    auth::require_admin(&headers)?;

    let actor_target = form.actor.trim();
    if actor_target.is_empty() {
        return Err(AppError::InvalidRequest("a follower actor is required".to_string()));
    }
    state.store.remove_follower(actor_target).await?;
    tracing::info!(actor = %actor_target, "follower removed by admin");

    let actor = if email.is_empty() { &sub } else { &email };
    state.audit.emit(AuditEvent::notice(
        "crier.admin.follower.remove",
        actor,
        actor_target,
        "remove",
    ));

    Ok(redirect("/admin"))
}

/// Delete-note form body for `POST /admin/notes/delete`.
#[derive(Debug, Deserialize)]
pub struct DeleteNoteForm {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /admin/notes/delete` — delete ANY note regardless of author, then bounce to `/admin`.
pub async fn delete_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteNoteForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    auth::require_admin(&headers)?;

    let id = form.id.trim();
    if id.is_empty() {
        return Err(AppError::InvalidRequest("a note id is required".to_string()));
    }
    let deleted = state.store.admin_delete_note(id).await?;
    if !deleted {
        return Err(AppError::NotFound("no such note".to_string()));
    }
    tracing::info!(%id, "note deleted by admin");

    let actor = if email.is_empty() { &sub } else { &email };
    state
        .audit
        .emit(AuditEvent::notice("crier.admin.note.delete", actor, id, "deleted"));

    // Best-effort federation: announce a Delete/Tombstone to followers (spawned; never blocks).
    if state.config.federate {
        let client = state.http.clone();
        let cfg = state.config.clone();
        let store = state.store.clone();
        let signer = state.signer.clone();
        tokio::spawn(federation::deliver_delete(client, cfg, store, signer, id.to_string()));
    }

    Ok(redirect("/admin"))
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// A muted "nothing here" row for an empty section.
fn empty(msg: &str) -> String {
    format!(r#"<li class="list__meta">{}</li>"#, esc(msg))
}

/// One blocklist row: the target + kind badge + an Unblock button.
fn render_block(block: &Blocked, csrf: &str) -> String {
    format!(
        r#"<li>
  <span class="title">{target}</span>
  <span class="list__meta">{kind}</span>
  <form class="inline-form" method="post" action="/admin/unblock" style="margin-left:auto">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="target" value="{target}">
    <button class="btn btn-secondary btn-sm" type="submit">Unblock</button>
  </form>
</li>"#,
        target = esc(&block.target),
        kind = esc(&block.kind),
        csrf = esc(csrf),
    )
}

/// One follower row: the actor id + a Remove button.
fn render_follower(actor: &str, csrf: &str) -> String {
    format!(
        r#"<li>
  <span class="title">{actor}</span>
  <form class="inline-form" method="post" action="/admin/followers/remove" style="margin-left:auto" onsubmit="return confirm('Remove this follower?');">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="actor" value="{actor}">
    <button class="btn btn-danger btn-sm" type="submit">Remove</button>
  </form>
</li>"#,
        actor = esc(actor),
        csrf = esc(csrf),
    )
}

/// One note row: the (escaped) content + date + a Delete button.
fn render_note_row(note: &crate::store::Note, csrf: &str) -> String {
    format!(
        r#"<li>
  <span class="title">{body}</span>
  <span class="list__meta">{date}</span>
  <form class="inline-form" method="post" action="/admin/notes/delete" style="margin-left:auto" onsubmit="return confirm('Delete this note? This federates a delete to your followers.');">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="id" value="{id}">
    <button class="btn btn-danger btn-sm" type="submit">Delete</button>
  </form>
</li>"#,
        body = render_note_html(&note.content),
        date = esc(&fmt_date(note.created_at)),
        id = esc(&note.id),
        csrf = esc(csrf),
    )
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_str(location).expect("valid location"))],
    )
        .into_response()
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}
