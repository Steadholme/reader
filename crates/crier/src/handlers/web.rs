//! The SSO-gated web surface: the timeline + a composer.
//!
//! `GET /` renders the local microblog (notes newest-first) plus a compose box. `POST /api/notes`
//! creates a note: the author is ALWAYS taken from the injected `X-Auth-Subject` (never a client
//! field), and the POST is double-submit CSRF protected. A successful post is audited
//! (`crier.note.create`) and best-effort fanned out to followers (non-blocking).

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::MAX_CONTENT_CHARS;
use crate::error::AppError;
use crate::handlers::{
    app_css, esc, feed_tabs, fmt_date, render_note_html, render_note_html_tagged, time_el, topbar,
    ICON_BAN, ICON_BELL, ICON_BOOST, ICON_EDIT, ICON_EXTLINK, ICON_HOME, ICON_LIST, ICON_MORE,
    ICON_REPLY, ICON_REPLYCTX, ICON_THREAD, ICON_TRASH,
};
use crate::hashtag::parse_hashtags;
use crate::store::{ActorFilter, Boost, Following, HomeNote, List, Note, Notification, Profile};
use crate::{federation, now_nanos, now_secs, AppState};

/// Hard cap on a list name, in characters.
const MAX_LIST_NAME_CHARS: usize = 120;
/// How many top tags the timeline "Tags" section shows.
const TOP_TAGS_LIMIT: i64 = 20;

const TIMELINE_HTML: &str = include_str!("../../templates/timeline.html");

/// Compose form body. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct NoteForm {
    #[serde(default)]
    pub content: String,
    /// Optional image URL (an Aperture share URL) to attach to the note. Empty => no attachment.
    #[serde(default)]
    pub attachment_url: String,
    /// Optional ActivityPub object id this note replies to. Existing forms leave it empty.
    #[serde(default)]
    pub in_reply_to: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `GET /` — the timeline: the actor handle, follower count, a composer, and notes newest-first.
pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let viewer = auth::author_sub(&headers).unwrap_or_default();
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let notes = state.store.list_notes().await;
    let boosts = state.store.list_boosts().await;
    let follower_count = state.store.count_followers().await;
    let profile = state.store.get_profile().await;
    let top_tags = state.store.top_tags(TOP_TAGS_LIMIT).await;
    let owner_av = owner_avatar(&profile, &state.config);

    // Merge the owner's notes + their boosts into one newest-first timeline. A boost is attributed
    // as "boosted" and carries its own un-boost control.
    let mut timeline: Vec<(i64, String, String)> = Vec::new();
    for n in &notes {
        let owned = !viewer.is_empty() && n.author_sub == viewer;
        timeline.push((
            n.created_at,
            n.id.clone(),
            render_note(n, &csrf, owned, &state.config, &owner_av),
        ));
    }
    for b in &boosts {
        timeline.push((b.created_at, b.id.clone(), render_boost_card(b, &csrf)));
    }
    // Newest-first; id as a stable tiebreak.
    timeline.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

    let items = if timeline.is_empty() {
        r#"<div class="empty-state"><h2>No posts yet</h2><p>Say something — your first note will appear here and federate to your followers.</p></div>"#.to_string()
    } else {
        timeline
            .into_iter()
            .map(|(_, _, html)| html)
            .collect::<String>()
    };
    let tags_html = render_tags_section(&top_tags);

    let header_html = if profile.header_url.is_empty() {
        r#"<div class="crier-hero__banner crier-hero__banner--brand"></div>"#.to_string()
    } else {
        format!(
            r#"<div class="profile__banner crier-hero__banner"><img src="{url}" alt="Profile header"></div>"#,
            url = esc(&profile.header_url),
        )
    };
    let avatar_html = if profile.avatar_url.is_empty() {
        format!(
            r#"<span class="avatar crier-hero__avatar" aria-hidden="true">{initial}</span>"#,
            initial = esc(&initial_of(&state.config.display_name)),
        )
    } else {
        format!(
            r#"<img class="profile__avatar crier-hero__avatar" src="{url}" alt="Profile avatar">"#,
            url = esc(&profile.avatar_url),
        )
    };

    let page = TIMELINE_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{TOPBAR}}", &topbar("Crier", &email))
        .replace("{{FEEDTABS}}", &feed_tabs("profile"))
        .replace("{{HEADER}}", &header_html)
        .replace("{{AVATAR}}", &avatar_html)
        .replace("{{HANDLE}}", &esc(&state.config.handle()))
        .replace("{{DISPLAY_NAME}}", &esc(&state.config.display_name))
        .replace("{{SUMMARY}}", &esc(&state.config.summary))
        .replace("{{FOLLOWERS}}", &follower_count.to_string())
        .replace("{{NOTE_COUNT}}", &notes.len().to_string())
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{COMPOSE_AVATAR}}", &compose_avatar(&profile, &state.config))
        .replace("{{FOLLOW}}", &render_follow_card(&csrf))
        .replace("{{AVATAR_URL}}", &esc(&profile.avatar_url))
        .replace("{{HEADER_URL}}", &esc(&profile.header_url))
        .replace("{{TAGS}}", &tags_html)
        .replace("{{ITEMS}}", &items);

    html_with_cookie(page, set_cookie)
}

/// The "Tags" section: the actor's most-used tags as `/tags/{tag}` links with counts. Empty markup
/// when there are no tags yet (so the section quietly disappears).
fn render_tags_section(top: &[(String, i64)]) -> String {
    if top.is_empty() {
        return String::new();
    }
    let pills = top
        .iter()
        .enumerate()
        .map(|(i, (tag, count))| {
            let hot = if i < 3 { " tag--hot" } else { "" };
            format!(
                "<a class=\"tag{hot}\" href=\"/tags/{href}\">#{label} <span class=\"list__meta\">{count}</span></a>",
                hot = hot,
                href = esc(tag),
                label = esc(tag),
                count = count,
            )
        })
        .collect::<String>();
    format!(
        "<section class=\"card crier-trend\"><div class=\"card__body\">\
           <h2>Tags</h2>\
           <div class=\"tagcloud\">{pills}</div>\
         </div></section>",
        pills = pills,
    )
}

/// One boost card in the timeline: attributed as "boosted <actor>", the (escaped) snapshot content,
/// a link to the original, and an un-boost control.
fn render_boost_card(boost: &Boost, csrf: &str) -> String {
    let (name, handle, initial) = actor_display(&boost.actor);
    let handle_html = render_handle(&handle);
    format!(
        r#"<article class="note note--boost">
  <div class="note__boostline">{icon_boost}Boosted <a href="{url}" rel="noopener noreferrer nofollow">{actor}</a></div>{avatar}
  <div class="note__main">
    <header class="note__head">
      <a class="note__author" href="{url}" rel="noopener noreferrer nofollow"><span class="note__name">{name}</span>{handle_html}</a>
      <a class="note__time" href="{url}" rel="noopener noreferrer nofollow">{date}</a>
    </header>
    <div class="note__body">{body}</div>
    <div class="note__actionbar">
      <form method="post" action="/api/unboost">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <input type="hidden" name="note_uri" value="{uri}">
        <button class="note-act note-act--boost" type="submit" title="Un-boost">{icon_boost}<span>Un-boost</span></button>
      </form>
    </div>
  </div>
</article>"#,
        icon_boost = ICON_BOOST,
        url = esc(&boost.url),
        actor = esc(&boost.actor),
        name = esc(&name),
        handle_html = handle_html,
        avatar = avatar_glyph("", &initial),
        body = render_note_html(&boost.content),
        date = time_el(boost.created_at),
        csrf = esc(csrf),
        uri = esc(&boost.note_uri),
    )
}

/// `POST /api/notes` — create a note (author from the injected `X-Auth-*`), then bounce to `/`.
pub async fn create_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<NoteForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let content = validate_content(&form.content)?;
    // An attached image must be a plain http(s) URL — this blocks `javascript:`/`data:` payloads
    // from ever reaching the timeline `<img src>` or the federated attachment.
    let attachment_url = validate_optional_url(&form.attachment_url)?;
    let in_reply_to = validate_optional_object_id(&form.in_reply_to)?;

    let now = now_secs();
    let note = Note {
        id: format!("note_{}", now_nanos()),
        author_sub: sub.clone(),
        content: content.to_string(),
        visibility: "public".to_string(),
        created_at: now,
        in_reply_to,
        updated_at: 0,
        attachment_url,
    };
    state.store.create_note(&note).await?;
    tracing::info!(id = %note.id, "note created");

    // Parse + persist hashtags so the tag pages + tag counts pick the note up.
    let tags = parse_hashtags(content);
    if !tags.is_empty() {
        if let Err(e) = state.store.add_note_hashtags(&note.id, &tags).await {
            tracing::warn!(id = %note.id, error = %e, "failed to store note hashtags");
        }
    }

    // Audit (non-blocking): WHO posted WHICH note — never the body.
    state.audit.emit(AuditEvent::info(
        "crier.note.create",
        &sub,
        &note.id,
        &format!("len={}", content.chars().count()),
    ));

    // Best-effort federation fan-out: spawned so a slow/unreachable remote never blocks the post.
    if state.config.federate {
        let client = state.http.clone();
        let cfg = state.config.clone();
        let store = state.store.clone();
        let signer = state.signer.clone();
        tokio::spawn(federation::deliver_note(client, cfg, store, signer, note));
    }

    Ok(redirect("/"))
}

/// Edit form body for `POST /api/notes/{id}/edit`. Identity is NEVER taken from the form.
#[derive(Debug, Deserialize)]
pub struct EditForm {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// Bare CSRF-only form body for `POST /api/notes/{id}/delete`.
#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /api/notes/{id}/edit` — owner-scoped edit of one's own note, then bounce to `/`.
pub async fn edit_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<EditForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let content = validate_content(&form.content)?;

    let now = now_secs();
    // Owner-scoped in the store: only a note whose author_sub == sub is touched. A missing note OR
    // someone else's note both report `false` — surfaced as 404 (never revealing another's note).
    let updated = state.store.update_note(&id, &sub, content, now).await?;
    if !updated {
        return Err(AppError::NotFound("no such note".to_string()));
    }
    tracing::info!(id = %id, "note edited");

    // Re-parse hashtags: drop the old set, store the new one (an edit can add/remove tags).
    if let Err(e) = state.store.remove_note_hashtags(&id).await {
        tracing::warn!(id = %id, error = %e, "failed to clear note hashtags on edit");
    }
    let tags = parse_hashtags(content);
    if !tags.is_empty() {
        if let Err(e) = state.store.add_note_hashtags(&id, &tags).await {
            tracing::warn!(id = %id, error = %e, "failed to store note hashtags on edit");
        }
    }

    state.audit.emit(AuditEvent::info(
        "crier.note.edit",
        &sub,
        &id,
        &format!("len={}", content.chars().count()),
    ));

    // Best-effort federation: announce the revision as an Update (spawned; never blocks the edit).
    if state.config.federate {
        if let Some(note) = state.store.get_note(&id).await {
            let client = state.http.clone();
            let cfg = state.config.clone();
            let store = state.store.clone();
            let signer = state.signer.clone();
            tokio::spawn(federation::deliver_update(client, cfg, store, signer, note));
        }
    }

    Ok(redirect("/"))
}

/// `POST /api/notes/{id}/delete` — owner-scoped delete of one's own note, then bounce to `/`.
pub async fn delete_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let deleted = state.store.delete_note(&id, &sub).await?;
    if !deleted {
        return Err(AppError::NotFound("no such note".to_string()));
    }
    tracing::info!(id = %id, "note deleted");

    // Drop the note's hashtags so it no longer appears on any tag page.
    if let Err(e) = state.store.remove_note_hashtags(&id).await {
        tracing::warn!(id = %id, error = %e, "failed to clear note hashtags on delete");
    }

    // Destructive action -> warning severity. WHO deleted WHICH note — never the body.
    state.audit.emit(AuditEvent::warning(
        "crier.note.delete",
        &sub,
        &id,
        "deleted",
    ));

    // Best-effort federation: announce a Delete/Tombstone to followers (spawned; never blocks).
    if state.config.federate {
        let client = state.http.clone();
        let cfg = state.config.clone();
        let store = state.store.clone();
        let signer = state.signer.clone();
        tokio::spawn(federation::deliver_delete(client, cfg, store, signer, id));
    }

    Ok(redirect("/"))
}

/// Follow form body for `POST /api/follow`. Identity is NEVER taken from the form.
#[derive(Debug, Deserialize)]
pub struct FollowForm {
    /// A remote actor URL (`https://…/users/foo`) or an `acct` handle (`foo@domain`).
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /api/follow` — follow a REMOTE actor: record the follow, deliver a signed `Follow`, bounce
/// to `/home`. A direct actor URL is recorded immediately (so the home timeline gates correctly);
/// an `acct` handle is resolved via WebFinger inside the spawned delivery task.
pub async fn follow_remote(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<FollowForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let target = form.target.trim().to_string();
    if target.is_empty() {
        return Err(AppError::InvalidRequest(
            "a remote actor is required".to_string(),
        ));
    }

    // A direct actor URL is recorded up front so `is_following` gates the home timeline even before
    // the async delivery resolves the inbox. A handle is left to the task's WebFinger step.
    if target.starts_with("http://") || target.starts_with("https://") {
        state
            .store
            .add_following(&Following {
                actor: target.clone(),
                inbox_url: String::new(),
                created_at: now_secs(),
            })
            .await?;
    }

    state.audit.emit(AuditEvent::notice(
        "crier.following.add",
        &sub,
        &target,
        "follow",
    ));

    if state.config.federate {
        let client = state.http.clone();
        let cfg = state.config.clone();
        let store = state.store.clone();
        let signer = state.signer.clone();
        tokio::spawn(federation::follow_target(
            client, cfg, store, signer, target,
        ));
    }

    Ok(redirect("/home"))
}

/// Profile-image form for `POST /api/profile`. Identity is NEVER taken from the form; both URLs are
/// optional (an empty field clears that image).
#[derive(Debug, Deserialize)]
pub struct ProfileForm {
    #[serde(default)]
    pub avatar_url: String,
    #[serde(default)]
    pub header_url: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /api/profile` — set the actor's avatar (icon) + header (image) image URLs, then bounce to
/// `/`. SSO-gated + double-submit CSRF; each URL is validated http(s) before it is stored (so it can
/// never inject markup into the timeline `<img src>` or the federated Actor JSON). Audited.
pub async fn set_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ProfileForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let profile = crate::store::Profile {
        avatar_url: validate_optional_url(&form.avatar_url)?,
        header_url: validate_optional_url(&form.header_url)?,
    };
    state.store.set_profile(&profile).await?;
    tracing::info!("actor profile images updated");

    // Audit WHO changed the profile + which images are now set — never the URLs themselves.
    state.audit.emit(AuditEvent::notice(
        "crier.profile.update",
        &sub,
        &state.config.actor_url(),
        &format!(
            "avatar={} header={}",
            !profile.avatar_url.is_empty(),
            !profile.header_url.is_empty()
        ),
    ));

    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

/// `GET /notifications` — owner-scoped notification inbox, newest-first. The unread count shown on
/// the page is captured before marking the rows read.
pub async fn notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let email = auth::display_email(&headers);
    let owner = auth::require_author(&headers)?.0;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let unread = state.store.count_unread_notifications(&owner).await;
    let notifications = state.store.list_notifications(&owner).await;
    state.store.mark_notifications_read(&owner).await?;

    let rows = if notifications.is_empty() {
        format!(
            r#"<div class="empty"><div class="empty__ico">{icon}</div><h3>No notifications</h3><p>Mentions, replies, boosts, and new followers will appear here.</p></div>"#,
            icon = ICON_BELL,
        )
    } else {
        notifications
            .iter()
            .map(|n| render_notification(n, &state.config))
            .collect::<String>()
    };

    let head = render_pagehead(
        ICON_BELL,
        "Notifications",
        &format!(r#"<span class="pill pill-accent">{unread} unread</span>"#, unread = unread),
    );
    let main = format!(
        r#"{head}
    <div class="note-list">
      {rows}
    </div>"#,
        head = head,
        rows = rows,
    );
    let page = page_shell("Notifications", "Notifications", &email, "notifications", &main, None);

    let _ = csrf; // keep CSRF cookie issuance consistent with other SSO pages.
    Ok(html_with_cookie(page, set_cookie))
}

fn render_notification(n: &Notification, cfg: &crate::config::Config) -> String {
    let (title, detail) = match n.kind.as_str() {
        "reply" => ("Reply", "replied to your post"),
        "mention" => ("Mention", "mentioned you"),
        "boost" => ("Boost", "boosted your post"),
        "follow" => ("Follow", "followed you"),
        _ => ("Notification", "notified you"),
    };
    let unread = if n.read {
        ""
    } else {
        r#"<span class="pill pill-info">Unread</span>"#
    };
    let link = notification_link(cfg, &n.note_uri);
    let (name, handle, initial) = actor_display(&n.actor);
    let handle_html = render_handle(&handle);
    format!(
        r#"<article class="note notification{unread_cls}">{avatar}
  <div class="note__main">
    <header class="note__head">
      <a class="note__author" href="{actor}" rel="noopener noreferrer nofollow"><span class="note__name">{name}</span>{handle_html}</a>{unread}
      <span class="note__time">{date}</span>
    </header>
    <div class="note__body"><strong>{title}</strong> — {detail}{link}</div>
  </div>
</article>"#,
        unread_cls = if n.read { "" } else { " notification--unread" },
        avatar = avatar_glyph("", &initial),
        title = esc(title),
        unread = unread,
        actor = esc(&n.actor),
        name = esc(&name),
        handle_html = handle_html,
        detail = esc(detail),
        link = link,
        date = time_el(n.created_at),
    )
}

fn notification_link(cfg: &crate::config::Config, note_uri: &str) -> String {
    if note_uri.is_empty() {
        return String::new();
    }
    let href = thread_href_for_uri(cfg, note_uri).unwrap_or_else(|| note_uri.to_string());
    format!(
        r#" · <a href="{href}" rel="noopener noreferrer nofollow">View</a>"#,
        href = esc(&href),
    )
}

// ---------------------------------------------------------------------------
// Conversation threads
// ---------------------------------------------------------------------------

/// `GET /thread/{id}` — a local note with local ancestors and direct local/remote replies.
pub async fn thread(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let email = auth::display_email(&headers);
    let viewer = auth::author_sub(&headers).unwrap_or_default();
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let Some(note) = state.store.get_note(&id).await else {
        return Err(AppError::NotFound("no such note".to_string()));
    };

    let mut ancestors = Vec::new();
    let mut cursor = note.in_reply_to.clone();
    for _ in 0..32 {
        let Some(parent_id) = local_note_id_from_uri(&state.config, &cursor) else {
            break;
        };
        let Some(parent) = state.store.get_note(&parent_id).await else {
            break;
        };
        cursor = parent.in_reply_to.clone();
        ancestors.push(parent);
    }
    ancestors.reverse();

    let note_uri = state.config.note_url(&id);
    let local_replies = state.store.list_local_replies(&note_uri).await;
    let remote_replies = state.store.list_home_replies(&note_uri).await;

    let profile = state.store.get_profile().await;
    let owner_av = owner_avatar(&profile, &state.config);

    let mut items = String::new();
    for n in &ancestors {
        let owned = !viewer.is_empty() && n.author_sub == viewer;
        items.push_str(&render_note(n, &csrf, owned, &state.config, &owner_av));
    }
    let owned = !viewer.is_empty() && note.author_sub == viewer;
    items.push_str(&render_note(&note, &csrf, owned, &state.config, &owner_av));

    let mut replies: Vec<(i64, String, String)> = Vec::new();
    for n in &local_replies {
        let owned = !viewer.is_empty() && n.author_sub == viewer;
        replies.push((
            n.created_at,
            n.id.clone(),
            render_note(n, &csrf, owned, &state.config, &owner_av),
        ));
    }
    for n in &remote_replies {
        let when = if n.published > 0 {
            n.published
        } else {
            n.received_at
        };
        replies.push((when, n.id.clone(), render_home_note_plain(n, &state.config)));
    }
    replies.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    for (_, _, html) in replies {
        items.push_str(&html);
    }

    let head = render_pagehead(
        ICON_THREAD,
        "Thread",
        r#"This post with its local ancestors and direct replies. · <a href="/">&larr; Your profile</a>"#,
    );
    let main = format!(
        r#"{head}
    <div class="note-list">
      {items}
    </div>"#,
        head = head,
        items = items,
    );
    let page = page_shell("Thread", "Thread", &email, "", &main, None);

    Ok(html_with_cookie(page, set_cookie))
}

// ---------------------------------------------------------------------------
// Blocks / mutes
// ---------------------------------------------------------------------------

/// Actor filter form: CSRF + a remote actor id URL.
#[derive(Debug, Deserialize)]
pub struct ActorFilterForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub actor: String,
}

/// `GET /blocks` — owner-scoped block/mute management for remote actors.
pub async fn blocks_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let email = auth::display_email(&headers);
    let owner = auth::require_author(&headers)?.0;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let blocks = state.store.list_actor_blocks(&owner).await;
    let mutes = state.store.list_mutes(&owner).await;
    let block_rows = if blocks.is_empty() {
        r#"<li class="list__meta">No blocked actors.</li>"#.to_string()
    } else {
        blocks
            .iter()
            .map(|b| {
                render_actor_filter_row(b, &csrf, "/blocks/unblock", "Unblock", "btn-secondary")
            })
            .collect::<String>()
    };
    let mute_rows = if mutes.is_empty() {
        r#"<li class="list__meta">No muted actors.</li>"#.to_string()
    } else {
        mutes
            .iter()
            .map(|m| render_actor_filter_row(m, &csrf, "/blocks/unmute", "Unmute", "btn-secondary"))
            .collect::<String>()
    };

    let head = render_pagehead(
        ICON_BAN,
        "Blocks &amp; mutes",
        "Muted actors are hidden from Home. Blocked actors are hidden and rejected at the inbox.",
    );
    let main = format!(
        r#"{head}
    <section class="card"><div class="card__body">
      <h2>Block an actor</h2>
      <form method="post" action="/blocks/block">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <div class="field">
          <label for="block-actor">Remote actor URL</label>
          <input id="block-actor" name="actor" class="input" placeholder="https://mastodon.social/users/foo" required>
        </div>
        <div class="composer__actions"><button class="btn btn-danger" type="submit">Block</button></div>
      </form>
      <ul class="list">{block_rows}</ul>
    </div></section>
    <section class="card"><div class="card__body">
      <h2>Mute an actor</h2>
      <form method="post" action="/blocks/mute">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <div class="field">
          <label for="mute-actor">Remote actor URL</label>
          <input id="mute-actor" name="actor" class="input" placeholder="https://mastodon.social/users/foo" required>
        </div>
        <div class="composer__actions"><button class="btn btn-primary" type="submit">Mute</button></div>
      </form>
      <ul class="list">{mute_rows}</ul>
    </div></section>"#,
        head = head,
        csrf = esc(&csrf),
        block_rows = block_rows,
        mute_rows = mute_rows,
    );
    let page = page_shell("Blocks", "Blocks", &email, "", &main, None);

    Ok(html_with_cookie(page, set_cookie))
}

pub async fn block_actor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ActorFilterForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    let actor = validate_actor_url(&form.actor)?;
    state
        .store
        .add_actor_block(&ActorFilter {
            owner_sub: sub.clone(),
            actor: actor.clone(),
            created_at: now_secs(),
        })
        .await?;
    tracing::info!(%actor, "actor blocked");
    state
        .audit
        .emit(AuditEvent::notice("crier.block.add", &sub, &actor, "block"));
    Ok(redirect("/blocks"))
}

pub async fn unblock_actor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ActorFilterForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    let actor = validate_actor_url(&form.actor)?;
    state.store.remove_actor_block(&sub, &actor).await?;
    tracing::info!(%actor, "actor unblocked");
    state.audit.emit(AuditEvent::notice(
        "crier.block.remove",
        &sub,
        &actor,
        "unblock",
    ));
    Ok(redirect("/blocks"))
}

pub async fn mute_actor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ActorFilterForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    let actor = validate_actor_url(&form.actor)?;
    state
        .store
        .add_mute(&ActorFilter {
            owner_sub: sub.clone(),
            actor: actor.clone(),
            created_at: now_secs(),
        })
        .await?;
    tracing::info!(%actor, "actor muted");
    state
        .audit
        .emit(AuditEvent::notice("crier.mute.add", &sub, &actor, "mute"));
    Ok(redirect("/blocks"))
}

pub async fn unmute_actor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ActorFilterForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    let actor = validate_actor_url(&form.actor)?;
    state.store.remove_mute(&sub, &actor).await?;
    tracing::info!(%actor, "actor unmuted");
    state.audit.emit(AuditEvent::notice(
        "crier.mute.remove",
        &sub,
        &actor,
        "unmute",
    ));
    Ok(redirect("/blocks"))
}

fn render_actor_filter_row(
    filter: &ActorFilter,
    csrf: &str,
    action: &str,
    label: &str,
    class_name: &str,
) -> String {
    format!(
        r#"<li>
  <span class="title">{actor}</span>
  <span class="list__meta">{date}</span>
  <form class="inline-form" method="post" action="{action}" style="margin-left:auto">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="actor" value="{actor}">
    <button class="btn {class_name} btn-sm" type="submit">{label}</button>
  </form>
</li>"#,
        actor = esc(&filter.actor),
        date = esc(&fmt_date(filter.created_at)),
        action = esc(action),
        csrf = esc(csrf),
        class_name = esc(class_name),
        label = esc(label),
    )
}

// ---------------------------------------------------------------------------
// Boost / reblog
// ---------------------------------------------------------------------------

/// Boost/un-boost form: CSRF + the boosted note's object id (uri) + an optional origin page.
#[derive(Debug, Deserialize)]
pub struct BoostForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub note_uri: String,
    /// Where to bounce back to (`home` -> `/home`, anything else -> `/`).
    #[serde(default)]
    pub from: String,
}

/// Resolve a boost form's origin to a redirect target.
fn boost_return(from: &str) -> &'static str {
    if from == "home" {
        "/home"
    } else {
        "/"
    }
}

/// `POST /api/boost` — boost a home-timeline note: snapshot it (server-side, from the home note),
/// store the boost, and emit a signed `Announce` to followers. Bounce back to the origin page.
pub async fn boost(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BoostForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let note_uri = form.note_uri.trim();
    if note_uri.is_empty() {
        return Err(AppError::InvalidRequest("a note is required".to_string()));
    }
    // Snapshot from OUR home note (never trust a client-supplied body) so the boost renders even if
    // the source home note is later pruned.
    let Some(hn) = state.store.get_home_note(note_uri).await else {
        return Err(AppError::NotFound("no such note to boost".to_string()));
    };
    let boost = Boost {
        id: format!("boost_{}", now_nanos()),
        note_uri: hn.id.clone(),
        actor: hn.actor.clone(),
        content: hn.content.clone(),
        url: hn.url.clone(),
        created_at: now_secs(),
    };
    state.store.add_boost(&boost).await?;
    tracing::info!(uri = %hn.id, "note boosted");
    state
        .audit
        .emit(AuditEvent::notice("crier.boost.add", &sub, &hn.id, "boost"));

    // Best-effort federation: Announce the boost to our followers (spawned; never blocks).
    if state.config.federate {
        let client = state.http.clone();
        let cfg = state.config.clone();
        let store = state.store.clone();
        let signer = state.signer.clone();
        tokio::spawn(federation::deliver_announce(
            client, cfg, store, signer, hn.id, hn.actor,
        ));
    }

    Ok(redirect(boost_return(&form.from)))
}

/// `POST /api/unboost` — remove a boost by its note uri, then emit an `Undo`(`Announce`). Bounce
/// back to the origin page.
pub async fn unboost(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BoostForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let note_uri = form.note_uri.trim().to_string();
    if note_uri.is_empty() {
        return Err(AppError::InvalidRequest("a note is required".to_string()));
    }
    state.store.remove_boost(&note_uri).await?;
    tracing::info!(uri = %note_uri, "note un-boosted");
    state.audit.emit(AuditEvent::notice(
        "crier.boost.remove",
        &sub,
        &note_uri,
        "unboost",
    ));

    if state.config.federate {
        let client = state.http.clone();
        let cfg = state.config.clone();
        let store = state.store.clone();
        let signer = state.signer.clone();
        tokio::spawn(federation::deliver_undo_announce(
            client, cfg, store, signer, note_uri,
        ));
    }

    Ok(redirect(boost_return(&form.from)))
}

// ---------------------------------------------------------------------------
// JSON siblings of /api/boost and /api/unboost (progressive enhancement)
// ---------------------------------------------------------------------------
//
// Same double-submit CSRF, same store mutations, same audit + best-effort federation as the form
// routes above, but they return small JSON and DO NOT redirect. The form routes are untouched, so
// a no-JS browser still works; JS uses these for an optimistic, no-reload boost toggle on /home.

/// `POST /api/boost/json` — boost a home note (server-side snapshot), returning
/// `{ "ok": true, "boosted": true, "note_uri": … }`.
pub async fn api_boost_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BoostForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let note_uri = form.note_uri.trim();
    if note_uri.is_empty() {
        return Err(AppError::InvalidRequest("a note is required".to_string()));
    }
    let Some(hn) = state.store.get_home_note(note_uri).await else {
        return Err(AppError::NotFound("no such note to boost".to_string()));
    };
    let boost = Boost {
        id: format!("boost_{}", now_nanos()),
        note_uri: hn.id.clone(),
        actor: hn.actor.clone(),
        content: hn.content.clone(),
        url: hn.url.clone(),
        created_at: now_secs(),
    };
    state.store.add_boost(&boost).await?;
    tracing::info!(uri = %hn.id, "note boosted (json)");
    state
        .audit
        .emit(AuditEvent::notice("crier.boost.add", &sub, &hn.id, "boost"));

    if state.config.federate {
        let client = state.http.clone();
        let cfg = state.config.clone();
        let store = state.store.clone();
        let signer = state.signer.clone();
        tokio::spawn(federation::deliver_announce(
            client,
            cfg,
            store,
            signer,
            hn.id.clone(),
            hn.actor,
        ));
    }

    Ok(
        axum::Json(serde_json::json!({ "ok": true, "boosted": true, "note_uri": hn.id }))
            .into_response(),
    )
}

/// `POST /api/unboost/json` — remove a boost by note uri, returning
/// `{ "ok": true, "boosted": false, "note_uri": … }`.
pub async fn api_unboost_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BoostForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let note_uri = form.note_uri.trim().to_string();
    if note_uri.is_empty() {
        return Err(AppError::InvalidRequest("a note is required".to_string()));
    }
    state.store.remove_boost(&note_uri).await?;
    tracing::info!(uri = %note_uri, "note un-boosted (json)");
    state.audit.emit(AuditEvent::notice(
        "crier.boost.remove",
        &sub,
        &note_uri,
        "unboost",
    ));

    if state.config.federate {
        let client = state.http.clone();
        let cfg = state.config.clone();
        let store = state.store.clone();
        let signer = state.signer.clone();
        tokio::spawn(federation::deliver_undo_announce(
            client,
            cfg,
            store,
            signer,
            note_uri.clone(),
        ));
    }

    Ok(
        axum::Json(serde_json::json!({ "ok": true, "boosted": false, "note_uri": note_uri }))
            .into_response(),
    )
}

/// `GET /api/notifications/unread` — the authed owner's unread notification count as
/// `{ "unread": <n> }`. Read-only; drives the live nav badge.
pub async fn api_notifications_unread(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let owner = auth::require_author(&headers)?.0;
    let unread = state.store.count_unread_notifications(&owner).await;
    Ok(axum::Json(serde_json::json!({ "unread": unread })).into_response())
}

// ---------------------------------------------------------------------------
// Hashtag pages
// ---------------------------------------------------------------------------

/// `GET /tags/{tag}` — a page listing this actor's public notes carrying `{tag}`. SSO-gated web page
/// (same chrome as the timeline). The tag is lower-cased to match how tags are stored.
pub async fn tag_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tag): Path<String>,
) -> Response {
    let email = auth::display_email(&headers);
    let viewer = auth::author_sub(&headers).unwrap_or_default();
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let tag_lc = tag.trim().to_lowercase();
    let notes = state.store.notes_with_tag(&tag_lc).await;
    let profile = state.store.get_profile().await;
    let owner_av = owner_avatar(&profile, &state.config);

    let items = if notes.is_empty() {
        r#"<div class="empty"><div class="empty__ico">#</div><h3>No posts with this tag</h3><p>Post a note containing this hashtag and it will appear here.</p></div>"#.to_string()
    } else {
        notes
            .iter()
            .map(|n| {
                let owned = !viewer.is_empty() && n.author_sub == viewer;
                render_note(n, &csrf, owned, &state.config, &owner_av)
            })
            .collect::<String>()
    };

    let title = format!("#{}", esc(&tag_lc));
    let head = render_pagehead(
        "#",
        &title,
        &format!(
            r#"<strong>{n}</strong> posts · <a href="/">&larr; Your profile</a>"#,
            n = notes.len(),
        ),
    );
    let main = format!(
        r#"{head}
    <div class="note-list">
      {items}
    </div>"#,
        head = head,
        items = items,
    );
    let page = page_shell(&title, "Crier", &email, "", &main, None);

    html_with_cookie(page, set_cookie)
}

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

/// Create-list form: CSRF + the list name.
#[derive(Debug, Deserialize)]
pub struct ListForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
}

/// List-member form: CSRF + a followed actor id.
#[derive(Debug, Deserialize)]
pub struct MemberForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub actor: String,
}

/// Bare CSRF-only form for list deletion.
#[derive(Debug, Deserialize)]
pub struct ListDeleteForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// `GET /lists` — manage lists: a create form + one row per list (open / delete).
pub async fn lists_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let owner = auth::author_sub(&headers).unwrap_or_default();
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let lists = state.store.list_lists(&owner).await;
    let rows = if lists.is_empty() {
        r#"<li class="list__meta">No lists yet. Create one to build a focused timeline.</li>"#
            .to_string()
    } else {
        lists
            .iter()
            .map(|l| {
                format!(
                    r#"<li>
  <a class="title" href="/lists/{id}">{name}</a>
  <form class="inline-form" method="post" action="/lists/{id}/delete" style="margin-left:auto" onsubmit="return confirm('Delete this list?');">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <button class="btn btn-danger btn-sm" type="submit">Delete</button>
  </form>
</li>"#,
                    id = esc(&l.id),
                    name = esc(&l.name),
                    csrf = esc(&csrf),
                )
            })
            .collect::<String>()
    };

    let head = render_pagehead(
        ICON_LIST,
        "Lists",
        "Group the remote actors you follow into focused timelines.",
    );
    let main = format!(
        r#"{head}
    <section class="card"><div class="card__body">
      <form method="post" action="/lists">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <div class="field">
          <label for="list-name">New list</label>
          <input id="list-name" name="name" class="input" maxlength="120" placeholder="e.g. Rustaceans" required>
        </div>
        <div class="composer__actions"><button class="btn btn-primary" type="submit">Create list</button></div>
      </form>
    </div></section>
    <section class="card"><div class="card__body">
      <h2>Your lists</h2>
      <ul class="list">{rows}</ul>
    </div></section>"#,
        head = head,
        csrf = esc(&csrf),
        rows = rows,
    );
    let page = page_shell("Lists", "Lists", &email, "", &main, None);

    html_with_cookie(page, set_cookie)
}

/// `POST /lists` — create a list (owner-scoped), then bounce to `/lists`.
pub async fn create_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ListForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_LIST_NAME_CHARS {
        return Err(AppError::InvalidRequest(
            "a list name (up to 120 characters) is required".to_string(),
        ));
    }
    let list = List {
        id: format!("list_{}", now_nanos()),
        owner_sub: sub.clone(),
        name: name.to_string(),
        created_at: now_secs(),
    };
    state.store.create_list(&list).await?;
    tracing::info!(id = %list.id, "list created");
    state
        .audit
        .emit(AuditEvent::info("crier.list.create", &sub, &list.id, name));
    Ok(redirect("/lists"))
}

/// `POST /lists/{id}/delete` — delete a list + its members (owner-scoped), then bounce to `/lists`.
pub async fn delete_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ListDeleteForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let deleted = state.store.delete_list(&id, &sub).await?;
    if !deleted {
        return Err(AppError::NotFound("no such list".to_string()));
    }
    tracing::info!(id = %id, "list deleted");
    state.audit.emit(AuditEvent::notice(
        "crier.list.delete",
        &sub,
        &id,
        "deleted",
    ));
    Ok(redirect("/lists"))
}

/// `GET /lists/{id}` — a list's filtered timeline (only its members' home notes) + member
/// management (add / remove). Owner-scoped: a missing or foreign list is a 404.
pub async fn list_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let email = auth::display_email(&headers);
    let owner = auth::require_author(&headers)?.0;
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let Some(list) = state.store.get_list(&id, &owner).await else {
        return Err(AppError::NotFound("no such list".to_string()));
    };
    let members = state.store.list_members(&id).await;
    let notes = state.store.list_home_notes_for_list(&id).await;

    let items = if notes.is_empty() {
        format!(
            r#"<div class="empty"><div class="empty__ico">{icon}</div><h3>Nothing here yet</h3><p>Add members below; their posts will stream into this list.</p></div>"#,
            icon = ICON_LIST,
        )
    } else {
        notes
            .iter()
            .map(|n| render_home_note_plain(n, &state.config))
            .collect::<String>()
    };

    let member_rows = if members.is_empty() {
        r#"<li class="list__meta">No members yet.</li>"#.to_string()
    } else {
        members
            .iter()
            .map(|actor| {
                format!(
                    r#"<li>
  <span class="title">{actor}</span>
  <form class="inline-form" method="post" action="/lists/{id}/members/remove" style="margin-left:auto">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="actor" value="{actor}">
    <button class="btn btn-secondary btn-sm" type="submit">Remove</button>
  </form>
</li>"#,
                    actor = esc(actor),
                    id = esc(&id),
                    csrf = esc(&csrf),
                )
            })
            .collect::<String>()
    };

    let name = esc(&list.name);
    let id = esc(&id);
    let head = render_pagehead(
        ICON_LIST,
        &name,
        r#"A focused timeline of this list's members. · <a href="/lists">&larr; All lists</a>"#,
    );
    let main = format!(
        r#"{head}
    <section class="card"><div class="card__body">
      <h2>Members</h2>
      <form method="post" action="/lists/{id}/members">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <div class="field">
          <label for="member-actor">Add a followed actor</label>
          <input id="member-actor" name="actor" class="input" placeholder="https://mastodon.social/users/Gargron" required>
        </div>
        <div class="composer__actions"><button class="btn btn-primary btn-sm" type="submit">Add member</button></div>
      </form>
      <ul class="list">{member_rows}</ul>
    </div></section>
    <div class="note-list">
      {items}
    </div>"#,
        head = head,
        id = id,
        csrf = esc(&csrf),
        member_rows = member_rows,
        items = items,
    );
    let page = page_shell(&list.name, "Lists", &email, "", &main, None);

    Ok(html_with_cookie(page, set_cookie))
}

/// `POST /lists/{id}/members` — add a member to a list (owner-scoped), then bounce to `/lists/{id}`.
pub async fn add_list_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<MemberForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let actor = form.actor.trim();
    if actor.is_empty() {
        return Err(AppError::InvalidRequest("an actor is required".to_string()));
    }
    let ok = state.store.add_list_member(&id, &sub, actor).await?;
    if !ok {
        return Err(AppError::NotFound("no such list".to_string()));
    }
    tracing::info!(list = %id, %actor, "list member added");
    Ok(redirect(&format!("/lists/{id}")))
}

/// `POST /lists/{id}/members/remove` — remove a member (owner-scoped), then bounce to `/lists/{id}`.
pub async fn remove_list_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<MemberForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_author(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let actor = form.actor.trim();
    if actor.is_empty() {
        return Err(AppError::InvalidRequest("an actor is required".to_string()));
    }
    let ok = state.store.remove_list_member(&id, &sub, actor).await?;
    if !ok {
        return Err(AppError::NotFound("no such list".to_string()));
    }
    tracing::info!(list = %id, %actor, "list member removed");
    Ok(redirect(&format!("/lists/{id}")))
}

/// A home-note card without boost controls (used inside the list timeline).
fn render_home_note_plain(note: &HomeNote, cfg: &crate::config::Config) -> String {
    let when = if note.published > 0 {
        note.published
    } else {
        note.received_at
    };
    let replyctx = render_reply_link(cfg, &note.in_reply_to);
    let (name, handle, initial) = actor_display(&note.actor);
    let handle_html = render_handle(&handle);
    format!(
        r#"<article class="note">{avatar}
  <div class="note__main">
    <header class="note__head">
      <a class="note__author" href="{actor_url}" rel="noopener noreferrer nofollow"><span class="note__name">{name}</span>{handle_html}</a>
      <a class="note__time" href="{url}" rel="noopener noreferrer nofollow">{date}</a>
    </header>{replyctx}
    <div class="note__body">{body}</div>
  </div>
</article>"#,
        avatar = avatar_glyph("", &initial),
        actor_url = esc(&note.actor),
        url = esc(&note.url),
        name = esc(&name),
        handle_html = handle_html,
        body = render_note_html(&note.content),
        date = time_el(when),
        replyctx = replyctx,
    )
}

/// `GET /home` — the home timeline: notes delivered by the remote actors we follow, newest-first.
/// Each note carries a boost / un-boost control (boosting re-shares it to our followers).
pub async fn home(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let owner = auth::author_sub(&headers).unwrap_or_default();
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let notes = if owner.is_empty() {
        state.store.list_home_notes().await
    } else {
        state.store.list_home_notes_for_owner(&owner).await
    };
    let following = state.store.list_following().await;

    let mut items = String::new();
    if notes.is_empty() {
        items.push_str(&format!(
            r#"<div class="empty"><div class="empty__ico">{icon}</div><h3>Your home is quiet</h3><p>Follow a remote actor from the timeline; their posts will stream in here.</p></div>"#,
            icon = ICON_HOME,
        ));
    } else {
        for n in &notes {
            let boosted = state.store.is_boosted(&n.id).await;
            items.push_str(&render_home_note(n, &csrf, boosted, &state.config));
        }
    }

    let head = render_pagehead(
        ICON_HOME,
        "Home timeline",
        &format!(
            "Posts from the <strong>{}</strong> remote actor(s) you follow.",
            following.len()
        ),
    );
    let main = format!(
        r#"{head}
    <div class="note-list">
      {items}
    </div>"#,
        head = head,
        items = items,
    );
    let page = page_shell(
        "Home",
        "Home",
        &email,
        "home",
        &main,
        Some(&render_follow_card(&csrf)),
    );

    html_with_cookie(page, set_cookie)
}

/// One home-timeline card: the source actor + the (escaped) remote content + a UTC date, plus a
/// boost / un-boost control. `boosted` selects which action the button offers.
fn render_home_note(
    note: &HomeNote,
    csrf: &str,
    boosted: bool,
    cfg: &crate::config::Config,
) -> String {
    let when = if note.published > 0 {
        note.published
    } else {
        note.received_at
    };
    let action = if boosted {
        "/api/unboost"
    } else {
        "/api/boost"
    };
    let label = if boosted { "Un-boost" } else { "Boost" };
    let replyctx = render_reply_link(cfg, &note.in_reply_to);
    let boosted_flag = if boosted { "1" } else { "0" };
    let replybox = render_reply_composer(&note.id, csrf);
    let (name, handle, initial) = actor_display(&note.actor);
    let handle_html = render_handle(&handle);
    format!(
        r#"<article class="note">{avatar}
  <div class="note__main">
    <header class="note__head">
      <a class="note__author" href="{actor_url}" rel="noopener noreferrer nofollow"><span class="note__name">{name}</span>{handle_html}</a>
      <a class="note__time" href="{url}" rel="noopener noreferrer nofollow">{date}</a>
    </header>{replyctx}
    <div class="note__body">{body}</div>
    <div class="note__actionbar">{replybox}
      <form method="post" action="{action}" data-boost-form data-boosted="{boosted_flag}" data-note-uri="{uri}">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <input type="hidden" name="note_uri" value="{uri}">
        <button class="note-act note-act--boost" type="submit" title="Boost">{icon_boost}<span data-boost-label>{label}</span></button>
      </form>
      <a class="note-act" href="{url}" rel="noopener noreferrer nofollow" title="Original">{icon_ext}<span>Original</span></a>
    </div>
  </div>
</article>"#,
        avatar = avatar_glyph("", &initial),
        actor_url = esc(&note.actor),
        url = esc(&note.url),
        name = esc(&name),
        handle_html = handle_html,
        body = render_note_html(&note.content),
        date = time_el(when),
        replyctx = replyctx,
        action = action,
        label = label,
        boosted_flag = boosted_flag,
        csrf = esc(csrf),
        uri = esc(&note.id),
        replybox = replybox,
        icon_boost = ICON_BOOST,
        icon_ext = ICON_EXTLINK,
    )
}

/// Trim + length-validate note content, returning the trimmed slice or an `InvalidRequest`.
fn validate_content(raw: &str) -> Result<&str, AppError> {
    let content = raw.trim();
    if content.is_empty() {
        return Err(AppError::InvalidRequest(
            "note content is required".to_string(),
        ));
    }
    if content.chars().count() > MAX_CONTENT_CHARS {
        return Err(AppError::InvalidRequest(format!(
            "note exceeds {MAX_CONTENT_CHARS} characters"
        )));
    }
    Ok(content)
}

/// Max characters accepted for an image URL (avatar / header / attachment).
const MAX_URL_CHARS: usize = 2048;

/// Validate an OPTIONAL image URL: an empty field is accepted (means "unset / no attachment"); a
/// non-empty value MUST be a plain `http(s)` URL under the length cap. Rejecting anything else keeps
/// `javascript:` / `data:` payloads out of the `<img src>` and the federated JSON. Returns the
/// trimmed URL (or the empty string).
fn validate_optional_url(raw: &str) -> Result<String, AppError> {
    let url = raw.trim();
    if url.is_empty() {
        return Ok(String::new());
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(AppError::InvalidRequest(
            "image URL must start with http:// or https://".to_string(),
        ));
    }
    if url.chars().count() > MAX_URL_CHARS {
        return Err(AppError::InvalidRequest(
            "image URL is too long".to_string(),
        ));
    }
    Ok(url.to_string())
}

fn validate_optional_object_id(raw: &str) -> Result<String, AppError> {
    let uri = raw.trim();
    if uri.is_empty() {
        return Ok(String::new());
    }
    if !(uri.starts_with("https://") || uri.starts_with("http://")) {
        return Err(AppError::InvalidRequest(
            "reply target must start with http:// or https://".to_string(),
        ));
    }
    if uri.chars().count() > MAX_URL_CHARS {
        return Err(AppError::InvalidRequest(
            "reply target is too long".to_string(),
        ));
    }
    Ok(uri.to_string())
}

fn validate_actor_url(raw: &str) -> Result<String, AppError> {
    let actor = raw.trim();
    if actor.is_empty() {
        return Err(AppError::InvalidRequest("an actor is required".to_string()));
    }
    if !(actor.starts_with("https://") || actor.starts_with("http://")) {
        return Err(AppError::InvalidRequest(
            "actor must start with http:// or https://".to_string(),
        ));
    }
    if actor.chars().count() > MAX_URL_CHARS {
        return Err(AppError::InvalidRequest(
            "actor URL is too long".to_string(),
        ));
    }
    Ok(actor.to_string())
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// Derive a `(display name, @handle, initial)` triple for a remote actor. Federation gives us
/// either a friendly display name or a raw actor URL; both resolve to something showable, and the
/// initial drives a colored fallback avatar (no remote image is ever fetched). Pure string work.
fn actor_display(actor: &str) -> (String, String, String) {
    let a = actor.trim();
    let initial_of = |name: &str| {
        name.chars()
            .find(|c| !c.is_whitespace())
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "?".to_string())
    };
    if let Some(rest) = a.strip_prefix("https://").or_else(|| a.strip_prefix("http://")) {
        let mut parts = rest.splitn(2, '/');
        let host = parts.next().unwrap_or("").trim_end_matches('/');
        let path = parts.next().unwrap_or("");
        let seg = path.rsplit('/').find(|s| !s.is_empty()).unwrap_or(host);
        let name = seg.trim_start_matches('@');
        let name = if name.is_empty() { host } else { name };
        let handle = if host.is_empty() {
            String::new()
        } else {
            format!("@{name}@{host}")
        };
        return (name.to_string(), handle, initial_of(name));
    }
    let name = if a.is_empty() { "Someone" } else { a };
    (name.to_string(), String::new(), initial_of(name))
}

/// A neutral initial-based avatar span for a remote actor (`extra` adds a modifier class).
fn avatar_glyph(extra: &str, initial: &str) -> String {
    format!(
        r#"<span class="avatar note__avatar{extra}" aria-hidden="true">{initial}</span>"#,
        extra = extra,
        initial = esc(initial),
    )
}

/// A `.note__handle` span for a derived `@user@host`, or empty markup when it couldn't be derived.
fn render_handle(handle: &str) -> String {
    if handle.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="note__handle">{}</span>"#, esc(handle))
    }
}

/// The owner's 44px note avatar: their uploaded image, else a brand-tinted initial ("purple = you").
fn owner_avatar(profile: &Profile, cfg: &crate::config::Config) -> String {
    if profile.avatar_url.is_empty() {
        avatar_glyph(" note__avatar--own", &initial_of(&cfg.display_name))
    } else {
        format!(
            r#"<img class="note__avatar" src="{url}" alt="">"#,
            url = esc(&profile.avatar_url),
        )
    }
}

/// The owner's 40px composer avatar (same idiom as the app-bar user chip).
fn compose_avatar(profile: &Profile, cfg: &crate::config::Config) -> String {
    if profile.avatar_url.is_empty() {
        format!(
            r#"<span class="avatar crier-compose__avatar" aria-hidden="true">{initial}</span>"#,
            initial = esc(&initial_of(&cfg.display_name)),
        )
    } else {
        format!(
            r#"<img class="avatar crier-compose__avatar" src="{url}" alt="">"#,
            url = esc(&profile.avatar_url),
        )
    }
}

/// First non-whitespace character of `s`, upper-cased (fallback for empty).
fn initial_of(s: &str) -> String {
    s.chars()
        .find(|c| !c.is_whitespace())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// The "Follow someone" sidebar card (the /api/follow form, compact). Shared by index (via {{FOLLOW}})
/// and the /home rail. The form action/field/csrf are byte-for-byte the old follow form.
fn render_follow_card(csrf: &str) -> String {
    format!(
        r#"<section class="card"><div class="card__body">
    <h2>Follow someone</h2>
    <p class="crier-follow__hint">Paste a fediverse handle or actor URL — new posts land in <a href="/home">Home</a>.</p>
    <form class="crier-follow__form" method="post" action="/api/follow">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input id="follow-target" name="target" class="input" placeholder="user@mastodon.social" required>
      <button class="btn btn-primary" type="submit">Follow</button>
    </form>
  </div></section>"#,
        csrf = esc(csrf),
    )
}

/// The drill-down page head (thread / tag / lists / blocks / home / notifications): a brand glyph
/// tile + title + a meta line. `glyph` is raw HTML (an inline SVG or a literal like `#`); `title`
/// must be pre-escaped by the caller; `meta_html` is trusted markup the caller builds safely.
fn render_pagehead(glyph: &str, title: &str, meta_html: &str) -> String {
    format!(
        r#"<div class="crier-pagehead">
  <div class="crier-pagehead__glyph">{glyph}</div>
  <div>
    <h1 class="crier-pagehead__title">{title}</h1>
    <div class="crier-pagehead__meta">{meta}</div>
  </div>
</div>"#,
        glyph = glyph,
        title = title,
        meta = meta_html,
    )
}

/// The shared page skeleton for every SSO page except the profile index (which keeps its template):
/// doctype/head/app-bar, then the two-column crier-shell (feed spine + optional discovery rail).
/// `active_tab` selects the feed-tab highlight; `main_html` is the feed column content (page head +
/// items); `rail_html` renders the right sidebar when `Some` (else the shell is single-column).
fn page_shell(
    tab_title: &str,
    page_title: &str,
    email: &str,
    active_tab: &str,
    main_html: &str,
    rail_html: Option<&str>,
) -> String {
    let solo = if rail_html.is_none() {
        " crier-shell--solo"
    } else {
        ""
    };
    let rail = match rail_html {
        Some(r) => format!(
            r#"<aside class="crier-rail"><div class="crier-rail__inner">{r}</div></aside>"#,
            r = r
        ),
        None => String::new(),
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{tab_title} · Crier · Steadholme</title><style>{css}</style></head>
<body class="page-reading">
{topbar}
<main class="crier-shell{solo}">
  <div class="crier-main">
{feedtabs}
{main}
  </div>
{rail}
</main>
</body></html>"#,
        tab_title = esc(tab_title),
        css = app_css(),
        topbar = topbar(page_title, email),
        solo = solo,
        feedtabs = feed_tabs(active_tab),
        main = main_html,
        rail = rail,
    )
}

fn render_reply_link(cfg: &crate::config::Config, in_reply_to: &str) -> String {
    if in_reply_to.is_empty() {
        return String::new();
    }
    let href = thread_href_for_uri(cfg, in_reply_to).unwrap_or_else(|| in_reply_to.to_string());
    format!(
        r#"
    <div class="note__replyctx">{icon}<a href="{href}" rel="noopener noreferrer nofollow">In reply to</a></div>"#,
        icon = ICON_REPLYCTX,
        href = esc(&href),
    )
}

fn thread_href_for_uri(cfg: &crate::config::Config, uri: &str) -> Option<String> {
    local_note_id_from_uri(cfg, uri).map(|id| format!("/thread/{id}"))
}

fn local_note_id_from_uri(cfg: &crate::config::Config, uri: &str) -> Option<String> {
    let prefix = format!("{}/users/{}/notes/", cfg.base_url(), cfg.actor);
    uri.strip_prefix(&prefix)
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.contains('/'))
        .map(str::to_string)
}

/// The canonical ActivityPub object id for one of OUR local notes
/// (`{base}/users/{actor}/notes/{id}`) — the value `in_reply_to` carries to thread a reply onto it.
fn note_object_uri(cfg: &crate::config::Config, id: &str) -> String {
    format!("{}/users/{}/notes/{}", cfg.base_url(), cfg.actor, id)
}

/// An inline reply composer (progressive enhancement): a collapsible form that posts to the EXISTING
/// `/api/notes` form route with a hidden `in_reply_to`, so a reply is just a note threaded onto the
/// target. Works with no JS (full POST + redirect to `/`). `uri` is the object being replied to; an
/// empty uri renders nothing. The char counter is added client-side by the shared script.
fn render_reply_composer(uri: &str, csrf: &str) -> String {
    if uri.is_empty() {
        return String::new();
    }
    format!(
        r#"<details class="note__reply">
      <summary class="note-act" title="Reply">{icon}<span>Reply</span></summary>
      <form class="note__replyform" method="post" action="/api/notes" data-reply-form>
        <input type="hidden" name="csrf_token" value="{csrf}">
        <input type="hidden" name="in_reply_to" value="{uri}">
        <div class="field">
          <textarea name="content" class="composer__body" maxlength="5000" required placeholder="Write a reply…"></textarea>
        </div>
        <div class="actions">
          <button class="btn btn-primary btn-sm" type="submit">Reply</button>
        </div>
      </form>
    </details>"#,
        icon = ICON_REPLY,
        csrf = esc(csrf),
        uri = esc(uri),
    )
}

/// One timeline note card: rendered (escaped) content + a UTC date, plus owner-only edit/delete
/// controls when `owned`. Every interpolated field is escaped.
fn render_note(note: &Note, csrf: &str, owned: bool, cfg: &crate::config::Config, avatar: &str) -> String {
    let edited = if note.updated_at > 0 {
        r#"<span class="note__edited">edited</span>"#
    } else {
        ""
    };
    let controls = if owned {
        render_controls(note, csrf)
    } else {
        String::new()
    };
    let media = render_media(&note.attachment_url);
    let replyctx = render_reply_link(cfg, &note.in_reply_to);
    let replybox = render_reply_composer(&note_object_uri(cfg, &note.id), csrf);
    format!(
        r#"<article class="note">{avatar}
  <div class="note__main">
    <header class="note__head">
      <a class="note__author" href="/"><span class="note__name">{name}</span><span class="note__handle">@{handle}</span></a>{edited}
      <a class="note__time" href="/thread/{id}">{date}</a>{controls}
    </header>{replyctx}
    <div class="note__body">{body}</div>{media}
    <div class="note__actionbar">{replybox}<a class="note-act" href="/thread/{id}" title="Thread">{icon_thread}<span>Thread</span></a></div>
  </div>
</article>"#,
        avatar = avatar,
        name = esc(&cfg.display_name),
        handle = esc(&cfg.handle()),
        edited = edited,
        id = esc(&note.id),
        body = render_note_html_tagged(&note.content),
        media = media,
        date = time_el(note.created_at),
        replyctx = replyctx,
        replybox = replybox,
        controls = controls,
        icon_thread = ICON_THREAD,
    )
}

/// Render an optional inline attachment image (escaped src). Empty URL => no markup. The URL was
/// validated http(s) at write time; it is escaped again here as defense in depth.
fn render_media(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    format!(
        r#"
  <div class="note__media"><img src="{url}" alt="Attached image" loading="lazy"></div>"#,
        url = esc(url),
    )
}

/// Owner-only edit (collapsible inline form) + delete controls for a note. The note id rides the
/// form `action` (path), the CSRF token a hidden field; the edit textarea is prefilled with the
/// escaped current content. Both POSTs are double-submit CSRF protected server-side.
fn render_controls(note: &Note, csrf: &str) -> String {
    let id = esc(&note.id);
    let csrf = esc(csrf);
    format!(
        r#"<details class="note__more">
      <summary title="More" aria-label="More">{icon_more}</summary>
      <div class="note__morepop">
        <details class="note__edit">
          <summary class="note__moreitem">{icon_edit}Edit</summary>
          <form class="note__editform" method="post" action="/api/notes/{id}/edit">
            <input type="hidden" name="csrf_token" value="{csrf}">
            <div class="field">
              <textarea name="content" class="composer__body" maxlength="5000" required>{content}</textarea>
            </div>
            <div class="actions">
              <button class="btn btn-primary btn-sm" type="submit">Save</button>
            </div>
          </form>
        </details>
        <form method="post" action="/api/notes/{id}/delete" onsubmit="return confirm('Delete this note? This will federate a delete to your followers.');">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <button class="note__moreitem note__moreitem--danger" type="submit">{icon_trash}Delete</button>
        </form>
      </div>
    </details>"#,
        icon_more = ICON_MORE,
        icon_edit = ICON_EDIT,
        icon_trash = ICON_TRASH,
        id = id,
        csrf = csrf,
        content = esc(&note.content),
    )
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(location).expect("valid location"),
        )],
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
