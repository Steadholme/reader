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
use crate::hashtag::parse_hashtags;
use crate::handlers::{
    esc, fmt_date, render_note_html, render_note_html_tagged, topbar, APP_CSS,
};
use crate::store::{Boost, Following, HomeNote, List, Note};
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

    // Merge the owner's notes + their boosts into one newest-first timeline. A boost is attributed
    // as "boosted" and carries its own un-boost control.
    let mut timeline: Vec<(i64, String, String)> = Vec::new();
    for n in &notes {
        let owned = !viewer.is_empty() && n.author_sub == viewer;
        timeline.push((n.created_at, n.id.clone(), render_note(n, &csrf, owned)));
    }
    for b in &boosts {
        timeline.push((b.created_at, b.id.clone(), render_boost_card(b, &csrf)));
    }
    // Newest-first; id as a stable tiebreak.
    timeline.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

    let items = if timeline.is_empty() {
        r#"<div class="empty-state"><h2>No posts yet</h2><p>Say something — your first note will appear here and federate to your followers.</p></div>"#.to_string()
    } else {
        timeline.into_iter().map(|(_, _, html)| html).collect::<String>()
    };
    let tags_html = render_tags_section(&top_tags);

    let header_html = if profile.header_url.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="profile__banner"><img src="{url}" alt="Profile header"></div>"#,
            url = esc(&profile.header_url),
        )
    };
    let avatar_html = if profile.avatar_url.is_empty() {
        String::new()
    } else {
        format!(
            r#"<img class="profile__avatar" src="{url}" alt="Profile avatar">"#,
            url = esc(&profile.avatar_url),
        )
    };

    let page = TIMELINE_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Crier", &email))
        .replace("{{HEADER}}", &header_html)
        .replace("{{AVATAR}}", &avatar_html)
        .replace("{{HANDLE}}", &esc(&state.config.handle()))
        .replace("{{DISPLAY_NAME}}", &esc(&state.config.display_name))
        .replace("{{SUMMARY}}", &esc(&state.config.summary))
        .replace("{{FOLLOWERS}}", &follower_count.to_string())
        .replace("{{NOTE_COUNT}}", &notes.len().to_string())
        .replace("{{CSRF}}", &esc(&csrf))
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
        .map(|(tag, count)| {
            format!(
                "<a class=\"tag\" href=\"/tags/{href}\">#{label} <span class=\"list__meta\">{count}</span></a>",
                href = esc(tag),
                label = esc(tag),
                count = count,
            )
        })
        .collect::<String>();
    format!(
        "<section class=\"card\"><div class=\"card__body\">\
           <h2>Tags</h2>\
           <div class=\"tagcloud\">{pills}</div>\
         </div></section>",
        pills = pills,
    )
}

/// One boost card in the timeline: attributed as "boosted <actor>", the (escaped) snapshot content,
/// a link to the original, and an un-boost control.
fn render_boost_card(boost: &Boost, csrf: &str) -> String {
    format!(
        r#"<article class="note note--boost">
  <div class="note__meta">🔁 Boosted <a href="{url}" rel="noopener noreferrer nofollow">{actor}</a></div>
  <div class="note__body">{body}</div>
  <div class="note__meta">{date}</div>
  <div class="note__actions">
    <form method="post" action="/api/unboost">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="note_uri" value="{uri}">
      <button class="btn btn-ghost btn-sm" type="submit">Un-boost</button>
    </form>
  </div>
</article>"#,
        url = esc(&boost.url),
        actor = esc(&boost.actor),
        body = render_note_html(&boost.content),
        date = esc(&fmt_date(boost.created_at)),
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

    let now = now_secs();
    let note = Note {
        id: format!("note_{}", now_nanos()),
        author_sub: sub.clone(),
        content: content.to_string(),
        visibility: "public".to_string(),
        created_at: now,
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
    state
        .audit
        .emit(AuditEvent::warning("crier.note.delete", &sub, &id, "deleted"));

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
        return Err(AppError::InvalidRequest("a remote actor is required".to_string()));
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
        tokio::spawn(federation::follow_target(client, cfg, store, signer, target));
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
    state.audit.emit(AuditEvent::notice(
        "crier.boost.add",
        &sub,
        &hn.id,
        "boost",
    ));

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

    let items = if notes.is_empty() {
        r#"<div class="empty-state"><h2>No posts with this tag</h2><p>Post a note containing this hashtag and it will appear here.</p></div>"#.to_string()
    } else {
        notes
            .iter()
            .map(|n| {
                let owned = !viewer.is_empty() && n.author_sub == viewer;
                render_note(n, &csrf, owned)
            })
            .collect::<String>()
    };

    let page = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>#{tag} · Crier · HOLDFAST</title><style>{css}</style></head>
<body class="page-reading">
{topbar}
<main class="reader">
  <div class="profile">
    <h1 class="profile__name">#{tag}</h1>
    <p class="profile__summary">Your posts tagged #{tag}.</p>
    <div class="profile__stats"><span><a class="btn btn-ghost btn-sm" href="/">&larr; Your profile</a></span></div>
  </div>
  <div class="note-list">
    {items}
  </div>
</main>
</body></html>"#,
        css = APP_CSS,
        topbar = topbar("Crier", &email),
        tag = esc(&tag_lc),
        items = items,
    );

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
        r#"<li class="list__meta">No lists yet. Create one to build a focused timeline.</li>"#.to_string()
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

    let page = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Lists · Crier · HOLDFAST</title><style>{css}</style></head>
<body class="page-reading">
{topbar}
<main class="reader">
  <div class="profile">
    <h1 class="profile__name">Lists</h1>
    <p class="profile__summary">Group the remote actors you follow into focused timelines.</p>
  </div>
  <section class="card composer"><div class="card__body">
    <form method="post" action="/lists">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="list-name">New list</label>
        <input id="list-name" name="name" class="composer__body" maxlength="120" placeholder="e.g. Rustaceans" required>
      </div>
      <div class="composer__actions"><button class="btn btn-primary" type="submit">Create list</button></div>
    </form>
  </div></section>
  <section class="card"><div class="card__body">
    <h2>Your lists</h2>
    <ul class="list">{rows}</ul>
  </div></section>
</main>
</body></html>"#,
        css = APP_CSS,
        topbar = topbar("Lists", &email),
        csrf = esc(&csrf),
        rows = rows,
    );

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
    state.audit.emit(AuditEvent::info("crier.list.create", &sub, &list.id, name));
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
    state.audit.emit(AuditEvent::notice("crier.list.delete", &sub, &id, "deleted"));
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
        r#"<div class="empty-state"><h2>Nothing here yet</h2><p>Add members below; their posts will stream into this list.</p></div>"#.to_string()
    } else {
        notes.iter().map(render_home_note_plain).collect::<String>()
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

    let page = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{name} · Lists · Crier</title><style>{css}</style></head>
<body class="page-reading">
{topbar}
<main class="reader">
  <div class="profile">
    <h1 class="profile__name">{name}</h1>
    <p class="profile__summary">A focused timeline of this list's members.</p>
    <div class="profile__stats"><span><a class="btn btn-ghost btn-sm" href="/lists">&larr; All lists</a></span></div>
  </div>
  <section class="card"><div class="card__body">
    <h2>Members</h2>
    <form method="post" action="/lists/{id}/members">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="member-actor">Add a followed actor</label>
        <input id="member-actor" name="actor" class="composer__body" placeholder="https://mastodon.social/users/Gargron" required>
      </div>
      <div class="composer__actions"><button class="btn btn-primary btn-sm" type="submit">Add member</button></div>
    </form>
    <ul class="list">{member_rows}</ul>
  </div></section>
  <div class="note-list">
    {items}
  </div>
</main>
</body></html>"#,
        css = APP_CSS,
        topbar = topbar("Lists", &email),
        name = esc(&list.name),
        id = esc(&id),
        csrf = esc(&csrf),
        member_rows = member_rows,
        items = items,
    );

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
fn render_home_note_plain(note: &HomeNote) -> String {
    let when = if note.published > 0 { note.published } else { note.received_at };
    format!(
        r#"<article class="note">
  <div class="note__meta"><a href="{url}" rel="noopener noreferrer nofollow">{actor}</a></div>
  <div class="note__body">{body}</div>
  <div class="note__meta">{date}</div>
</article>"#,
        url = esc(&note.url),
        actor = esc(&note.actor),
        body = render_note_html(&note.content),
        date = esc(&fmt_date(when)),
    )
}

/// `GET /home` — the home timeline: notes delivered by the remote actors we follow, newest-first.
/// Each note carries a boost / un-boost control (boosting re-shares it to our followers).
pub async fn home(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let notes = state.store.list_home_notes().await;
    let following = state.store.list_following().await;

    let mut items = String::new();
    if notes.is_empty() {
        items.push_str(
            r#"<div class="empty-state"><h2>Your home is quiet</h2><p>Follow a remote actor from the timeline; their posts will stream in here.</p></div>"#,
        );
    } else {
        for n in &notes {
            let boosted = state.store.is_boosted(&n.id).await;
            items.push_str(&render_home_note(n, &csrf, boosted));
        }
    }

    let page = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Home · Crier · HOLDFAST</title><style>{css}</style></head>
<body class="page-reading">
{topbar}
<main class="reader">
  <div class="profile">
    <h1 class="profile__name">Home timeline</h1>
    <p class="profile__summary">Posts from the {following} remote actor(s) you follow.</p>
    <div class="profile__stats"><span><a class="btn btn-ghost btn-sm" href="/">&larr; Your profile</a></span></div>
  </div>
  <div class="note-list">
    {items}
  </div>
</main>
</body></html>"#,
        css = APP_CSS,
        topbar = topbar("Home", &email),
        following = following.len(),
        items = items,
    );

    html_with_cookie(page, set_cookie)
}

/// One home-timeline card: the source actor + the (escaped) remote content + a UTC date, plus a
/// boost / un-boost control. `boosted` selects which action the button offers.
fn render_home_note(note: &HomeNote, csrf: &str, boosted: bool) -> String {
    let when = if note.published > 0 { note.published } else { note.received_at };
    let action = if boosted { "/api/unboost" } else { "/api/boost" };
    let label = if boosted { "🔁 Un-boost" } else { "🔁 Boost" };
    format!(
        r#"<article class="note">
  <div class="note__meta"><a href="{url}" rel="noopener noreferrer nofollow">{actor}</a></div>
  <div class="note__body">{body}</div>
  <div class="note__meta">{date}</div>
  <div class="note__actions">
    <form method="post" action="{action}">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="note_uri" value="{uri}">
      <button class="btn btn-ghost btn-sm" type="submit">{label}</button>
    </form>
  </div>
</article>"#,
        url = esc(&note.url),
        actor = esc(&note.actor),
        body = render_note_html(&note.content),
        date = esc(&fmt_date(when)),
        action = action,
        label = label,
        csrf = esc(csrf),
        uri = esc(&note.id),
    )
}

/// Trim + length-validate note content, returning the trimmed slice or an `InvalidRequest`.
fn validate_content(raw: &str) -> Result<&str, AppError> {
    let content = raw.trim();
    if content.is_empty() {
        return Err(AppError::InvalidRequest("note content is required".to_string()));
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
        return Err(AppError::InvalidRequest("image URL is too long".to_string()));
    }
    Ok(url.to_string())
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// One timeline note card: rendered (escaped) content + a UTC date, plus owner-only edit/delete
/// controls when `owned`. Every interpolated field is escaped.
fn render_note(note: &Note, csrf: &str, owned: bool) -> String {
    let edited = if note.updated_at > 0 { " · edited" } else { "" };
    let controls = if owned {
        render_controls(note, csrf)
    } else {
        String::new()
    };
    let media = render_media(&note.attachment_url);
    format!(
        r#"<article class="note">
  <div class="note__body">{body}</div>{media}
  <div class="note__meta">{date}{edited}</div>{controls}
</article>"#,
        body = render_note_html_tagged(&note.content),
        media = media,
        date = esc(&fmt_date(note.created_at)),
        edited = edited,
        controls = controls,
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
        r#"
  <div class="note__actions">
    <details class="note__edit">
      <summary class="btn btn-ghost btn-sm">Edit</summary>
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
      <button class="btn btn-danger btn-sm" type="submit">Delete</button>
    </form>
  </div>"#,
        id = id,
        csrf = csrf,
        content = esc(&note.content),
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
