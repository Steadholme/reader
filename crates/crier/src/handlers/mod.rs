//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `web` carries the SSO timeline + composer; `ap`
//! carries the public ActivityPub / WebFinger surface.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the HOLDFAST enterprise brand (the same look as the Keystone/inkwell UI): brand
//! gradient, indigo accent, cards, app-bar.

pub mod admin;
pub mod ap;
pub mod health;
pub mod web;

use axum::http::StatusCode;

/// Embedded design system, inlined into each rendered page's `<style>`.
pub const APP_CSS: &str = include_str!("../../static/app.css");

/// Cross-subdomain gateway logout (Crier lives at social.w33d.xyz; the IdP is at id.w33d.xyz).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// The Social app icon (Lucide "at-sign") shown in the app-bar brand tile.
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"/></svg>"##;

/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth on every field).
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Render note text for the timeline: HTML-escaped, with newlines turned into `<br>` (no markup of
/// any kind survives — notes are plain text).
pub fn render_note_html(content: &str) -> String {
    esc(content).replace('\n', "<br>")
}

/// Render LOCAL note text with hashtags linkified to their `/tags/{tag}` page. Otherwise identical
/// to [`render_note_html`]: every non-tag character is HTML-escaped and newlines become `<br>`, so
/// no author markup survives. The escaping is done per-character in the SAME pass that recognizes
/// tags, so an escaped entity like `&#x27;` can never be mistaken for a hashtag. Used ONLY for our
/// own notes — remote/home content stays plain [`render_note_html`].
pub fn render_note_html_tagged(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(content.len());
    let mut i = 0;
    while i < n {
        let c = chars[i];
        let at_boundary = i == 0 || !crate::hashtag::is_tag_char(chars[i - 1]);
        if c == '#' && at_boundary {
            let start = i + 1;
            let mut j = start;
            while j < n && crate::hashtag::is_tag_char(chars[j]) {
                j += 1;
            }
            if j > start {
                let tag: String = chars[start..j].iter().collect();
                let lower = tag.to_lowercase();
                // `lower` is all `[A-Za-z0-9_]` (URL-safe); escape both for defense in depth.
                out.push_str(&format!(
                    "<a class=\"tag\" href=\"/tags/{href}\">#{label}</a>",
                    href = esc(&lower),
                    label = esc(&tag),
                ));
                i = j;
                continue;
            }
        }
        match c {
            '\n' => out.push_str("<br>"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

/// The 3x3 "All apps" grid glyph for the apex-portal back link (also the All-apps menu item).
const ALLAPPS_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##;
/// Lucide-style line icons for the app-bar nav + user menu.
const ICON_USER: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"##;
const ICON_HOME: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/></svg>"##;
const ICON_LIST: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>"##;
const ICON_CARET: &str = r##"<svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>"##;
const ICON_LOGOUT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>"##;

/// Render the shared app-bar (v2): the at-sign brand tile + Social lockup on the left; the
/// Profile/Home nav; then an "All apps" waffle back to the apex portal and a CSS focus-within
/// avatar menu (Account · All apps · Log out). `page_title` selects the active nav item. The
/// logout route/method are preserved exactly (a GET link to the gateway) as a danger menu item;
/// with no gateway identity (public/error chrome) the avatar falls back to a neutral glyph.
pub fn topbar(page_title: &str, email: &str) -> String {
    // "Profile" is the default active section; Home / Lists highlight when selected.
    let profile_cls = if page_title == "Home" || page_title == "Lists" {
        ""
    } else {
        " is-active"
    };
    let home_cls = if page_title == "Home" { " is-active" } else { "" };
    let lists_cls = if page_title == "Lists" { " is-active" } else { "" };
    let ident = if email.is_empty() || email == "—" { "" } else { email };
    let (initials, name, sub) = identity_bits(ident);
    format!(
        r#"<header class="appbar">
  <a class="appbar__brand" href="/" aria-label="HOLDFAST Social">
    <span class="app-tile" style="--app:#7c3aed;--app-soft:#f4f0fe" aria-hidden="true">{shield}</span>
    <span class="appbar__name"><b>Social</b><span>social.w33d.xyz</span></span>
  </a>
  <nav class="appbar__nav">
    <a class="appnav{profile_cls}" href="/">{icon_user}Profile</a>
    <a class="appnav{home_cls}" href="/home">{icon_home}Home</a>
    <a class="appnav{lists_cls}" href="/lists">{icon_list}Lists</a>
  </nav>
  <span class="appbar__spacer"></span>
  <div class="appbar__right">
    <a class="iconbtn" href="https://w33d.xyz" title="All apps" aria-label="All apps">{allapps}</a>
    <div class="usermenu">
      <button class="usermenu__btn" type="button" aria-haspopup="true" aria-label="Account menu">
        <span class="avatar" aria-hidden="true">{initials}</span>
        <span class="usermenu__name">{name}</span>{icon_caret}</button>
      <div class="usermenu__pop" role="menu">
        <div class="usermenu__head"><span class="avatar avatar--lg" aria-hidden="true">{initials}</span><div><b>{name}</b><span>{sub}</span></div></div>
        <a class="menuitem" href="https://account.w33d.xyz" role="menuitem">{icon_user}Account</a>
        <a class="menuitem" href="https://w33d.xyz" role="menuitem">{allapps}All apps</a>
        <a class="menuitem menuitem--danger" href="{logout}" role="menuitem">{icon_logout}Log out</a>
      </div>
    </div>
  </div>
</header>"#,
        shield = SHIELD_SVG,
        profile_cls = profile_cls,
        home_cls = home_cls,
        lists_cls = lists_cls,
        icon_user = ICON_USER,
        icon_home = ICON_HOME,
        icon_list = ICON_LIST,
        icon_caret = ICON_CARET,
        icon_logout = ICON_LOGOUT,
        allapps = ALLAPPS_SVG,
        initials = esc(&initials),
        name = esc(&name),
        sub = esc(&sub),
        logout = LOGOUT_URL,
    )
}

/// Derive the avatar initials, the primary display name, and a secondary menu line from a
/// (possibly empty) signed-in email. With no identity we fall back to a neutral glyph so the
/// chrome always renders.
fn identity_bits(email: &str) -> (String, String, String) {
    let e = email.trim();
    if e.is_empty() {
        return ("H".to_string(), "Account".to_string(), "Signed in".to_string());
    }
    let local = e.split('@').next().unwrap_or(e);
    let initials = local
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "H".to_string());
    (initials, e.to_string(), "HOLDFAST SSO".to_string())
}

/// Format epoch seconds as a compact UTC date `Mon D, YYYY` (e.g. `Jun 29, 2026`). std `time` only.
pub fn fmt_date(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!("{} {}, {}", month_abbr(dt.month()), dt.day(), dt.year()),
        Err(_) => secs.to_string(),
    }
}

fn month_abbr(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}

/// A small, branded HTML error page (used by [`crate::error::AppError`]).
pub fn error_page(status: StatusCode, message: &str) -> String {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{code} {reason} · Crier</title><style>{css}</style></head>
<body class="page-reading">
{topbar}
<main class="reader">
  <div class="error-card">
    <div class="error-card__code">{code}</div>
    <h1 class="error-card__title">{reason}</h1>
    <p class="error-card__msg">{msg}</p>
    <a class="btn btn-primary" href="/">Back to the timeline</a>
  </div>
</main>
</body></html>"#,
        css = APP_CSS,
        topbar = topbar("Crier", "—"),
        code = code,
        reason = esc(reason),
        msg = esc(message),
    )
}
