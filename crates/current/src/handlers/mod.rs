//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`river`] — the unified reading river (`/`), item open/mark-read, mark-all-read.
//! - [`feeds`] — feed management (`/feeds`): add by URL, remove.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every
//! page, matching the HOLDFAST enterprise brand: brand gradient, indigo accent, cards,
//! buttons, the app-bar with the shield + wordmark + signed-in email + logout. ALL
//! producer-supplied AND remote feed text is HTML-escaped on render (defense-in-depth against
//! stored XSS); the service injects NO raw HTML.

pub mod feeds;
pub mod health;
pub mod reader;
pub mod river;

use axum::http::{header, StatusCode};
use axum::response::{Html, Response};

use crate::auth;

/// Embedded design system, inlined into each rendered page's `<style>`.
pub const APP_CSS: &str = include_str!("../../static/app.css");

/// The Feeds app icon (Lucide "rss") shown in the app-bar brand tile and the Feeds nav item.
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>"##;

/// Lucide-style line icons for the app-bar (nav + user menu).
const ICON_RIVER: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>"##;
const ICON_GRID: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##;
const ICON_CARET: &str = r##"<svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>"##;
const ICON_ACCOUNT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"##;
const ICON_LOGOUT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>"##;

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Branded error page shell.
const ERROR_HTML: &str = include_str!("../../templates/error.html");

/// The app-bar right side (v2): the River/Feeds nav, an "All apps" waffle back to the apex
/// portal, and a CSS focus-within avatar menu (Account · All apps · Log out). `active`
/// highlights the current section (`"river"` / `"feeds"`). The logout route/method are
/// preserved exactly (a GET link to the gateway) as a danger menu item.
pub fn userbox(active: &str, email: Option<&str>) -> String {
    let river_cls = if active == "river" { " is-active" } else { "" };
    let feeds_cls = if active == "feeds" { " is-active" } else { "" };
    let (initials, name, sub) = identity_bits(email.unwrap_or(""));
    format!(
        concat!(
            "<nav class=\"appbar__nav\">",
            "<a class=\"appnav{river_cls}\" href=\"/\">{icon_river}River</a>",
            "<a class=\"appnav{feeds_cls}\" href=\"/feeds\">{icon_rss}Feeds</a>",
            "</nav>",
            "<span class=\"appbar__spacer\"></span>",
            "<div class=\"appbar__right\">",
            "<a class=\"iconbtn\" href=\"https://w33d.xyz\" title=\"All apps\" aria-label=\"All apps\">{icon_grid}</a>",
            "<div class=\"usermenu\">",
            "<button class=\"usermenu__btn\" type=\"button\" aria-haspopup=\"true\" aria-label=\"Account menu\">",
            "<span class=\"avatar\" aria-hidden=\"true\">{initials}</span>",
            "<span class=\"usermenu__name\">{name}</span>{icon_caret}</button>",
            "<div class=\"usermenu__pop\" role=\"menu\">",
            "<div class=\"usermenu__head\"><span class=\"avatar avatar--lg\" aria-hidden=\"true\">{initials}</span>",
            "<div><b>{name}</b><span>{sub}</span></div></div>",
            "<a class=\"menuitem\" href=\"https://account.w33d.xyz\" role=\"menuitem\">{icon_account}Account</a>",
            "<a class=\"menuitem\" href=\"https://w33d.xyz\" role=\"menuitem\">{icon_grid}All apps</a>",
            "<a class=\"menuitem menuitem--danger\" href=\"{logout}\" role=\"menuitem\">{icon_logout}Log out</a>",
            "</div></div></div>",
        ),
        river_cls = river_cls,
        feeds_cls = feeds_cls,
        icon_river = ICON_RIVER,
        icon_rss = SHIELD_SVG,
        icon_grid = ICON_GRID,
        icon_caret = ICON_CARET,
        icon_account = ICON_ACCOUNT,
        icon_logout = ICON_LOGOUT,
        initials = esc(&initials),
        name = esc(&name),
        sub = esc(&sub),
        logout = LOGOUT_URL,
    )
}

/// Derive the avatar initials, the primary display name, and a secondary line for the user menu
/// from a (possibly empty) signed-in email. With no identity we fall back to a neutral glyph so
/// the chrome always renders.
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

/// Render the branded error page (used by [`crate::error::AppError`] and the not-found paths).
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let body = ERROR_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("", email))
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message));
    (status, Html(body))
}

/// Wrap rendered HTML in a response that also (re)sets the CSRF cookie (so every form on the
/// page can echo the matching token).
pub fn html_with_csrf(status: StatusCode, html: String, csrf: &str) -> Response {
    use axum::response::IntoResponse;
    (
        status,
        [(header::SET_COOKIE, auth::csrf_cookie(csrf))],
        Html(html),
    )
        .into_response()
}

/// A `303 See Other` redirect (the POST-then-GET response for our form actions).
pub fn redirect_see_other(location: &str) -> Response {
    use axum::response::IntoResponse;
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// A `302 Found` redirect (used when "opening" an item out to its external article link).
pub fn redirect_found(location: &str) -> Response {
    use axum::response::IntoResponse;
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// Format epoch seconds as a compact UTC timestamp `YYYY-MM-DD HH:MM:SSZ` (used as a tooltip).
pub fn fmt_ts(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => secs.to_string(),
    }
}

/// A short, human relative time ("just now", "5m ago", "3h ago", "2d ago"); future or unknown
/// times fall back to the absolute timestamp.
pub fn fmt_rel(secs: i64, now: i64) -> String {
    let delta = now - secs;
    if delta < 0 {
        return fmt_ts(secs);
    }
    match delta {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{}m ago", delta / 60),
        3600..=86399 => format!("{}h ago", delta / 3600),
        86400..=2591999 => format!("{}d ago", delta / 86400),
        _ => fmt_ts(secs),
    }
}

/// Minimal HTML escaping for text/attribute interpolation.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn relative_time_buckets() {
        assert_eq!(fmt_rel(1000, 1000), "just now");
        assert_eq!(fmt_rel(1000, 1000 + 120), "2m ago");
        assert_eq!(fmt_rel(1000, 1000 + 7200), "2h ago");
        assert_eq!(fmt_rel(1000, 1000 + 172800), "2d ago");
    }
}
