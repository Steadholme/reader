//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`clips`] — the SSO clipper surface (reading list, save, reader, archive, delete).
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the HOLDFAST enterprise brand: brand gradient, indigo accent, cards, buttons, the
//! app-bar with the shield + wordmark. Every producer-supplied OR remote string is HTML-escaped
//! on render (defense-in-depth against stored XSS); the service emits NO raw remote HTML.

pub mod clips;
pub mod health;

use axum::http::StatusCode;
use axum::response::Html;

/// Embedded design system, inlined into each rendered page's `<style>`.
pub const APP_CSS: &str = include_str!("../../static/app.css");

/// The Clips app icon (Lucide "bookmark") shown in the app-bar brand tile.
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>"##;

/// Lucide-style line icons for the app-bar (nav + user menu).
const ICON_LIST: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>"##;
const ICON_HIGHLIGHT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 11-6 6v3h9l3-3"/><path d="m22 12-4.6 4.6a2 2 0 0 1-2.8 0l-5.2-5.2a2 2 0 0 1 0-2.8L14 4"/></svg>"##;
const ICON_GRID: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##;
const ICON_CARET: &str = r##"<svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>"##;
const ICON_ACCOUNT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"##;
const ICON_LOGOUT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>"##;

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Branded error page shell.
const ERROR_HTML: &str = include_str!("../../templates/error.html");

/// Format epoch seconds as a compact UTC timestamp `YYYY-MM-DD HH:MM:SSZ`.
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

/// The app-bar right side (v2): the Reading list / Highlights nav, an "All apps" waffle back to
/// the apex portal, and a CSS focus-within avatar menu (Account · All apps · Log out). `title`
/// selects the active nav item. The logout route/method are preserved exactly (a GET link to the
/// gateway) as a danger menu item.
pub fn userbox(title: &str, email: Option<&str>) -> String {
    let highlights_active = title == "Highlights";
    let reading_active = matches!(title, "Reading list" | "Reader" | "Search" | "Save");
    let list_cls = if reading_active { " is-active" } else { "" };
    let hl_cls = if highlights_active { " is-active" } else { "" };
    let (initials, name, sub) = identity_bits(email.unwrap_or(""));
    format!(
        concat!(
            "<nav class=\"appbar__nav\">",
            "<a class=\"appnav{list_cls}\" href=\"/\">{icon_list}Reading list</a>",
            "<a class=\"appnav{hl_cls}\" href=\"/highlights\">{icon_hl}Highlights</a>",
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
        list_cls = list_cls,
        hl_cls = hl_cls,
        icon_list = ICON_LIST,
        icon_hl = ICON_HIGHLIGHT,
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

/// Build the draggable bookmarklet `href` (a `javascript:` URL) for the given public base.
///
/// It opens `<base>/clip?u=<page>` as a TOP-LEVEL GET in a new tab. A top-level GET carries the
/// SameSite=Lax gateway SSO cookie (a cross-site POST would NOT), so the landing page is
/// authenticated; that page then POSTs to `/clip` same-origin with a real CSRF token.
pub fn bookmarklet_href(base_url: &str) -> String {
    // Single-quoted JS string literals so the value survives HTML-attribute escaping cleanly.
    format!(
        "javascript:(function(){{window.open('{base}/clip?u='+encodeURIComponent(location.href),'_blank');}})();void%200",
        base = base_url
    )
}

/// Render the branded error page (used by [`crate::error::AppError`] and the not-found paths).
/// `email` is shown in the app-bar when a gateway identity is known.
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let body = ERROR_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Magpie", email))
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message));
    (status, Html(body))
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
    fn bookmarklet_targets_clip_endpoint() {
        let href = bookmarklet_href("https://clip.w33d.xyz");
        assert!(href.starts_with("javascript:"));
        assert!(href.contains("https://clip.w33d.xyz/clip?u="));
        assert!(href.contains("encodeURIComponent(location.href)"));
    }
}
