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

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Branded error page shell.
const ERROR_HTML: &str = include_str!("../../templates/error.html");

/// The app-bar right side: the two nav links, the signed-in email, and the cross-subdomain
/// logout link. `active` highlights the current section (`"river"` / `"feeds"`).
pub fn userbox(active: &str, email: Option<&str>) -> String {
    let river_cls = if active == "river" { " is-active" } else { "" };
    let feeds_cls = if active == "feeds" { " is-active" } else { "" };
    // A user chip (avatar initial + email) when a gateway identity is known; the "All apps" link
    // back to the apex portal and the cross-subdomain logout complete the shared app-bar chrome.
    let chip = match email {
        Some(e) if !e.is_empty() => {
            let initial = e
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "H".to_string());
            format!(
                "<span class=\"userchip\"><span class=\"userchip__avatar\" aria-hidden=\"true\">{}</span><span class=\"user-email\">{}</span></span>",
                esc(&initial),
                esc(e),
            )
        }
        _ => String::new(),
    };
    format!(
        concat!(
            "<nav class=\"topnav\">",
            "<a class=\"topnav__link{river_cls}\" href=\"/\">River</a>",
            "<a class=\"topnav__link{feeds_cls}\" href=\"/feeds\">Feeds</a>",
            "</nav>",
            "<a class=\"allapps\" href=\"https://w33d.xyz\" title=\"All apps\">",
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">",
            "<rect x=\"3\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/>",
            "<rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/></svg>All apps</a>",
            "{chip}",
            "<a class=\"btn btn-ghost btn-sm\" href=\"{LOGOUT_URL}\">Log out</a>",
        ),
        river_cls = river_cls,
        feeds_cls = feeds_cls,
        chip = chip,
        LOGOUT_URL = LOGOUT_URL,
    )
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
