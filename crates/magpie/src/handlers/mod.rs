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

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://id.w33d.xyz/_gw/auth/logout";

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

/// The right side of the app-bar: a page title, an "All apps" pill back to the apex portal, a
/// user chip (avatar initial + signed-in email, when known), and the cross-subdomain logout link.
/// Shared by every page so the chrome stays identical across the estate.
pub fn userbox(title: &str, email: Option<&str>) -> String {
    // A user chip (avatar initial + email) is shown when a gateway identity is known.
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
            "<span class=\"topbar__title\">{title}</span>",
            "<a class=\"allapps\" href=\"https://w33d.xyz\" title=\"All apps\">",
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">",
            "<rect x=\"3\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/>",
            "<rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/></svg>All apps</a>",
            "{chip}",
            "<a class=\"btn btn-ghost btn-sm\" href=\"{LOGOUT_URL}\">Log out</a>",
        ),
        title = esc(title),
        chip = chip,
        LOGOUT_URL = LOGOUT_URL,
    )
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
