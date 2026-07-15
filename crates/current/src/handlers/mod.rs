//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`river`] — the unified reading river (`/`), item open/mark-read, mark-all-read.
//! - [`feeds`] — feed management (`/feeds`): add by URL, remove.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every
//! page, matching the Steadholme enterprise brand: brand gradient, Current azure, cards,
//! buttons, the app-bar with the shield + wordmark + signed-in email + logout. ALL
//! producer-supplied AND remote feed text is HTML-escaped on render (defense-in-depth against
//! stored XSS); the service injects NO raw HTML.

pub mod feeds;
pub mod health;
pub mod reader;
pub mod river;

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, Response};
use std::sync::OnceLock;

use crate::auth;

/// Current-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

static APP_CSS: OnceLock<String> = OnceLock::new();

/// Embedded design system, inlined into each rendered page's `<style>`.
pub fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

/// The Feeds app icon (Lucide "rss") shown in the app-bar brand tile and the Feeds nav item.
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>"##;

/// Lucide-style line icons for the app-bar (nav + user menu).
const ICON_RIVER: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>"##;
const ICON_GRID: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##;
const ICON_CARET: &str = r##"<svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>"##;
const ICON_ACCOUNT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"##;
const ICON_LOGOUT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>"##;
const ICON_INBOX: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>"##;
const ICON_DOT: &str = r##"<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="12" cy="12" r="5"/></svg>"##;
const ICON_STAR: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 2 3.09 6.26L22 9.27l-5 4.87L18.18 21 12 17.77 5.82 21 7 14.14l-5-4.87 6.91-1.01L12 2z"/></svg>"##;

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Branded error page shell.
const ERROR_HTML: &str = include_str!("../../templates/error.html");

/// Resolve the display theme (`"light"`/`"dark"`/`"auto"`) from the request's `Cookie:` header.
/// This is a DISPLAY preference only — carried by the gateway-owned `__Secure-theme` cookie that
/// lives outside both gateway HMACs — so it is NEVER consulted for auth, CSRF, or identity.
pub(crate) fn theme_of(headers: &HeaderMap) -> &'static str {
    odyssey::resolve_theme(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()))
}

/// Shared Current page chrome: document head, azure app-bar, optional section tabs, and shell width.
#[allow(clippy::too_many_arguments)]
pub(crate) fn page_shell(
    head_title: &str,
    active_nav: &str,
    section: Option<&str>,
    count_pill: &str,
    shell_cls: &str,
    email: Option<&str>,
    theme: &str,
    main_inner: &str,
    after_main: &str,
) -> String {
    let sections = section
        .map(|active| section_tabs(Some(active), count_pill))
        .unwrap_or_default();
    format!(
        concat!(
            "<!DOCTYPE html>\n",
            "<html lang=\"en\"{theme_attr}>\n",
            "<head>\n",
            "  <meta charset=\"utf-8\">\n",
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
            "  <meta name=\"color-scheme\" content=\"{color_scheme}\">\n",
            "  <title>{title} · Current · Steadholme</title>\n",
            "  <style>{css}</style>\n",
            "</head>\n",
            "<body class=\"page-console\">\n",
            "  <header class=\"appbar\">\n",
            "    <a class=\"appbar__brand\" href=\"/\" aria-label=\"Steadholme Current\">\n",
            "      <span class=\"app-tile\" style=\"--app:#0369a1;--app-soft:#f0f9ff\" aria-hidden=\"true\">{shield}</span>\n",
            "      <span class=\"appbar__name\"><b>Current</b><span>rss.w33d.xyz</span></span>\n",
            "    </a>\n",
            "    {userbox}\n",
            "  </header>\n\n",
            "  <main class=\"console{shell_cls}\">\n",
            "{sections}",
            "{main_inner}\n",
            "  </main>\n",
            "{after_main}",
            "</body>\n",
            "</html>"
        ),
        title = esc(head_title),
        theme_attr = odyssey::html_theme_attr(theme),
        color_scheme = odyssey::color_scheme_meta(theme),
        css = app_css(),
        shield = SHIELD_SVG,
        userbox = userbox(active_nav, email, theme),
        shell_cls = shell_cls,
        sections = sections,
        main_inner = main_inner,
        after_main = after_main,
    )
}

/// Sticky river/feed section navigation. The inner nav class must remain exactly `tabs`.
pub(crate) fn section_tabs(active: Option<&str>, count_pill: &str) -> String {
    let tab = |key: &str, href: &str, label: &str, icon: &str| {
        let on = active == Some(key);
        let active_cls = if on { " is-active" } else { "" };
        let current = if on { " aria-current=\"page\"" } else { "" };
        let pill = if on { count_pill } else { "" };
        format!(
            "<a class=\"tab{active_cls}\" href=\"{href}\"{current}>{icon}<span>{label}</span>{pill}</a>",
            active_cls = active_cls,
            href = href,
            current = current,
            icon = icon,
            label = label,
            pill = pill,
        )
    };
    let feeds_on = active == Some("feeds");
    let feeds_cls = if feeds_on { " is-active" } else { "" };
    let feeds_current = if feeds_on {
        " aria-current=\"page\""
    } else {
        ""
    };
    format!(
        concat!(
            "<div class=\"cur-sections\"><nav class=\"tabs\">",
            "{unread}{starred}{all}",
            "<a class=\"tab cur-tab--feeds{feeds_cls}\" href=\"/feeds\"{feeds_current}>{feeds_icon}<span>Feeds</span></a>",
            "</nav></div>"
        ),
        unread = tab("unread", "/", "Unread", ICON_DOT),
        starred = tab("starred", "/?filter=starred", "Starred", ICON_STAR),
        all = tab("all", "/?filter=all", "All", ICON_INBOX),
        feeds_cls = feeds_cls,
        feeds_current = feeds_current,
        feeds_icon = SHIELD_SVG,
    )
}

/// Stable source tile initial, escaped for direct insertion into HTML.
pub(crate) fn tile_initial(s: &str) -> String {
    let initial = s
        .chars()
        .find(|ch| ch.is_alphanumeric())
        .map(|ch| ch.to_uppercase().to_string())
        .unwrap_or_else(|| "#".to_string());
    esc(&initial)
}

/// Stable source tile tint, byte-identical to Magpie's tone convention.
pub(crate) fn tile_tint(s: &str) -> usize {
    s.bytes().map(usize::from).sum::<usize>() % 5 + 1
}

/// The app-bar right side (v2): the River/Feeds nav, an "All apps" waffle back to the apex
/// portal, and a CSS focus-within avatar menu (Account · All apps · Log out). `active`
/// highlights the current section (`"river"` / `"feeds"`). The logout route/method are
/// preserved exactly (a GET link to the gateway) as a danger menu item.
pub fn userbox(active: &str, email: Option<&str>, theme: &str) -> String {
    let river_cls = if active == "river" { " is-active" } else { "" };
    let feeds_cls = if active == "feeds" { " is-active" } else { "" };
    let (initials, name, sub) = identity_bits(email.unwrap_or(""));
    let themeswitch = themeswitch(theme);
    format!(
        concat!(
            "<nav class=\"appbar__nav\">",
            "<a class=\"appnav{river_cls}\" href=\"/\">{icon_river}River</a>",
            "<a class=\"appnav{feeds_cls}\" href=\"/feeds\">{icon_rss}Feeds</a>",
            "</nav>",
            "<span class=\"appbar__spacer\"></span>",
            "<div class=\"appbar__right\">",
            "{themeswitch}",
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
        themeswitch = themeswitch,
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

/// The app-bar three-state theme switcher (Light · Dark · System), a pure `<a href>` set that
/// flips the gateway-owned `__Secure-theme` cookie via `/_gw/theme` — no JS, no service route. The
/// `.themeswitch` / `.themeswitch__opt` styles ship in the vendored Odyssey APP_CSS. `active` is the
/// resolved theme (`"light"`/`"dark"`/`"auto"`); the matching option gets `is-active` + `aria-current`.
fn themeswitch(active: &str) -> String {
    let on = |k: &str| if active == k { " is-active" } else { "" };
    let cur = |k: &str| {
        if active == k {
            " aria-current=\"true\""
        } else {
            ""
        }
    };
    format!(
        concat!(
            "<div class=\"themeswitch\" role=\"group\" aria-label=\"Theme\">\n",
            "  <a class=\"themeswitch__opt{ls}\" href=\"/_gw/theme?to=light\" title=\"Light\" aria-label=\"Light\"{lc}><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"4\"/><path d=\"M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4\"/></svg></a>\n",
            "  <a class=\"themeswitch__opt{ds}\" href=\"/_gw/theme?to=dark\" title=\"Dark\" aria-label=\"Dark\"{dc}><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M12 3a6.5 6.5 0 0 0 9 9 9 9 0 1 1-9-9Z\"/></svg></a>\n",
            "  <a class=\"themeswitch__opt{as_}\" href=\"/_gw/theme?to=auto\" title=\"System\" aria-label=\"System\"{ac}><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><rect x=\"2\" y=\"3\" width=\"20\" height=\"14\" rx=\"2\"/><path d=\"M8 21h8M12 17v4\"/></svg></a>\n",
            "</div>",
        ),
        ls = on("light"),
        lc = cur("light"),
        ds = on("dark"),
        dc = cur("dark"),
        as_ = on("auto"),
        ac = cur("auto"),
    )
}

/// Derive the avatar initials, the primary display name, and a secondary line for the user menu
/// from a (possibly empty) signed-in email. With no identity we fall back to a neutral glyph so
/// the chrome always renders.
fn identity_bits(email: &str) -> (String, String, String) {
    let e = email.trim();
    if e.is_empty() {
        return (
            "H".to_string(),
            "Account".to_string(),
            "Signed in".to_string(),
        );
    }
    let local = e.split('@').next().unwrap_or(e);
    let initials = local
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "H".to_string());
    (initials, e.to_string(), "Steadholme SSO".to_string())
}

/// Render the branded error page (used by [`crate::error::AppError`] and the not-found paths).
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let main = ERROR_HTML
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message));
    let body = page_shell(
        &status.as_u16().to_string(),
        "",
        None,
        "",
        "",
        email,
        "light",
        &main,
        "",
    );
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
