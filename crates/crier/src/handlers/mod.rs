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
use std::sync::OnceLock;

/// Crier-only CSS layered after Odyssey's canonical font, tokens, and components.
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
pub const ICON_USER: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"##;
pub const ICON_HOME: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/></svg>"##;
pub const ICON_LIST: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>"##;
pub const ICON_BELL: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.27 21a2 2 0 0 0 3.46 0"/><path d="M3.26 15.33A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.67C19.8 14.29 18 12.6 18 8a6 6 0 0 0-12 0c0 4.6-1.8 6.29-2.74 7.33"/></svg>"##;
pub const ICON_BAN: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 14.14 14.14"/></svg>"##;
const ICON_CARET: &str = r##"<svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>"##;
const ICON_LOGOUT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>"##;

// Lucide-style line icons for the redesigned feed (post cards, action bars, overflow menus).
pub const ICON_REPLY: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.9 20A9 9 0 1 0 4 16.1L2 22z"/></svg>"##;
pub const ICON_BOOST: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m2 9 3-3 3 3"/><path d="M13 18H7a2 2 0 0 1-2-2V6"/><path d="m22 15-3 3-3-3"/><path d="M11 6h6a2 2 0 0 1 2 2v10"/></svg>"##;
pub const ICON_THREAD: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 9a2 2 0 0 1-2 2H6l-4 4V4c0-1.1.9-2 2-2h8a2 2 0 0 1 2 2z"/><path d="M18 9h2a2 2 0 0 1 2 2v11l-4-4h-6a2 2 0 0 1-2-2v-1"/></svg>"##;
pub const ICON_EXTLINK: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>"##;
pub const ICON_MORE: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg>"##;
pub const ICON_REPLYCTX: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="9 14 4 9 9 4"/><path d="M20 20v-7a4 4 0 0 0-4-4H4"/></svg>"##;
pub const ICON_IMAGE: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/></svg>"##;
pub const ICON_EDIT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>"##;
pub const ICON_TRASH: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>"##;

/// Progressive-enhancement companion emitted right after the app-bar on every SSO page: a fixed
/// toast host plus one small script that (1) renders relative timestamps from `<time data-ts>` (the
/// absolute date stays as the no-JS fallback + hover title), (2) fills the live unread-notifications
/// nav badge, (3) adds char counters to composer/reply textareas, and (4) makes the /home boost
/// button optimistic (no reload; rolls back + toasts on failure). All remote/dynamic text is set
/// via `textContent`, never `innerHTML`. It is inert on pages that lack the matching elements.
const TOPBAR_ENHANCE: &str = r#"
<div class="toast-host" data-toast-host aria-live="polite" aria-atomic="true"></div>
<script>
(function(){
  function cookie(n){var p=document.cookie?document.cookie.split('; '):[];for(var i=0;i<p.length;i++){var e=p[i].indexOf('=');if(e>-1&&p[i].slice(0,e)===n)return decodeURIComponent(p[i].slice(e+1));}return '';}
  var CSRF=cookie('__Host-csrf');
  var host=document.querySelector('[data-toast-host]');
  function toast(msg,ok){if(!host)return;var t=document.createElement('div');t.className='toast '+(ok?'toast--ok':'toast--err');t.setAttribute('role','status');t.textContent=msg;host.appendChild(t);setTimeout(function(){t.classList.add('is-leaving');setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},200);},2400);}
  function post(url,params){var b=Object.keys(params).map(function(k){return encodeURIComponent(k)+'='+encodeURIComponent(params[k]);}).join('&');return fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},body:b}).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();});}
  function rel(ts){var now=Math.floor(Date.now()/1000);var d=now-ts;if(d<0||isNaN(d))return null;if(d<60)return 'just now';if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';if(d<2592000)return Math.floor(d/86400)+'d ago';return null;}
  Array.prototype.forEach.call(document.querySelectorAll('time.ts[data-ts]'),function(t){var r=rel(parseInt(t.getAttribute('data-ts'),10));if(r)t.textContent=r;});
  var badges=document.querySelectorAll('[data-notif-badge]');
  if(badges.length){fetch('/api/notifications/unread',{credentials:'same-origin',headers:{'Accept':'application/json'}}).then(function(r){return r.ok?r.json():null;}).then(function(d){if(d&&d.unread>0){var txt=d.unread>99?'99+':String(d.unread);Array.prototype.forEach.call(badges,function(b){b.textContent=txt;b.removeAttribute('hidden');});}}).catch(function(){});}
  Array.prototype.forEach.call(document.querySelectorAll('textarea[maxlength]'),function(ta){var max=parseInt(ta.getAttribute('maxlength'),10);if(!max)return;var c=document.createElement('div');c.className='char-counter';function upd(){var n=ta.value.length;c.textContent=n+'/'+max;if(n>=max)c.classList.add('is-max');else c.classList.remove('is-max');}if(ta.parentNode)ta.parentNode.appendChild(c);upd();ta.addEventListener('input',upd);});
  function toggleBoost(form){var on=form.getAttribute('data-boosted')==='1';var uri=form.getAttribute('data-note-uri')||'';var btn=form.querySelector('button');if(!uri||!CSRF){form.submit();return;}if(btn)btn.setAttribute('aria-busy','true');var url=on?'/api/unboost/json':'/api/boost/json';post(url,{csrf_token:CSRF,note_uri:uri,from:'home'}).then(function(d){var nowOn=!!d.boosted;form.setAttribute('data-boosted',nowOn?'1':'0');form.setAttribute('action',nowOn?'/api/unboost':'/api/boost');if(btn){btn.removeAttribute('aria-busy');var lbl=btn.querySelector('[data-boost-label]');if(lbl){lbl.textContent=nowOn?'Un-boost':'Boost';}else{btn.textContent=nowOn?'Un-boost':'Boost';}}toast(nowOn?'Boost added':'Boost removed',true);}).catch(function(){if(btn)btn.removeAttribute('aria-busy');toast('Could not update — try again',false);});}
  document.addEventListener('submit',function(e){var f=e.target;if(!(f instanceof HTMLFormElement))return;if(f.hasAttribute('data-boost-form')){e.preventDefault();toggleBoost(f);}});
})();
</script>"#;

/// Render the shared app-bar (v2): the at-sign brand tile + Social lockup on the left; the
/// Profile/Home nav; then an "All apps" waffle back to the apex portal and a CSS focus-within
/// avatar menu (Account · All apps · Log out). `page_title` selects the active nav item. The
/// logout route/method are preserved exactly (a GET link to the gateway) as a danger menu item;
/// with no gateway identity (public/error chrome) the avatar falls back to a neutral glyph.
pub fn topbar(page_title: &str, email: &str) -> String {
    // "Profile" is the default active section; app sections highlight when selected.
    let profile_cls = if matches!(page_title, "Home" | "Lists" | "Notifications" | "Blocks") {
        ""
    } else {
        " is-active"
    };
    let home_cls = if page_title == "Home" {
        " is-active"
    } else {
        ""
    };
    let lists_cls = if page_title == "Lists" {
        " is-active"
    } else {
        ""
    };
    let notifications_cls = if page_title == "Notifications" {
        " is-active"
    } else {
        ""
    };
    let blocks_cls = if page_title == "Blocks" {
        " is-active"
    } else {
        ""
    };
    let ident = if email.is_empty() || email == "—" {
        ""
    } else {
        email
    };
    let (initials, name, sub) = identity_bits(ident);
    let header = format!(
        r#"<header class="appbar">
  <a class="appbar__brand" href="/" aria-label="HOLDFAST Social">
    <span class="app-tile" style="--app:#7c3aed;--app-soft:#f4f0fe" aria-hidden="true">{shield}</span>
    <span class="appbar__name"><b>Social</b><span>social.w33d.xyz</span></span>
  </a>
  <nav class="appbar__nav">
    <a class="appnav{profile_cls}" href="/">{icon_user}Profile</a>
    <a class="appnav{home_cls}" href="/home">{icon_home}Home</a>
    <a class="appnav{lists_cls}" href="/lists">{icon_list}Lists</a>
    <a class="appnav{notifications_cls}" href="/notifications">{icon_bell}Notifications<span class="nav-badge" data-notif-badge hidden aria-label="unread notifications"></span></a>
    <a class="appnav{blocks_cls}" href="/blocks">{icon_ban}Blocks</a>
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
        notifications_cls = notifications_cls,
        blocks_cls = blocks_cls,
        icon_user = ICON_USER,
        icon_home = ICON_HOME,
        icon_list = ICON_LIST,
        icon_bell = ICON_BELL,
        icon_ban = ICON_BAN,
        icon_caret = ICON_CARET,
        icon_logout = ICON_LOGOUT,
        allapps = ALLAPPS_SVG,
        initials = esc(&initials),
        name = esc(&name),
        sub = esc(&sub),
        logout = LOGOUT_URL,
    );
    // Append the shared toast host + progressive-enhancement script (inert where it finds nothing).
    format!(
        "{header}{enhance}",
        header = header,
        enhance = TOPBAR_ENHANCE
    )
}

/// The feed-scope tab strip that sits directly under the app-bar on every page: "Which timeline am
/// I looking at?" (Your posts / Following / Notifications). Deliberately worded apart from the
/// app-bar section nav so it doesn't read as a duplicate menu — and because the canonical app-bar
/// hides its nav below 720px, this strip IS the mobile section nav. `active` is one of
/// "profile" | "home" | "notifications" | "" (a drill-down page highlights nothing). The
/// Notifications tab carries a second live unread badge (the shared script fills every
/// `[data-notif-badge]`).
pub fn feed_tabs(active: &str) -> String {
    let cls = |k: &str| if active == k { " is-active" } else { "" };
    let aria = |k: &str| if active == k { r#" aria-current="page""# } else { "" };
    format!(
        r#"<nav class="tabs crier-feedtabs" aria-label="Timelines">
  <a class="tab{p_cls}" href="/"{p_aria}>{icon_user}Your posts</a>
  <a class="tab{h_cls}" href="/home"{h_aria}>{icon_home}Following</a>
  <a class="tab{n_cls}" href="/notifications"{n_aria}>{icon_bell}Notifications<span class="nav-badge" data-notif-badge hidden aria-label="unread notifications"></span></a>
</nav>"#,
        p_cls = cls("profile"),
        p_aria = aria("profile"),
        h_cls = cls("home"),
        h_aria = aria("home"),
        n_cls = cls("notifications"),
        n_aria = aria("notifications"),
        icon_user = ICON_USER,
        icon_home = ICON_HOME,
        icon_bell = ICON_BELL,
    )
}

/// Derive the avatar initials, the primary display name, and a secondary menu line from a
/// (possibly empty) signed-in email. With no identity we fall back to a neutral glyph so the
/// chrome always renders.
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
    (initials, e.to_string(), "HOLDFAST SSO".to_string())
}

/// Format epoch seconds as a compact UTC date `Mon D, YYYY` (e.g. `Jun 29, 2026`). std `time` only.
pub fn fmt_date(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!("{} {}, {}", month_abbr(dt.month()), dt.day(), dt.year()),
        Err(_) => secs.to_string(),
    }
}

/// A `<time>` element carrying the epoch seconds in `data-ts` so the shared client script can
/// render a live relative label ("5m ago"). The server-rendered text AND the hover `title` are the
/// absolute UTC date, so a no-JS reader still sees a real, stable timestamp (backward compatible).
pub fn time_el(secs: i64) -> String {
    let abs = fmt_date(secs);
    format!(
        r#"<time class="ts" data-ts="{secs}" title="{abs}">{abs}</time>"#,
        secs = secs,
        abs = esc(&abs),
    )
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
        css = app_css(),
        topbar = topbar("Crier", "—"),
        code = code,
        reason = esc(reason),
        msg = esc(message),
    )
}
