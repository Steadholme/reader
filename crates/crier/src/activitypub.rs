//! ActivityPub / WebFinger JSON document builders.
//!
//! Pure functions: each turns the [`Config`] + stored data into the exact JSON shape a fediverse
//! server expects. They are transport-agnostic (no axum, no store) so they are trivially unit
//! tested. Note CONTENT is HTML-escaped into a `<p>…</p>` fragment by [`content_to_html`], so a
//! remote that renders our notes can never receive script/markup we did not intend.
//!
//! Federation NOTE: Crier serves a fully correct actor / outbox / WebFinger, publishes the actor's
//! `publicKey` (see [`crate::httpsig`]), SIGNS every outbound delivery (draft-cavage HTTP
//! Signatures), and can verify inbound POSTs. Local correctness is independent of federation — the
//! microblog + actor/outbox JSON stay correct even with no remote reachable.

use serde_json::{json, Value};

use crate::config::Config;
use crate::store::{Follower, Note, Profile};

/// The ActivityStreams "public" magic collection every public post is addressed to.
pub const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

/// The `application/activity+json` content type Crier serves all ActivityPub documents as.
pub const ACTIVITY_JSON: &str = "application/activity+json";

/// Escape note text into a safe single-paragraph HTML fragment. Newlines become `<br>`; every other
/// character is HTML-escaped, so author text can never inject live markup downstream.
pub fn content_to_html(content: &str) -> String {
    let escaped = content
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
        .replace('\n', "<br>");
    format!("<p>{escaped}</p>")
}

/// Best-effort image `mediaType` guessed from a URL's file extension, defaulting to `image/jpeg`
/// when there is no recognizable extension (Aperture share URLs often omit one). Only used to label
/// an `Image` / `Document` object — remotes fetch the URL regardless.
pub fn guess_media_type(url: &str) -> &'static str {
    // Look only at the path's trailing extension, ignoring any query/fragment.
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "svg" => "image/svg+xml",
        "jpg" | "jpeg" => "image/jpeg",
        _ => "image/jpeg",
    }
}

/// The WebFinger JRD for `acct:<actor>@<domain>` — links the handle to the actor document.
pub fn webfinger(cfg: &Config) -> Value {
    json!({
        "subject": format!("acct:{}", cfg.handle()),
        "aliases": [cfg.actor_url(), cfg.base_url() + "/"],
        "links": [
            {
                "rel": "self",
                "type": ACTIVITY_JSON,
                "href": cfg.actor_url()
            },
            {
                "rel": "http://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": cfg.base_url() + "/"
            }
        ]
    })
}

/// The ActivityPub Actor (Person) document, publishing the actor's `publicKey` / `publicKeyPem` so
/// remotes can verify our signed deliveries and we can be followed. The `@context` gains the
/// security vocabulary that defines `publicKey` (what Mastodon and friends expect).
pub fn actor(cfg: &Config, public_pem: &str, profile: &Profile) -> Value {
    let mut a = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1"
        ],
        "id": cfg.actor_url(),
        "type": "Person",
        "preferredUsername": cfg.actor,
        "name": cfg.display_name,
        "summary": cfg.summary,
        "url": cfg.base_url() + "/",
        "inbox": cfg.inbox_url(),
        "outbox": cfg.outbox_url(),
        "followers": cfg.followers_url(),
        "manuallyApprovesFollowers": false,
        "discoverable": true,
        "publicKey": {
            "id": cfg.key_id(),
            "owner": cfg.actor_url(),
            "publicKeyPem": public_pem
        },
        "endpoints": {
            "sharedInbox": cfg.shared_inbox_url()
        }
    });
    // The avatar becomes the actor `icon`, the header the actor `image` — the properties Mastodon
    // and friends render as the profile picture + banner. Each is omitted when unset.
    if !profile.avatar_url.is_empty() {
        a["icon"] = json!({
            "type": "Image",
            "mediaType": guess_media_type(&profile.avatar_url),
            "url": profile.avatar_url,
        });
    }
    if !profile.header_url.is_empty() {
        a["image"] = json!({
            "type": "Image",
            "mediaType": guess_media_type(&profile.header_url),
            "url": profile.header_url,
        });
    }
    a
}

/// The ActivityStreams Note object for one stored note (dereferenceable at [`Config::note_url`]).
pub fn note_object(cfg: &Config, note: &Note) -> Value {
    let url = cfg.note_url(&note.id);
    let mut obj = json!({
        "id": url,
        "type": "Note",
        "attributedTo": cfg.actor_url(),
        "content": content_to_html(&note.content),
        "published": crate::rfc3339(note.created_at),
        "url": url,
        "to": [PUBLIC],
        "cc": [cfg.followers_url()]
    });
    // An edited note advertises its last-edit time (the AS2 `updated` property), so a remote that
    // already has the note knows this is a revision.
    if note.updated_at > 0 {
        obj["updated"] = json!(crate::rfc3339(note.updated_at));
    }
    // A single attached image rides as an AS2 `attachment` Document (mediaType + url), the shape
    // Mastodon renders as inline media.
    if !note.attachment_url.is_empty() {
        obj["attachment"] = json!([{
            "type": "Document",
            "mediaType": guess_media_type(&note.attachment_url),
            "url": note.attachment_url,
        }]);
    }
    obj
}

/// The `Create` activity that wraps a note in the outbox / outbound delivery.
pub fn create_activity(cfg: &Config, note: &Note) -> Value {
    let url = cfg.note_url(&note.id);
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{url}/activity"),
        "type": "Create",
        "actor": cfg.actor_url(),
        "published": crate::rfc3339(note.created_at),
        "to": [PUBLIC],
        "cc": [cfg.followers_url()],
        "object": note_object(cfg, note)
    })
}

/// The `Update` activity announcing an owner edit of a note. Carries the full (revised) note object
/// so a remote can replace its stored copy; `stamp` makes the activity id unique per edit.
pub fn update_activity(cfg: &Config, note: &Note, stamp: &str) -> Value {
    let url = cfg.note_url(&note.id);
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{url}/updates/{stamp}"),
        "type": "Update",
        "actor": cfg.actor_url(),
        "published": crate::rfc3339(if note.updated_at > 0 { note.updated_at } else { note.created_at }),
        "to": [PUBLIC],
        "cc": [cfg.followers_url()],
        "object": note_object(cfg, note)
    })
}

/// The `Delete` activity announcing an owner delete of a note. The object is a `Tombstone` bearing
/// the (now-gone) note's id; `stamp` makes the activity id unique.
pub fn delete_activity(cfg: &Config, note_id: &str, stamp: &str) -> Value {
    let url = cfg.note_url(note_id);
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{url}/deletes/{stamp}"),
        "type": "Delete",
        "actor": cfg.actor_url(),
        "to": [PUBLIC],
        "cc": [cfg.followers_url()],
        "object": {
            "id": url,
            "type": "Tombstone"
        }
    })
}

/// The outbox `OrderedCollection` of `Create` activities, newest-first.
pub fn outbox(cfg: &Config, notes: &[Note], total: i64) -> Value {
    let items: Vec<Value> = notes.iter().map(|n| create_activity(cfg, n)).collect();
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": cfg.outbox_url(),
        "type": "OrderedCollection",
        "totalItems": total,
        "orderedItems": items
    })
}

/// The followers `OrderedCollection` (actor ids only), newest-first.
pub fn followers_collection(cfg: &Config, followers: &[Follower], total: i64) -> Value {
    let items: Vec<Value> = followers.iter().map(|f| json!(f.actor)).collect();
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": cfg.followers_url(),
        "type": "OrderedCollection",
        "totalItems": total,
        "orderedItems": items
    })
}

/// A `Follow` activity we send to a REMOTE actor. `stamp` makes the activity id unique; `object`
/// is the remote actor id we want to follow.
pub fn follow_activity(cfg: &Config, remote_actor: &str, stamp: &str) -> Value {
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{}#follows/{}", cfg.actor_url(), stamp),
        "type": "Follow",
        "actor": cfg.actor_url(),
        "object": remote_actor
    })
}

/// An `Accept` activity acknowledging an inbound `Follow`. `follow` is echoed back verbatim as the
/// object (per the ActivityPub spec) and `stamp` makes the activity id unique.
pub fn accept_activity(cfg: &Config, follow: &Value, stamp: &str) -> Value {
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{}#accepts/{}", cfg.actor_url(), stamp),
        "type": "Accept",
        "actor": cfg.actor_url(),
        "object": follow
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = Config::dev();
        c.actor = "w33d".to_string();
        c.domain = "social.w33d.xyz".to_string();
        c.display_name = "w33d".to_string();
        c
    }

    #[test]
    fn content_html_escapes_and_breaks() {
        let h = content_to_html("hi <b>x</b>\nsecond & line");
        assert_eq!(h, "<p>hi &lt;b&gt;x&lt;/b&gt;<br>second &amp; line</p>");
        assert!(!h.contains("<b>"));
    }

    #[test]
    fn webfinger_links_to_actor() {
        let wf = webfinger(&cfg());
        assert_eq!(wf["subject"], "acct:w33d@social.w33d.xyz");
        assert_eq!(wf["links"][0]["rel"], "self");
        assert_eq!(wf["links"][0]["type"], ACTIVITY_JSON);
        assert_eq!(wf["links"][0]["href"], "https://social.w33d.xyz/users/w33d");
    }

    #[test]
    fn actor_has_required_fields_and_public_key() {
        let a = actor(
            &cfg(),
            "-----BEGIN PUBLIC KEY-----\nMII...\n-----END PUBLIC KEY-----\n",
            &Profile::default(),
        );
        assert_eq!(a["type"], "Person");
        assert_eq!(a["id"], "https://social.w33d.xyz/users/w33d");
        assert_eq!(a["preferredUsername"], "w33d");
        assert_eq!(a["inbox"], "https://social.w33d.xyz/users/w33d/inbox");
        assert_eq!(a["outbox"], "https://social.w33d.xyz/users/w33d/outbox");
        assert_eq!(a["endpoints"]["sharedInbox"], "https://social.w33d.xyz/inbox");
        // Signed mode: the actor advertises its HTTP-Signature public key.
        assert_eq!(a["publicKey"]["id"], "https://social.w33d.xyz/users/w33d#main-key");
        assert_eq!(a["publicKey"]["owner"], "https://social.w33d.xyz/users/w33d");
        assert!(a["publicKey"]["publicKeyPem"].as_str().unwrap().contains("BEGIN PUBLIC KEY"));
        // No profile images set -> the icon/image properties are absent.
        assert!(a.get("icon").is_none());
        assert!(a.get("image").is_none());
    }

    #[test]
    fn actor_surfaces_profile_avatar_and_header() {
        let profile = Profile {
            avatar_url: "https://aperture.w33d.xyz/s/avatar.png".to_string(),
            header_url: "https://aperture.w33d.xyz/s/banner.jpg".to_string(),
        };
        let a = actor(&cfg(), "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n", &profile);
        assert_eq!(a["icon"]["type"], "Image");
        assert_eq!(a["icon"]["mediaType"], "image/png");
        assert_eq!(a["icon"]["url"], "https://aperture.w33d.xyz/s/avatar.png");
        assert_eq!(a["image"]["type"], "Image");
        assert_eq!(a["image"]["mediaType"], "image/jpeg");
        assert_eq!(a["image"]["url"], "https://aperture.w33d.xyz/s/banner.jpg");
    }

    #[test]
    fn note_object_carries_image_attachment() {
        let c = cfg();
        let note = Note {
            id: "note_9".to_string(),
            author_sub: "u_w33d".to_string(),
            content: "with a picture".to_string(),
            visibility: "public".to_string(),
            created_at: 1_700_000_000,
            updated_at: 0,
            attachment_url: "https://aperture.w33d.xyz/s/pic.webp".to_string(),
        };
        let obj = note_object(&c, &note);
        let att = &obj["attachment"][0];
        assert_eq!(att["type"], "Document");
        assert_eq!(att["mediaType"], "image/webp");
        assert_eq!(att["url"], "https://aperture.w33d.xyz/s/pic.webp");
    }

    #[test]
    fn note_object_omits_attachment_when_absent() {
        let c = cfg();
        let note = Note {
            id: "note_10".to_string(),
            author_sub: "u_w33d".to_string(),
            content: "no picture".to_string(),
            visibility: "public".to_string(),
            created_at: 1_700_000_000,
            updated_at: 0,
            attachment_url: String::new(),
        };
        let obj = note_object(&c, &note);
        assert!(obj.get("attachment").is_none());
    }

    #[test]
    fn outbox_wraps_notes_in_create() {
        let c = cfg();
        let note = Note {
            id: "note_1".to_string(),
            author_sub: "u_w33d".to_string(),
            content: "hello world".to_string(),
            visibility: "public".to_string(),
            created_at: 1_700_000_000,
            updated_at: 0,
            attachment_url: String::new(),
        };
        let ob = outbox(&c, std::slice::from_ref(&note), 1);
        assert_eq!(ob["type"], "OrderedCollection");
        assert_eq!(ob["totalItems"], 1);
        let item = &ob["orderedItems"][0];
        assert_eq!(item["type"], "Create");
        assert_eq!(item["actor"], "https://social.w33d.xyz/users/w33d");
        assert_eq!(item["object"]["type"], "Note");
        assert_eq!(item["object"]["id"], "https://social.w33d.xyz/users/w33d/notes/note_1");
        assert_eq!(item["object"]["content"], "<p>hello world</p>");
        assert_eq!(item["to"][0], PUBLIC);
    }
}
