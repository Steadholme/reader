//! Server configuration, env-driven with working dev defaults.
//!
//! The in-memory dev path boots with NO configuration and NO database — exactly like
//! inkwell/relay. Production overrides each value via the environment. All ActivityPub object
//! ids are derived from `actor` + `domain`, so they stay stable and correct regardless of which
//! interface the process binds.

/// Default listen address (all interfaces, internal-only port 9190).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9190";
/// Default actor handle (the single user's `preferredUsername`).
pub const DEFAULT_ACTOR: &str = "w33d";
/// Default federation domain — the public host the actor ids resolve under.
pub const DEFAULT_DOMAIN: &str = "social.w33d.xyz";
/// Default profile summary shown on the actor + the timeline.
pub const DEFAULT_SUMMARY: &str = "Sovereign microblog on the open social web — part of the Steadholme estate.";
/// Hard cap on how many notes the timeline / outbox render (keeps an unbounded list bounded).
pub const LIST_LIMIT: usize = 200;
/// Hard cap on a single note's content, in characters.
pub const MAX_CONTENT_CHARS: usize = 5000;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// The single user's actor handle / `preferredUsername` (`CRIER_ACTOR`).
    pub actor: String,
    /// Federation domain the actor ids resolve under (`CRIER_DOMAIN`).
    pub domain: String,
    /// Display name shown on the actor + UI (`CRIER_DISPLAY_NAME`, defaults to the handle).
    pub display_name: String,
    /// Profile summary / bio (`CRIER_SUMMARY`).
    pub summary: String,
    /// When true (`CRIER_FEDERATE`, default on), attempt best-effort outbound delivery (Accept on
    /// Follow, Create fan-out). Deliveries are HTTP-Signature signed with the actor key; turning it
    /// off keeps the local microblog + actor/outbox JSON fully functional with no network at all.
    pub federate: bool,
    /// When true (`CRIER_VERIFY_INBOX`, default OFF), inbound POSTs to the inbox MUST carry a valid
    /// draft-cavage HTTP Signature (verified against the sender's fetched public key) or they are
    /// rejected `401`. Off by default so the network-free dev/test path (which cannot dereference a
    /// remote key) keeps working; production sets it on — the same env-gated posture as
    /// `GATEWAY_HMAC_KEY`.
    pub verify_inbox: bool,
}

impl Config {
    /// Default development configuration (in-memory friendly, no database).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            actor: DEFAULT_ACTOR.to_string(),
            domain: DEFAULT_DOMAIN.to_string(),
            display_name: DEFAULT_ACTOR.to_string(),
            summary: DEFAULT_SUMMARY.to_string(),
            federate: true,
            verify_inbox: false,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("CRIER_ACTOR") {
            config.actor = v;
        }
        if let Some(v) = env_nonempty("CRIER_DOMAIN") {
            config.domain = v.trim_end_matches('/').to_string();
        }
        // Display name defaults to the resolved handle when unset.
        config.display_name = env_nonempty("CRIER_DISPLAY_NAME").unwrap_or_else(|| config.actor.clone());
        if let Some(v) = env_nonempty("CRIER_SUMMARY") {
            config.summary = v;
        }
        if let Some(v) = env_nonempty("CRIER_FEDERATE") {
            config.federate = matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "on" | "true" | "1" | "yes"
            );
        }
        if let Some(v) = env_nonempty("CRIER_VERIFY_INBOX") {
            config.verify_inbox = matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "on" | "true" | "1" | "yes"
            );
        }
        config
    }

    /// The `keyId` remotes dereference to fetch our public key (`<actor_url>#main-key`).
    pub fn key_id(&self) -> String {
        format!("{}#main-key", self.actor_url())
    }

    /// `acct:` handle, e.g. `w33d@social.w33d.xyz` (the WebFinger subject without the scheme).
    pub fn handle(&self) -> String {
        format!("{}@{}", self.actor, self.domain)
    }

    /// Public HTTPS base URL the actor ids resolve under (`https://<domain>`).
    pub fn base_url(&self) -> String {
        format!("https://{}", self.domain)
    }

    /// The actor (Person) id URL: `https://<domain>/users/<actor>`.
    pub fn actor_url(&self) -> String {
        format!("{}/users/{}", self.base_url(), self.actor)
    }

    /// The actor inbox URL.
    pub fn inbox_url(&self) -> String {
        format!("{}/inbox", self.actor_url())
    }

    /// The actor outbox URL.
    pub fn outbox_url(&self) -> String {
        format!("{}/outbox", self.actor_url())
    }

    /// The actor followers-collection URL.
    pub fn followers_url(&self) -> String {
        format!("{}/followers", self.actor_url())
    }

    /// The instance-level shared inbox URL (`https://<domain>/inbox`).
    pub fn shared_inbox_url(&self) -> String {
        format!("{}/inbox", self.base_url())
    }

    /// The dereferenceable object id URL for a note (under the public `/users/` prefix).
    pub fn note_url(&self, id: &str) -> String {
        format!("{}/notes/{}", self.actor_url(), id)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_helpers_derive_from_actor_and_domain() {
        let mut c = Config::dev();
        c.actor = "w33d".to_string();
        c.domain = "social.w33d.xyz".to_string();
        assert_eq!(c.handle(), "w33d@social.w33d.xyz");
        assert_eq!(c.actor_url(), "https://social.w33d.xyz/users/w33d");
        assert_eq!(c.inbox_url(), "https://social.w33d.xyz/users/w33d/inbox");
        assert_eq!(c.outbox_url(), "https://social.w33d.xyz/users/w33d/outbox");
        assert_eq!(c.followers_url(), "https://social.w33d.xyz/users/w33d/followers");
        assert_eq!(c.shared_inbox_url(), "https://social.w33d.xyz/inbox");
        assert_eq!(c.note_url("note_1"), "https://social.w33d.xyz/users/w33d/notes/note_1");
    }
}
