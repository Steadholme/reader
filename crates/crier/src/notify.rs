use std::time::Duration;

#[derive(Clone)]
pub struct KlaxonNotifier {
    url: String,
    token: String,
    client: reqwest::Client,
}

impl KlaxonNotifier {
    /// Build from KLAXON_NOTIFY_URL + KLAXON_INGEST_TOKEN; missing values disable Klaxon.
    pub fn from_env() -> Option<KlaxonNotifier> {
        let url = std::env::var("KLAXON_NOTIFY_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let token = std::env::var("KLAXON_INGEST_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        Some(KlaxonNotifier {
            url,
            token,
            client: reqwest::Client::new(),
        })
    }

    /// Fire-and-forget Klaxon notification. Failures are logged and never returned to handlers.
    pub fn notify(&self, source: &str, user_sub: &str, title: &str, body: &str, url: &str) {
        let this = self.clone();
        let source = source.to_string();
        let log_source = source.clone();
        let user_sub = user_sub.to_string();
        let title = title.to_string();
        let body = body.to_string();
        let url = url.to_string();
        tokio::spawn(async move {
            let payload = serde_json::json!({
                "user_sub": user_sub,
                "source": source,
                "severity": "info",
                "title": title,
                "body": body,
                "url": url,
            });
            let res = this
                .client
                .post(&this.url)
                .bearer_auth(&this.token)
                .json(&payload)
                .timeout(Duration::from_secs(5))
                .send()
                .await;
            match res {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => {
                    tracing::warn!(
                        status = %resp.status(),
                        source = %log_source,
                        "klaxon notify failed"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        source = %log_source,
                        "klaxon notify failed"
                    );
                }
            }
        });
    }
}
