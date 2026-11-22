//! The webhook authorizer (ruling M3-R8): the operator's own service
//! decides every action, over HTTP.
//!
//! For each decision OpenXet POSTs `openxet.authz.v1` JSON naming the
//! action, the resource (`{namespace}/{name}`, as a repository's URL names
//! it) and the verified user, with the request's bearer token in
//! `Authorization`. With a secret, `X-Openxet-Signature` is
//! `sha256={hex HMAC-SHA256 of "{timestamp}.{body}"}`, the timestamp being
//! `X-Openxet-Timestamp`, so the service can tell OpenXet's requests from
//! anyone else's and refuse replays. The answer is `true` or `false`, or
//! `{"allow": bool}` with an optional `"ttl_seconds"`.
//!
//! It fails closed: a timeout, a redirect, a non-`2xx` answer or a body
//! that is neither is an [`AuthzError`], which the routes answer `503`,
//! never an allow. Decisions are cached per caller: the key is the
//! SHA-256 of the request body and the bearer token, so two callers never
//! share an answer (design §5.9 requirement 3).

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use url::Url;
use zeroize::Zeroizing;

use crate::{Action, Authorizer, AuthzError, Target, UserPrincipal};

/// The most decisions cached at once. Past it, expired ones are dropped,
/// and if none has expired, all of them.
const MAX_CACHED: usize = 100_000;

/// The largest answer read: far more than `{"allow": true}` needs.
const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// `[authorizer]`, checked.
#[derive(Clone)]
pub struct WebhookConfig {
    /// Where decisions are asked: `https://`, or `http://` to a loopback
    /// address.
    pub url: Url,
    /// The HMAC key requests are signed with, if any.
    pub secret: Option<Zeroizing<Vec<u8>>>,
    /// How long one decision may take before it fails closed.
    pub timeout: Duration,
    /// The longest an allow is reused.
    pub allow_ttl: Duration,
    /// The longest a deny is reused.
    pub deny_ttl: Duration,
}

impl WebhookConfig {
    /// Whether `url` may be the authorizer's: `https://`, or `http://` to a
    /// loopback address, without user info, query or fragment.
    ///
    /// # Errors
    ///
    /// What is wrong with it.
    pub fn check_url(url: &Url) -> Result<(), &'static str> {
        crate::oidc::check_endpoint(url)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err("the URL must not carry user info; sign requests with a secret instead");
        }
        if url.fragment().is_some() {
            return Err("the URL must not have a fragment");
        }
        Ok(())
    }
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("url", &self.url.as_str())
            .field("signed", &self.secret.is_some())
            .field("timeout", &self.timeout)
            .field("allow_ttl", &self.allow_ttl)
            .field("deny_ttl", &self.deny_ttl)
            .finish()
    }
}

/// Asks the operator's service whether a user may do an action.
pub struct WebhookAuthorizer {
    cfg: WebhookConfig,
    http: reqwest::Client,
    cache: Mutex<HashMap<[u8; 32], Cached>>,
}

impl fmt::Debug for WebhookAuthorizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookAuthorizer")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct Cached {
    allow: bool,
    until: Instant,
}

/// The body OpenXet POSTs. Its field order is fixed, so equal requests
/// have equal bytes and share a cache entry.
#[derive(Serialize)]
struct Ask<'a> {
    schema: &'static str,
    action: &'static str,
    resource: String,
    namespace: &'a str,
    name: Option<&'a str>,
    path: Option<&'a str>,
    subject: &'a str,
    claims: &'a std::collections::BTreeMap<String, Vec<String>>,
}

/// The service's answer.
struct Answer {
    allow: bool,
    ttl: Option<Duration>,
}

impl WebhookAuthorizer {
    /// The authorizer asking `cfg.url` through `http`, a client that must
    /// not follow redirects: an answer has to come from the URL configured.
    ///
    /// # Errors
    ///
    /// A message if the URL isn't `https://` or loopback `http://`, or
    /// carries user info.
    pub fn new(cfg: WebhookConfig, http: reqwest::Client) -> Result<Self, String> {
        WebhookConfig::check_url(&cfg.url).map_err(|why| format!("{}: {why}", cfg.url))?;
        Ok(Self {
            cfg,
            http,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The body of a decision, for [`WebhookAuthorizer`] and for callers
    /// that show the operator what will be sent.
    #[must_use]
    pub fn body(who: &UserPrincipal, action: Action, target: Target<'_>) -> Vec<u8> {
        let ask = Ask {
            schema: "openxet.authz.v1",
            action: action.name(),
            resource: target.resource(),
            namespace: target.namespace,
            name: target.name,
            path: target.path,
            subject: &who.subject,
            claims: &who.claims,
        };
        // A struct of strings and string maps always serializes.
        serde_json::to_vec(&ask).unwrap_or_default()
    }

    fn cache_key(body: &[u8], who: &UserPrincipal) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(body);
        hash.update([0]);
        if let Some(token) = &who.bearer {
            hash.update(token.expose().as_bytes());
        }
        hash.finalize().into()
    }

    fn cached(&self, key: &[u8; 32]) -> Option<bool> {
        let cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache
            .get(key)
            .filter(|c| c.until > Instant::now())
            .map(|c| c.allow)
    }

    fn remember(&self, key: [u8; 32], answer: &Answer) {
        let most = if answer.allow {
            self.cfg.allow_ttl
        } else {
            self.cfg.deny_ttl
        };
        let ttl = answer.ttl.map_or(most, |ttl| ttl.min(most));
        if ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() >= MAX_CACHED {
            cache.retain(|_, c| c.until > now);
            if cache.len() >= MAX_CACHED {
                cache.clear();
            }
        }
        cache.insert(
            key,
            Cached {
                allow: answer.allow,
                until: now + ttl,
            },
        );
    }

    /// Sends `body` with `who`'s bearer token and reads the answer.
    async fn ask(&self, body: Vec<u8>, who: &UserPrincipal) -> Result<Answer, String> {
        let url = &self.cfg.url;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            .to_string();
        let mut request = self
            .http
            .post(url.clone())
            .timeout(self.cfg.timeout)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("x-openxet-timestamp", &timestamp);
        if let Some(secret) = &self.cfg.secret {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                .map_err(|_| "the authorizer secret can't key HMAC-SHA256".to_owned())?;
            mac.update(timestamp.as_bytes());
            mac.update(b".");
            mac.update(&body);
            let tag = mac.finalize().into_bytes();
            request = request.header("x-openxet-signature", format!("sha256={}", hex(&tag)));
        }
        if let Some(token) = &who.bearer {
            let mut value =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.expose()))
                    .map_err(|_| {
                        "the request's bearer token is not a valid header value".to_owned()
                    })?;
            value.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        // reqwest's errors name the URL, never a header.
        let mut response = request
            .body(body)
            .send()
            .await
            .map_err(|err| format!("could not reach {url}: {err}"))?;
        let status = response.status();
        if status.is_redirection() || response.url() != url {
            return Err(format!(
                "{url} answered with a redirect, which OpenXet never follows for the authorizer"
            ));
        }
        if !status.is_success() {
            return Err(format!("{url} answered {status}"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| format!("could not read the answer of {url}: {err}"))?
        {
            if bytes.len() + chunk.len() > MAX_ANSWER_BYTES {
                return Err(format!("{url} answered more than 64 KiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        parse_answer(&bytes).ok_or_else(|| {
            format!(
                "{url} answered neither `true`, `false` nor {{\"allow\": true|false}}; see \
                 docs/reference/authorizer.md"
            )
        })
    }
}

/// `true`, `false`, or `{"allow": bool, "ttl_seconds": n}`.
fn parse_answer(bytes: &[u8]) -> Option<Answer> {
    match serde_json::from_slice::<serde_json::Value>(bytes).ok()? {
        serde_json::Value::Bool(allow) => Some(Answer { allow, ttl: None }),
        serde_json::Value::Object(map) => {
            let allow = map.get("allow")?.as_bool()?;
            let ttl = match map.get("ttl_seconds") {
                None | Some(serde_json::Value::Null) => None,
                Some(ttl) => Some(Duration::from_secs(ttl.as_u64()?)),
            };
            Some(Answer { allow, ttl })
        }
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[async_trait]
impl Authorizer for WebhookAuthorizer {
    async fn allows(
        &self,
        who: &UserPrincipal,
        action: Action,
        target: Target<'_>,
    ) -> Result<bool, AuthzError> {
        let body = Self::body(who, action, target);
        let key = Self::cache_key(&body, who);
        if let Some(allow) = self.cached(&key) {
            return Ok(allow);
        }
        match self.ask(body, who).await {
            Ok(answer) => {
                self.remember(key, &answer);
                Ok(answer.allow)
            }
            Err(reason) => {
                tracing::warn!(
                    url = %self.cfg.url,
                    action = action.name(),
                    resource = %target.resource(),
                    %reason,
                    "the authorizer could not decide; the request is refused"
                );
                Err(AuthzError::Unavailable { reason })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_booleans_or_an_allow_object() {
        let allow = |text: &str| parse_answer(text.as_bytes()).map(|a| (a.allow, a.ttl));
        assert_eq!(allow("true"), Some((true, None)));
        assert_eq!(allow(" false\n"), Some((false, None)));
        assert_eq!(allow(r#"{"allow": true}"#), Some((true, None)));
        assert_eq!(
            allow(r#"{"allow": false, "ttl_seconds": 3}"#),
            Some((false, Some(Duration::from_secs(3))))
        );
        for bad in [
            "",
            "yes",
            "1",
            r#"{"allow": "true"}"#,
            r#"{"ok": true}"#,
            "[true]",
        ] {
            assert!(allow(bad).is_none(), "{bad}");
        }
        assert!(allow(r#"{"allow": true, "ttl_seconds": -1}"#).is_none());
    }
}
