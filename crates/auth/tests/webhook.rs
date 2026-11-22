//! The webhook authorizer (ruling M3-R8, `docs/reference/authorizer.md`)
//! against a service on a loopback port that answers what each test says.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use hmac::{Hmac, KeyInit as _, Mac as _};
use openxet_auth::{
    Action, Authorizer, AuthzError, BearerToken, Target, UserPrincipal, WebhookAuthorizer,
    WebhookConfig,
};
use serde_json::Value;
use sha2::Sha256;

/// One request the service received.
#[derive(Debug, Clone)]
struct Seen {
    headers: HeaderMap,
    body: Value,
    raw: Vec<u8>,
}

type Answer = Arc<dyn Fn(&Value) -> Response + Send + Sync>;

#[derive(Clone)]
struct Service {
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: Answer,
}

async fn handle(State(service): State<Service>, headers: HeaderMap, body: Bytes) -> Response {
    let json: Value = serde_json::from_slice(&body).unwrap();
    let answer = (service.answer)(&json);
    service.seen.lock().unwrap().push(Seen {
        headers,
        body: json,
        raw: body.to_vec(),
    });
    answer
}

/// A service answering with `answer`, and what it saw.
async fn start(answer: impl Fn(&Value) -> Response + Send + Sync + 'static) -> (String, Service) {
    let service = Service {
        seen: Arc::default(),
        answer: Arc::new(answer),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/authorize", listener.local_addr().unwrap());
    #[allow(
        clippy::disallowed_methods,
        reason = "the test service stands in for the operator's authorizer; it serves no OpenXet route"
    )]
    let router = Router::new()
        .route("/authorize", post(handle))
        .with_state(service.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, service)
}

const SECRET: &str = "a3f1c0ffee";

fn authorizer(url: &str, change: impl FnOnce(&mut WebhookConfig)) -> WebhookAuthorizer {
    let mut cfg = WebhookConfig {
        url: url.parse().unwrap(),
        secret: Some(zeroize::Zeroizing::new(SECRET.as_bytes().to_vec())),
        timeout: Duration::from_secs(2),
        allow_ttl: Duration::from_secs(30),
        deny_ttl: Duration::from_secs(5),
    };
    change(&mut cfg);
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    WebhookAuthorizer::new(cfg, http).unwrap()
}

fn user(subject: &str, token: &str) -> UserPrincipal {
    UserPrincipal {
        subject: subject.to_owned(),
        name: subject.to_owned(),
        email: None,
        claims: BTreeMap::from([("groups".to_owned(), vec!["ml".to_owned()])]),
        bearer: Some(BearerToken::new(token)),
    }
}

fn repo<'a>(namespace: &'a str, name: &'a str) -> Target<'a> {
    Target {
        namespace,
        name: Some(name),
        path: None,
    }
}

fn json(value: &str) -> Response {
    (StatusCode::OK, value.to_owned()).into_response()
}

#[tokio::test]
async fn webhook_allow_and_deny() {
    // Alice may read acme/*; nobody may do anything else.
    let (url, service) = start(|ask| {
        let read = ask["action"] == "read" && ask["namespace"] == "acme";
        json(if read { "true" } else { r#"{"allow": false}"# })
    })
    .await;
    let authz = authorizer(&url, |_| {});
    let alice = user("alice", "oxt_alice");
    assert!(
        authz
            .allows(&alice, Action::Read, repo("acme", "model"))
            .await
            .unwrap()
    );
    assert!(
        !authz
            .allows(&alice, Action::Write, repo("acme", "model"))
            .await
            .unwrap()
    );
    let ns = Target {
        namespace: "acme",
        name: None,
        path: None,
    };
    assert!(!authz.allows(&alice, Action::Create, ns).await.unwrap());
    let branch = Target {
        path: Some("branch/dev"),
        ..repo("acme", "model")
    };
    assert!(!authz.allows(&alice, Action::Delete, branch).await.unwrap());

    let seen = service.seen.lock().unwrap().clone();
    let asked: Vec<(String, String)> = seen
        .iter()
        .map(|s| {
            (
                s.body["action"].as_str().unwrap().to_owned(),
                s.body["resource"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        asked,
        [
            ("read".into(), "acme/model".into()),
            ("write".into(), "acme/model".into()),
            ("create".into(), "acme".into()),
            ("delete".into(), "acme/model/branch/dev".into()),
        ]
    );
    let first = &seen[0].body;
    assert_eq!(first["schema"], "openxet.authz.v1");
    assert_eq!(first["subject"], "alice");
    assert_eq!(first["claims"]["groups"][0], "ml");
}

#[tokio::test]
async fn request_is_signed_timestamped_and_carries_the_bearer_token() {
    let (url, service) = start(|_| json("true")).await;
    let authz = authorizer(&url, |_| {});
    authz
        .allows(
            &user("alice", "oxt_alice"),
            Action::Read,
            repo("acme", "model"),
        )
        .await
        .unwrap();
    let seen = service.seen.lock().unwrap()[0].clone();
    let header = |name: &str| seen.headers[name].to_str().unwrap().to_owned();
    assert_eq!(header("authorization"), "Bearer oxt_alice");
    assert_eq!(header("content-type"), "application/json");
    let timestamp = header("x-openxet-timestamp");
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(&seen.raw);
    let expected = mac
        .finalize()
        .into_bytes()
        .iter()
        .fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        });
    assert_eq!(header("x-openxet-signature"), format!("sha256={expected}"));

    // Without a secret nothing is signed; without a token none is sent.
    let unsigned = authorizer(&url, |cfg| cfg.secret = None);
    unsigned
        .allows(&UserPrincipal::anonymous(), Action::Read, repo("acme", "x"))
        .await
        .unwrap();
    let seen = service.seen.lock().unwrap()[1].clone();
    assert!(!seen.headers.contains_key("x-openxet-signature"));
    assert!(!seen.headers.contains_key("authorization"));
    assert_eq!(seen.body["subject"], "anonymous");
}

#[tokio::test]
async fn allow_and_deny_cached_per_ttl() {
    let (url, service) = start(|ask| {
        json(if ask["action"] == "read" {
            "true"
        } else {
            "false"
        })
    })
    .await;
    let authz = authorizer(&url, |cfg| cfg.deny_ttl = Duration::ZERO);
    let alice = user("alice", "oxt_alice");
    for _ in 0..3 {
        assert!(
            authz
                .allows(&alice, Action::Read, repo("acme", "m"))
                .await
                .unwrap()
        );
        assert!(
            !authz
                .allows(&alice, Action::Write, repo("acme", "m"))
                .await
                .unwrap()
        );
    }
    // One read, cached; three writes, since a deny is kept for 0s.
    let seen = service.seen.lock().unwrap().clone();
    let count = |action: &str| seen.iter().filter(|s| s.body["action"] == action).count();
    assert_eq!((count("read"), count("write")), (1, 3));

    // The service's own ttl_seconds shortens the configured one.
    let (url, service) = start(|_| json(r#"{"allow": true, "ttl_seconds": 0}"#)).await;
    let authz = authorizer(&url, |_| {});
    for _ in 0..2 {
        authz
            .allows(&alice, Action::Read, repo("acme", "m"))
            .await
            .unwrap();
    }
    assert_eq!(service.seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn cache_keyed_by_subject_and_claims() {
    let (url, service) = start(|_| json("true")).await;
    let authz = authorizer(&url, |_| {});
    let target = repo("acme", "m");
    authz
        .allows(&user("alice", "oxt_a"), Action::Read, target)
        .await
        .unwrap();
    authz
        .allows(&user("bob", "oxt_b"), Action::Read, target)
        .await
        .unwrap();
    // The same subject with other claims, or another token, is another
    // caller.
    let mut admin = user("alice", "oxt_a");
    admin
        .claims
        .insert("groups".to_owned(), vec!["admins".to_owned()]);
    authz.allows(&admin, Action::Read, target).await.unwrap();
    authz
        .allows(&user("alice", "oxt_a2"), Action::Read, target)
        .await
        .unwrap();
    authz
        .allows(&user("alice", "oxt_a"), Action::Read, target)
        .await
        .unwrap();
    assert_eq!(service.seen.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn timeout_fails_closed() {
    let (url, _service) = start(|_| {
        std::thread::sleep(Duration::from_millis(1500));
        json("true")
    })
    .await;
    let authz = authorizer(&url, |cfg| cfg.timeout = Duration::from_millis(300));
    let err = authz
        .allows(&user("alice", "oxt_alice"), Action::Read, repo("acme", "m"))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthzError::Unavailable { .. }), "{err}");
}

#[tokio::test]
async fn non_2xx_or_bad_body_fails_closed() {
    let answers: [fn(&Value) -> Response; 4] = [
        |_| (StatusCode::INTERNAL_SERVER_ERROR, "true").into_response(),
        |_| (StatusCode::FOUND, [("location", "http://127.0.0.1:1/")], "").into_response(),
        |_| json("yes"),
        |_| json(r#"{"allowed": true}"#),
    ];
    for answer in answers {
        let (url, _service) = start(answer).await;
        let authz = authorizer(&url, |_| {});
        let alice = user("alice", "oxt_secret_token");
        let err = authz
            .allows(&alice, Action::Read, repo("acme", "m"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthzError::Unavailable { .. }), "{err}");
        assert!(!err.to_string().contains("oxt_secret_token"), "{err}");
        // A failure is never cached as a deny: the next call asks again.
        assert!(
            authz
                .allows(&alice, Action::Read, repo("acme", "m"))
                .await
                .is_err()
        );
    }
}

#[test]
fn urls_must_be_https_or_loopback_and_secrets_never_shown() {
    for bad in [
        "http://auth.example.com/authorize",
        "ftp://127.0.0.1/",
        "https://user:pass@auth.example.com/",
        "https://auth.example.com/#frag",
    ] {
        assert!(
            WebhookConfig::check_url(&bad.parse().unwrap()).is_err(),
            "{bad}"
        );
    }
    for good in [
        "https://auth.example.com/openxet/authorize",
        "http://127.0.0.1:8000/authorize",
        "http://localhost:8000/authorize",
    ] {
        assert!(
            WebhookConfig::check_url(&good.parse().unwrap()).is_ok(),
            "{good}"
        );
    }
    let authz = authorizer("http://127.0.0.1:9/authorize", |_| {});
    assert!(!format!("{authz:?}").contains(SECRET));
    assert!(!format!("{:?}", user("a", "oxt_hidden")).contains("oxt_hidden"));
}

/// A writer the test's subscriber logs into.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A failed decision is logged with the URL, the action and the resource,
/// never the secret, the signature or the caller's token (design §5.9
/// requirement 6).
#[test]
fn webhook_secret_never_logged() {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let (url, _service) =
                start(|_| (StatusCode::INTERNAL_SERVER_ERROR, "no").into_response()).await;
            let authz = authorizer(&url, |_| {});
            let alice = user("alice", "oxt_secret_token");
            assert!(
                authz
                    .allows(&alice, Action::Write, repo("acme", "m"))
                    .await
                    .is_err()
            );
        });
    });
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("could not decide"), "{logged}");
    assert!(logged.contains("acme/m"), "{logged}");
    for secret in [SECRET, "oxt_secret_token", "sha256="] {
        assert!(!logged.contains(secret), "{secret} in {logged}");
    }
}
