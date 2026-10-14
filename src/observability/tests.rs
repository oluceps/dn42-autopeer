use super::*;
use crate::error::PeerError;
use axum::{Json, Router, body::Body, http::StatusCode, middleware, routing::post};
use serde_json::{Value, json};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    fn events(&self) -> Vec<Value> {
        self.text()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn logger() -> (impl tracing::Subscriber + Send + Sync, Capture) {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("dn42_autopeer=trace"))
        .json()
        .flatten_event(true)
        .without_time()
        .with_writer(capture.clone())
        .finish();
    (subscriber, capture)
}

async fn handler(Json(_payload): Json<Value>) -> StatusCode {
    record_peer(4200000291, Some("diag"));
    observe("test_database", async { Ok::<_, PeerError>(()) })
        .await
        .unwrap();
    StatusCode::CREATED
}

fn app() -> Router {
    Router::new()
        .route("/api/peers", post(handler))
        .layer(middleware::from_fn(log_request))
}

fn request(body: &str) -> Request {
    Request::builder()
        .method("POST")
        .uri("/api/peers?nonce=private-query-token")
        .header("content-type", "application/json")
        .header("x-request-id", "private-client-id")
        .header("cf-ray", "abc123-SIN")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn request_logs_status_duration_and_generated_id_without_secrets() {
    let (subscriber, capture) = logger();
    let response = app()
        .oneshot(request(
            &json!({
                "nonce": "private-nonce",
                "signature": "private-signature",
                "pubkey": "private-key-material",
            })
            .to_string(),
        ))
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let id = response.headers()[REQUEST_ID_HEADER].to_str().unwrap();
    assert_ne!(id, "private-client-id");
    let events = capture.events();
    let completed = events
        .iter()
        .find(|event| event["event"] == "request_completed")
        .unwrap();
    assert_eq!(completed["status"], 201);
    assert!(completed["elapsed_ms"].is_u64());
    assert_eq!(completed["span"]["request_id"], id);
    assert_eq!(completed["span"]["method"], "POST");
    assert_eq!(completed["span"]["route"], "/api/peers");
    assert_eq!(completed["span"]["cf_ray"], "abc123-SIN");
    assert_eq!(completed["span"]["asn"], 4200000291_u64);
    assert_eq!(completed["span"]["peer_name"], "diag");
    let text = capture.text();
    for secret in [
        "private-query-token",
        "private-client-id",
        "private-nonce",
        "private-signature",
        "private-key-material",
    ] {
        assert!(
            !text.contains(secret),
            "Unexpected sensitive field in the log"
        );
    }
}

#[tokio::test]
async fn concurrent_requests_have_distinct_correlated_ids() {
    let (subscriber, capture) = logger();
    let (one, two) =
        async { tokio::join!(app().oneshot(request("{}")), app().oneshot(request("{}"))) }
            .with_subscriber(subscriber)
            .await;
    let one = one.unwrap();
    let two = two.unwrap();
    let ids = [
        one.headers()[REQUEST_ID_HEADER].to_str().unwrap(),
        two.headers()[REQUEST_ID_HEADER].to_str().unwrap(),
    ];
    assert_ne!(ids[0], ids[1]);
    let events = capture.events();
    for id in ids {
        for event_name in ["request_started", "request_completed"] {
            assert_eq!(
                events
                    .iter()
                    .filter(
                        |event| event["event"] == event_name && event["span"]["request_id"] == id
                    )
                    .count(),
                1
            );
        }
    }
}

#[tokio::test]
async fn json_rejections_have_request_ids_without_logging_the_body() {
    let (subscriber, capture) = logger();
    let response = app()
        .oneshot(request("private-invalid-json"))
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().contains_key(REQUEST_ID_HEADER));
    assert!(!capture.text().contains("private-invalid-json"));
    assert!(
        capture
            .events()
            .iter()
            .any(|event| event["event"] == "request_completed" && event["status"] == 400)
    );
}

#[tokio::test]
async fn error_logs_contain_codes_not_raw_details() {
    let (subscriber, capture) = logger();
    let error = PeerError::BirdReload {
        stderr: "private-key-material private-nonce postgres://private-password@host/db".to_owned(),
    };
    async {
        let result = observe("bird_reload", async { Err::<(), _>(error) }).await;
        log_failure("api_error", &result.unwrap_err());
    }
    .with_subscriber(subscriber)
    .await;
    let events = capture.events();
    assert!(
        events
            .iter()
            .any(|event| event["error_code"] == "bird_reload")
    );
    let text = capture.text();
    for secret in ["private-key-material", "private-nonce", "private-password"] {
        assert!(!text.contains(secret));
    }
}

#[tokio::test]
async fn api_client_errors_are_warnings_and_server_errors_are_errors() {
    use axum::response::IntoResponse;
    let (subscriber, capture) = logger();
    async {
        let response = PeerError::UnauthorizedChallenge {
            detail: "private-token".to_owned(),
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = PeerError::Database {
            source: sqlx::Error::PoolTimedOut,
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    .with_subscriber(subscriber)
    .await;
    let events = capture.events();
    assert!(events.iter().any(|event| event["event"] == "api_error"
        && event["level"] == "WARN"
        && event["status"] == 403));
    assert!(events.iter().any(|event| event["event"] == "api_error"
        && event["level"] == "ERROR"
        && event["error_kind"] == "pool_timeout"
        && event["status"] == 500));
    assert!(!capture.text().contains("private-token"));
}

#[tokio::test(start_paused = true)]
async fn pending_stages_log_progress_and_interruption() {
    let (subscriber, capture) = logger();
    async {
        let result = tokio::time::timeout(
            Duration::from_secs(12),
            observe(
                "db_acquire",
                std::future::pending::<Result<(), sqlx::Error>>(),
            ),
        )
        .await;
        assert!(result.is_err());
    }
    .with_subscriber(subscriber)
    .await;
    let events = capture.events();
    let pending: Vec<_> = events
        .iter()
        .filter(|event| event["event"] == "stage_pending")
        .collect();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0]["elapsed_ms"], 5000);
    assert_eq!(pending[1]["elapsed_ms"], 10000);
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "stage_interrupted" && event["stage"] == "db_acquire")
    );
}

#[tokio::test(start_paused = true)]
async fn slow_successful_stages_emit_warnings() {
    let (subscriber, capture) = logger();
    async {
        observe("db_query", async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok::<_, sqlx::Error>(())
        })
        .await
        .unwrap();
    }
    .with_subscriber(subscriber)
    .await;
    let events = capture.events();
    let completed = events
        .iter()
        .find(|event| event["event"] == "stage_completed")
        .unwrap();
    assert_eq!(completed["level"], "WARN");
    assert_eq!(completed["elapsed_ms"], 2000);
    assert_eq!(completed["outcome"], "ok");
}

#[tokio::test(start_paused = true)]
async fn cancelled_requests_log_interruption() {
    let (subscriber, capture) = logger();
    let app = Router::new()
        .route(
            "/api/peers",
            post(|| async { std::future::pending::<StatusCode>().await }),
        )
        .layer(middleware::from_fn(log_request));
    async {
        assert!(
            tokio::time::timeout(Duration::from_secs(1), app.oneshot(request("{}")))
                .await
                .is_err()
        );
    }
    .with_subscriber(subscriber)
    .await;
    assert!(
        capture
            .events()
            .iter()
            .any(|event| event["event"] == "request_interrupted"
                && event["span"]["route"] == "/api/peers")
    );
}

#[tokio::test]
async fn nested_database_failures_keep_request_and_pool_context() {
    let (subscriber, capture) = logger();
    let app = Router::new()
        .route(
            "/api/peers",
            post(|| async {
                let span = tracing::info_span!(
                    "database",
                    db_operation = "consume_nonce",
                    pool_size = 10,
                    pool_idle = 0,
                    pool_max = 10
                );
                let _ = observe("db_acquire", async {
                    Err::<(), _>(sqlx::Error::PoolTimedOut)
                })
                .instrument(span)
                .await;
                StatusCode::INTERNAL_SERVER_ERROR
            }),
        )
        .layer(middleware::from_fn(log_request));
    let response = app
        .oneshot(request("{}"))
        .with_subscriber(subscriber)
        .await
        .unwrap();
    let id = response.headers()[REQUEST_ID_HEADER].to_str().unwrap();
    let events = capture.events();
    let stage = events
        .iter()
        .find(|event| event["event"] == "stage_completed")
        .unwrap();
    assert_eq!(stage["error_kind"], "pool_timeout");
    assert_eq!(stage["span"]["pool_size"], 10);
    assert_eq!(stage["span"]["pool_idle"], 0);
    assert_eq!(stage["span"]["db_operation"], "consume_nonce");
    assert!(
        stage["spans"]
            .as_array()
            .unwrap()
            .iter()
            .any(|span| span["request_id"] == id)
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "request_completed"
                && event["level"] == "ERROR"
                && event["status"] == 500)
    );
}

#[tokio::test(start_paused = true)]
async fn slow_requests_log_total_latency() {
    let (subscriber, capture) = logger();
    let app = Router::new()
        .route(
            "/api/peers",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(6)).await;
                StatusCode::CREATED
            }),
        )
        .layer(middleware::from_fn(log_request));
    app.oneshot(request("{}"))
        .with_subscriber(subscriber)
        .await
        .unwrap();
    let events = capture.events();
    let completed = events
        .iter()
        .find(|event| event["event"] == "request_completed")
        .unwrap();
    assert_eq!(completed["level"], "WARN");
    assert_eq!(completed["elapsed_ms"], 6000);
    assert_eq!(completed["slow"], true);
}

#[test]
fn database_errors_distinguish_pool_waits_and_socket_failures() {
    let pool = sqlx::Error::PoolTimedOut.log_info();
    assert_eq!(pool.code, "database");
    assert_eq!(pool.kind, "pool_timeout");
    let socket = sqlx::Error::Io(std::io::Error::from_raw_os_error(110)).log_info();
    assert_eq!(socket.kind, "io");
    assert_eq!(socket.io_code, Some(110));
}

#[test]
fn invalid_cloudflare_headers_are_not_logged() {
    let request = Request::builder()
        .header("cf-ray", "private token with spaces")
        .body(Body::empty())
        .unwrap();
    assert!(cloudflare_ray(&request).is_none());
}
