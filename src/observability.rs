use axum::{
    extract::{MatchedPath, Request},
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::{
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use tracing::{Instrument, field};
use tracing_subscriber::EnvFilter;

const SLOW_STAGE: Duration = Duration::from_secs(1);
const SLOW_REQUEST: Duration = Duration::from_secs(5);
const PENDING_INTERVAL: Duration = Duration::from_secs(5);
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
pub const REQUEST_ID_HEADER: &str = "x-request-id";

pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,dn42_autopeer=info,sqlx=off,reqwest=off"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_ansi(false)
        .init();
}

fn request_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{now:x}-{sequence:x}", std::process::id())
}

fn cloudflare_ray(request: &Request) -> Option<&str> {
    request
        .headers()
        .get("cf-ray")?
        .to_str()
        .ok()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub async fn log_request(request: Request, next: Next) -> Response {
    let id = request_id();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("<unmatched>", MatchedPath::as_str);
    let span = tracing::info_span!(
        "http_request",
        request_id = %id,
        method = %request.method(),
        route,
        cf_ray = cloudflare_ray(&request),
        asn = field::Empty,
        peer_name = field::Empty,
    );
    async move {
        let mut guard = RequestGuard {
            started: Instant::now(),
            completed: false,
        };
        tracing::info!(event = "request_started", "Request started");
        let mut response = next.run(request).await;
        response.headers_mut().insert(
            HeaderName::from_static(REQUEST_ID_HEADER),
            HeaderValue::from_str(&id).expect("The generated request ID is ASCII"),
        );
        let status = response.status().as_u16();
        let elapsed_ms = elapsed_ms(guard.started);
        let slow = guard.started.elapsed() >= SLOW_REQUEST;
        guard.completed = true;
        if response.status().is_server_error() {
            tracing::error!(
                event = "request_completed",
                status,
                elapsed_ms,
                slow,
                "Request completed"
            );
        } else if slow || response.status().is_client_error() {
            tracing::warn!(
                event = "request_completed",
                status,
                elapsed_ms,
                slow,
                "Request completed"
            );
        } else {
            tracing::info!(
                event = "request_completed",
                status,
                elapsed_ms,
                slow,
                "Request completed"
            );
        }
        response
    }
    .instrument(span)
    .await
}

struct RequestGuard {
    started: Instant,
    completed: bool,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if !self.completed {
            tracing::warn!(
                event = "request_interrupted",
                elapsed_ms = elapsed_ms(self.started),
                "Request future did not complete"
            );
        }
    }
}

pub fn record_peer(asn: u32, peer_name: Option<&str>) {
    let span = tracing::Span::current();
    span.record("asn", asn);
    if let Some(name) = peer_name {
        span.record("peer_name", name);
    }
}

pub struct ErrorInfo {
    pub code: &'static str,
    pub kind: &'static str,
    pub io_code: Option<i32>,
    pub sqlstate: Option<String>,
    pub http_status: Option<u16>,
}

impl ErrorInfo {
    pub fn new(code: &'static str, kind: &'static str) -> Self {
        Self {
            code,
            kind,
            io_code: None,
            sqlstate: None,
            http_status: None,
        }
    }
}

pub trait LogError {
    fn log_info(&self) -> ErrorInfo;
}

impl LogError for sqlx::Error {
    fn log_info(&self) -> ErrorInfo {
        let kind = match self {
            Self::PoolTimedOut => "pool_timeout",
            Self::PoolClosed => "pool_closed",
            Self::Io(_) => "io",
            Self::Tls(_) => "tls",
            Self::Database(_) => "server",
            _ => "other",
        };
        let mut info = ErrorInfo::new("database", kind);
        if let Self::Io(source) = self {
            info.io_code = source.raw_os_error();
        }
        if let Some(error) = self.as_database_error() {
            info.sqlstate = error
                .code()
                .filter(|code| {
                    code.len() == 5 && code.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
                .map(|code| code.into_owned());
        }
        info
    }
}

impl LogError for reqwest::Error {
    fn log_info(&self) -> ErrorInfo {
        let kind = if self.is_timeout() {
            "timeout"
        } else if self.is_connect() {
            "connect"
        } else if self.is_status() {
            "http_status"
        } else if self.is_decode() {
            "decode"
        } else {
            "other"
        };
        let mut info = ErrorInfo::new("registry", kind);
        info.http_status = self.status().map(|status| status.as_u16());
        info
    }
}

impl LogError for std::convert::Infallible {
    fn log_info(&self) -> ErrorInfo {
        match *self {}
    }
}

pub async fn observe_lock<'a, T: Send>(
    name: &'static str,
    lock: &'a tokio::sync::Mutex<T>,
) -> tokio::sync::MutexGuard<'a, T> {
    observe(name, async {
        Ok::<_, std::convert::Infallible>(lock.lock().await)
    })
    .await
    .unwrap_or_else(|error| match error {})
}

pub fn log_failure(event: &'static str, error: &impl LogError) {
    emit_failure(event, &error.log_info(), None);
}

pub fn log_api_failure(status: u16, info: &ErrorInfo) {
    emit_failure("api_error", info, Some(status));
}

fn emit_failure(event: &'static str, info: &ErrorInfo, status: Option<u16>) {
    if status.is_some_and(|status| status < 500) {
        tracing::warn!(
            event,
            status,
            error_code = info.code,
            error_kind = info.kind,
            io_code = info.io_code,
            sqlstate = info.sqlstate.as_deref(),
            http_status = info.http_status,
            "Request rejected"
        );
    } else {
        tracing::error!(
            event,
            status,
            error_code = info.code,
            error_kind = info.kind,
            io_code = info.io_code,
            sqlstate = info.sqlstate.as_deref(),
            http_status = info.http_status,
            "Operation failed"
        );
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

struct StageGuard {
    name: &'static str,
    started: Instant,
    completed: bool,
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        if !self.completed {
            tracing::warn!(
                event = "stage_interrupted",
                stage = self.name,
                elapsed_ms = elapsed_ms(self.started),
                "Stage future did not complete"
            );
        }
    }
}

pub async fn observe<T, E: LogError>(
    name: &'static str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut guard = StageGuard {
        name,
        started: Instant::now(),
        completed: false,
    };
    tracing::debug!(event = "stage_started", stage = name, "Stage started");
    tokio::pin!(future);
    let mut pending = tokio::time::interval_at(
        tokio::time::Instant::now() + PENDING_INTERVAL,
        PENDING_INTERVAL,
    );
    pending.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result = loop {
        tokio::select! {
            result = &mut future => break result,
            _ = pending.tick() => {
                tracing::warn!(event = "stage_pending", stage = name,
                    elapsed_ms = elapsed_ms(guard.started), "Stage still pending");
            }
        }
    };
    guard.completed = true;
    let elapsed_ms = elapsed_ms(guard.started);
    match &result {
        Ok(_) if guard.started.elapsed() >= SLOW_STAGE => {
            tracing::warn!(
                event = "stage_completed",
                stage = name,
                elapsed_ms,
                outcome = "ok",
                "Slow stage completed"
            );
        }
        Ok(_) => tracing::debug!(
            event = "stage_completed",
            stage = name,
            elapsed_ms,
            outcome = "ok",
            "Stage completed"
        ),
        Err(error) => {
            let info = error.log_info();
            tracing::warn!(
                event = "stage_completed",
                stage = name,
                elapsed_ms,
                outcome = "error",
                error_code = info.code,
                error_kind = info.kind,
                io_code = info.io_code,
                sqlstate = info.sqlstate.as_deref(),
                http_status = info.http_status,
                "Stage failed"
            );
        }
    }
    result
}

pub trait ObserveResult<T, E: LogError>: Future<Output = Result<T, E>> + Sized {
    fn observed(self, name: &'static str) -> impl Future<Output = Result<T, E>> + Send
    where
        Self: Send,
        T: Send,
        E: Send,
    {
        observe(name, self)
    }
}

impl<T, E: LogError, F: Future<Output = Result<T, E>>> ObserveResult<T, E> for F {}

#[cfg(test)]
mod tests;
