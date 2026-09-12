use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use snafu::prelude::*;
use std::net::AddrParseError;
use std::path::PathBuf;
use utoipa::ToSchema;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum PubKeyError {
    #[snafu(display("wireguard public key must be exactly 44 characters"))]
    PubKeyLength,
}

// define the custom error enum for the peer management domain
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum PeerError {
    #[snafu(display("Invalid WireGuard public key: length must be exactly 44, got {len}"))]
    InvalidWgPubKeyLength { len: usize },

    #[snafu(display("Failed to base64 decode WireGuard public key: {source}"))]
    InvalidWgPubKeyBase64 { source: base64::DecodeError },

    #[snafu(display("failed to parse ip address '{ip}': {source}"))]
    InvalidIp { source: AddrParseError, ip: String },

    #[snafu(display("peer asn {asn} is not allowed (must be in dn42 range)"))]
    InvalidAsn { asn: u32 },

    #[snafu(display("failed to manipulate netlink interface '{iface_name}': {source}"))]
    Netlink {
        source: std::io::Error,
        iface_name: String,
    },

    #[snafu(display("failed to write bird config to {}: {source}", path.display()))]
    BirdConfigIo {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("bird syntax check or reload failed. stderr: {stderr}"))]
    BirdReload { stderr: String },

    #[snafu(display("challenge verification failed: {detail}"))]
    UnauthorizedChallenge { detail: String },

    #[snafu(display("invalid request: {detail}"))]
    Validation { detail: String },

    #[snafu(display("Database error: {source}"))]
    Database { source: sqlx::Error },

    #[snafu(display("SSH signature verification failed: {detail}"))]
    SignatureVerificationFailed { detail: String },

    #[snafu(display("Provided SSH key is not identical with DN42 registry records"))]
    RegistryMismatch,
}

// unified api error response body: a stable machine-readable code plus
// optional human-readable detail, so 4xx/5xx responses carry real info.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    #[schema(example = "unauthorized_challenge")]
    pub error: String,
    #[schema(example = "signature verification failed: bad signature")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl IntoResponse for PeerError {
    fn into_response(self) -> axum::response::Response {
        eprintln!("API Error: {:?}", self);
        let (status, error, detail) = match self {
            PeerError::UnauthorizedChallenge { detail } => (
                StatusCode::FORBIDDEN,
                "unauthorized_challenge".to_string(),
                Some(detail),
            ),
            PeerError::InvalidIp { ip, .. } => (
                StatusCode::BAD_REQUEST,
                "invalid_ip".to_string(),
                Some(format!("ip '{ip}' is not parseable")),
            ),
            PeerError::InvalidAsn { asn } => (
                StatusCode::BAD_REQUEST,
                "invalid_asn".to_string(),
                Some(format!("asn {asn} not in dn42 range")),
            ),
            PeerError::InvalidWgPubKeyLength { len } => (
                StatusCode::BAD_REQUEST,
                "invalid_wg_pubkey_length".to_string(),
                Some(format!("WireGuard public key length must be 44, got {}", len)),
            ),
            PeerError::InvalidWgPubKeyBase64 { source } => (
                StatusCode::BAD_REQUEST,
                "invalid_wg_pubkey_base64".to_string(),
                Some(format!("WireGuard public key must be valid base64: {}", source)),
            ),
            PeerError::Validation { detail } => (
                StatusCode::BAD_REQUEST,
                "validation_failed".to_string(),
                Some(detail),
            ),
            PeerError::SignatureVerificationFailed { detail } => (
                StatusCode::BAD_REQUEST,
                "signature_verification_failed".to_string(),
                Some(detail),
            ),
            PeerError::RegistryMismatch => (
                StatusCode::FORBIDDEN,
                "registry_mismatch".to_string(),
                Some("Provided SSH key is not identical with DN42 registry records".to_string()),
            ),
            // everything below is a server-side failure
            // TODO: handle
            PeerError::Netlink { .. }
            | PeerError::BirdConfigIo { .. }
            | PeerError::BirdReload { .. }
            | PeerError::Database { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error".to_string(),
                None,
            ),
        };
        (status, Json(ErrorResponse { error, detail })).into_response()
    }
}


