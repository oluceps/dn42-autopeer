use crate::{challenge::RequestAuthorizer, error::ErrorResponse, wg_pubkey::WgPubKey};
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use std::{net::Ipv6Addr, sync::Arc};
use url::{Host, Url};
use utoipa::{OpenApi, ToSchema};

use crate::error::PeerError;

#[derive(Debug, Deserialize, ToSchema)]
pub struct Challenge {
    #[schema(
        example = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMDcYqby4TnhKV6xGyuZUtxOmTtXjKYp8r+uCxbGph65"
    )]
    auth: String,
    #[schema(example = "-----BEGIN SSH SIGNATURE-----\n...")]
    signature: String,
    #[schema(example = "N2fH1XWlJpB9q7yC0kD5aQ8sR4uV6zE3mT1oG9iL0xA=")]
    nonce: String,
    #[schema(example = 1789372800_i64)]
    expires_at: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChallengeRequest {
    #[schema(example = 4242421234_u32)]
    pub asn: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChallengeResponse {
    pub nonce: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePeerReq {
    #[schema(example = 4242421234_u32)]
    pub asn: u32,
    #[schema(example = "fra1")]
    pub peer_name: String,
    #[schema(example = "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz=", value_type = String)]
    pub pubkey: WgPubKey,
    #[schema(example = "peer.example.net:51820")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub manual_lla: bool,
    pub local_ll_ip: Option<String>,
    pub remote_ll_ip: Option<String>,
    pub challenge: Challenge,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePeerReq {
    #[schema(example = 4242421234_u32)]
    pub asn: u32,
    #[schema(example = "fra1")]
    pub peer_name: String,
    #[schema(example = "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz=", value_type = String)]
    pub pubkey: WgPubKey,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    #[schema(value_type = Option<String>, nullable = true, example = "peer.example.net:51820")]
    pub endpoint: Option<Option<String>>,
    #[serde(default)]
    pub manual_lla: bool,
    pub local_ll_ip: Option<String>,
    pub remote_ll_ip: Option<String>,
    pub challenge: Challenge,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeletePeerReq {
    #[schema(example = 4242421234_u32)]
    pub asn: u32,
    #[schema(example = "fra1")]
    pub peer_name: String,
    pub challenge: Challenge,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerResponse {
    #[schema(example = "success")]
    pub status: String,
    pub message: String,
    pub peer_id: u32,
    pub peer_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_config: Option<WgConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bgp_config: Option<BgpConfig>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WgConfig {
    pub your_assigned_ip: String,
    pub my_endpoint: String,
    pub my_pubkey: String,
    pub allowed_ips: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BgpConfig {
    pub my_asn: u32,
    pub my_neighbor_ip: String,
    pub multiprotocol: bool,
    pub extended_next_hop: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub manager: Arc<crate::manager::PeerManager>,
    pub authorizer: RequestAuthorizer,
}

pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

#[utoipa::path(
    post,
    path = "/api/challenges",
    summary = "Create a short-lived signing challenge",
    request_body = ChallengeRequest,
    responses(
        (status = 201, description = "Challenge created", body = ChallengeResponse)
    ),
    tag = "Authentication"
)]
pub async fn create_challenge(
    State(state): State<AppState>,
    Json(payload): Json<ChallengeRequest>,
) -> Result<(StatusCode, Json<ChallengeResponse>), PeerError> {
    let (nonce, expires_at) = state.authorizer.issue_challenge(payload.asn).await?;
    Ok((
        StatusCode::CREATED,
        Json(ChallengeResponse { nonce, expires_at }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/peers",
    summary = "Create and configure a new DN42 BGP peer",
    request_body = CreatePeerReq,
    responses(
        (status = 201, description = "Peer successfully configured", body = PeerResponse),
        (status = 403, description = "Challenge verification failed", body = ErrorResponse),
        (status = 400, description = "Request validation failed", body = ErrorResponse)
    ),
    tag = "Peering"
)]
pub async fn create_peer(
    State(state): State<AppState>,
    Json(payload): Json<CreatePeerReq>,
) -> Result<(StatusCode, Json<PeerResponse>), PeerError> {
    let peer_name = parse_peer_name(&payload.peer_name)?;
    let endpoint = parse_endpoint(payload.endpoint.as_deref())?;
    let link_local = parse_link_local(
        payload.manual_lla,
        payload.local_ll_ip.as_deref(),
        payload.remote_ll_ip.as_deref(),
    )?;
    let message = crate::challenge::build_create_message(
        payload.asn,
        &peer_name,
        &payload.pubkey,
        endpoint.as_deref(),
        link_local,
        &payload.challenge.nonce,
        payload.challenge.expires_at,
    );
    authorize(&state, payload.asn, &payload.challenge, &message).await?;

    let peer = state
        .manager
        .create_peer(payload.asn, peer_name, payload.pubkey, endpoint, link_local)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(PeerResponse {
            status: "success".to_string(),
            message: "The server configured the peer in BIRD and the kernel".to_string(),
            peer_id: peer.peer_id,
            peer_name: peer.peer_name.clone(),
            wg_config: Some(WgConfig {
                your_assigned_ip: format!("{}/64", peer.remote_ll_ip),
                my_endpoint: format!("{}:{}", state.manager.public_endpoint, peer.listen_port),
                my_pubkey: state.manager.local_wg_pubkey.clone(),
                allowed_ips: "0.0.0.0/0, ::/0".to_string(),
            }),
            bgp_config: Some(BgpConfig {
                my_asn: state.manager.local_asn,
                my_neighbor_ip: peer.local_ll_ip.to_string(),
                multiprotocol: true,
                extended_next_hop: true,
            }),
        }),
    ))
}

#[utoipa::path(
    patch,
    path = "/api/peers",
    summary = "Update an existing peer configuration",
    request_body = UpdatePeerReq,
    responses(
        (status = 200, description = "Peer successfully updated", body = PeerResponse),
        (status = 404, description = "Peer not found", body = ErrorResponse),
        (status = 403, description = "Challenge verification failed", body = ErrorResponse)
    ),
    tag = "Peering"
)]
pub async fn update_peer(
    State(state): State<AppState>,
    Json(payload): Json<UpdatePeerReq>,
) -> Result<Json<PeerResponse>, PeerError> {
    let peer_name = parse_peer_name(&payload.peer_name)?;
    let endpoint = payload
        .endpoint
        .as_ref()
        .map(|value| parse_endpoint(value.as_deref()))
        .transpose()?;
    let link_local = parse_link_local(
        payload.manual_lla,
        payload.local_ll_ip.as_deref(),
        payload.remote_ll_ip.as_deref(),
    )?;
    let message = crate::challenge::build_update_message(
        payload.asn,
        &peer_name,
        &payload.pubkey,
        endpoint.as_ref().map(|value| value.as_deref()),
        link_local,
        &payload.challenge.nonce,
        payload.challenge.expires_at,
    );
    authorize(&state, payload.asn, &payload.challenge, &message).await?;

    let peer = state
        .manager
        .update_peer(payload.asn, peer_name, payload.pubkey, endpoint, link_local)
        .await?;
    Ok(Json(PeerResponse {
        status: "success".to_string(),
        message: "The server updated the peer".to_string(),
        peer_id: peer.peer_id,
        peer_name: peer.peer_name,
        wg_config: None,
        bgp_config: None,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/peers",
    summary = "Remove an existing peer",
    request_body = DeletePeerReq,
    responses(
        (status = 200, description = "Peer successfully removed", body = PeerResponse),
        (status = 404, description = "Peer not found", body = ErrorResponse),
        (status = 403, description = "Challenge verification failed", body = ErrorResponse)
    ),
    tag = "Peering"
)]
pub async fn delete_peer(
    State(state): State<AppState>,
    Json(payload): Json<DeletePeerReq>,
) -> Result<Json<PeerResponse>, PeerError> {
    let peer_name = parse_peer_name(&payload.peer_name)?;
    let message = crate::challenge::build_delete_message(
        payload.asn,
        &peer_name,
        &payload.challenge.nonce,
        payload.challenge.expires_at,
    );
    authorize(&state, payload.asn, &payload.challenge, &message).await?;
    let peer = state.manager.delete_peer(payload.asn, peer_name).await?;
    Ok(Json(PeerResponse {
        status: "success".to_string(),
        message: "The server removed the peer".to_string(),
        peer_id: peer.peer_id,
        peer_name: peer.peer_name,
        wg_config: None,
        bgp_config: None,
    }))
}

async fn authorize(
    state: &AppState,
    asn: u32,
    challenge: &Challenge,
    message: &str,
) -> Result<(), PeerError> {
    state
        .authorizer
        .authorize_request(
            asn,
            &challenge.auth,
            &challenge.signature,
            &challenge.nonce,
            challenge.expires_at,
            message,
        )
        .await
}

fn parse_endpoint(endpoint: Option<&str>) -> Result<Option<String>, PeerError> {
    endpoint.map(parse_endpoint_value).transpose()
}

fn parse_endpoint_value(endpoint: &str) -> Result<String, PeerError> {
    let endpoint = endpoint.trim();
    let url = Url::parse(&format!("udp://{endpoint}")).map_err(|_| PeerError::Validation {
        detail: "The endpoint must use the HOST:PORT format".to_string(),
    })?;
    if url.username() != ""
        || url.password().is_some()
        || !url.path().is_empty()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PeerError::Validation {
            detail: "The endpoint must use the HOST:PORT format".to_string(),
        });
    }
    let port = url.port().ok_or_else(|| PeerError::Validation {
        detail: "The endpoint must include a port".to_string(),
    })?;
    let host = url.host().ok_or_else(|| PeerError::Validation {
        detail: "The endpoint must include an IP address or hostname".to_string(),
    })?;
    Ok(match host {
        Host::Domain(host) => format!("{}:{port}", host.to_ascii_lowercase()),
        Host::Ipv4(host) => format!("{host}:{port}"),
        Host::Ipv6(host) => format!("[{host}]:{port}"),
    })
}

fn parse_link_local(
    manual_lla: bool,
    local_ll_ip: Option<&str>,
    remote_ll_ip: Option<&str>,
) -> Result<Option<(Ipv6Addr, Ipv6Addr)>, PeerError> {
    if !manual_lla {
        if local_ll_ip.is_some() || remote_ll_ip.is_some() {
            return Err(PeerError::Validation {
                detail: "local_ll_ip and remote_ll_ip require manual_lla=true".to_string(),
            });
        }
        return Ok(None);
    }
    let local = parse_link_local_address("local_ll_ip", local_ll_ip)?;
    let remote = parse_link_local_address("remote_ll_ip", remote_ll_ip)?;
    if local == remote {
        return Err(PeerError::Validation {
            detail: "local_ll_ip and remote_ll_ip must differ".to_string(),
        });
    }
    Ok(Some((local, remote)))
}

fn parse_link_local_address(name: &str, value: Option<&str>) -> Result<Ipv6Addr, PeerError> {
    let address = value
        .ok_or_else(|| PeerError::Validation {
            detail: format!("{name} is required when manual_lla=true"),
        })?
        .trim()
        .parse::<Ipv6Addr>()
        .map_err(|_| PeerError::Validation {
            detail: format!("{name} must be a valid IPv6 address"),
        })?;
    if !address.is_unicast_link_local() {
        return Err(PeerError::Validation {
            detail: format!("{name} must be an IPv6 link-local address"),
        });
    }
    Ok(address)
}

fn parse_peer_name(peer_name: &str) -> Result<String, PeerError> {
    let peer_name = peer_name.trim();
    let mut characters = peer_name.chars();
    let valid_first = characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit());
    let valid_rest = characters.all(|character| {
        character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
    });
    if !valid_first || !valid_rest || peer_name.len() > 32 {
        return Err(PeerError::Validation {
            detail: "peer_name must match [a-z0-9][a-z0-9-]{0,31}".to_string(),
        });
    }
    Ok(peer_name.to_string())
}

fn deserialize_present_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "DN42 Autopeer API",
        description = "Automated peering setup and configuration API for DN42 networks.",
        version = "2.0.0",
        contact(name = "DN42 Admin")
    ),
    paths(create_challenge, create_peer, update_peer, delete_peer),
    components(schemas(
        ChallengeRequest,
        ChallengeResponse,
        CreatePeerReq,
        UpdatePeerReq,
        DeletePeerReq,
        Challenge,
        PeerResponse,
        WgConfig,
        BgpConfig,
        ErrorResponse
    ))
)]
pub struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_endpoint_distinguishes_missing_null_and_value() {
        let missing: UpdatePeerReq = serde_json::from_str(
            r#"{"asn":4242420001,"peer_name":"fra1","pubkey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","challenge":{"auth":"a","signature":"s","nonce":"n","expires_at":1}}"#,
        )
        .unwrap();
        let null: UpdatePeerReq = serde_json::from_str(
            r#"{"asn":4242420001,"peer_name":"fra1","pubkey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","endpoint":null,"challenge":{"auth":"a","signature":"s","nonce":"n","expires_at":1}}"#,
        )
        .unwrap();
        let value: UpdatePeerReq = serde_json::from_str(
            r#"{"asn":4242420001,"peer_name":"fra1","pubkey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","endpoint":"198.51.100.1:51820","challenge":{"auth":"a","signature":"s","nonce":"n","expires_at":1}}"#,
        )
        .unwrap();

        assert_eq!(missing.endpoint, None);
        assert_eq!(null.endpoint, Some(None));
        assert_eq!(value.endpoint, Some(Some("198.51.100.1:51820".to_string())));
    }

    #[test]
    fn peer_name_is_normalized_and_validated() {
        assert_eq!(parse_peer_name(" fra1 ").unwrap(), "fra1");
        assert!(parse_peer_name("FRA1").is_err());
        assert!(parse_peer_name("fra_1").is_err());
        assert!(parse_peer_name("").is_err());
    }

    #[test]
    fn endpoint_accepts_hostnames_and_normalizes_addresses() {
        assert_eq!(
            parse_endpoint(Some("Peer.Example.NET:51820")).unwrap(),
            Some("peer.example.net:51820".to_string())
        );
        assert_eq!(
            parse_endpoint(Some("[2001:db8::1]:51820")).unwrap(),
            Some("[2001:db8::1]:51820".to_string())
        );
        assert!(parse_endpoint(Some("peer.example.net")).is_err());
        assert!(parse_endpoint(Some("https://peer.example.net:51820")).is_err());
    }

    #[test]
    fn link_local_addresses_require_manual_mode() {
        let pair = parse_link_local(true, None, None);
        assert!(pair.is_err());
        assert_eq!(parse_link_local(false, None, None).unwrap(), None);
        assert!(parse_link_local(false, Some("fe80::1"), None).is_err());
        assert_eq!(
            parse_link_local(true, Some("fe80::1"), Some("fe80::2")).unwrap(),
            Some(("fe80::1".parse().unwrap(), "fe80::2".parse().unwrap()))
        );
    }
}
