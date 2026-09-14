use crate::{challenge::RequestAuthorizer, error::ErrorResponse, wg_pubkey::WgPubKey};
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
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
    #[schema(example = "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz=", value_type = String)]
    pub pubkey: WgPubKey,
    #[schema(example = "198.51.100.1:51820")]
    pub endpoint: Option<String>,
    pub challenge: Challenge,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePeerReq {
    #[schema(example = 4242421234_u32)]
    pub asn: u32,
    #[schema(example = "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz=", value_type = String)]
    pub pubkey: WgPubKey,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    #[schema(value_type = Option<String>, nullable = true, example = "198.51.100.1:51820")]
    pub endpoint: Option<Option<String>>,
    pub challenge: Challenge,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeletePeerReq {
    #[schema(example = 4242421234_u32)]
    pub asn: u32,
    pub challenge: Challenge,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerResponse {
    #[schema(example = "success")]
    pub status: String,
    pub message: String,
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
    let endpoint = parse_endpoint(payload.endpoint.as_deref())?;
    let message = crate::challenge::build_create_message(
        payload.asn,
        &payload.pubkey,
        endpoint,
        &payload.challenge.nonce,
        payload.challenge.expires_at,
    );
    authorize(&state, payload.asn, &payload.challenge, &message).await?;

    let peer = state
        .manager
        .create_peer(payload.asn, payload.pubkey, endpoint)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(PeerResponse {
            status: "success".to_string(),
            message: "The server configured the peer in BIRD and the kernel".to_string(),
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
    let endpoint = payload
        .endpoint
        .as_ref()
        .map(|value| parse_endpoint(value.as_deref()))
        .transpose()?;
    let message = crate::challenge::build_update_message(
        payload.asn,
        &payload.pubkey,
        endpoint,
        &payload.challenge.nonce,
        payload.challenge.expires_at,
    );
    authorize(&state, payload.asn, &payload.challenge, &message).await?;

    state
        .manager
        .update_peer(payload.asn, payload.pubkey, endpoint)
        .await?;
    Ok(Json(PeerResponse {
        status: "success".to_string(),
        message: "The server updated the peer".to_string(),
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
    let message = crate::challenge::build_delete_message(
        payload.asn,
        &payload.challenge.nonce,
        payload.challenge.expires_at,
    );
    authorize(&state, payload.asn, &payload.challenge, &message).await?;
    state.manager.delete_peer(payload.asn).await?;
    Ok(Json(PeerResponse {
        status: "success".to_string(),
        message: "The server removed the peer".to_string(),
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

fn parse_endpoint(endpoint: Option<&str>) -> Result<Option<SocketAddr>, PeerError> {
    endpoint
        .map(SocketAddr::from_str)
        .transpose()
        .map_err(|_| PeerError::Validation {
            detail: "The endpoint must use the IP:PORT format".to_string(),
        })
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
        version = "1.1.0",
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
            r#"{"asn":4242420001,"pubkey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","challenge":{"auth":"a","signature":"s","nonce":"n","expires_at":1}}"#,
        )
        .unwrap();
        let null: UpdatePeerReq = serde_json::from_str(
            r#"{"asn":4242420001,"pubkey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","endpoint":null,"challenge":{"auth":"a","signature":"s","nonce":"n","expires_at":1}}"#,
        )
        .unwrap();
        let value: UpdatePeerReq = serde_json::from_str(
            r#"{"asn":4242420001,"pubkey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","endpoint":"198.51.100.1:51820","challenge":{"auth":"a","signature":"s","nonce":"n","expires_at":1}}"#,
        )
        .unwrap();

        assert_eq!(missing.endpoint, None);
        assert_eq!(null.endpoint, Some(None));
        assert_eq!(value.endpoint, Some(Some("198.51.100.1:51820".to_string())));
    }
}
