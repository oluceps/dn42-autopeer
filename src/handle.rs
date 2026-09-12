
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};
use serde::{Deserialize, Serialize};
use crate::wg_pubkey::WgPubKey;

// ==========================================
// part 2: api data transfer objects (请求与响应载荷)
// ==========================================

// TODO: don't forget verify auth pubkey with registry on backend
// user sign message with a auth prvkey which on registry.
#[derive(Debug, Deserialize, ToSchema)]
pub struct Challenge {
    #[schema(example = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMDcYqby4TnhKV6xGyuZUtxOmTtXjKYp8r+uCxbGph65")]
    auth: String,
    #[schema(example = "-----BEGIN SSH SIGNATURE-----\n...")]
    signature: String
}


// payload received from restful post request to create a peer
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePeerReq {
    #[schema(example = 4242421234u32)]
    pub asn: u32,

    #[schema(example = "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz=", value_type = String)]
    pub pubkey: WgPubKey,

    // endpoint string, e.g., "198.51.100.1:51820", can be none
    #[schema(example = "198.51.100.1:51820")]
    pub endpoint: Option<String>,

    pub challenge: Challenge

}




// payload for restful patch/put request
#[derive(Debug, Deserialize,ToSchema)]
pub struct UpdatePeerReq {

    // as identity
    #[schema(example = 4242421234u32)]
    pub asn: u32,

    #[schema(example = "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz=", value_type = String)]
    pub pubkey: WgPubKey,

    // optionally update endpoint if peer ip changed
    #[schema(example = "198.51.100.1:51820")]
    pub endpoint: Option<String>,
    // // optionally change status to suspend or resume the peer
    // pub status: Option<PeerStatus>,
    pub challenge: Challenge
}

#[derive(Debug, Deserialize,ToSchema)]
pub struct DeletePeerReq {
    #[schema(example = 4242421234u32)]
    pub asn: u32,

    pub challenge: Challenge
}

// root response structure for peering requests
#[derive(Debug, Serialize, ToSchema)]
pub struct PeerResponse {
    #[schema(example = "success")]
    pub status: String,

    #[schema(example = "Peer successfully configured in BIRD and Kernel.")]
    pub message: String,

    pub wg_config: WgConfig,

    pub bgp_config: BgpConfig,
}

// wireguard layer configuration details for the user
#[derive(Debug, Serialize, ToSchema)]
pub struct WgConfig {
    #[schema(example = "fe80::4242:4212:3400:2/64")]
    pub your_assigned_ip: String,

    #[schema(example = "dn42-us.yourdomain.com:21234")]
    pub my_endpoint: String,

    #[schema(example = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy=")]
    pub my_pubkey: String,

    // hint for the user's allowed_ips setting
    #[schema(example = "0.0.0.0/0, ::/0")]
    pub allowed_ips: String,
}

// bgp layer configuration details for the user
#[derive(Debug, Serialize, ToSchema)]
pub struct BgpConfig {
    // using u32 literal suffix as discussed earlier
    #[schema(example = 4242420291_u32)]
    pub my_asn: u32,

    #[schema(example = "fe80::4242:4202:9100:1")]
    pub my_neighbor_ip: String,

    #[schema(example = true)]
    pub multiprotocol: bool,

    #[schema(example = true)]
    pub extended_next_hop: bool,
}


// shared state injected into restful handlers (e.g., via axum state)
#[derive(Clone)]
pub struct AppState {
    pub manager: Arc<crate::manager::PeerManager>,
}

use axum::{Json, extract::State};
use std::str::FromStr;
use std::net::SocketAddr;

use crate::error::{ErrorResponse, PeerError};

#[utoipa::path(
    post,
    path = "/api/peers",
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
) -> Result<Json<PeerResponse>, PeerError> {
    let expected_msg = crate::challenge::build_expected_message(payload.asn, Some(&payload.pubkey));
    crate::challenge::authorize_request(payload.asn, &payload.challenge.auth, &payload.challenge.signature, &expected_msg).await?;

    let endpoint = payload.endpoint.as_deref().map(SocketAddr::from_str).transpose()
        .map_err(|_| PeerError::Validation { detail: "Invalid endpoint format".to_string() })?;

    let peer = state.manager.upsert_peer(payload.asn, payload.pubkey, endpoint).await?;

    Ok(Json(PeerResponse {
        status: "success".to_string(),
        message: "Peer successfully configured in BIRD and Kernel.".to_string(),
        wg_config: WgConfig {
            your_assigned_ip: format!("{}/64", peer.remote_ll_ip),
            my_endpoint: "dn42-node.example.com:20000".to_string(), // Need to get public IP
            my_pubkey: "dummy_pubkey".to_string(),
            allowed_ips: "0.0.0.0/0, ::/0".to_string(),
        },
        bgp_config: BgpConfig {
            my_asn: 4242420291,
            my_neighbor_ip: peer.local_ll_ip.to_string(),
            multiprotocol: true,
            extended_next_hop: true,
        },
    }))
}

#[utoipa::path(
    patch,
    path = "/api/peers",
    request_body = UpdatePeerReq,
    responses(
        (status = 201, description = "Peer successfully configured", body = PeerResponse),
        (status = 403, description = "Challenge verification failed", body = ErrorResponse),
        (status = 400, description = "Request validation failed", body = ErrorResponse)
    ),
    tag = "Peering"
)]
pub async fn update_peer(
    State(state): State<AppState>,
    Json(payload): Json<UpdatePeerReq>,
) -> Result<Json<PeerResponse>, PeerError> {
    let expected_msg = crate::challenge::build_expected_message(payload.asn, Some(&payload.pubkey));
    crate::challenge::authorize_request(payload.asn, &payload.challenge.auth, &payload.challenge.signature, &expected_msg).await?;

    let endpoint = payload.endpoint.as_deref().map(SocketAddr::from_str).transpose()
        .map_err(|_| PeerError::Validation { detail: "Invalid endpoint format".to_string() })?;

    let peer = state.manager.upsert_peer(payload.asn, payload.pubkey, endpoint).await?;

    Ok(Json(PeerResponse {
        status: "success".to_string(),
        message: "Peer successfully updated.".to_string(),
        wg_config: WgConfig {
            your_assigned_ip: format!("{}/64", peer.remote_ll_ip),
            my_endpoint: "dn42-node.example.com:20000".to_string(),
            my_pubkey: "dummy_pubkey".to_string(),
            allowed_ips: "0.0.0.0/0, ::/0".to_string(),
        },
        bgp_config: BgpConfig {
            my_asn: 4242420291,
            my_neighbor_ip: peer.local_ll_ip.to_string(),
            multiprotocol: true,
            extended_next_hop: true,
        },
    }))
}

#[utoipa::path(
    delete,
    path = "/api/peers",
    request_body = DeletePeerReq,
    responses(
        (status = 201, description = "Peer successfully configured", body = PeerResponse),
        (status = 403, description = "Challenge verification failed", body = ErrorResponse),
        (status = 400, description = "Request validation failed", body = ErrorResponse)
    ),
    tag = "Peering"
)]
pub async fn delete_peer(
    State(state): State<AppState>,
    Json(payload): Json<DeletePeerReq>,
) -> Result<Json<PeerResponse>, PeerError> {
    let expected_msg = crate::challenge::build_expected_message(payload.asn, None);
    crate::challenge::authorize_request(payload.asn, &payload.challenge.auth, &payload.challenge.signature, &expected_msg).await?;

    state.manager.delete_peer(payload.asn).await?;

    Ok(Json(PeerResponse {
        status: "success".to_string(),
        message: "Peer successfully removed.".to_string(),
        wg_config: WgConfig {
            your_assigned_ip: "".to_string(),
            my_endpoint: "".to_string(),
            my_pubkey: "".to_string(),
            allowed_ips: "".to_string(),
        },
        bgp_config: BgpConfig {
            my_asn: 0,
            my_neighbor_ip: "".to_string(),
            multiprotocol: false,
            extended_next_hop: false,
        },
    }))
}




#[derive(OpenApi)]
#[openapi(
    paths(create_peer, update_peer, delete_peer),
    // all nested schemas must be declared here explicitly
    components(schemas(
        Challenge,

        ErrorResponse,

        CreatePeerReq, 
        UpdatePeerReq,
        DeletePeerReq,
        PeerResponse, 
        WgConfig, 
        BgpConfig
    ))
)]
pub struct ApiDoc;
