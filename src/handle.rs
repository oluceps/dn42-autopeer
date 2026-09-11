
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

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

    #[schema(example = "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz=")]
    pub pubkey: String,

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

    #[schema(example = "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz=")]
    pub pubkey: String,

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
    // high-performance concurrent hashmap storing peer state in memory
    // key is the interface name (e.g., "wg-peer-4242")
    pub peers: Arc<DashMap<String, Peer>>,
    // path to the bird include directory
    pub bird_conf_dir: String,
    // the local private key for our side of the wireguard tunnels
    pub local_wg_privkey: String,
}

use axum::{Json, extract::State};

use crate::error::{ErrorResponse, PeerError};
use crate::peer::Peer;

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
    // 你的业务逻辑...
    todo!()
}

#[utoipa::path(
    post,
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
    Json(payload): Json<CreatePeerReq>,
) -> Result<Json<PeerResponse>, PeerError> {
    // 你的业务逻辑...
    todo!()
}

#[utoipa::path(
    post,
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
    Json(payload): Json<CreatePeerReq>,
) -> Result<Json<PeerResponse>, PeerError> {
    // 你的业务逻辑...
    todo!()
}




#[derive(OpenApi)]
#[openapi(
    paths(create_peer),
    // all nested schemas must be declared here explicitly
    components(schemas(
        Challenge,

        ErrorResponse,

        CreatePeerReq, 
        PeerResponse, 
        WgConfig, 
        BgpConfig
    ))
)]
struct ApiDoc;
