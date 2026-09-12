use serde::{Deserialize, Serialize};
use std::net::{Ipv6Addr, SocketAddr};

use crate::wg_pubkey::WgPubKey;

// represents a fully resolved, active wireguard and bgp peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    // unique interface name, e.g., "wg-peer-4242"
    pub iface_name: String,
    // dn42 autonomous system number
    pub asn: u32,
    // wireguard public key in base64
    pub pubkey: WgPubKey,
    // remote endpoint, optional for roaming peers
    pub endpoint: Option<SocketAddr>,
    // the local ipv6 link-local address assigned to our side of the wg interface
    pub local_ll_ip: Ipv6Addr,
    // the remote ipv6 link-local address used for the bgp session
    pub remote_ll_ip: Ipv6Addr,
    // peer administrative and operational status
    pub status: PeerStatus,
}

// operational status of the peer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    // configured in both kernel and bird
    Active,
    // administratively down, config removed from bird/kernel
    Disabled,
    // failed to configure (e.g., netlink error or bird syntax error)
    Error(String),
}
