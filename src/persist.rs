pub struct PeerEntity {
    pub iface_name: String,
    pub asn: u32,
    pub pubkey: WgPubKey,
    pub endpoint: Option<SocketAddr>,
    pub local_ll_ip: Ipv6Addr,
    pub remote_ll_ip: Ipv6Addr,
    pub status: PeerStatus,

    pub listen_port: u16,

    pub created_at: i64,
    pub updated_at: i64,
}

use sqlx::postgres::PgPoolOptions;
use std::{
    env,
    net::{Ipv6Addr, SocketAddr},
};

use crate::{peer::PeerStatus, wg_pubkey::WgPubKey};

pub async fn init_db() -> sqlx::PgPool {
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to Postgres via peer authentication")
}
