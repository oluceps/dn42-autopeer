use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;
use crate::{peer::{Peer, PeerStatus}, error::PeerError};

pub struct PeerStore {
    pool: PgPool,
}

impl PeerStore {
    pub async fn new() -> Result<Self, PeerError> {
        let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://dn42-bot@localhost/dn42".to_string());
        
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .map_err(|source| PeerError::Database { source })?;

        // Initialize schema if not exists
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS peers (
                asn BIGINT PRIMARY KEY,
                iface_name VARCHAR NOT NULL,
                pubkey VARCHAR NOT NULL,
                endpoint VARCHAR,
                local_ll_ip VARCHAR NOT NULL,
                remote_ll_ip VARCHAR NOT NULL,
                status VARCHAR NOT NULL,
                listen_port INT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            "#
        )
        .execute(&pool)
        .await
        .map_err(|source| PeerError::Database { source })?;

        Ok(Self { pool })
    }

    pub async fn insert_peer(&self, peer: &Peer, listen_port: u16) -> Result<(), PeerError> {
        let endpoint_str = peer.endpoint.map(|e| e.to_string());
        let status_str = match &peer.status {
            PeerStatus::Active => "active",
            PeerStatus::Disabled => "disabled",
            PeerStatus::Error(_) => "error",
        };
        
        sqlx::query(
            r#"
            INSERT INTO peers (asn, iface_name, pubkey, endpoint, local_ll_ip, remote_ll_ip, status, listen_port)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (asn) DO UPDATE SET
                pubkey = EXCLUDED.pubkey,
                endpoint = EXCLUDED.endpoint,
                local_ll_ip = EXCLUDED.local_ll_ip,
                remote_ll_ip = EXCLUDED.remote_ll_ip,
                status = EXCLUDED.status,
                listen_port = EXCLUDED.listen_port,
                updated_at = CURRENT_TIMESTAMP
            "#
        )
        .bind(peer.asn as i64)
        .bind(&peer.iface_name)
        .bind(peer.pubkey.as_str())
        .bind(endpoint_str)
        .bind(peer.local_ll_ip.to_string())
        .bind(peer.remote_ll_ip.to_string())
        .bind(status_str)
        .bind(listen_port as i32)
        .execute(&self.pool)
        .await
        .map_err(|source| PeerError::Database { source })?;

        Ok(())
    }

    pub async fn delete_peer(&self, asn: u32) -> Result<bool, PeerError> {
        let result = sqlx::query("DELETE FROM peers WHERE asn = $1")
            .bind(asn as i64)
            .execute(&self.pool)
            .await
            .map_err(|source| PeerError::Database { source })?;
        
        Ok(result.rows_affected() > 0)
    }

    pub async fn peer_exists(&self, asn: u32) -> Result<bool, PeerError> {
        let (exists,): (bool,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM peers WHERE asn = $1)")
            .bind(asn as i64)
            .fetch_one(&self.pool)
            .await
            .map_err(|source| PeerError::Database { source })?;
        Ok(exists)
    }
}
