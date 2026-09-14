use crate::{
    error::PeerError,
    peer::{Peer, PeerStatus},
    wg_pubkey::WgPubKey,
};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::{env, net::SocketAddr, str::FromStr};

#[derive(Clone)]
pub struct PeerStore {
    pool: PgPool,
}

impl PeerStore {
    pub async fn new() -> Result<Self, PeerError> {
        let db_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://dn42-bot@localhost/dn42".to_string());

        let mut opts = sqlx::postgres::PgConnectOptions::from_str(&db_url)
            .map_err(|source| PeerError::Database { source })?;

        // sqlx 0.9.0 retains brackets around IPv6 literals. Remove them before DNS lookup.
        if let Ok(parsed_url) = url::Url::parse(&db_url)
            && let Some(host) = parsed_url.host_str()
            && host.starts_with('[')
            && host.ends_with(']')
        {
            opts = opts.host(&host[1..host.len() - 1]);
        }

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect_with(opts)
            .await
            .map_err(|source| PeerError::Database { source })?;

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
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|source| PeerError::Database { source })?;

        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS peers_listen_port_key ON peers (listen_port)",
        )
        .execute(&pool)
        .await
        .map_err(|source| PeerError::Database { source })?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS auth_nonces (
                nonce VARCHAR PRIMARY KEY,
                asn BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|source| PeerError::Database { source })?;

        Ok(Self { pool })
    }

    pub async fn insert_nonce(
        &self,
        asn: u32,
        nonce: &str,
        expires_at: i64,
    ) -> Result<bool, PeerError> {
        sqlx::query("DELETE FROM auth_nonces WHERE expires_at < $1")
            .bind(unix_timestamp())
            .execute(&self.pool)
            .await
            .map_err(|source| PeerError::Database { source })?;

        let result = sqlx::query(
            "INSERT INTO auth_nonces (nonce, asn, expires_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(nonce)
        .bind(asn as i64)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|source| PeerError::Database { source })?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn consume_nonce(
        &self,
        asn: u32,
        nonce: &str,
        expires_at: i64,
    ) -> Result<bool, PeerError> {
        let result = sqlx::query(
            r#"
            DELETE FROM auth_nonces
            WHERE nonce = $1 AND asn = $2 AND expires_at = $3 AND expires_at >= $4
            "#,
        )
        .bind(nonce)
        .bind(asn as i64)
        .bind(expires_at)
        .bind(unix_timestamp())
        .execute(&self.pool)
        .await
        .map_err(|source| PeerError::Database { source })?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn reserve_peer(&self, peer: &Peer) -> Result<bool, PeerError> {
        let result = sqlx::query(
            r#"
            INSERT INTO peers
                (asn, iface_name, pubkey, endpoint, local_ll_ip, remote_ll_ip, status, listen_port)
            VALUES ($1, $2, $3, $4, $5, $6, 'provisioning', $7)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(peer.asn as i64)
        .bind(&peer.iface_name)
        .bind(peer.pubkey.as_str())
        .bind(peer.endpoint.map(|value| value.to_string()))
        .bind(peer.local_ll_ip.to_string())
        .bind(peer.remote_ll_ip.to_string())
        .bind(peer.listen_port as i32)
        .execute(&self.pool)
        .await
        .map_err(|source| PeerError::Database { source })?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn update_peer_desired(&self, peer: &Peer) -> Result<bool, PeerError> {
        let result = sqlx::query(
            r#"
            UPDATE peers SET
                iface_name = $2,
                pubkey = $3,
                endpoint = $4,
                local_ll_ip = $5,
                remote_ll_ip = $6,
                status = 'provisioning',
                listen_port = $7,
                updated_at = CURRENT_TIMESTAMP
            WHERE asn = $1
            "#,
        )
        .bind(peer.asn as i64)
        .bind(&peer.iface_name)
        .bind(peer.pubkey.as_str())
        .bind(peer.endpoint.map(|value| value.to_string()))
        .bind(peer.local_ll_ip.to_string())
        .bind(peer.remote_ll_ip.to_string())
        .bind(peer.listen_port as i32)
        .execute(&self.pool)
        .await
        .map_err(|source| PeerError::Database { source })?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn set_status(&self, asn: u32, status: PeerStatus) -> Result<bool, PeerError> {
        let status = status_to_str(&status);
        let result = sqlx::query(
            "UPDATE peers SET status = $2, updated_at = CURRENT_TIMESTAMP WHERE asn = $1",
        )
        .bind(asn as i64)
        .bind(status)
        .execute(&self.pool)
        .await
        .map_err(|source| PeerError::Database { source })?;
        Ok(result.rows_affected() == 1)
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
        let (exists,): (bool,) =
            sqlx::query_as("SELECT EXISTS(SELECT 1 FROM peers WHERE asn = $1)")
                .bind(asn as i64)
                .fetch_one(&self.pool)
                .await
                .map_err(|source| PeerError::Database { source })?;
        Ok(exists)
    }

    pub async fn get_peer(&self, asn: u32) -> Result<Option<Peer>, PeerError> {
        let row = sqlx::query(
            r#"
            SELECT asn, iface_name, pubkey, endpoint, local_ll_ip, remote_ll_ip, status, listen_port
            FROM peers WHERE asn = $1
            "#,
        )
        .bind(asn as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(|source| PeerError::Database { source })?;
        row.map(row_to_peer).transpose()
    }

    pub async fn list_peers(&self) -> Result<Vec<Peer>, PeerError> {
        let rows = sqlx::query(
            r#"
            SELECT asn, iface_name, pubkey, endpoint, local_ll_ip, remote_ll_ip, status, listen_port
            FROM peers ORDER BY asn
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|source| PeerError::Database { source })?;
        rows.into_iter().map(row_to_peer).collect()
    }
}

fn row_to_peer(row: sqlx::postgres::PgRow) -> Result<Peer, PeerError> {
    let asn = u32::try_from(row.get::<i64, _>("asn")).map_err(|_| PeerError::Validation {
        detail: "The database contains an invalid ASN".to_string(),
    })?;
    let pubkey = WgPubKey::try_from(row.get::<String, _>("pubkey"))?;
    let endpoint = row
        .get::<Option<String>, _>("endpoint")
        .map(|value| value.parse::<SocketAddr>())
        .transpose()
        .map_err(|_| PeerError::Validation {
            detail: format!("The database contains an invalid endpoint for AS{asn}"),
        })?;
    let local_ll_ip =
        row.get::<String, _>("local_ll_ip")
            .parse()
            .map_err(|_| PeerError::Validation {
                detail: format!("The database contains an invalid local address for AS{asn}"),
            })?;
    let remote_ll_ip =
        row.get::<String, _>("remote_ll_ip")
            .parse()
            .map_err(|_| PeerError::Validation {
                detail: format!("The database contains an invalid remote address for AS{asn}"),
            })?;
    let listen_port =
        u16::try_from(row.get::<i32, _>("listen_port")).map_err(|_| PeerError::Validation {
            detail: format!("The database contains an invalid listen port for AS{asn}"),
        })?;

    Ok(Peer {
        iface_name: row.get("iface_name"),
        asn,
        pubkey,
        endpoint,
        local_ll_ip,
        remote_ll_ip,
        status: str_to_status(row.get("status")),
        listen_port,
    })
}

fn status_to_str(status: &PeerStatus) -> &str {
    match status {
        PeerStatus::Provisioning => "provisioning",
        PeerStatus::Active => "active",
        PeerStatus::Deleting => "deleting",
        PeerStatus::Disabled => "disabled",
        PeerStatus::Error(_) => "error",
    }
}

fn str_to_status(status: String) -> PeerStatus {
    match status.as_str() {
        "provisioning" => PeerStatus::Provisioning,
        "active" => PeerStatus::Active,
        "deleting" => PeerStatus::Deleting,
        "disabled" => PeerStatus::Disabled,
        other => PeerStatus::Error(format!("unknown database status: {other}")),
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
