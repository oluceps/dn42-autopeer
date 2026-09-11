use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use snafu::{ResultExt, prelude::*};
use std::net::AddrParseError;
use std::path::{Path, PathBuf};
use std::process::Command;
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
    fn into_response(self) -> Response {
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
            PeerError::Validation { detail } => (
                StatusCode::BAD_REQUEST,
                "validation_failed".to_string(),
                Some(detail),
            ),
            // everything below is a server-side failure
            // TODO: handle
            PeerError::Netlink { .. }
            | PeerError::BirdConfigIo { .. }
            | PeerError::BirdReload { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error".to_string(),
                None,
            ),
        };
        (status, Json(ErrorResponse { error, detail })).into_response()
    }
}

pub struct PeerManager {
    bird_conf_dir: PathBuf,
}

impl PeerManager {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            bird_conf_dir: dir.as_ref().to_path_buf(),
        }
    }

    // provision_peer returns our custom PeerError
    pub async fn provision_peer(
        &self,
        asn: u32,
        iface_name: &str,
        remote_ip_str: &str,
    ) -> Result<(), PeerError> {
        if asn < 4242420000 || asn > 4242423999 {
            return InvalidAsnSnafu { asn }.fail();
        }

        // 2. 数据解析转换
        // 使用 .context(...) 将底层的 AddrParseError 转换为我们定义的 InvalidIp 错误
        let _remote_ip: std::net::IpAddr = remote_ip_str
            .parse()
            .context(InvalidIpSnafu { ip: remote_ip_str })?;

        // 3. 模拟 netlink 创建网卡
        // 假如底层的 create_wg_interface 返回 std::io::Error
        self.create_wg_interface(iface_name)
            .context(NetlinkSnafu { iface_name })?;

        // 4. 生成并写入 bird 配置
        let conf_path = self.bird_conf_dir.join(format!("{}.conf", iface_name));
        let mock_conf_content = format!("# bgp config for AS{}", asn);

        std::fs::write(&conf_path, mock_conf_content)
            .context(BirdConfigIoSnafu { path: conf_path })?;

        // 5. 执行 birdc configure 命令
        let output = Command::new("birdc")
            .arg("configure")
            .output()
            // 匹配由于找不到 birdc 命令或权限不足导致的 io error
            .context(BirdConfigIoSnafu {
                path: PathBuf::from("birdc"),
            })?;

        if !output.status.success() {
            // 命令成功执行，但 bird 返回了错误状态码（如配置文件语法错误）
            // 这里没有 source error，直接构建并抛出
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            return BirdReloadSnafu { stderr }.fail();
        }

        Ok(())
    }

    // a mock function that simulates a failing netlink call
    fn create_wg_interface(&self, _iface: &str) -> std::io::Result<()> {
        // simulate a "file exists" error (e.g., interface already exists)
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "device already exists",
        ))
    }
}
