use crate::error::{NetlinkSnafu, PeerError};
use crate::wg_pubkey::WgPubKey;
use rtnetlink::{LinkUnspec, LinkWireguard, new_connection};
use snafu::ResultExt;
use std::net::SocketAddr;
use std::str::FromStr;
use wireguard_control::{Backend, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

pub struct WgManager;

impl WgManager {
    pub async fn ensure_wg_interface(iface_name: &str) -> Result<(), PeerError> {
        let (connection, handle, _) = new_connection()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        tokio::spawn(connection);

        // Check if interface exists
        let mut links = handle
            .link()
            .get()
            .match_name(iface_name.to_string())
            .execute();
        use futures::StreamExt;
        if links.next().await.is_some() {
            // Already exists
            return Ok(());
        }

        // Create wireguard interface
        handle
            .link()
            .add(LinkWireguard::new(iface_name).build())
            .execute()
            .await
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;

        // Bring interface up
        let mut links = handle
            .link()
            .get()
            .match_name(iface_name.to_string())
            .execute();
        if let Some(link) = links.next().await {
            let link = link
                .map_err(std::io::Error::other)
                .context(NetlinkSnafu { iface_name })?;
            handle
                .link()
                .set(LinkUnspec::new_with_index(link.header.index).up().build())
                .execute()
                .await
                .map_err(std::io::Error::other)
                .context(NetlinkSnafu { iface_name })?;
        }

        Ok(())
    }

    pub fn configure_peer(
        iface_name: &str,
        private_key: &str,
        listen_port: u16,
        peer_pubkey: &WgPubKey,
        endpoint: Option<SocketAddr>,
    ) -> Result<(), PeerError> {
        let priv_key = Key::from_base64(private_key).map_err(|_| PeerError::Validation {
            detail: "Invalid local private key".to_string(),
        })?;
        let peer_key =
            Key::from_base64(peer_pubkey.as_str()).map_err(|_| PeerError::Validation {
                detail: "Invalid peer public key".to_string(),
            })?;

        let mut peer_config = PeerConfigBuilder::new(&peer_key);
        if let Some(ep) = endpoint {
            peer_config = peer_config.set_endpoint(ep);
        }

        peer_config = peer_config.add_allowed_ip("fe80::".parse().unwrap(), 64);
        peer_config = peer_config.add_allowed_ip("::".parse().unwrap(), 0);
        peer_config = peer_config.add_allowed_ip("0.0.0.0".parse().unwrap(), 0);

        let interface_name =
            InterfaceName::from_str(iface_name).map_err(|_| PeerError::Validation {
                detail: "Invalid interface name".to_string(),
            })?;

        DeviceUpdate::new()
            .set_private_key(priv_key)
            .set_listen_port(listen_port)
            .add_peer(peer_config)
            .apply(&interface_name, Backend::Kernel)
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;

        Ok(())
    }
}
