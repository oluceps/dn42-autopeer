use crate::error::{NetlinkSnafu, PeerError};
use crate::wg_pubkey::WgPubKey;
use futures::StreamExt;
use rtnetlink::{LinkUnspec, LinkWireguard, new_connection};
use snafu::ResultExt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

pub struct WgManager;

impl WgManager {
    pub async fn ensure_wg_interface(iface_name: &str) -> Result<(), PeerError> {
        let (connection, handle, _) = new_connection()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        tokio::spawn(connection);

        let mut links = handle
            .link()
            .get()
            .match_name(iface_name.to_string())
            .execute();
        let existing = links
            .next()
            .await
            .transpose()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;

        if existing.is_none() {
            handle
                .link()
                .add(LinkWireguard::new(iface_name).build())
                .execute()
                .await
                .map_err(std::io::Error::other)
                .context(NetlinkSnafu { iface_name })?;
        } else {
            let interface_name = parse_interface_name(iface_name)?;
            Device::get(&interface_name, Backend::Kernel).context(NetlinkSnafu { iface_name })?;
        }

        let mut links = handle
            .link()
            .get()
            .match_name(iface_name.to_string())
            .execute();
        let link = links
            .next()
            .await
            .transpose()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?
            .ok_or_else(|| PeerError::Netlink {
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "The interface disappeared after creation",
                ),
                iface_name: iface_name.to_string(),
            })?;

        // Apply the up state on every call. This repairs a partial earlier attempt.
        handle
            .link()
            .set(LinkUnspec::new_with_index(link.header.index).up().build())
            .execute()
            .await
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        Ok(())
    }

    pub async fn configure_local_address(
        iface_name: &str,
        address: Ipv6Addr,
    ) -> Result<(), PeerError> {
        let (connection, handle, _) = new_connection()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        tokio::spawn(connection);

        let mut links = handle
            .link()
            .get()
            .match_name(iface_name.to_string())
            .execute();
        let link = links
            .next()
            .await
            .transpose()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?
            .ok_or_else(|| PeerError::Netlink {
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "Interface not found"),
                iface_name: iface_name.to_string(),
            })?;

        handle
            .address()
            .add(link.header.index, IpAddr::V6(address), 64)
            .replace()
            .execute()
            .await
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
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
            detail: "The local WireGuard private key is invalid".to_string(),
        })?;
        let peer_key =
            Key::from_base64(peer_pubkey.as_str()).map_err(|_| PeerError::Validation {
                detail: "The peer WireGuard public key is invalid".to_string(),
            })?;

        let mut peer_config = PeerConfigBuilder::new(&peer_key);
        if let Some(endpoint) = endpoint {
            peer_config = peer_config.set_endpoint(endpoint);
        }

        // WireGuard uses AllowedIPs as its cryptographic address selector. This service does not
        // install routes. The peer receives the full DN42 address space for route-server use.
        peer_config = peer_config.add_allowed_ip("fe80::".parse().unwrap(), 64);
        peer_config = peer_config.add_allowed_ip("::".parse().unwrap(), 0);
        peer_config = peer_config.add_allowed_ip("0.0.0.0".parse().unwrap(), 0);

        let interface_name = parse_interface_name(iface_name)?;
        DeviceUpdate::new()
            .set_private_key(priv_key)
            .set_listen_port(listen_port)
            .replace_peers()
            .add_peer(peer_config)
            .apply(&interface_name, Backend::Kernel)
            .context(NetlinkSnafu { iface_name })?;
        Ok(())
    }

    pub fn listen_port_in_use(port: u16, except_iface: Option<&str>) -> Result<bool, PeerError> {
        for interface_name in Device::list(Backend::Kernel).context(NetlinkSnafu {
            iface_name: "all WireGuard interfaces",
        })? {
            if except_iface == Some(interface_name.as_str_lossy().as_ref()) {
                continue;
            }
            let device = Device::get(&interface_name, Backend::Kernel).context(NetlinkSnafu {
                iface_name: interface_name.as_str_lossy().as_ref(),
            })?;
            if device.listen_port == Some(port) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn delete_interface(iface_name: &str) -> Result<(), PeerError> {
        let (connection, handle, _) = new_connection()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        tokio::spawn(connection);

        let mut links = handle
            .link()
            .get()
            .match_name(iface_name.to_string())
            .execute();
        match links
            .next()
            .await
            .transpose()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?
        {
            Some(link) => handle
                .link()
                .del(link.header.index)
                .execute()
                .await
                .map_err(std::io::Error::other)
                .context(NetlinkSnafu { iface_name }),
            None => Ok(()),
        }
    }
}

fn parse_interface_name(iface_name: &str) -> Result<InterfaceName, PeerError> {
    InterfaceName::from_str(iface_name).map_err(|_| PeerError::Validation {
        detail: "The interface name is invalid".to_string(),
    })
}
