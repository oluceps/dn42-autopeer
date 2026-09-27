use crate::error::{NetlinkSnafu, PeerError};
use crate::wg_pubkey::WgPubKey;
use futures::StreamExt;
use rtnetlink::{
    Handle, LinkUnspec, LinkWireguard, new_connection,
    packet_core::{DefaultNla, Emitable, NLA_F_NESTED},
    packet_route::link::{AfSpecInet, AfSpecUnspec, LinkAttribute, LinkMessage},
};
use snafu::ResultExt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

pub struct WgManager;

impl WgManager {
    pub async fn ensure_wg_interface(
        iface_name: &str,
        peer_id: u32,
        mtu: u16,
    ) -> Result<(), PeerError> {
        #[cfg(debug_assertions)]
        if std::env::var("MOCK_NETLINK").is_ok() {
            return Ok(());
        }

        let (connection, handle, _) = new_connection()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        tokio::spawn(connection);

        let existing = find_link(&handle, iface_name).await?;

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

        let link = find_link(&handle, iface_name)
            .await?
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
            .set(
                LinkUnspec::new_with_index(link.header.index)
                    .mtu(mtu as u32)
                    .alias(format!("dn42-autopeer:{peer_id}"))
                    .append_extra_attribute(disable_rp_filter_attribute())
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        Ok(())
    }

    pub async fn list_managed_interfaces() -> Result<Vec<String>, PeerError> {
        #[cfg(debug_assertions)]
        if std::env::var("MOCK_NETLINK").is_ok() {
            return Ok(Vec::new());
        }

        let (connection, handle, _) =
            new_connection()
                .map_err(std::io::Error::other)
                .context(NetlinkSnafu {
                    iface_name: "all managed interfaces",
                })?;
        tokio::spawn(connection);

        let mut links = handle.link().get().execute();
        let mut names = Vec::new();
        while let Some(link) = links.next().await {
            let link = link.map_err(std::io::Error::other).context(NetlinkSnafu {
                iface_name: "all managed interfaces",
            })?;
            let is_managed = link.attributes.iter().any(|attribute| {
                matches!(attribute, LinkAttribute::IfAlias(alias) if alias.starts_with("dn42-autopeer:"))
            });
            if !is_managed {
                continue;
            }
            if let Some(name) = link
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::IfName(name) => Some(name.clone()),
                    _ => None,
                })
            {
                names.push(name);
            }
        }
        Ok(names)
    }

    pub async fn configure_local_address(
        iface_name: &str,
        address: Ipv6Addr,
    ) -> Result<(), PeerError> {
        #[cfg(debug_assertions)]
        if std::env::var("MOCK_NETLINK").is_ok() {
            return Ok(());
        }

        let (connection, handle, _) = new_connection()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        tokio::spawn(connection);

        let link = find_link(&handle, iface_name)
            .await?
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
        #[cfg(debug_assertions)]
        if std::env::var("MOCK_NETLINK").is_ok() {
            return Ok(());
        }

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
        #[cfg(debug_assertions)]
        if std::env::var("MOCK_NETLINK").is_ok() {
            return Ok(false);
        }

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
        #[cfg(debug_assertions)]
        if std::env::var("MOCK_NETLINK").is_ok() {
            return Ok(());
        }

        let (connection, handle, _) = new_connection()
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        tokio::spawn(connection);

        match find_link(&handle, iface_name).await? {
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

fn disable_rp_filter_attribute() -> LinkAttribute {
    const IFLA_INET_CONF: u16 = 1;
    const IPV4_DEVCONF_RP_FILTER: u16 = 8;

    let rp_filter = DefaultNla::new(IPV4_DEVCONF_RP_FILTER, 0_u32.to_ne_bytes().to_vec());
    let mut devconf = vec![0; rp_filter.buffer_len()];
    rp_filter.emit(&mut devconf);

    LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet(vec![AfSpecInet::Other(
        DefaultNla::new(IFLA_INET_CONF | NLA_F_NESTED, devconf),
    )])])
}

async fn find_link(handle: &Handle, iface_name: &str) -> Result<Option<LinkMessage>, PeerError> {
    let mut links = handle.link().get().execute();
    while let Some(link) = links.next().await {
        let link = link
            .map_err(std::io::Error::other)
            .context(NetlinkSnafu { iface_name })?;
        if link
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, LinkAttribute::IfName(name) if name == iface_name))
        {
            return Ok(Some(link));
        }
    }
    Ok(None)
}

fn parse_interface_name(iface_name: &str) -> Result<InterfaceName, PeerError> {
    InterfaceName::from_str(iface_name).map_err(|_| PeerError::Validation {
        detail: "The interface name is invalid".to_string(),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rtnetlink::packet_core::Nla;

    #[test]
    fn rp_filter_update_encodes_an_explicit_zero() {
        let LinkAttribute::AfSpecUnspec(families) = disable_rp_filter_attribute() else {
            panic!("expected an AF_SPEC attribute");
        };
        let AfSpecUnspec::Inet(settings) = &families[0] else {
            panic!("expected an IPv4 setting");
        };
        let AfSpecInet::Other(devconf) = &settings[0] else {
            panic!("expected a nested IPv4 devconf setting");
        };

        assert_eq!(devconf.kind(), 1 | NLA_F_NESTED);
        let mut encoded = vec![0; devconf.value_len()];
        devconf.emit_value(&mut encoded);
        assert_eq!(
            encoded,
            [8, 0, 8, 0, 0, 0, 0, 0],
            "the nested rp_filter value must include an explicit zero"
        );
    }

    #[tokio::test]
    #[ignore = "requires access to the host Netlink socket"]
    async fn link_dump_distinguishes_existing_and_missing_interfaces() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);

        assert!(find_link(&handle, "lo").await.unwrap().is_some());
        assert!(
            find_link(&handle, "missing-autopeer-link")
                .await
                .unwrap()
                .is_none()
        );
    }
}
