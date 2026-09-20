use crate::{
    error::{BirdConfigIoSnafu, PeerError},
    netlink::WgManager,
    peer::{Peer, PeerStatus},
    persist::PeerStore,
    template::PeerTemplate,
    wg_pubkey::WgPubKey,
};
use askama::Template;
use dashmap::DashMap;
use snafu::ResultExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    net::{Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixStream, lookup_host},
    sync::Mutex,
};

pub struct PeerManager {
    db: PeerStore,
    bird_conf_dir: String,
    bird_socket: String,
    local_wg_privkey: String,
    pub local_wg_pubkey: String,
    pub public_endpoint: String,
    pub local_asn: u32,
    mutation_locks: DashMap<(u32, String), Arc<Mutex<()>>>,
    port_lock: Mutex<()>,
}

impl PeerManager {
    pub fn new(
        db: PeerStore,
        bird_conf_dir: String,
        bird_socket: String,
        local_wg_privkey: String,
        local_wg_pubkey: String,
        public_endpoint: String,
        local_asn: u32,
    ) -> Self {
        Self {
            db,
            bird_conf_dir,
            bird_socket,
            local_wg_privkey,
            local_wg_pubkey,
            public_endpoint,
            local_asn,
            mutation_locks: DashMap::new(),
            port_lock: Mutex::new(()),
        }
    }

    pub async fn create_peer(
        &self,
        asn: u32,
        peer_name: String,
        pubkey: WgPubKey,
        endpoint: Option<String>,
        link_local: Option<(Ipv6Addr, Ipv6Addr)>,
    ) -> Result<Peer, PeerError> {
        let operation_lock = self.operation_lock(asn, &peer_name);
        let _operation_guard = operation_lock.lock().await;
        if self.db.peer_exists(asn, &peer_name).await? {
            return Err(PeerError::AlreadyExists { asn, peer_name });
        }

        let peer = {
            let _port_guard = self.port_lock.lock().await;
            self.reserve_peer(asn, peer_name, pubkey, endpoint, link_local)
                .await?
        };

        if let Err(error) = self.apply_peer(&peer).await {
            self.compensate_failed_create(&peer).await;
            return Err(error);
        }
        if !self.db.set_status(peer.peer_id, PeerStatus::Active).await? {
            return Err(PeerError::NotFound {
                asn,
                peer_name: peer.peer_name,
            });
        }
        Ok(Peer {
            status: PeerStatus::Active,
            ..peer
        })
    }

    pub async fn update_peer(
        &self,
        asn: u32,
        peer_name: String,
        pubkey: WgPubKey,
        endpoint: Option<Option<String>>,
        link_local: Option<(Ipv6Addr, Ipv6Addr)>,
    ) -> Result<Peer, PeerError> {
        let operation_lock = self.operation_lock(asn, &peer_name);
        let _operation_guard = operation_lock.lock().await;
        let old_peer =
            self.db
                .get_peer(asn, &peer_name)
                .await?
                .ok_or_else(|| PeerError::NotFound {
                    asn,
                    peer_name: peer_name.clone(),
                })?;
        if old_peer.status == PeerStatus::Deleting {
            return Err(PeerError::NotFound { asn, peer_name });
        }

        let desired_peer = Peer {
            pubkey,
            endpoint: endpoint.unwrap_or_else(|| old_peer.endpoint.clone()),
            local_ll_ip: link_local.map_or_else(|| asn_link_local(self.local_asn), |value| value.0),
            remote_ll_ip: link_local.map_or_else(|| asn_link_local(asn), |value| value.1),
            status: PeerStatus::Provisioning,
            ..old_peer.clone()
        };
        if !self.db.update_peer_desired(&desired_peer).await? {
            return Err(PeerError::NotFound { asn, peer_name });
        }

        if let Err(error) = self.apply_peer(&desired_peer).await {
            self.compensate_failed_update(&old_peer).await;
            return Err(error);
        }
        if !self
            .db
            .set_status(desired_peer.peer_id, PeerStatus::Active)
            .await?
        {
            return Err(PeerError::NotFound { asn, peer_name });
        }
        Ok(Peer {
            status: PeerStatus::Active,
            ..desired_peer
        })
    }

    pub async fn delete_peer(&self, asn: u32, peer_name: String) -> Result<Peer, PeerError> {
        let operation_lock = self.operation_lock(asn, &peer_name);
        let _operation_guard = operation_lock.lock().await;
        let peer = self
            .db
            .get_peer(asn, &peer_name)
            .await?
            .ok_or_else(|| PeerError::NotFound {
                asn,
                peer_name: peer_name.clone(),
            })?;
        if !self
            .db
            .set_status(peer.peer_id, PeerStatus::Deleting)
            .await?
        {
            return Err(PeerError::NotFound { asn, peer_name });
        }

        if let Err(error) = self.remove_external_state(&peer).await {
            if self.apply_peer(&peer).await.is_ok() {
                let _ = self.db.set_status(peer.peer_id, PeerStatus::Active).await;
            }
            return Err(error);
        }

        // If this delete fails, the durable deleting state makes startup finish the operation.
        if !self.db.delete_peer(peer.peer_id).await? {
            return Err(PeerError::NotFound { asn, peer_name });
        }
        Ok(peer)
    }

    pub async fn recover(&self) -> Result<(), PeerError> {
        let peers = self.db.list_peers().await?;

        for peer in peers.iter().filter(|peer| {
            peer.status != PeerStatus::Deleting && peer.status != PeerStatus::Disabled
        }) {
            self.apply_wireguard(peer).await?;
        }

        for peer in peers
            .iter()
            .filter(|peer| peer.status == PeerStatus::Deleting)
        {
            let operation_lock = self.operation_lock(peer.asn, &peer.peer_name);
            let _operation_guard = operation_lock.lock().await;
            self.remove_external_state(peer).await?;
            if !self.db.delete_peer(peer.peer_id).await? {
                return Err(PeerError::NotFound {
                    asn: peer.asn,
                    peer_name: peer.peer_name.clone(),
                });
            }
        }

        for peer in peers.iter().filter(|peer| {
            peer.status != PeerStatus::Deleting && peer.status != PeerStatus::Disabled
        }) {
            let operation_lock = self.operation_lock(peer.asn, &peer.peer_name);
            let _operation_guard = operation_lock.lock().await;
            self.install_bird_config(peer).await?;
            if !self.db.set_status(peer.peer_id, PeerStatus::Active).await? {
                return Err(PeerError::NotFound {
                    asn: peer.asn,
                    peer_name: peer.peer_name.clone(),
                });
            }
        }
        Ok(())
    }

    async fn reserve_peer(
        &self,
        asn: u32,
        peer_name: String,
        pubkey: WgPubKey,
        endpoint: Option<String>,
        link_local: Option<(Ipv6Addr, Ipv6Addr)>,
    ) -> Result<Peer, PeerError> {
        let peer_id = self.db.allocate_peer_id().await?;
        let preferred_offset = asn % 10_000;
        let link_local =
            link_local.unwrap_or_else(|| (asn_link_local(self.local_asn), asn_link_local(asn)));
        for increment in 0..10_000_u32 {
            let offset = (preferred_offset + increment) % 10_000;
            let listen_port = 20_000 + offset as u16;
            if WgManager::listen_port_in_use(listen_port, None)? {
                continue;
            }

            let peer = Self::build_peer(
                peer_id,
                asn,
                peer_name.clone(),
                pubkey.clone(),
                endpoint.clone(),
                link_local,
                listen_port,
            );
            if self.db.reserve_peer(&peer).await? {
                return Ok(peer);
            }
            if self.db.peer_exists(asn, &peer_name).await? {
                return Err(PeerError::AlreadyExists { asn, peer_name });
            }
        }
        Err(PeerError::Validation {
            detail: "No WireGuard listen port is available from 20000 through 29999".to_string(),
        })
    }

    fn build_peer(
        peer_id: u32,
        asn: u32,
        peer_name: String,
        pubkey: WgPubKey,
        endpoint: Option<String>,
        link_local: (Ipv6Addr, Ipv6Addr),
        listen_port: u16,
    ) -> Peer {
        Peer {
            peer_id,
            peer_name,
            iface_name: format!("wgp{peer_id}"),
            asn,
            pubkey,
            endpoint,
            local_ll_ip: link_local.0,
            remote_ll_ip: link_local.1,
            status: PeerStatus::Provisioning,
            listen_port,
        }
    }

    async fn apply_peer(&self, peer: &Peer) -> Result<(), PeerError> {
        self.apply_wireguard(peer).await?;
        self.install_bird_config(peer).await
    }

    async fn apply_wireguard(&self, peer: &Peer) -> Result<(), PeerError> {
        WgManager::ensure_wg_interface(&peer.iface_name).await?;
        let endpoint = match peer.endpoint.as_deref() {
            Some(endpoint) => Some(resolve_endpoint(endpoint).await?),
            None => None,
        };
        WgManager::configure_peer(
            &peer.iface_name,
            &self.local_wg_privkey,
            peer.listen_port,
            &peer.pubkey,
            endpoint,
        )?;
        WgManager::configure_local_address(&peer.iface_name, peer.local_ll_ip).await?;
        Ok(())
    }

    async fn compensate_failed_create(&self, peer: &Peer) {
        let _ = self.db.set_status(peer.peer_id, PeerStatus::Deleting).await;
        if self.remove_external_state(peer).await.is_ok() {
            let _ = self.db.delete_peer(peer.peer_id).await;
        }
    }

    async fn compensate_failed_update(&self, old_peer: &Peer) {
        if self.apply_peer(old_peer).await.is_err() {
            return;
        }
        if self.db.update_peer_desired(old_peer).await.is_ok() {
            let _ = self
                .db
                .set_status(old_peer.peer_id, PeerStatus::Active)
                .await;
        }
    }

    async fn install_bird_config(&self, peer: &Peer) -> Result<(), PeerError> {
        let template = PeerTemplate {
            peer_id: peer.peer_id,
            peer_name: &peer.peer_name,
            asn: peer.asn,
            local_asn: self.local_asn,
            iface: &peer.iface_name,
            local_ll_ip: peer.local_ll_ip,
            remote_ll_ip: peer.remote_ll_ip,
        };
        let content = template.render().map_err(|error| PeerError::BirdReload {
            stderr: format!("Failed to render the BIRD configuration: {error}"),
        })?;
        let path = self.config_path(&peer.iface_name);
        let old_content = read_optional(&path).await?;
        self.write_atomic(&path, content.as_bytes()).await?;

        if let Err(reload_error) = self.reload_bird().await {
            let restore_result = match old_content {
                Some(old_content) => self.write_atomic(&path, &old_content).await,
                None => remove_optional(&path).await,
            };
            if let Err(restore_error) = restore_result {
                return Err(PeerError::BirdReload {
                    stderr: format!(
                        "{reload_error}. The previous configuration could not be restored: {restore_error}"
                    ),
                });
            }
            let _ = self.reload_bird().await;
            return Err(reload_error);
        }
        Ok(())
    }

    async fn remove_external_state(&self, peer: &Peer) -> Result<(), PeerError> {
        let path = self.config_path(&peer.iface_name);
        let old_content = read_optional(&path).await?;
        remove_optional(&path).await?;
        if let Err(reload_error) = self.reload_bird().await {
            if let Some(content) = old_content {
                self.write_atomic(&path, &content).await?;
                let _ = self.reload_bird().await;
            }
            return Err(reload_error);
        }

        if let Err(netlink_error) = WgManager::delete_interface(&peer.iface_name).await {
            // Rebuild both external components before the caller restores the active state.
            let _ = self.apply_peer(peer).await;
            return Err(netlink_error);
        }
        Ok(())
    }

    async fn write_atomic(&self, path: &Path, content: &[u8]) -> Result<(), PeerError> {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("peer.conf");
        let temporary_path = path.with_file_name(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            unique_suffix()
        ));
        let directory_mode = tokio::fs::metadata(&self.bird_conf_dir)
            .await
            .map(|metadata| {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o666
            })
            .context(BirdConfigIoSnafu {
                path: PathBuf::from(&self.bird_conf_dir),
            })?;

        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(directory_mode);
        let mut file = options
            .open(&temporary_path)
            .await
            .context(BirdConfigIoSnafu {
                path: temporary_path.clone(),
            })?;
        file.write_all(content).await.context(BirdConfigIoSnafu {
            path: temporary_path.clone(),
        })?;
        file.flush().await.context(BirdConfigIoSnafu {
            path: temporary_path.clone(),
        })?;
        file.sync_all().await.context(BirdConfigIoSnafu {
            path: temporary_path.clone(),
        })?;
        #[cfg(unix)]
        file.set_permissions(std::fs::Permissions::from_mode(directory_mode))
            .await
            .context(BirdConfigIoSnafu {
                path: temporary_path.clone(),
            })?;
        drop(file);
        tokio::fs::rename(&temporary_path, path)
            .await
            .context(BirdConfigIoSnafu {
                path: path.to_path_buf(),
            })?;
        Ok(())
    }

    async fn reload_bird(&self) -> Result<(), PeerError> {
        #[cfg(debug_assertions)]
        if std::env::var("MOCK_BIRD").is_ok() {
            return Ok(());
        }

        match tokio::time::timeout(Duration::from_secs(10), self.reload_bird_inner()).await {
            Ok(result) => result,
            Err(_) => Err(PeerError::BirdReload {
                stderr: "BIRD did not respond within 10 seconds".to_string(),
            }),
        }
    }

    async fn reload_bird_inner(&self) -> Result<(), PeerError> {
        let mut stream = UnixStream::connect(&self.bird_socket)
            .await
            .map_err(|source| PeerError::BirdConfigIo {
                source,
                path: PathBuf::from(&self.bird_socket),
            })?;
        let (read_half, mut write_half) = stream.split();
        let mut reader = BufReader::new(read_half);
        let mut line = Vec::new();

        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line).await.unwrap_or(0) == 0 {
                return Err(PeerError::BirdReload {
                    stderr: "The BIRD socket closed before it sent the banner".to_string(),
                });
            }
            if line.len() >= 5 && line[4] == b' ' {
                break;
            }
        }

        write_half
            .write_all(b"configure soft\n")
            .await
            .map_err(|source| PeerError::BirdConfigIo {
                source,
                path: PathBuf::from(&self.bird_socket),
            })?;

        let mut output = String::new();
        loop {
            line.clear();
            let count = reader.read_until(b'\n', &mut line).await.map_err(|error| {
                PeerError::BirdReload {
                    stderr: format!("BIRD socket read failed: {error}. Output: {output}"),
                }
            })?;
            if count == 0 {
                return Err(PeerError::BirdReload {
                    stderr: format!("The BIRD socket closed early. Output: {}", output.trim()),
                });
            }

            output.push_str(&String::from_utf8_lossy(&line));
            if line.len() >= 5 && line[4] == b' ' {
                let code = &line[0..4];
                if code.starts_with(b"8") || code.starts_with(b"9") {
                    return Err(PeerError::BirdReload {
                        stderr: output.trim().to_string(),
                    });
                }
                return Ok(());
            }
        }
    }

    fn operation_lock(&self, asn: u32, peer_name: &str) -> Arc<Mutex<()>> {
        self.mutation_locks
            .entry((asn, peer_name.to_string()))
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn config_path(&self, iface_name: &str) -> PathBuf {
        Path::new(&self.bird_conf_dir).join(format!("{iface_name}.conf"))
    }
}

async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr, PeerError> {
    let addresses = tokio::time::timeout(Duration::from_secs(5), lookup_host(endpoint))
        .await
        .map_err(|_| PeerError::Validation {
            detail: format!("DNS lookup timed out for endpoint {endpoint}"),
        })?
        .map_err(|_| PeerError::Validation {
            detail: format!("DNS lookup failed for endpoint {endpoint}"),
        })?;
    addresses
        .into_iter()
        .next()
        .ok_or_else(|| PeerError::Validation {
            detail: format!("DNS lookup returned no addresses for endpoint {endpoint}"),
        })
}

fn asn_link_local(asn: u32) -> Ipv6Addr {
    Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        0,
        0,
        (asn >> 16) as u16,
        (asn & 0xffff) as u16,
    )
}

async fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, PeerError> {
    match tokio::fs::read(path).await {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(PeerError::BirdConfigIo {
            source,
            path: path.to_path_buf(),
        }),
    }
}

async fn remove_optional(path: &Path) -> Result<(), PeerError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PeerError::BirdConfigIo {
            source,
            path: path.to_path_buf(),
        }),
    }
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
