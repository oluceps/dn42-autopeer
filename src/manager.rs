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
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
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
    mutation_locks: DashMap<u32, Arc<Mutex<()>>>,
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
        pubkey: WgPubKey,
        endpoint: Option<SocketAddr>,
    ) -> Result<Peer, PeerError> {
        let operation_lock = self.operation_lock(asn);
        let _operation_guard = operation_lock.lock().await;
        if self.db.peer_exists(asn).await? {
            return Err(PeerError::AlreadyExists { asn });
        }

        let peer = {
            let _port_guard = self.port_lock.lock().await;
            self.reserve_peer(asn, pubkey, endpoint).await?
        };

        if let Err(error) = self.apply_peer(&peer).await {
            self.compensate_failed_create(&peer).await;
            return Err(error);
        }
        if !self.db.set_status(asn, PeerStatus::Active).await? {
            return Err(PeerError::NotFound { asn });
        }
        Ok(Peer {
            status: PeerStatus::Active,
            ..peer
        })
    }

    pub async fn update_peer(
        &self,
        asn: u32,
        pubkey: WgPubKey,
        endpoint: Option<Option<SocketAddr>>,
    ) -> Result<Peer, PeerError> {
        let operation_lock = self.operation_lock(asn);
        let _operation_guard = operation_lock.lock().await;
        let old_peer = self
            .db
            .get_peer(asn)
            .await?
            .ok_or(PeerError::NotFound { asn })?;
        if old_peer.status == PeerStatus::Deleting {
            return Err(PeerError::NotFound { asn });
        }

        let desired_peer = Peer {
            pubkey,
            endpoint: endpoint.unwrap_or(old_peer.endpoint),
            status: PeerStatus::Provisioning,
            ..old_peer.clone()
        };
        if !self.db.update_peer_desired(&desired_peer).await? {
            return Err(PeerError::NotFound { asn });
        }

        if let Err(error) = self.apply_peer(&desired_peer).await {
            self.compensate_failed_update(&old_peer).await;
            return Err(error);
        }
        if !self.db.set_status(asn, PeerStatus::Active).await? {
            return Err(PeerError::NotFound { asn });
        }
        Ok(Peer {
            status: PeerStatus::Active,
            ..desired_peer
        })
    }

    pub async fn delete_peer(&self, asn: u32) -> Result<(), PeerError> {
        let operation_lock = self.operation_lock(asn);
        let _operation_guard = operation_lock.lock().await;
        let peer = self
            .db
            .get_peer(asn)
            .await?
            .ok_or(PeerError::NotFound { asn })?;
        if !self.db.set_status(asn, PeerStatus::Deleting).await? {
            return Err(PeerError::NotFound { asn });
        }

        if let Err(error) = self.remove_external_state(&peer).await {
            if self.apply_peer(&peer).await.is_ok() {
                let _ = self.db.set_status(asn, PeerStatus::Active).await;
            }
            return Err(error);
        }

        // If this delete fails, the durable deleting state makes startup finish the operation.
        if !self.db.delete_peer(asn).await? {
            return Err(PeerError::NotFound { asn });
        }
        Ok(())
    }

    pub async fn recover(&self) -> Result<(), PeerError> {
        for peer in self.db.list_peers().await? {
            let operation_lock = self.operation_lock(peer.asn);
            let _operation_guard = operation_lock.lock().await;
            if peer.status == PeerStatus::Deleting {
                self.remove_external_state(&peer).await?;
                if !self.db.delete_peer(peer.asn).await? {
                    return Err(PeerError::NotFound { asn: peer.asn });
                }
                continue;
            }
            if peer.status == PeerStatus::Disabled {
                continue;
            }

            self.apply_peer(&peer).await?;
            if !self.db.set_status(peer.asn, PeerStatus::Active).await? {
                return Err(PeerError::NotFound { asn: peer.asn });
            }
        }
        Ok(())
    }

    async fn reserve_peer(
        &self,
        asn: u32,
        pubkey: WgPubKey,
        endpoint: Option<SocketAddr>,
    ) -> Result<Peer, PeerError> {
        let preferred_offset = asn % 10_000;
        for increment in 0..10_000_u32 {
            let offset = (preferred_offset + increment) % 10_000;
            let listen_port = 20_000 + offset as u16;
            if WgManager::listen_port_in_use(listen_port, None)? {
                continue;
            }

            let peer = self.build_peer(asn, pubkey.clone(), endpoint, listen_port);
            if self.db.reserve_peer(&peer).await? {
                return Ok(peer);
            }
            if self.db.peer_exists(asn).await? {
                return Err(PeerError::AlreadyExists { asn });
            }
        }
        Err(PeerError::Validation {
            detail: "No WireGuard listen port is available from 20000 through 29999".to_string(),
        })
    }

    fn build_peer(
        &self,
        asn: u32,
        pubkey: WgPubKey,
        endpoint: Option<SocketAddr>,
        listen_port: u16,
    ) -> Peer {
        Peer {
            iface_name: format!("wg{asn}"),
            asn,
            pubkey,
            endpoint,
            local_ll_ip: asn_link_local(self.local_asn),
            remote_ll_ip: asn_link_local(asn),
            status: PeerStatus::Provisioning,
            listen_port,
        }
    }

    async fn apply_peer(&self, peer: &Peer) -> Result<(), PeerError> {
        WgManager::ensure_wg_interface(&peer.iface_name).await?;
        WgManager::configure_peer(
            &peer.iface_name,
            &self.local_wg_privkey,
            peer.listen_port,
            &peer.pubkey,
            peer.endpoint,
        )?;
        WgManager::configure_local_address(&peer.iface_name, peer.local_ll_ip).await?;
        self.install_bird_config(peer).await
    }

    async fn compensate_failed_create(&self, peer: &Peer) {
        let _ = self.db.set_status(peer.asn, PeerStatus::Deleting).await;
        if self.remove_external_state(peer).await.is_ok() {
            let _ = self.db.delete_peer(peer.asn).await;
        }
    }

    async fn compensate_failed_update(&self, old_peer: &Peer) {
        if self.apply_peer(old_peer).await.is_err() {
            return;
        }
        if self.db.update_peer_desired(old_peer).await.is_ok() {
            let _ = self.db.set_status(old_peer.asn, PeerStatus::Active).await;
        }
    }

    async fn install_bird_config(&self, peer: &Peer) -> Result<(), PeerError> {
        let template = PeerTemplate {
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

    fn operation_lock(&self, asn: u32) -> Arc<Mutex<()>> {
        self.mutation_locks
            .entry(asn)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn config_path(&self, iface_name: &str) -> PathBuf {
        Path::new(&self.bird_conf_dir).join(format!("{iface_name}.conf"))
    }
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
