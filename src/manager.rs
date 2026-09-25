use crate::{
    error::{BirdConfigIoSnafu, PeerError},
    netlink::WgManager,
    peer::{Peer, PeerStatus},
    persist::{PeerChange, PeerStore},
    template::PeerTemplate,
    wg_pubkey::WgPubKey,
};
use askama::Template;
use dashmap::DashMap;
use snafu::ResultExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, HashSet},
    net::{Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixStream, lookup_host},
    process::Command,
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
    nft_sync_lock: Mutex<()>,
    bird_sync_lock: Mutex<()>,
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
            nft_sync_lock: Mutex::new(()),
            bird_sync_lock: Mutex::new(()),
        }
    }

    pub async fn create_peer(
        &self,
        asn: u32,
        peer_name: String,
        pubkey: WgPubKey,
        endpoint: Option<String>,
        link_local: Option<(Ipv6Addr, Ipv6Addr)>,
        mtu: Option<u16>,
    ) -> Result<Peer, PeerError> {
        let operation_lock = self.operation_lock(asn, &peer_name);
        let _operation_guard = operation_lock.lock().await;
        if self.db.peer_exists(asn, &peer_name).await? {
            return Err(PeerError::AlreadyExists { asn, peer_name });
        }

        let peer = {
            let _port_guard = self.port_lock.lock().await;
            self.reserve_peer(
                asn,
                peer_name,
                pubkey,
                endpoint,
                link_local,
                mtu.unwrap_or(1420),
            )
            .await?
        };

        if let Err(error) = self.apply_peer(&peer).await {
            self.compensate_failed_create(&peer).await;
            return Err(error);
        }
        if let Err(error) = self.sync_nft_ports().await {
            self.compensate_failed_create(&peer).await;
            return Err(error);
        }
        match self.db.set_status(peer.peer_id, PeerStatus::Active).await {
            Ok(true) => {}
            Ok(false) => {
                self.compensate_failed_create(&peer).await;
                return Err(PeerError::NotFound {
                    asn,
                    peer_name: peer.peer_name,
                });
            }
            Err(error) => {
                self.compensate_failed_create(&peer).await;
                return Err(error);
            }
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
        mtu: Option<Option<u16>>,
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
            mtu: mtu.unwrap_or(Some(old_peer.mtu)).unwrap_or(1420),
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

    pub async fn get_peer_infos_by_asn(
        &self,
        asn: u32,
    ) -> Result<Vec<crate::handle::PeerInfo>, PeerError> {
        self.db.get_peer_infos_by_asn(asn).await
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

        if let Err(error) = self.sync_nft_ports().await {
            let _ = self.db.set_status(peer.peer_id, PeerStatus::Active).await;
            return Err(error);
        }

        if let Err(error) = self.remove_external_state(&peer).await {
            if self
                .db
                .set_status(peer.peer_id, PeerStatus::Active)
                .await
                .is_ok()
                && self.apply_peer(&peer).await.is_ok()
            {
                let _ = self.sync_nft_ports().await;
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
        let desired = peers
            .iter()
            .filter(|peer| {
                peer.status != PeerStatus::Deleting && peer.status != PeerStatus::Disabled
            })
            .collect::<Vec<_>>();

        for peer in &desired {
            self.apply_wireguard(peer).await?;
        }

        self.sync_nft_ports_for(&peers).await?;
        self.sync_bird_configs_for(&peers, true).await?;

        for peer in peers.iter().filter(|peer| {
            peer.status == PeerStatus::Deleting || peer.status == PeerStatus::Disabled
        }) {
            let operation_lock = self.operation_lock(peer.asn, &peer.peer_name);
            let _operation_guard = operation_lock.lock().await;
            WgManager::delete_interface(&peer.iface_name).await?;
        }

        let desired_interfaces = desired
            .iter()
            .map(|peer| peer.iface_name.as_str())
            .collect::<HashSet<_>>();
        for iface_name in WgManager::list_managed_interfaces().await? {
            if !desired_interfaces.contains(iface_name.as_str()) {
                WgManager::delete_interface(&iface_name).await?;
            }
        }

        for change in self.db.list_peer_changes().await? {
            if change.operation == "DELETE"
                && self.db.get_peer_by_id(change.peer.peer_id).await?.is_none()
                && change.peer.iface_name == format!("wgp{}", change.peer.peer_id)
            {
                WgManager::delete_interface(&change.peer.iface_name).await?;
            }
        }

        for peer in peers
            .iter()
            .filter(|peer| peer.status == PeerStatus::Deleting)
        {
            if !self.db.delete_peer(peer.peer_id).await? {
                return Err(PeerError::NotFound {
                    asn: peer.asn,
                    peer_name: peer.peer_name.clone(),
                });
            }
        }

        for peer in desired {
            let operation_lock = self.operation_lock(peer.asn, &peer.peer_name);
            let _operation_guard = operation_lock.lock().await;
            if !self.db.set_status(peer.peer_id, PeerStatus::Active).await? {
                return Err(PeerError::NotFound {
                    asn: peer.asn,
                    peer_name: peer.peer_name.clone(),
                });
            }
        }
        Ok(())
    }

    pub async fn sync_pending_peer_changes(&self) -> Result<(), PeerError> {
        let changes = self.db.list_peer_changes().await?;
        let mut first_error = None;

        for change in changes {
            match self.apply_peer_change(&change).await {
                Ok(()) => match self.db.delete_peer_change(change.event_id).await {
                    Ok(true) => {}
                    Ok(false) => {}
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                },
                Err(error) => {
                    eprintln!(
                        "Could not apply durable peer change {} ({}) for peer {}: {}",
                        change.event_id, change.operation, change.peer.peer_name, error
                    );
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn apply_peer_change(&self, change: &PeerChange) -> Result<(), PeerError> {
        let snapshot = &change.peer;
        let operation_lock = self.operation_lock(snapshot.asn, &snapshot.peer_name);
        let _operation_guard = operation_lock.lock().await;

        match self.db.get_peer_by_id(snapshot.peer_id).await? {
            Some(peer) => {
                if peer.status != PeerStatus::Deleting && peer.status != PeerStatus::Disabled {
                    self.apply_peer(&peer).await?;
                    if peer.status != PeerStatus::Active
                        && !self.db.set_status(peer.peer_id, PeerStatus::Active).await?
                    {
                        return Err(PeerError::NotFound {
                            asn: peer.asn,
                            peer_name: peer.peer_name,
                        });
                    }
                } else if peer.status == PeerStatus::Deleting {
                    self.remove_external_state(&peer).await?;
                    if !self.db.delete_peer(peer.peer_id).await? {
                        return Err(PeerError::NotFound {
                            asn: peer.asn,
                            peer_name: peer.peer_name,
                        });
                    }
                } else {
                    self.remove_external_state(&peer).await?;
                }
            }
            None => {
                self.remove_external_state(snapshot).await?;
            }
        }
        self.sync_nft_ports().await?;
        Ok(())
    }

    pub async fn sync_nft_ports(&self) -> Result<(), PeerError> {
        let peers = self.db.list_peers().await?;
        self.sync_nft_ports_for(&peers).await
    }

    async fn sync_nft_ports_for(&self, peers: &[Peer]) -> Result<(), PeerError> {
        let _guard = self.nft_sync_lock.lock().await;
        let mut ports = peers
            .iter()
            .filter(|peer| {
                peer.status != PeerStatus::Deleting && peer.status != PeerStatus::Disabled
            })
            .map(|peer| peer.listen_port)
            .collect::<Vec<_>>();
        ports.sort_unstable();
        ports.dedup();
        run_nft_batch(&nft_port_batch(&ports)).await
    }

    async fn reserve_peer(
        &self,
        asn: u32,
        peer_name: String,
        pubkey: WgPubKey,
        endpoint: Option<String>,
        link_local: Option<(Ipv6Addr, Ipv6Addr)>,
        mtu: u16,
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
                mtu,
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

    #[allow(clippy::too_many_arguments)]
    fn build_peer(
        peer_id: u32,
        asn: u32,
        peer_name: String,
        pubkey: WgPubKey,
        endpoint: Option<String>,
        link_local: (Ipv6Addr, Ipv6Addr),
        listen_port: u16,
        mtu: u16,
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
            mtu,
        }
    }

    async fn apply_peer(&self, peer: &Peer) -> Result<(), PeerError> {
        self.apply_wireguard(peer).await?;
        self.sync_bird_configs().await
    }

    async fn apply_wireguard(&self, peer: &Peer) -> Result<(), PeerError> {
        WgManager::ensure_wg_interface(&peer.iface_name, peer.peer_id, peer.mtu).await?;
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
        let _ = self.sync_nft_ports().await;
    }

    async fn compensate_failed_update(&self, old_peer: &Peer) {
        if self.db.update_peer_desired(old_peer).await.is_err() {
            return;
        }
        if self.apply_peer(old_peer).await.is_ok() {
            let _ = self
                .db
                .set_status(old_peer.peer_id, PeerStatus::Active)
                .await;
        }
    }

    async fn remove_external_state(&self, peer: &Peer) -> Result<(), PeerError> {
        self.sync_bird_configs().await?;
        WgManager::delete_interface(&peer.iface_name).await
    }

    async fn sync_bird_configs(&self) -> Result<(), PeerError> {
        let peers = self.db.list_peers().await?;
        self.sync_bird_configs_for(&peers, false).await
    }

    async fn sync_bird_configs_for(
        &self,
        peers: &[Peer],
        force_reload: bool,
    ) -> Result<(), PeerError> {
        let _guard = self.bird_sync_lock.lock().await;
        self.ensure_bird_layout().await?;

        let mut desired = BTreeMap::new();
        for peer in peers.iter().filter(|peer| {
            peer.status != PeerStatus::Deleting && peer.status != PeerStatus::Disabled
        }) {
            if peer.iface_name != format!("wgp{}", peer.peer_id) {
                return Err(PeerError::Validation {
                    detail: format!(
                        "The database contains an invalid interface name for peer {}",
                        peer.peer_id
                    ),
                });
            }
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
            desired.insert(format!("{}.conf", peer.iface_name), content.into_bytes());
        }

        if self.current_generation_matches(&desired).await? {
            return if force_reload {
                self.reload_bird().await
            } else {
                Ok(())
            };
        }

        let generation_name = format!("generation-{}", unique_suffix());
        let generation_path = self.generations_path().join(&generation_name);
        tokio::fs::create_dir(&generation_path)
            .await
            .context(BirdConfigIoSnafu {
                path: generation_path.clone(),
            })?;
        self.set_directory_mode(&generation_path).await?;
        for (file_name, content) in &desired {
            self.write_atomic(&generation_path.join(file_name), content)
                .await?;
        }
        sync_directory(&generation_path).await?;

        let current_path = self.current_path();
        let old_target = tokio::fs::read_link(&current_path).await.ok();
        self.switch_current(Path::new("generations").join(&generation_name))
            .await?;

        if let Err(reload_error) = self.reload_bird().await {
            let restore_result = match old_target {
                Some(target) => self.switch_current(target).await,
                None => remove_optional(&current_path).await,
            };
            if let Err(restore_error) = restore_result {
                return Err(PeerError::BirdReload {
                    stderr: format!(
                        "{reload_error}. The previous generation could not be restored: {restore_error}"
                    ),
                });
            }
            let _ = self.reload_bird().await;
            return Err(reload_error);
        }

        self.remove_old_generations(&generation_name).await;
        Ok(())
    }

    async fn ensure_bird_layout(&self) -> Result<(), PeerError> {
        let generations = self.generations_path();
        let empty = generations.join("empty");
        tokio::fs::create_dir_all(&empty)
            .await
            .context(BirdConfigIoSnafu {
                path: empty.clone(),
            })?;
        self.set_directory_mode(&generations).await?;
        self.set_directory_mode(&empty).await?;

        let current = self.current_path();
        match tokio::fs::symlink_metadata(&current).await {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.switch_current(PathBuf::from("generations/empty"))
                    .await
            }
            Err(source) => Err(PeerError::BirdConfigIo {
                source,
                path: current,
            }),
        }
    }

    async fn set_directory_mode(&self, path: &Path) -> Result<(), PeerError> {
        #[cfg(unix)]
        {
            let mode = tokio::fs::metadata(&self.bird_conf_dir)
                .await
                .map(|metadata| metadata.permissions().mode() & 0o2777)
                .context(BirdConfigIoSnafu {
                    path: PathBuf::from(&self.bird_conf_dir),
                })?;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .await
                .context(BirdConfigIoSnafu {
                    path: path.to_path_buf(),
                })?;
        }
        Ok(())
    }

    async fn current_generation_matches(
        &self,
        desired: &BTreeMap<String, Vec<u8>>,
    ) -> Result<bool, PeerError> {
        generation_matches(&self.current_path(), desired).await
    }

    async fn switch_current(&self, target: PathBuf) -> Result<(), PeerError> {
        atomic_switch_current(self.bird_root(), &target).await
    }

    async fn remove_old_generations(&self, current_name: &str) {
        let generations = self.generations_path();
        let Ok(mut entries) = tokio::fs::read_dir(&generations).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "empty" || name == current_name || !name.starts_with("generation-") {
                continue;
            }
            let _ = tokio::fs::remove_dir_all(entry.path()).await;
        }
    }

    fn bird_root(&self) -> &Path {
        Path::new(&self.bird_conf_dir)
    }

    fn generations_path(&self) -> PathBuf {
        self.bird_root().join("generations")
    }

    fn current_path(&self) -> PathBuf {
        self.bird_root().join("current")
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
        let parent = path.parent().unwrap_or_else(|| self.bird_root());
        let directory_mode = tokio::fs::metadata(parent)
            .await
            .map(|metadata| {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o666
            })
            .context(BirdConfigIoSnafu {
                path: parent.to_path_buf(),
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

async fn sync_directory(path: &Path) -> Result<(), PeerError> {
    let directory = tokio::fs::File::open(path)
        .await
        .context(BirdConfigIoSnafu {
            path: path.to_path_buf(),
        })?;
    directory.sync_all().await.context(BirdConfigIoSnafu {
        path: path.to_path_buf(),
    })
}

async fn generation_matches(
    generation_path: &Path,
    desired: &BTreeMap<String, Vec<u8>>,
) -> Result<bool, PeerError> {
    let mut actual = BTreeMap::new();
    let mut entries = match tokio::fs::read_dir(generation_path).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(PeerError::BirdConfigIo {
                source,
                path: generation_path.to_path_buf(),
            });
        }
    };
    while let Some(entry) = entries.next_entry().await.context(BirdConfigIoSnafu {
        path: generation_path.to_path_buf(),
    })? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".conf") {
            continue;
        }
        let path = entry.path();
        let content = tokio::fs::read(&path)
            .await
            .context(BirdConfigIoSnafu { path })?;
        actual.insert(name, content);
    }
    Ok(&actual == desired)
}

async fn atomic_switch_current(root: &Path, target: &Path) -> Result<(), PeerError> {
    let current = root.join("current");
    let temporary = root.join(format!(".current.{}.tmp", unique_suffix()));
    std::os::unix::fs::symlink(target, &temporary).map_err(|source| PeerError::BirdConfigIo {
        source,
        path: temporary.clone(),
    })?;
    if let Err(source) = tokio::fs::rename(&temporary, &current).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(PeerError::BirdConfigIo {
            source,
            path: current,
        });
    }
    sync_directory(root).await
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn nft_port_batch(ports: &[u16]) -> String {
    let mut batch = "flush set inet nixos-fw autopeer-ports\n".to_string();
    if !ports.is_empty() {
        let ports = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        batch.push_str(&format!(
            "add element inet nixos-fw autopeer-ports {{ {ports} }}\n"
        ));
    }
    batch
}

async fn run_nft_batch(batch: &str) -> Result<(), PeerError> {
    #[cfg(debug_assertions)]
    if std::env::var("MOCK_NFTABLES").is_ok() {
        return Ok(());
    }

    tokio::time::timeout(Duration::from_secs(10), run_nft_batch_inner(batch))
        .await
        .map_err(|_| PeerError::Nftables {
            detail: "nft did not finish within 10 seconds".to_string(),
        })?
}

async fn run_nft_batch_inner(batch: &str) -> Result<(), PeerError> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|source| PeerError::Nftables {
            detail: format!("Could not start nft: {source}"),
        })?;

    let mut stdin = child.stdin.take().ok_or_else(|| PeerError::Nftables {
        detail: "Could not open standard input for nft".to_string(),
    })?;
    stdin
        .write_all(batch.as_bytes())
        .await
        .map_err(|source| PeerError::Nftables {
            detail: format!("Could not write the nftables batch: {source}"),
        })?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .map_err(|source| PeerError::Nftables {
            detail: format!("Could not read the nft result: {source}"),
        })?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(PeerError::Nftables {
        detail: format!(
            "nft failed with status {}: {}",
            output.status,
            stderr.trim()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::{atomic_switch_current, generation_matches, nft_port_batch, unique_suffix};
    use std::{collections::BTreeMap, path::PathBuf};

    #[test]
    fn nft_batch_flushes_an_empty_set() {
        assert_eq!(
            nft_port_batch(&[]),
            "flush set inet nixos-fw autopeer-ports\n"
        );
    }

    #[test]
    fn nft_batch_replaces_all_ports() {
        assert_eq!(
            nft_port_batch(&[20_001, 29_999]),
            concat!(
                "flush set inet nixos-fw autopeer-ports\n",
                "add element inet nixos-fw autopeer-ports { 20001, 29999 }\n"
            )
        );
    }

    #[tokio::test]
    async fn bird_generation_switch_is_atomic_and_comparable() {
        let root = std::env::temp_dir().join(format!("autopeer-generation-{}", unique_suffix()));
        let first = root.join("generations/first");
        let second = root.join("generations/second");
        tokio::fs::create_dir_all(&first).await.unwrap();
        tokio::fs::create_dir_all(&second).await.unwrap();
        std::os::unix::fs::symlink(PathBuf::from("generations/first"), root.join("current"))
            .unwrap();

        tokio::fs::write(second.join("wgp7.conf"), b"protocol bgp test {}\n")
            .await
            .unwrap();
        atomic_switch_current(&root, &PathBuf::from("generations/second"))
            .await
            .unwrap();

        assert_eq!(
            tokio::fs::read_link(root.join("current")).await.unwrap(),
            PathBuf::from("generations/second")
        );
        let desired =
            BTreeMap::from([("wgp7.conf".to_string(), b"protocol bgp test {}\n".to_vec())]);
        assert!(
            generation_matches(&root.join("current"), &desired)
                .await
                .unwrap()
        );

        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}
