use std::{path::Path, net::{Ipv6Addr, SocketAddr}};
use snafu::ResultExt;
use crate::{
    peer::{Peer, PeerStatus},
    persist::PeerStore,
    wg_pubkey::WgPubKey,
    error::{PeerError, BirdConfigIoSnafu},
    netlink::WgManager,
    template::PeerTemplate,
};
use askama::Template;
use tokio::process::Command;

pub struct PeerManager {
    db: PeerStore,
    bird_conf_dir: String,
    local_wg_privkey: String,
    local_asn: u32,
}

impl PeerManager {
    pub fn new(db: PeerStore, bird_conf_dir: String, local_wg_privkey: String, local_asn: u32) -> Self {
        Self { db, bird_conf_dir, local_wg_privkey, local_asn }
    }

    pub async fn upsert_peer(
        &self,
        asn: u32,
        pubkey: WgPubKey,
        endpoint: Option<SocketAddr>,
    ) -> Result<Peer, PeerError> {
        let iface_name = format!("wg{}", asn);
        let listen_port = 20000 + (asn % 10000) as u16;

        // Generate deterministic LL IPs
        // e.g., fe80::local_asn and fe80::remote_asn
        let local_ll_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, (self.local_asn >> 16) as u16, (self.local_asn & 0xFFFF) as u16);
        let remote_ll_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, (asn >> 16) as u16, (asn & 0xFFFF) as u16);

        let peer = Peer {
            iface_name: iface_name.clone(),
            asn,
            pubkey: pubkey.clone(),
            endpoint,
            local_ll_ip,
            remote_ll_ip,
            status: PeerStatus::Active,
        };

        // 1. Store in DB
        self.db.insert_peer(&peer, listen_port).await?;

        // 2. Configure WireGuard Interface
        if let Err(e) = WgManager::ensure_wg_interface(&iface_name).await {
            if cfg!(debug_assertions) {
                eprintln!("DEBUG: Skipping netlink WG creation due to error: {:?}", e);
            } else {
                return Err(e);
            }
        } else if let Err(e) = WgManager::configure_peer(&iface_name, &self.local_wg_privkey, listen_port, &pubkey, endpoint) {
            if cfg!(debug_assertions) {
                eprintln!("DEBUG: Skipping WG config due to error: {:?}", e);
            } else {
                return Err(e);
            }
        }

        // 3. Write BIRD config
        let bird_template = PeerTemplate {
            asn,
            local_asn: self.local_asn,
            iface: &iface_name,
            local_ll_ip,
            remote_ll_ip,
        };
        let bird_conf_content = bird_template.render().unwrap();
        
        let conf_path = Path::new(&self.bird_conf_dir).join(format!("{}.conf", iface_name));
        tokio::fs::write(&conf_path, bird_conf_content)
            .await
            .context(BirdConfigIoSnafu { path: conf_path })?;

        // 4. Reload BIRD
        if let Err(e) = self.reload_bird().await {
            if cfg!(debug_assertions) {
                eprintln!("DEBUG: Skipping BIRD reload due to error: {:?}", e);
            } else {
                return Err(e);
            }
        }

        Ok(peer)
    }

    pub async fn delete_peer(&self, asn: u32) -> Result<(), PeerError> {
        let iface_name = format!("wg{}", asn);
        let conf_path = Path::new(&self.bird_conf_dir).join(format!("{}.conf", iface_name));
        
        // Remove BIRD conf
        if conf_path.exists() {
            tokio::fs::remove_file(&conf_path).await.ok();
            if let Err(e) = self.reload_bird().await {
                if cfg!(debug_assertions) {
                    eprintln!("DEBUG: Skipping BIRD reload on delete due to error: {:?}", e);
                } else {
                    return Err(e);
                }
            }
        }

        // We can optionally delete the WG interface via netlink here
        // rtnetlink's LinkDelRequest...
        // For now just deleting BIRD config removes BGP session.
        // Actually, deleting the wireguard interface is important to prevent orphan interfaces.
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);
        
        let mut links = handle.link().get().match_name(iface_name.to_string()).execute();
        use futures::StreamExt;
        if let Some(Ok(link)) = links.next().await {
            handle.link().del(link.header.index).execute().await.ok();
        }

        // Ideally we also mark as deleted in DB
        Ok(())
    }

    async fn reload_bird(&self) -> Result<(), PeerError> {
        let output = Command::new("birdc")
            .args(["configure", "soft"])
            .output()
            .await
            .map_err(|e| PeerError::BirdConfigIo { source: e, path: std::path::PathBuf::from("birdc") })?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PeerError::BirdReload { stderr: stderr.into_owned() });
        }
        Ok(())
    }
}

impl Drop for PeerManager {
    fn drop(&mut self) {
        println!("PeerManager dropping: cleaning up BIRD configs and reloading...");
        
        // 1. Clean up the configuration directory
        // We attempt to remove the directory and recreate it to wipe all generated configs
        if std::fs::remove_dir_all(&self.bird_conf_dir).is_ok() {
            std::fs::create_dir_all(&self.bird_conf_dir).ok();
        }

        // 2. Soft reload BIRD synchronously to apply the clean state
        let _ = std::process::Command::new("birdc")
            .args(["configure", "soft"])
            .output();
            
        println!("Cleanup complete.");
    }
}
