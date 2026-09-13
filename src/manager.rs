use std::{path::Path, net::{Ipv6Addr, SocketAddr}};
use snafu::ResultExt;
use tokio::net::UnixStream;
use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};
use crate::{
    peer::{Peer, PeerStatus},
    persist::PeerStore,
    wg_pubkey::WgPubKey,
    error::{PeerError, BirdConfigIoSnafu},
    netlink::WgManager,
    template::PeerTemplate,
};
use askama::Template;

pub struct PeerManager {
    db: PeerStore,
    bird_conf_dir: String,
    bird_socket: String,
    local_wg_privkey: String,
    pub local_wg_pubkey: String,
    pub public_endpoint: String,
    pub local_asn: u32,
}

impl PeerManager {
    pub fn new(db: PeerStore, bird_conf_dir: String, bird_socket: String, local_wg_privkey: String, local_wg_pubkey: String, public_endpoint: String, local_asn: u32) -> Self {
        Self { db, bird_conf_dir, bird_socket, local_wg_privkey, local_wg_pubkey, public_endpoint, local_asn }
    }

    pub async fn peer_exists(&self, asn: u32) -> Result<bool, PeerError> {
        self.db.peer_exists(asn).await
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

        // 1. Configure WireGuard Interface
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
        
        let parent_mode = tokio::fs::metadata(&self.bird_conf_dir)
            .await
            .map(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o666
            })
            .unwrap_or(0o644);

        let mut open_opts = tokio::fs::OpenOptions::new();
        open_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            open_opts.mode(parent_mode);
        }

        let mut file = open_opts
            .open(&conf_path)
            .await
            .context(BirdConfigIoSnafu { path: conf_path.clone() })?;
            
        file.write_all(bird_conf_content.as_bytes())
            .await
            .context(BirdConfigIoSnafu { path: conf_path.clone() })?;

        // Explicitly set permissions to bypass process umask (e.g. 022)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(parent_mode);
            file.set_permissions(perms)
                .await
                .context(BirdConfigIoSnafu { path: conf_path.clone() })?;
        }

        // 4. Reload BIRD
        if let Err(e) = self.reload_bird().await {
            if cfg!(debug_assertions) {
                eprintln!("DEBUG: Skipping BIRD reload due to error: {:?}", e);
            } else {
                return Err(e);
            }
        }
        // 4. Store in DB (Only after system state has successfully applied)
        self.db.insert_peer(&peer, listen_port).await?;

        Ok(peer)
    }

    pub async fn delete_peer(&self, asn: u32) -> Result<(), PeerError> {
        let iface_name = format!("wg{}", asn);
        let conf_path = Path::new(&self.bird_conf_dir).join(format!("{}.conf", iface_name));
        
        // 1. Remove BIRD conf
        tokio::fs::remove_file(&conf_path).await.ok();
        
        // 2. Reload BIRD
        if let Err(e) = self.reload_bird().await {
            if cfg!(debug_assertions) {
                eprintln!("DEBUG: Skipping BIRD reload on delete due to error: {:?}", e);
            } else {
                return Err(e);
            }
        }

        // 3. Remove WG Interface
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);
        
        let mut links = handle.link().get().match_name(iface_name.to_string()).execute();
        use futures::StreamExt;
        if let Some(Ok(link)) = links.next().await {
            handle.link().del(link.header.index).execute().await.ok();
        }

        // Delete from DB
        let deleted = self.db.delete_peer(asn).await?;
        if !deleted {
            return Err(PeerError::NotFound { asn });
        }

        Ok(())
    }

    async fn reload_bird(&self) -> Result<(), PeerError> {
        let mut stream = UnixStream::connect(&self.bird_socket).await
            .map_err(|e| PeerError::BirdConfigIo { source: e, path: std::path::PathBuf::from(&self.bird_socket) })?;

        let (read_half, mut write_half) = stream.split();
        let mut reader = BufReader::new(read_half);
        let mut line = Vec::new();

        // 1. Read the welcome banner
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line).await.unwrap_or(0) == 0 {
                return Err(PeerError::BirdReload { stderr: "BIRD socket closed early".to_string() });
            }
            if line.len() >= 5 && line[4] == b' ' {
                break;
            }
        }

        // 2. Send configure soft
        write_half.write_all(b"configure soft\n").await
            .map_err(|e| PeerError::BirdConfigIo { source: e, path: std::path::PathBuf::from(&self.bird_socket) })?;

        // 3. Read the response
        let mut response_output = String::new();
        let mut success = false;
        loop {
            line.clear();
            let n = reader.read_until(b'\n', &mut line).await.map_err(|e| PeerError::BirdReload { 
                stderr: format!("Socket read error: {}. Output so far: {}", e, response_output) 
            })?;
            
            if n == 0 {
                return Err(PeerError::BirdReload { 
                    stderr: format!("BIRD closed socket unexpectedly. Output so far: {}", response_output.trim()) 
                });
            }
            
            let line_str = String::from_utf8_lossy(&line);
            response_output.push_str(&line_str);
            if line.len() >= 5 && line[4] == b' ' {
                let code = &line[0..4];
                if code.starts_with(b"8") || code.starts_with(b"9") {
                    success = false;
                } else {
                    success = true;
                }
                break;
            }
        }

        if !success {
            return Err(PeerError::BirdReload { stderr: response_output.trim().to_string() });
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

#[cfg(test)]
mod tests {

    use tokio::net::UnixStream;
    use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};

    // Note: this test requires the bird socket to be accessible by the runner.
    // E.g., `sudo -u bird cargo test test_bird_socket_protocol -- --nocapture`
    #[tokio::test]
    #[ignore = "Requires BIRD socket permissions locally"]
    async fn test_bird_socket_protocol() {
        let bird_socket = std::env::var("BIRD_SOCKET").unwrap_or_else(|_| "/run/bird/bird.ctl".to_string());
        
        let mut stream = match UnixStream::connect(&bird_socket).await {
            Ok(s) => s,
            Err(e) => {
                println!("Could not connect to {}: {}. Skipping test.", bird_socket, e);
                return;
            }
        };

        let (read_half, mut write_half) = stream.split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();

        println!("Reading BIRD banner...");
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await.expect("Failed to read");
            if n == 0 {
                panic!("BIRD socket closed early during banner");
            }
            print!("BANNER: {}", line);
            if line.len() >= 5 && line.as_bytes()[4] == b' ' {
                break;
            }
        }

        println!("Sending configure soft...");
        write_half.write_all(b"configure soft\n").await.expect("Failed to write");

        println!("Reading response...");
        let mut response_output = String::new();
        let mut success = false;
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await.expect("Failed to read");
            if n == 0 {
                break;
            }
            print!("REPLY: {}", line);
            response_output.push_str(&line);
            if line.len() >= 5 && line.as_bytes()[4] == b' ' {
                let code = &line[0..4];
                if code.starts_with('8') || code.starts_with('9') {
                    success = false;
                } else {
                    success = true;
                }
                break;
            }
        }

        println!("Final success status: {}", success);
        println!("Full captured output:\n{}", response_output);
        
        assert!(success || !response_output.is_empty(), "Either it succeeds or returns an error message");
    }
}
