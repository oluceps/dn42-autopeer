use crate::{
    error::{BirdConfigIoSnafu, PeerError},
    netlink::WgManager,
    peer::{Peer, PeerStatus},
    persist::PeerStore,
    template::PeerTemplate,
    wg_pubkey::WgPubKey,
};
use askama::Template;
use snafu::ResultExt;
use std::{
    net::{Ipv6Addr, SocketAddr},
    path::Path,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

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
        }
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
        let local_ll_ip = Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            0,
            0,
            (self.local_asn >> 16) as u16,
            (self.local_asn & 0xFFFF) as u16,
        );
        let remote_ll_ip = Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            0,
            0,
            (asn >> 16) as u16,
            (asn & 0xFFFF) as u16,
        );

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
        } else if let Err(e) = WgManager::configure_peer(
            &iface_name,
            &self.local_wg_privkey,
            listen_port,
            &pubkey,
            endpoint,
        ) {
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
                    eprintln!(
                        "DEBUG: Skipping BIRD reload on delete due to error: {:?}",
                        e
                    );
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

        let mut links = handle
            .link()
            .get()
            .match_name(iface_name.to_string())
            .execute();
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
        let mut stream =
            UnixStream::connect(&self.bird_socket)
                .await
                .map_err(|e| PeerError::BirdConfigIo {
                    source: e,
                    path: std::path::PathBuf::from(&self.bird_socket),
                })?;

        let (read_half, mut write_half) = stream.split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();

        // 1. Read the welcome banner
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return Err(PeerError::BirdReload {
                    stderr: "BIRD socket closed early".to_string(),
                });
            }
            if line.len() >= 5 && line.as_bytes()[4] == b' ' {
                break;
            }
        }

        // 2. Send configure soft
        write_half
            .write_all(b"configure soft\n")
            .await
            .map_err(|e| PeerError::BirdConfigIo {
                source: e,
                path: std::path::PathBuf::from(&self.bird_socket),
            })?;

        // 3. Read the response
        let mut response_output = String::new();
        let mut success = false;
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                break;
            }
            response_output.push_str(&line);
            if line.len() >= 5 && line.as_bytes()[4] == b' ' {
                let code = &line[0..4];
                success = !(code.starts_with('8') || code.starts_with('9'));
                break;
            }
        }

        if !success {
            return Err(PeerError::BirdReload {
                stderr: response_output.trim().to_string(),
            });
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
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(&self.bird_conf_dir) {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o755);
                    let _ = std::fs::set_permissions(&self.bird_conf_dir, perms);
                }
            }
        }

        // 2. Soft reload BIRD synchronously to apply the clean state
        let _ = std::process::Command::new("birdc")
            .args(["configure", "soft"])
            .output();

        println!("Cleanup complete.");
    }
}

/*
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
*/
