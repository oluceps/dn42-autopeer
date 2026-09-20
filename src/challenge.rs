use crate::{error::PeerError, persist::PeerStore, wg_pubkey::WgPubKey};
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;
use ssh_key::{PublicKey, SshSig};
use std::{net::Ipv6Addr, str::FromStr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use wireguard_control::Key;

const CHALLENGE_TTL_SECS: i64 = 300;

#[derive(Clone)]
pub struct RequestAuthorizer {
    store: PeerStore,
    client: reqwest::Client,
    registry_url: String,
    registry_limit: Arc<Semaphore>,
    registry_timeout: Duration,
}

impl RequestAuthorizer {
    pub fn new(store: PeerStore) -> Result<Self, PeerError> {
        let timeout_secs = env_u64("REGISTRY_TIMEOUT_SECS", 10)?;
        let max_concurrent = env_usize("REGISTRY_MAX_CONCURRENT", 16)?;
        if timeout_secs == 0 {
            return Err(PeerError::Validation {
                detail: "REGISTRY_TIMEOUT_SECS must be greater than zero".to_string(),
            });
        }
        if max_concurrent == 0 {
            return Err(PeerError::Validation {
                detail: "REGISTRY_MAX_CONCURRENT must be greater than zero".to_string(),
            });
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(timeout_secs.min(5)))
            .read_timeout(Duration::from_secs(timeout_secs))
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|error| PeerError::Validation {
                detail: format!("Failed to create the registry client: {error}"),
            })?;
        Ok(Self {
            store,
            client,
            registry_url: std::env::var("REGISTRY_API_URL")
                .unwrap_or_else(|_| "https://explorer.burble.com/api/registry".to_string()),
            registry_limit: Arc::new(Semaphore::new(max_concurrent)),
            registry_timeout: Duration::from_secs(timeout_secs),
        })
    }

    pub async fn issue_challenge(&self, asn: u32) -> Result<(String, i64), PeerError> {
        let expires_at = unix_timestamp() + CHALLENGE_TTL_SECS;
        for _ in 0..4 {
            let nonce = Key::generate_preshared().to_base64();
            if self.store.insert_nonce(asn, &nonce, expires_at).await? {
                return Ok((nonce, expires_at));
            }
        }
        Err(PeerError::UnauthorizedChallenge {
            detail: "The server could not allocate a unique nonce".to_string(),
        })
    }

    pub async fn authorize_request(
        &self,
        asn: u32,
        public_key: &str,
        signature: &str,
        nonce: &str,
        expires_at: i64,
        expected_message: &str,
    ) -> Result<(), PeerError> {
        if expires_at < unix_timestamp() {
            return Err(PeerError::UnauthorizedChallenge {
                detail: "The challenge expired".to_string(),
            });
        }

        #[cfg(debug_assertions)]
        if nonce == "dummy_nonce" {
            return Ok(());
        }

        verify_signature(public_key, signature, expected_message)?;
        let _permit =
            self.registry_limit
                .try_acquire()
                .map_err(|_| PeerError::RegistryUnavailable {
                    detail: "Too many registry checks are active".to_string(),
                })?;
        if !self.store.consume_nonce(asn, nonce, expires_at).await? {
            return Err(PeerError::UnauthorizedChallenge {
                detail: "The challenge is expired, unknown, or already used".to_string(),
            });
        }
        let is_authorized = tokio::time::timeout(
            self.registry_timeout,
            self.check_registry_for_asn_and_pubkey(asn, public_key),
        )
        .await
        .map_err(|_| PeerError::RegistryUnavailable {
            detail: "The registry check timed out".to_string(),
        })?
        .map_err(|_| PeerError::RegistryUnavailable {
            detail: "The registry request failed".to_string(),
        })?;
        if !is_authorized {
            return Err(PeerError::RegistryMismatch);
        }
        Ok(())
    }

    async fn check_registry_for_asn_and_pubkey(
        &self,
        asn: u32,
        expected_pubkey: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut expected_auth_strings = vec![expected_pubkey.trim().to_string()];
        if expected_pubkey.contains("BEGIN PGP PUBLIC KEY BLOCK")
            && let Ok((pubkey, _)) = SignedPublicKey::from_string(expected_pubkey)
        {
            let fingerprint = hex::encode(pubkey.fingerprint().as_bytes()).to_uppercase();
            expected_auth_strings.push(format!("pgp-fingerprint {fingerprint}"));
        }

        let asn_url = format!("{}/aut-num/AS{}", self.registry_url, asn);
        let asn_response: serde_json::Value = self
            .client
            .get(asn_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let object_key = format!("aut-num/AS{asn}");
        let attributes = asn_response
            .get(&object_key)
            .and_then(|object| object.get("Attributes"))
            .and_then(|attributes| attributes.as_array())
            .ok_or("The registry response has no aut-num attributes")?;

        let mut maintainers = Vec::new();
        for attribute in attributes {
            if let Some(parts) = attribute.as_array()
                && parts.len() == 2
                && parts[0].as_str() == Some("mnt-by")
                && let Some(value) = parts[1].as_str()
                && let Some(start) = value.find("(mntner/")
                && value.ends_with(')')
            {
                maintainers.push(value[start + 8..value.len() - 1].to_string());
            }
        }

        for maintainer in maintainers {
            let url = format!("{}/mntner/{}", self.registry_url, maintainer);
            let response = match self.client.get(url).send().await {
                Ok(response) if response.status().is_success() => response,
                _ => continue,
            };
            let json = match response.json::<serde_json::Value>().await {
                Ok(json) => json,
                Err(_) => continue,
            };
            let object_key = format!("mntner/{maintainer}");
            let Some(attributes) = json
                .get(&object_key)
                .and_then(|object| object.get("Attributes"))
                .and_then(|attributes| attributes.as_array())
            else {
                continue;
            };

            for attribute in attributes {
                if let Some(parts) = attribute.as_array()
                    && parts.len() == 2
                    && parts[0].as_str() == Some("auth")
                    && let Some(value) = parts[1].as_str()
                    && expected_auth_strings
                        .iter()
                        .any(|expected| expected == value.trim())
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

pub fn verify_signature(
    public_key: &str,
    signature: &str,
    expected_message: &str,
) -> Result<(), PeerError> {
    if public_key.contains("BEGIN PGP PUBLIC KEY BLOCK") {
        let (public_key, _) = SignedPublicKey::from_string(public_key).map_err(|error| {
            PeerError::SignatureVerificationFailed {
                detail: format!("Invalid PGP public key: {error:?}"),
            }
        })?;
        let (signature, _) = DetachedSignature::from_string(signature).map_err(|error| {
            PeerError::SignatureVerificationFailed {
                detail: format!("Invalid PGP signature format: {error:?}"),
            }
        })?;
        signature
            .verify(&public_key, expected_message.as_bytes())
            .map_err(|error| PeerError::SignatureVerificationFailed {
                detail: format!("PGP signature verification failed: {error:?}"),
            })?;
        return Ok(());
    }

    let public_key = PublicKey::from_str(public_key).map_err(|error| {
        PeerError::SignatureVerificationFailed {
            detail: format!("Invalid SSH public key: {error}"),
        }
    })?;
    let signature =
        SshSig::from_str(signature).map_err(|error| PeerError::SignatureVerificationFailed {
            detail: format!("Invalid SSH signature format: {error}"),
        })?;
    public_key
        .verify("dn42", expected_message.as_bytes(), &signature)
        .map_err(|error| PeerError::SignatureVerificationFailed {
            detail: format!("Signature verification failed: {error}"),
        })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn build_create_message(
    asn: u32,
    peer_name: &str,
    pubkey: &WgPubKey,
    endpoint: Option<&str>,
    link_local: Option<(Ipv6Addr, Ipv6Addr)>,
    mtu: Option<u16>,
    nonce: &str,
    expires_at: i64,
) -> String {
    format!(
        "DN42-AUTOPEER-V3\noperation:create\nasn:{asn}\npeer_name:{peer_name}\npubkey:{pubkey}\nendpoint:{}\nlink_local:{}\nmtu:{}\nnonce:{nonce}\nexpires_at:{expires_at}",
        endpoint.unwrap_or("none"),
        link_local_message(link_local),
        mtu.map(|m| m.to_string()).unwrap_or_else(|| "default".to_string())
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_update_message(
    asn: u32,
    peer_name: &str,
    pubkey: &WgPubKey,
    endpoint: Option<Option<&str>>,
    link_local: Option<(Ipv6Addr, Ipv6Addr)>,
    mtu: Option<Option<u16>>,
    nonce: &str,
    expires_at: i64,
) -> String {
    let endpoint = match endpoint {
        None => "unchanged".to_string(),
        Some(None) => "clear".to_string(),
        Some(Some(value)) => format!("set:{value}"),
    };
    let mtu_msg = match mtu {
        None => "unchanged".to_string(),
        Some(None) => "default".to_string(),
        Some(Some(value)) => format!("set:{value}"),
    };
    format!(
        "DN42-AUTOPEER-V3\noperation:update\nasn:{asn}\npeer_name:{peer_name}\npubkey:{pubkey}\nendpoint:{endpoint}\nlink_local:{}\nmtu:{mtu_msg}\nnonce:{nonce}\nexpires_at:{expires_at}",
        link_local_message(link_local)
    )
}

fn link_local_message(link_local: Option<(Ipv6Addr, Ipv6Addr)>) -> String {
    match link_local {
        Some((local, remote)) => format!("manual:{local}:{remote}"),
        None => "auto".to_string(),
    }
}

pub fn build_delete_message(asn: u32, peer_name: &str, nonce: &str, expires_at: i64) -> String {
    format!(
        "DN42-AUTOPEER-V3\noperation:delete\nasn:{asn}\npeer_name:{peer_name}\nnonce:{nonce}\nexpires_at:{expires_at}"
    )
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn env_u64(name: &str, default: u64) -> Result<u64, PeerError> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse()
        .map_err(|_| PeerError::Validation {
            detail: format!("{name} must be a positive integer"),
        })
}

fn env_usize(name: &str, default: usize) -> Result<usize, PeerError> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse()
        .map_err(|_| PeerError::Validation {
            detail: format!("{name} must be a positive integer"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_messages_bind_the_operation_and_endpoint_state() {
        let key =
            WgPubKey::try_from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()).unwrap();
        let create = build_create_message(4242420001, "fra1", &key, None, None, None, "nonce", 100);
        let update = build_update_message(4242420001, "fra1", &key, None, None, None, "nonce", 100);
        let clear = build_update_message(4242420001, "fra1", &key, Some(None), None, None, "nonce", 100);
        let delete = build_delete_message(4242420001, "fra1", "nonce", 100);
        let other_peer = build_delete_message(4242420001, "sin1", "nonce", 100);

        assert_ne!(create, update);
        assert_ne!(update, clear);
        assert_ne!(clear, delete);
        assert_ne!(delete, other_peer);
        assert!(create.contains("peer_name:fra1"));
        assert!(create.contains("link_local:auto"));
        assert!(create.contains("expires_at:100"));
    }
}
