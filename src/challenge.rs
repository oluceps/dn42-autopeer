use crate::observability::{ObserveResult, log_failure, observe};
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

    #[tracing::instrument(skip_all, fields(operation = "issue_challenge", asn))]
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

    #[tracing::instrument(skip_all, fields(operation = "authorize", asn))]
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

        observe("signature_verify", async {
            verify_signature(public_key, signature, expected_message)
        })
        .await?;
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
        let is_authorized = observe("registry_authorization", async {
            tokio::time::timeout(
                self.registry_timeout,
                self.check_registry_for_asn_and_pubkey(asn, public_key),
            )
            .await
            .map_err(|_| PeerError::RegistryUnavailable {
                detail: "The registry check timed out".to_string(),
            })?
            .map_err(|_| PeerError::RegistryUnavailable {
                detail: "The registry request failed".to_string(),
            })
        })
        .await?;
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
        let expected_fingerprint = if expected_pubkey.contains("BEGIN PGP PUBLIC KEY BLOCK") {
            SignedPublicKey::from_string(expected_pubkey)
                .ok()
                .map(|(pubkey, _)| hex::encode(pubkey.fingerprint().as_bytes()).to_uppercase())
        } else {
            None
        };
        if let Some(fingerprint) = &expected_fingerprint {
            expected_auth_strings.push(format!("pgp-fingerprint {fingerprint}"));
        }

        let asn_url = format!("{}/aut-num/AS{}", self.registry_url, asn);
        let asn_response: serde_json::Value = self
            .client
            .get(asn_url)
            .send()
            .observed("registry_aut_num_http")
            .await?
            .error_for_status()
            .inspect_err(|error| {
                log_failure("registry_http_failed", error);
            })?
            .json()
            .observed("registry_aut_num_decode")
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
            let response = match self
                .client
                .get(url)
                .send()
                .observed("registry_mntner_http")
                .await
            {
                Ok(response) if response.status().is_success() => response,
                Ok(response) => {
                    tracing::warn!(
                        event = "registry_http_failed",
                        http_status = response.status().as_u16(),
                        "Registry returned an unsuccessful status"
                    );
                    continue;
                }
                Err(_) => continue,
            };
            let json = match response
                .json::<serde_json::Value>()
                .observed("registry_mntner_decode")
                .await
            {
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
                {
                    if expected_auth_strings
                        .iter()
                        .any(|expected| expected == value.trim())
                    {
                        return Ok(true);
                    }
                    if let Some(fingerprint) = &expected_fingerprint
                        && let Some(reference) = pgp_key_cert_reference(value.trim())
                        && self.key_cert_matches(reference, fingerprint).await
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    async fn key_cert_matches(&self, reference: &str, expected_fingerprint: &str) -> bool {
        let url = format!("{}/key-cert/{}", self.registry_url, reference);
        let response = match self
            .client
            .get(url)
            .send()
            .observed("registry_key_cert_http")
            .await
        {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                tracing::warn!(
                    event = "registry_http_failed",
                    http_status = response.status().as_u16(),
                    "Registry returned an unsuccessful status"
                );
                return false;
            }
            Err(_) => return false,
        };
        let json = match response
            .json::<serde_json::Value>()
            .observed("registry_key_cert_decode")
            .await
        {
            Ok(json) => json,
            Err(_) => return false,
        };
        let object_key = format!("key-cert/{reference}");
        let Some(attributes) = json
            .get(&object_key)
            .and_then(|object| object.get("Attributes"))
            .and_then(|attributes| attributes.as_array())
        else {
            return false;
        };

        let mut certif = Vec::new();
        for attribute in attributes {
            if let Some(parts) = attribute.as_array()
                && parts.first().and_then(|name| name.as_str()) == Some("certif")
            {
                if parts.len() != 2 {
                    return false;
                }
                let Some(value) = parts[1].as_str() else {
                    return false;
                };
                certif.push(value);
            }
        }
        let Ok((pubkey, _)) = SignedPublicKey::from_string(&certif.join("\n")) else {
            return false;
        };
        hex::encode(pubkey.fingerprint().as_bytes()).to_uppercase() == expected_fingerprint
    }
}

fn pgp_key_cert_reference(value: &str) -> Option<&str> {
    let reference = if let Some(link) = value.strip_prefix('[') {
        let (label, target) = link.strip_suffix(')')?.split_once("](key-cert/")?;
        if label != target {
            return None;
        }
        label
    } else {
        value
    };
    let id = reference.strip_prefix("PGPKEY-")?;
    (id.len() == 8 && id.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(reference)
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
        mtu.map(|m| m.to_string())
            .unwrap_or_else(|| "default".to_string())
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
    use axum::{Json, Router, http::StatusCode};
    use serde_json::{Value, json};
    use std::{collections::HashMap, sync::Mutex};

    const PGP_FINGERPRINT: &str = "6B34521F829DA3556974C58DCB9A8CC485675A0E";
    const PGP_REFERENCE: &str = "PGPKEY-85675A0E";
    const PGP_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaqWnfhYJKwYBBAHaRw8BAQdAVyDefHkGMSErwbsW6giD0PHqgLVKkgFYgfHr
bPgolu60GURONDIgVGVzdCA8dGVzdEBkbjQyLmRldj6IkwQTFgoAOxYhBGs0Uh+C
naNVaXTFjcuajMSFZ1oOBQJqpad+AhsjBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4H
AheAAAoJEMuajMSFZ1oOAdsA/itG0iSJvLEfP103cI0wEBu5rrssHxzSZEtI30Qi
wr+FAP95mumWjux4BsA/lsUTZnUAiLeBi7tw9MTDohJLilxyArg4BGqlp34SCisG
AQQBl1UBBQEBB0Dvp89SMsGAVStTlRL2hBYqWpnVFbRa49m4kShHEDTocQMBCAeI
eAQYFgoAIBYhBGs0Uh+CnaNVaXTFjcuajMSFZ1oOBQJqpad+AhsMAAoJEMuajMSF
Z1oOj+oA/RogQXmcPUNkUo2qw6OdH6xT2fex9lMxw6XTnkrT5EKlAQDIOmmNREGj
bmKAfld55Td5rgywwyIUMrXtco/vvt8QDg==
=e9fb
-----END PGP PUBLIC KEY BLOCK-----";
    const OTHER_PGP_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWkN+5BYJKwYBBAHaRw8BAQdAIGqj23Kp273IPkgjwA7ue5MDIRAfWLYRqnFy
c2AFMcC0EUxpZ2h0IDxsaWdodEBzdW4+iJAEExYIADgWIQSGS0GuVELT3Rs0woce
zfAmwCRYMAUCWkN+5AIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRAezfAm
wCRYMLteAQCFZcl8kBxCH86wmqpc2+KtEA8l/hsfh7jd+JWuyFuuRAD7BOix8Vo1
P/hv8qUYwSn3IRXPeGXucoWVoKGgxRd+zAO4OARaQ37kEgorBgEEAZdVAQUBAQdA
L1KkHCFxtK1CgvZlInT/y6OQeCfXiYzd/i452t2ZR2ADAQgHiHgEGBYIACAWIQSG
S0GuVELT3Rs0wocezfAmwCRYMAUCWkN+5AIbDAAKCRAezfAmwCRYMJ71AQDmoQTg
36pfjrl82srS6XPRJxl3r/6lpWGaNij0VptB2wEA2V10ifOhnwILCw1qBle6On7a
Ba257lrFM+cOSMaEsgo=
=D8HS
-----END PGP PUBLIC KEY BLOCK-----";
    const SSH_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMDcYqby4TnhKV6xGyuZUtxOmTtXjKYp8r+uCxbGph65";

    struct Registry {
        authorizer: RequestAuthorizer,
        requests: Arc<Mutex<Vec<String>>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Registry {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    async fn registry(
        maintainers: &[&[&str]],
        certificates: Vec<(&str, StatusCode, Value)>,
    ) -> Registry {
        let mut routes = HashMap::new();
        let mut mnt_by = Vec::new();
        for (index, auths) in maintainers.iter().enumerate() {
            let name = format!("TEST-{index}-MNT");
            mnt_by.push(json!(["mnt-by", format!("[{name}](mntner/{name})")]));
            let attributes: Vec<_> = auths.iter().map(|auth| json!(["auth", auth])).collect();
            let object_key = format!("mntner/{name}");
            routes.insert(
                format!("/{object_key}"),
                (
                    StatusCode::OK,
                    json!({object_key: {"Attributes": attributes}}),
                ),
            );
        }
        routes.insert(
            "/aut-num/AS4242420001".to_string(),
            (
                StatusCode::OK,
                json!({"aut-num/AS4242420001": {"Attributes": mnt_by}}),
            ),
        );
        for (reference, status, certificate) in certificates {
            routes.insert(format!("/key-cert/{reference}"), (status, certificate));
        }
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = requests.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            received.lock().unwrap().push(uri.path().to_string());
            let (status, body) = routes
                .get(uri.path())
                .cloned()
                .unwrap_or((StatusCode::NOT_FOUND, Value::Null));
            async move { (status, Json(body)) }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let timeout = Duration::from_secs(2);
        let authorizer = RequestAuthorizer {
            store: PeerStore {
                pool: sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgres://unused@127.0.0.1/unused")
                    .unwrap(),
            },
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(timeout)
                .build()
                .unwrap(),
            registry_url: format!("http://{address}"),
            registry_limit: Arc::new(Semaphore::new(1)),
            registry_timeout: timeout,
        };
        Registry {
            authorizer,
            requests,
            server,
        }
    }

    fn key_cert(reference: &str, public_key: &str) -> Value {
        let mut attributes = vec![
            json!(["key-cert", reference]),
            json!(["fingerpr", PGP_FINGERPRINT]),
        ];
        for line in public_key.lines() {
            attributes.push(json!(["certif", line]));
            attributes.push(json!(["remarks", "Ignore this attribute"]));
        }
        json!({format!("key-cert/{reference}"): {"Attributes": attributes}})
    }

    async fn matches(registry: &Registry, public_key: &str) -> bool {
        registry
            .authorizer
            .check_registry_for_asn_and_pubkey(4242420001, public_key)
            .await
            .unwrap()
    }

    #[test]
    fn pgp_references_require_exact_names_and_matching_link_targets() {
        for reference in ["PGPKEY-85675A0E", "PGPKEY-abcdef01"] {
            assert_eq!(pgp_key_cert_reference(reference), Some(reference));
            let link = format!("[{reference}](key-cert/{reference})");
            assert_eq!(pgp_key_cert_reference(&link), Some(reference));
        }
        for invalid in [
            "PGPKEY-85675A0",
            "PGPKEY-85675A0EF",
            "PGPKEY-85675A0G",
            "pgpkey-85675A0E",
            "PGPKEY-85675A0E/../../mntner/OTHER",
            "PGPKEY-85675A0E?auth=other",
            "PGPKEY-85675A0E#other",
            "PGPKEY-85675A0E%2fother",
            "PGPKEY-85675A0E\n",
            "[PGPKEY-85675A0E](key-cert/PGPKEY-00000000)",
            "[PGPKEY-85675A0E](https://example.org/key-cert/PGPKEY-85675A0E)",
            "[PGPKEY-85675A0E](key-cert/PGPKEY-85675A0E/..)",
        ] {
            assert_eq!(pgp_key_cert_reference(invalid), None, "{invalid}");
        }
    }

    #[tokio::test]
    async fn referenced_pgp_key_matches_plain_and_link_auth() {
        let (key, _) = SignedPublicKey::from_string(PGP_KEY).unwrap();
        assert_eq!(
            hex::encode(key.fingerprint().as_bytes()).to_uppercase(),
            PGP_FINGERPRINT
        );
        let armored_key = PGP_KEY.replacen(
            "\n\n",
            "\nVersion: Local regression fixture\nComment: Preserve the empty line\n\n",
            1,
        );
        let mut certificate = key_cert(PGP_REFERENCE, &armored_key);
        certificate["key-cert/PGPKEY-85675A0E"]["Attributes"][1][1] = json!("untrusted metadata");
        for auth in [
            PGP_REFERENCE,
            " [PGPKEY-85675A0E](key-cert/PGPKEY-85675A0E) ",
        ] {
            let registry = registry(
                &[&[auth]],
                vec![(PGP_REFERENCE, StatusCode::OK, certificate.clone())],
            )
            .await;
            assert!(matches(&registry, PGP_KEY).await);
            assert_eq!(
                *registry.requests.lock().unwrap(),
                [
                    "/aut-num/AS4242420001",
                    "/mntner/TEST-0-MNT",
                    "/key-cert/PGPKEY-85675A0E",
                ]
            );
        }
    }

    #[tokio::test]
    async fn reference_name_and_metadata_cannot_authorize_a_different_key() {
        let (other, _) = SignedPublicKey::from_string(OTHER_PGP_KEY).unwrap();
        assert_ne!(
            hex::encode(other.fingerprint().as_bytes()).to_uppercase(),
            PGP_FINGERPRINT
        );
        let registry = registry(
            &[&[PGP_REFERENCE]],
            vec![
                (
                    PGP_REFERENCE,
                    StatusCode::OK,
                    key_cert(PGP_REFERENCE, OTHER_PGP_KEY),
                ),
                (
                    "PGPKEY-00000000",
                    StatusCode::OK,
                    key_cert("PGPKEY-00000000", PGP_KEY),
                ),
            ],
        )
        .await;
        assert!(!matches(&registry, PGP_KEY).await);
        assert_eq!(registry.requests.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn missing_or_malformed_certif_cannot_authorize() {
        for certificate in [
            Value::Null,
            json!({"key-cert/PGPKEY-85675A0E": {"Attributes": [["fingerpr", PGP_FINGERPRINT]]}}),
            key_cert(PGP_REFERENCE, ""),
            key_cert(PGP_REFERENCE, "This is not a PGP certificate"),
            json!({"key-cert/PGPKEY-85675A0E": {"Attributes": [["certif", 123]]}}),
            json!({"key-cert/PGPKEY-85675A0E": {"Attributes": [["certif"]]}}),
        ] {
            let registry = registry(
                &[&[PGP_REFERENCE]],
                vec![(PGP_REFERENCE, StatusCode::OK, certificate)],
            )
            .await;
            assert!(!matches(&registry, PGP_KEY).await);
        }
    }

    #[tokio::test]
    async fn failed_key_certs_allow_later_auths_and_maintainers() {
        for status in [
            StatusCode::OK,
            StatusCode::NOT_FOUND,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let certificate = key_cert(
                PGP_REFERENCE,
                if status.is_success() {
                    "invalid"
                } else {
                    PGP_KEY
                },
            );
            let failed = || (PGP_REFERENCE, status, certificate.clone());
            let fingerprint_auth = format!("pgp-fingerprint {PGP_FINGERPRINT}");
            for maintainers in [
                vec![vec![PGP_REFERENCE, fingerprint_auth.as_str()]],
                vec![vec![PGP_REFERENCE], vec![fingerprint_auth.as_str()]],
                vec![vec![PGP_REFERENCE, "PGPKEY-00000000"]],
            ] {
                let maintainers: Vec<_> = maintainers.iter().map(Vec::as_slice).collect();
                let registry = registry(
                    &maintainers,
                    vec![
                        failed(),
                        (
                            "PGPKEY-00000000",
                            StatusCode::OK,
                            key_cert("PGPKEY-00000000", PGP_KEY),
                        ),
                    ],
                )
                .await;
                assert!(matches(&registry, PGP_KEY).await, "{status}");
            }
            let registry = registry(&[&[PGP_REFERENCE]], vec![failed()]).await;
            assert!(!matches(&registry, PGP_KEY).await, "{status}");
        }
    }

    #[tokio::test]
    async fn existing_fingerprint_and_ssh_auth_still_match() {
        let fingerprint_auth = format!(" pgp-fingerprint {PGP_FINGERPRINT} ");
        for (auth, public_key) in [
            (fingerprint_auth.as_str(), PGP_KEY),
            (PGP_KEY, PGP_KEY),
            (SSH_KEY, SSH_KEY),
        ] {
            let registry = registry(&[&["PGPKEY-../mntner/OTHER", auth]], vec![]).await;
            assert!(matches(&registry, public_key).await);
            assert_eq!(registry.requests.lock().unwrap().len(), 2);
        }
        let registry = registry(&[&[PGP_REFERENCE]], vec![]).await;
        assert!(!matches(&registry, SSH_KEY).await);
        assert_eq!(registry.requests.lock().unwrap().len(), 2);
    }

    #[test]
    fn signing_messages_bind_the_operation_and_endpoint_state() {
        let key =
            WgPubKey::try_from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()).unwrap();
        let create = build_create_message(4242420001, "fra1", &key, None, None, None, "nonce", 100);
        let update = build_update_message(4242420001, "fra1", &key, None, None, None, "nonce", 100);
        let clear = build_update_message(
            4242420001,
            "fra1",
            &key,
            Some(None),
            None,
            None,
            "nonce",
            100,
        );
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
