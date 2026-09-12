use crate::error::PeerError;
use crate::wg_pubkey::WgPubKey;
use ssh_key::{PublicKey, SshSig};
use std::str::FromStr;
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;

#[allow(dead_code)]
pub fn verify_signature(
    public_key_str: &str,
    signature_str: &str,
    expected_message: &str,
) -> Result<(), PeerError> {
    if public_key_str.contains("BEGIN PGP PUBLIC KEY BLOCK") {
        let (pubkey, _) = SignedPublicKey::from_string(public_key_str).map_err(|e| {
            PeerError::SignatureVerificationFailed {
                detail: format!("Invalid PGP public key: {:?}", e),
            }
        })?;
        let (sig, _) = DetachedSignature::from_string(signature_str).map_err(|e| {
            PeerError::SignatureVerificationFailed {
                detail: format!("Invalid PGP signature format: {:?}", e),
            }
        })?;
        sig.verify(&pubkey, expected_message.as_bytes())
            .map_err(|e| PeerError::SignatureVerificationFailed {
                detail: format!("PGP signature verification failed: {:?}", e),
            })?;
        return Ok(());
    }

    // 1. Parse SSH public key (e.g., ssh-ed25519 AAAAC3...)
    let pubkey = PublicKey::from_str(public_key_str).map_err(|e| {
        PeerError::SignatureVerificationFailed {
            detail: format!("Invalid SSH public key: {}", e),
        }
    })?;

    // 2. Parse SSH signature (e.g., -----BEGIN SSH SIGNATURE----- ...)
    let sig =
        SshSig::from_str(signature_str).map_err(|e| PeerError::SignatureVerificationFailed {
            detail: format!("Invalid SSH signature format: {}", e),
        })?;

    // 3. Verify the signature against the expected message
    // Note: ssh-keygen -Y sign uses a namespace. We standardize on "dn42"
    pubkey
        .verify("dn42", expected_message.as_bytes(), &sig)
        .map_err(|e| PeerError::SignatureVerificationFailed {
            detail: format!("Signature verification failed: {}", e),
        })?;

    // Verify that this public key belongs to the ASN in the DN42 Registry
    // Since this makes an HTTP request, we can't await it easily here if verify_signature isn't async
    // Let's change the function signature to async!
    // But wait, the function is synchronous. I'll make it async.

    Ok(())
}

pub async fn authorize_request(
    asn: u32,
    public_key_str: &str,
    signature_str: &str,
    expected_message: &str,
) -> Result<(), PeerError> {
    // 1. Verify signature cryptographically
    verify_signature(public_key_str, signature_str, expected_message)?;

    // 2. Fetch from DN42 Registry via HTTP API
    let is_authorized = check_registry_for_asn_and_pubkey(asn, public_key_str)
        .await
        .map_err(|e| PeerError::SignatureVerificationFailed {
            detail: format!("Registry API error: {}", e),
        })?;

    if !is_authorized {
        return Err(PeerError::RegistryMismatch);
    }

    Ok(())
}

#[allow(dead_code)]
async fn check_registry_for_asn_and_pubkey(
    asn: u32,
    expected_pubkey: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let registry_url = std::env::var("REGISTRY_API_URL")
        .unwrap_or_else(|_| "https://explorer.burble.com/api/registry".to_string());

    let mut expected_auth_strings = vec![expected_pubkey.trim().to_string()];
    if expected_pubkey.contains("BEGIN PGP PUBLIC KEY BLOCK") {
        if let Ok((pubkey, _)) = SignedPublicKey::from_string(expected_pubkey) {
            let fpr = pubkey.fingerprint();
            let fpr_hex = hex::encode(fpr.as_bytes()).to_uppercase();
            expected_auth_strings.push(format!("pgp-fingerprint {}", fpr_hex));
        }
    }

    // 1. Get aut-num object
    let asn_url = format!("{}/aut-num/AS{}", registry_url, asn);
    let asn_resp: serde_json::Value = client
        .get(&asn_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let aut_num_key = format!("aut-num/AS{}", asn);
    let aut_num_obj = asn_resp.get(&aut_num_key).ok_or("Missing aut-num object")?;
    let attributes = aut_num_obj
        .get("Attributes")
        .ok_or("Missing Attributes")?
        .as_array()
        .ok_or("Attributes not an array")?;

    let mut mntners = Vec::new();
    for attr in attributes {
        if let Some(arr) = attr.as_array()
            && arr.len() == 2
            && let (Some(key), Some(val)) = (arr[0].as_str(), arr[1].as_str())
            && key == "mnt-by"
        {
            // value is something like "[MNTNER-NAME](mntner/MNTNER-NAME)"
            // let's extract MNTNER-NAME
            if let Some(start) = val.find("(mntner/") {
                let end = val.len() - 1; // remove closing parenthesis
                let mntner_name = &val[start + 8..end];
                mntners.push(mntner_name.to_string());
            }
        }
    }

    // 2. Check each mntner for the auth key
    for mntner in mntners {
        let mntner_url = format!("{}/mntner/{}", registry_url, mntner);
        let mntner_resp_res = client.get(&mntner_url).send().await;

        if let Ok(resp) = mntner_resp_res {
            if !resp.status().is_success() {
                continue;
            }
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let mntner_key = format!("mntner/{}", mntner);
                if let Some(obj) = json.get(&mntner_key)
                    && let Some(attrs) = obj.get("Attributes").and_then(|a| a.as_array())
                {
                    for attr in attrs {
                        if let Some(arr) = attr.as_array()
                            && arr.len() == 2
                            && arr[0].as_str() == Some("auth")
                            && let Some(auth_val) = arr[1].as_str()
                        {
                            // The auth_val will be exactly the ssh key like "ssh-ed25519 AAA..."
                            // Sometimes there are multiple spaces, so trim and compare, or check if it contains the pubkey
                            // Because public_key_str contains "ssh-ed25519 AAAA...", an exact string match is usually correct
                            // For PGP, we check if it matches the pgp-fingerprint
                            let auth_trim = auth_val.trim();
                            if expected_auth_strings.iter().any(|s| s.as_str() == auth_trim) {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

pub fn build_expected_message(asn: u32, wg_pubkey: Option<&WgPubKey>) -> String {
    match wg_pubkey {
        Some(key) => format!("ASN:{}|PUBKEY:{}", asn, key),
        None => format!("ASN:{}|DELETE", asn),
    }
}
