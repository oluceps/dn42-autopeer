use std::fmt;
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use snafu::ResultExt;
use crate::error::{PeerError, InvalidWgPubKeyLengthSnafu, InvalidWgPubKeyBase64Snafu};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WgPubKey(String);

impl TryFrom<String> for WgPubKey {
    type Error = PeerError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 44 {
            return InvalidWgPubKeyLengthSnafu { len: value.len() }.fail();
        }
        STANDARD.decode(&value).context(InvalidWgPubKeyBase64Snafu)?;
        Ok(Self(value))
    }
}

impl From<WgPubKey> for String {
    fn from(val: WgPubKey) -> Self {
        val.0
    }
}

impl WgPubKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WgPubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_wg_pubkey() {
        let valid_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
        let pubkey = WgPubKey::try_from(valid_key.clone()).unwrap();
        assert_eq!(pubkey.as_str(), valid_key);
    }

    #[test]
    fn test_invalid_length() {
        let invalid_key = "too_short=".to_string();
        let err = WgPubKey::try_from(invalid_key).unwrap_err();
        match err {
            PeerError::InvalidWgPubKeyLength { len } => assert_eq!(len, 10),
            _ => panic!("Expected InvalidWgPubKeyLength"),
        }
    }

    #[test]
    fn test_invalid_base64() {
        let invalid_key = "invalid_base64!@#$%^&*()_+{}|:<>?~`-=[]\\;',.".to_string();
        let err = WgPubKey::try_from(invalid_key).unwrap_err();
        match err {
            PeerError::InvalidWgPubKeyBase64 { .. } => (),
            _ => panic!("Expected InvalidWgPubKeyBase64"),
        }
    }
}
