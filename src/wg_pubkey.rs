use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
// newtype pattern: wrap a string but restrict how it can be created
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WgPubKey(String);

impl WgPubKey {
    // the only way to instantiate this struct is through this parse method
    pub fn parse(s: String) -> Result<Self, &'static str> {
        if s.len() != 44 {
            return Err("wireguard public key must be exactly 44 characters");
        }

        let bytes = STANDARD.decode(&s).map_err(|_| "invalid base64 encoding")?;

        if bytes.len() != 32 {
            return Err("wireguard public key must decode to exactly 32 bytes");
        }

        // if all checks pass, wrap and return
        Ok(Self(s))
    }

    // allows borrowing as a string slice for askama templates or netlink
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// implement display so askama templates can render it directly like {{ pubkey }}
impl fmt::Display for WgPubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
