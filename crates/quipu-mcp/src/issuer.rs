//! Access-token issuer: mint a scoped bearer token for an agent (or any
//! `quipu-server` client) and print the line to paste into the server's
//! `auth.tokens` config.
//!
//! Quipu-Log's token infrastructure already does the hard parts — tokens are
//! stored hashed (`sha256:<hex>`), can carry an expiry, and reload on SIGHUP
//! (see the quipu-server token-lifecycle docs). What was missing is the
//! issuing end: a way to generate a fresh token and the config entry for it
//! without hand-rolling `openssl`/`shasum`. That is all this is.
//!
//! "Scopes" are not a separate system: they are the existing **roles**. An MCP
//! agent that should only read gets a token mapped to a `query`-granted role;
//! one that may also run integrity checks gets an `administer`-granted role.
//! The issuer just names the role on the token; the grant lives in the
//! server's `auth.grants`. See the crate README's scope design.

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// A freshly issued token and the artifacts an operator needs.
pub struct IssuedToken {
    /// The secret to hand to the client. Printed once — it is never recoverable
    /// from the config, which stores only its hash.
    pub token: String,
    /// `sha256:<hex>` — the config-side key, so the config file is not itself a
    /// credential.
    pub hashed_key: String,
    pub role: String,
    pub expires: Option<u64>,
}

impl IssuedToken {
    /// The JSON entry to add under `auth.tokens` (value is bare role, or
    /// `{role, expires}` when an expiry was set).
    pub fn config_entry(&self) -> String {
        match self.expires {
            None => format!("\"{}\": \"{}\"", self.hashed_key, self.role),
            Some(exp) => format!(
                "\"{}\": {{ \"role\": \"{}\", \"expires\": {} }}",
                self.hashed_key, self.role, exp
            ),
        }
    }
}

/// Mint a token for `role`, optionally expiring at `expires` (unix seconds).
/// The token is 32 random bytes, URL-safe-base64-ish hex — opaque and
/// high-entropy, so its `sha256` cannot be brute-forced off the config.
pub fn issue(role: &str, expires: Option<u64>) -> IssuedToken {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = hex(&bytes);
    let hashed_key = format!("sha256:{}", sha256_hex(&token));
    IssuedToken {
        token,
        hashed_key,
        role: role.to_string(),
        expires,
    }
}

/// SHA-256 as lowercase hex — the same encoding `quipu-server` hashes tokens
/// with, so the printed `sha256:` key matches what the server computes.
pub fn sha256_hex(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_token_hash_matches_server_hashing() {
        let issued = issue("audit-reader", None);
        // the hashed key is exactly sha256: + sha256_hex(token)
        assert_eq!(
            issued.hashed_key,
            format!("sha256:{}", sha256_hex(&issued.token))
        );
        assert_eq!(issued.token.len(), 64); // 32 bytes hex
        assert!(issued.config_entry().contains("audit-reader"));
        assert!(
            !issued.config_entry().contains(&issued.token),
            "config stores the hash, not the token"
        );
    }

    #[test]
    fn expiry_shapes_the_config_entry() {
        let issued = issue("audit-admin", Some(1_900_000_000));
        assert!(issued.config_entry().contains("\"expires\": 1900000000"));
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(issue("r", None).token, issue("r", None).token);
    }
}
