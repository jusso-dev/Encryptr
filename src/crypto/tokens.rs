//! Opaque token generation and hashing (refresh tokens, API keys).
//!
//! Raw tokens are handed to the client exactly once; only a SHA-256 digest is
//! persisted, so a database leak cannot be replayed against the API.

use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Generate a 256-bit random token, URL-safe base64 encoded.
pub fn generate_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hex digest used as the stored lookup key for opaque tokens.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(&digest)
}

/// Constant-time comparison of two token hashes.
pub fn hashes_equal(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn hex_encode(bytes: &[u8]) -> String {
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
    fn tokens_are_unique_and_urlsafe() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_eq!(a.len(), 43); // 32 bytes base64url without padding
    }

    #[test]
    fn hash_is_deterministic_hex() {
        let h1 = hash_token("token");
        let h2 = hash_token("token");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_tokens_hash_differently() {
        assert_ne!(hash_token("a"), hash_token("b"));
    }

    #[test]
    fn constant_time_compare() {
        let h = hash_token("x");
        assert!(hashes_equal(&h, &h.clone()));
        assert!(!hashes_equal(&h, &hash_token("y")));
    }
}
