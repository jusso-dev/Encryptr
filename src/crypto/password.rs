//! Argon2id password hashing.

use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// Hash a password with Argon2id and a random salt.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored Argon2id hash.
///
/// Argon2 verification is constant-time in the hash comparison; a `false`
/// return covers both "wrong password" and "malformed hash" so callers can't
/// distinguish the two.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &hash));
    }

    #[test]
    fn wrong_password_fails() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(!verify_password("incorrect horse", &hash));
    }

    #[test]
    fn malformed_hash_fails_closed() {
        assert!(!verify_password("anything", "not-a-phc-string"));
    }

    #[test]
    fn hashes_are_salted() {
        let a = hash_password("same password").unwrap();
        let b = hash_password("same password").unwrap();
        assert_ne!(a, b);
    }
}
