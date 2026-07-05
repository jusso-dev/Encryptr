//! Validation of client-uploaded public keys.
//!
//! The server stores only public keys — an Ed25519 signing key and an X25519
//! key-agreement key per device. Both are validated on upload so that garbage
//! or weak keys are rejected early.

use anyhow::{bail, Result};
use ed25519_dalek::VerifyingKey;

pub const PUBLIC_KEY_LEN: usize = 32;

/// Validate an Ed25519 public key: correct length, a valid curve point, and
/// not from the small-order (torsion) subgroup.
pub fn validate_ed25519_public_key(bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN]> {
    let arr: [u8; PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed25519 public key must be exactly 32 bytes"))?;
    let key = match VerifyingKey::from_bytes(&arr) {
        Ok(key) => key,
        Err(_) => bail!("ed25519 public key is not a valid curve point"),
    };
    if key.is_weak() {
        bail!("ed25519 public key is a weak (small-order) point");
    }
    Ok(arr)
}

/// Validate an X25519 public key: correct length and not a small-order point
/// (which would force the shared secret to a known value).
pub fn validate_x25519_public_key(bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN]> {
    let arr: [u8; PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("x25519 public key must be exactly 32 bytes"))?;
    if is_small_order_x25519(&arr) {
        bail!("x25519 public key is a small-order point");
    }
    Ok(arr)
}

/// The canonical low-order points on Curve25519 (RFC 7748 / libsodium's
/// blocklist). Any of these as a peer public key yields an all-zero or
/// attacker-known shared secret.
fn is_small_order_x25519(key: &[u8; 32]) -> bool {
    const SMALL_ORDER: [[u8; 32]; 7] = [
        // 0 (order 1)
        [0; 32],
        // 1 (order 1)
        {
            let mut p = [0; 32];
            p[0] = 1;
            p
        },
        // 325606250916557431795983626356110631294008115727848805560023387167927233504
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        // p - 1 (order 2)
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // p (order 4, equivalent to 0)
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // p + 1 (order 1, equivalent to 1)
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];
    // The high bit of an X25519 public key is ignored by the DH function, so
    // mask it before comparing against the blocklist.
    let mut masked = *key;
    masked[31] &= 0x7f;
    SMALL_ORDER.iter().any(|p| {
        let mut p_masked = *p;
        p_masked[31] &= 0x7f;
        p_masked == masked
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn accepts_valid_ed25519_key() {
        let signing = SigningKey::generate(&mut OsRng);
        let bytes = signing.verifying_key().to_bytes();
        assert!(validate_ed25519_public_key(&bytes).is_ok());
    }

    #[test]
    fn rejects_wrong_length_ed25519() {
        assert!(validate_ed25519_public_key(&[0u8; 31]).is_err());
        assert!(validate_ed25519_public_key(&[0u8; 33]).is_err());
    }

    #[test]
    fn rejects_weak_ed25519_key() {
        // The identity point is small-order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(validate_ed25519_public_key(&identity).is_err());
    }

    #[test]
    fn accepts_valid_x25519_key() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        assert!(validate_x25519_public_key(public.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_small_order_x25519_keys() {
        assert!(validate_x25519_public_key(&[0u8; 32]).is_err());
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(validate_x25519_public_key(&one).is_err());
    }

    #[test]
    fn rejects_wrong_length_x25519() {
        assert!(validate_x25519_public_key(&[7u8; 16]).is_err());
    }
}
