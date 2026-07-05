//! AES-256-GCM authenticated encryption.
//!
//! Used for in-memory transport encryption on the WebSocket streaming path.
//! Persisted message ciphertext is produced client-side; the server only ever
//! sees it as opaque bytes.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// A 256-bit AEAD key that is wiped from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKey(pub [u8; KEY_LEN]);

impl AeadKey {
    pub fn random() -> Self {
        let mut key = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self(key)
    }
}

/// Encrypt `plaintext` with a fresh random nonce.
///
/// Returns `(ciphertext_with_tag, nonce)`.
pub fn encrypt(key: &AeadKey, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = encrypt_with_nonce(key, plaintext, aad, &nonce)?;
    Ok((ciphertext, nonce))
}

/// Encrypt with an explicit nonce (used by the counter-based stream cipher —
/// the caller is responsible for never reusing a nonce under the same key).
pub fn encrypt_with_nonce(
    key: &AeadKey,
    plaintext: &[u8],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|e| anyhow!("bad key length: {e}"))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))
}

/// Decrypt and authenticate. Fails on any tampering of ciphertext, nonce, or AAD.
pub fn decrypt(
    key: &AeadKey,
    ciphertext: &[u8],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|e| anyhow!("bad key length: {e}"))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("decryption failed: ciphertext rejected"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = AeadKey::random();
        let (ciphertext, nonce) = encrypt(&key, b"attack at dawn", b"aad").unwrap();
        assert_ne!(&ciphertext[..14.min(ciphertext.len())], b"attack at dawn");
        let plaintext = decrypt(&key, &ciphertext, b"aad", &nonce).unwrap();
        assert_eq!(plaintext, b"attack at dawn");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = AeadKey::random();
        let (mut ciphertext, nonce) = encrypt(&key, b"hello", b"").unwrap();
        ciphertext[0] ^= 0x01;
        assert!(decrypt(&key, &ciphertext, b"", &nonce).is_err());
    }

    #[test]
    fn wrong_aad_rejected() {
        let key = AeadKey::random();
        let (ciphertext, nonce) = encrypt(&key, b"hello", b"context-a").unwrap();
        assert!(decrypt(&key, &ciphertext, b"context-b", &nonce).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let key = AeadKey::random();
        let (ciphertext, nonce) = encrypt(&key, b"hello", b"").unwrap();
        let other = AeadKey::random();
        assert!(decrypt(&other, &ciphertext, b"", &nonce).is_err());
    }

    #[test]
    fn ciphertext_includes_tag() {
        let key = AeadKey::random();
        let (ciphertext, _) = encrypt(&key, b"x", b"").unwrap();
        assert_eq!(ciphertext.len(), 1 + TAG_LEN);
    }
}
