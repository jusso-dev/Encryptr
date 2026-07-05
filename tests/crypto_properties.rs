//! Property-based tests for the crypto layer.

use encryptr_server::crypto::aead::{self, AeadKey};
use encryptr_server::crypto::tokens;
use proptest::prelude::*;

proptest! {
    /// Any payload encrypts and decrypts back to itself.
    #[test]
    fn aead_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
                      aad in proptest::collection::vec(any::<u8>(), 0..64)) {
        let key = AeadKey::random();
        let (ciphertext, nonce) = aead::encrypt(&key, &plaintext, &aad).unwrap();
        let decrypted = aead::decrypt(&key, &ciphertext, &aad, &nonce).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    /// Flipping any single bit of the ciphertext (or its tag) is detected.
    #[test]
    fn aead_detects_any_bitflip(plaintext in proptest::collection::vec(any::<u8>(), 1..256),
                                byte_index: prop::sample::Index,
                                bit in 0u8..8) {
        let key = AeadKey::random();
        let (mut ciphertext, nonce) = aead::encrypt(&key, &plaintext, b"").unwrap();
        let index = byte_index.index(ciphertext.len());
        ciphertext[index] ^= 1 << bit;
        prop_assert!(aead::decrypt(&key, &ciphertext, b"", &nonce).is_err());
    }

    /// Ciphertext is always plaintext length plus the 16-byte tag.
    #[test]
    fn aead_length_is_predictable(plaintext in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let key = AeadKey::random();
        let (ciphertext, _) = aead::encrypt(&key, &plaintext, b"").unwrap();
        prop_assert_eq!(ciphertext.len(), plaintext.len() + aead::TAG_LEN);
    }

    /// Token hashing is deterministic and 64 hex chars, whatever the input.
    #[test]
    fn token_hash_shape(token in ".{0,128}") {
        let h1 = tokens::hash_token(&token);
        let h2 = tokens::hash_token(&token);
        prop_assert_eq!(&h1, &h2);
        prop_assert_eq!(h1.len(), 64);
        prop_assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
