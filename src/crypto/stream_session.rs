//! Per-connection transport encryption for the WebSocket chat stream.
//!
//! Each connection performs an ephemeral X25519 key agreement. The shared
//! secret is expanded with HKDF-SHA256 into two independent AES-256-GCM keys,
//! one per direction. Nonces are strictly monotonic counters, which both
//! prevents nonce reuse and gives replay/reordering protection: a frame with
//! an out-of-sequence counter fails authentication.
//!
//! Plaintext exists only inside this process's memory and is zeroized as soon
//! as each frame has been handled.

use anyhow::{anyhow, bail, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use super::aead::{self, AeadKey, NONCE_LEN};
use super::keys::validate_x25519_public_key;

const HKDF_INFO_CLIENT_TO_SERVER: &[u8] = b"encryptr chat-stream v1 c2s";
const HKDF_INFO_SERVER_TO_CLIENT: &[u8] = b"encryptr chat-stream v1 s2c";

/// Server side of the handshake: holds an ephemeral secret until the client's
/// public key arrives.
pub struct Handshake {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl Default for Handshake {
    fn default() -> Self {
        Self::new()
    }
}

impl Handshake {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Complete the handshake with the client's ephemeral public key.
    pub fn complete(self, client_public: &[u8]) -> Result<StreamSession> {
        let client_key_bytes = validate_x25519_public_key(client_public)?;
        let client_key = PublicKey::from(client_key_bytes);
        let shared = self.secret.diffie_hellman(&client_key);
        if !shared.was_contributory() {
            bail!("non-contributory key exchange");
        }

        // Salt binds the derived keys to this exact handshake transcript.
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(self.public.as_bytes());
        salt.extend_from_slice(&client_key_bytes);

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut recv_key = AeadKey([0u8; 32]);
        let mut send_key = AeadKey([0u8; 32]);
        hk.expand(HKDF_INFO_CLIENT_TO_SERVER, &mut recv_key.0)
            .map_err(|_| anyhow!("hkdf expand failed"))?;
        hk.expand(HKDF_INFO_SERVER_TO_CLIENT, &mut send_key.0)
            .map_err(|_| anyhow!("hkdf expand failed"))?;

        Ok(StreamSession {
            recv_key,
            send_key,
            recv_counter: 0,
            send_counter: 0,
        })
    }
}

/// An established, bidirectional encrypted session.
pub struct StreamSession {
    recv_key: AeadKey,
    send_key: AeadKey,
    recv_counter: u64,
    send_counter: u64,
}

impl StreamSession {
    /// Encrypt a server→client frame. Returns `(ciphertext, nonce)`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
        let nonce = counter_nonce(self.send_counter);
        let ciphertext = aead::encrypt_with_nonce(&self.send_key, plaintext, b"s2c", &nonce)?;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("send counter exhausted"))?;
        Ok((ciphertext, nonce))
    }

    /// Decrypt a client→server frame. The nonce must be the next expected
    /// counter value — anything else (replay, reorder, tamper) is rejected.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let expected = counter_nonce(self.recv_counter);
        if nonce != &expected {
            bail!("unexpected nonce: replay or out-of-order frame rejected");
        }
        let plaintext = aead::decrypt(&self.recv_key, ciphertext, b"c2s", nonce)?;
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("recv counter exhausted"))?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Client-side construction, used by tests and reference clients: same
    /// derivation with the directions swapped.
    pub fn client_side(
        client_secret: EphemeralSecret,
        client_public: &PublicKey,
        server_public_bytes: &[u8],
    ) -> Result<Self> {
        let server_key_bytes = validate_x25519_public_key(server_public_bytes)?;
        let server_key = PublicKey::from(server_key_bytes);
        let shared = client_secret.diffie_hellman(&server_key);
        if !shared.was_contributory() {
            bail!("non-contributory key exchange");
        }

        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(&server_key_bytes);
        salt.extend_from_slice(client_public.as_bytes());

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut send_key = AeadKey([0u8; 32]); // client sends c2s
        let mut recv_key = AeadKey([0u8; 32]); // client receives s2c
        hk.expand(HKDF_INFO_CLIENT_TO_SERVER, &mut send_key.0)
            .map_err(|_| anyhow!("hkdf expand failed"))?;
        hk.expand(HKDF_INFO_SERVER_TO_CLIENT, &mut recv_key.0)
            .map_err(|_| anyhow!("hkdf expand failed"))?;

        // For the client, "send" is c2s and "recv" is s2c, which mirrors the
        // server's naming, so swap into the same struct shape.
        Ok(StreamSession {
            recv_key,
            send_key,
            recv_counter: 0,
            send_counter: 0,
        })
    }

    /// Encrypt a client→server frame (client side of the session).
    pub fn encrypt_client(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
        let nonce = counter_nonce(self.send_counter);
        let ciphertext = aead::encrypt_with_nonce(&self.send_key, plaintext, b"c2s", &nonce)?;
        self.send_counter += 1;
        Ok((ciphertext, nonce))
    }

    /// Decrypt a server→client frame (client side of the session).
    pub fn decrypt_client(
        &mut self,
        ciphertext: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let expected = counter_nonce(self.recv_counter);
        if nonce != &expected {
            bail!("unexpected nonce");
        }
        let plaintext = aead::decrypt(&self.recv_key, ciphertext, b"s2c", nonce)?;
        self.recv_counter += 1;
        Ok(Zeroizing::new(plaintext))
    }
}

fn counter_nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn establish() -> (StreamSession, StreamSession) {
        let server = Handshake::new();
        let server_public = server.public_key_bytes();

        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        let server_session = server.complete(client_public.as_bytes()).unwrap();
        let client_session =
            StreamSession::client_side(client_secret, &client_public, &server_public).unwrap();
        (server_session, client_session)
    }

    #[test]
    fn client_to_server_roundtrip() {
        let (mut server, mut client) = establish();
        let (ciphertext, nonce) = client.encrypt_client(b"encrypted prompt").unwrap();
        let plaintext = server.decrypt(&ciphertext, &nonce).unwrap();
        assert_eq!(&plaintext[..], b"encrypted prompt");
    }

    #[test]
    fn server_to_client_roundtrip() {
        let (mut server, mut client) = establish();
        let (ciphertext, nonce) = server.encrypt(b"streamed chunk").unwrap();
        let plaintext = client.decrypt_client(&ciphertext, &nonce).unwrap();
        assert_eq!(&plaintext[..], b"streamed chunk");
    }

    #[test]
    fn replayed_frame_rejected() {
        let (mut server, mut client) = establish();
        let (ciphertext, nonce) = client.encrypt_client(b"one").unwrap();
        server.decrypt(&ciphertext, &nonce).unwrap();
        // Replaying the same frame must fail: the counter has moved on.
        assert!(server.decrypt(&ciphertext, &nonce).is_err());
    }

    #[test]
    fn directions_use_independent_keys() {
        let (server, mut client) = establish();
        let (ciphertext, nonce) = client.encrypt_client(b"hello").unwrap();
        // A server→client decrypt of a client→server frame must fail even at
        // matching counters, because keys and AAD differ per direction.
        assert!(client.decrypt_client(&ciphertext, &nonce).is_err());
        let _ = server;
    }

    #[test]
    fn rejects_small_order_client_key() {
        let server = Handshake::new();
        assert!(server.complete(&[0u8; 32]).is_err());
    }

    #[test]
    fn sequence_of_frames() {
        let (mut server, mut client) = establish();
        for i in 0..10u32 {
            let msg = format!("chunk {i}");
            let (ciphertext, nonce) = server.encrypt(msg.as_bytes()).unwrap();
            let plaintext = client.decrypt_client(&ciphertext, &nonce).unwrap();
            assert_eq!(&plaintext[..], msg.as_bytes());
        }
    }
}
