//! Cryptographic services.
//!
//! Everything security-sensitive lives here so it can be audited and tested
//! in isolation: password hashing, JWT issuance/validation, AEAD encryption,
//! client public-key validation, and the per-connection stream cipher used by
//! the WebSocket chat endpoint.

pub mod aead;
pub mod jwt;
pub mod keys;
pub mod password;
pub mod stream_session;
pub mod tokens;
