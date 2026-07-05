//! JWT access-token issuance and validation.

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// User id.
    pub sub: Uuid,
    /// Session id — lets us revoke every token issued for a session.
    pub sid: Uuid,
    /// Unique token id (replay tracing / audit correlation).
    pub jti: Uuid,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
}

const ISSUER: &str = "encryptr-server";

pub struct JwtService {
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl: Duration,
    validation: Validation,
}

impl JwtService {
    pub fn new(secret: &[u8], ttl: Duration) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[ISSUER]);
        validation.leeway = 5;
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            ttl,
            validation,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn issue(&self, user_id: Uuid, session_id: Uuid) -> anyhow::Result<String> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: user_id,
            sid: session_id,
            jti: Uuid::new_v4(),
            iat: now,
            exp: now + self.ttl.as_secs() as i64,
            iss: ISSUER.to_string(),
        };
        Ok(encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &self.encoding,
        )?)
    }

    pub fn verify(&self, token: &str) -> Option<Claims> {
        decode::<Claims>(token, &self.decoding, &self.validation)
            .map(|data| data.claims)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> JwtService {
        JwtService::new(
            b"0123456789abcdef0123456789abcdef",
            Duration::from_secs(900),
        )
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let svc = service();
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        let token = svc.issue(user, session).unwrap();
        let claims = svc.verify(&token).unwrap();
        assert_eq!(claims.sub, user);
        assert_eq!(claims.sid, session);
        assert_eq!(claims.iss, "encryptr-server");
    }

    #[test]
    fn rejects_wrong_secret() {
        let token = service().issue(Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let other = JwtService::new(
            b"another-secret-another-secret-32",
            Duration::from_secs(900),
        );
        assert!(other.verify(&token).is_none());
    }

    #[test]
    fn rejects_expired_token() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: Uuid::new_v4(),
            sid: Uuid::new_v4(),
            jti: Uuid::new_v4(),
            iat: now - 3600,
            exp: now - 1800, // expired half an hour ago
            iss: ISSUER.to_string(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        assert!(service().verify(&token).is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(service().verify("not.a.jwt").is_none());
    }
}
