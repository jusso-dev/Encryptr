//! Request validation helpers.

use crate::error::AppError;

pub const MIN_PASSWORD_LEN: usize = 10;
pub const MAX_PASSWORD_LEN: usize = 128;
pub const MAX_EMAIL_LEN: usize = 254;
pub const MAX_TITLE_LEN: usize = 200;
pub const MAX_LABEL_LEN: usize = 64;
/// 256 KiB of ciphertext per message is generous for chat while bounding abuse.
pub const MAX_CIPHERTEXT_BYTES: usize = 256 * 1024;

pub fn email(raw: &str) -> Result<String, AppError> {
    let email = raw.trim().to_ascii_lowercase();
    let valid = email.len() <= MAX_EMAIL_LEN
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !email.chars().any(char::is_whitespace)
        });
    if !valid {
        return Err(AppError::Validation("email address is invalid".into()));
    }
    Ok(email)
}

pub fn password(raw: &str) -> Result<(), AppError> {
    if raw.len() < MIN_PASSWORD_LEN {
        return Err(AppError::Validation(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if raw.len() > MAX_PASSWORD_LEN {
        return Err(AppError::Validation(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

pub fn title(raw: &str) -> Result<String, AppError> {
    let title = raw.trim();
    if title.is_empty() {
        return Err(AppError::Validation("title must not be empty".into()));
    }
    if title.chars().count() > MAX_TITLE_LEN {
        return Err(AppError::Validation(format!(
            "title must be at most {MAX_TITLE_LEN} characters"
        )));
    }
    Ok(title.to_string())
}

pub fn label(raw: &str) -> Result<String, AppError> {
    let label = raw.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL_LEN {
        return Err(AppError::Validation(format!(
            "label must be 1..={MAX_LABEL_LEN} characters"
        )));
    }
    Ok(label.to_string())
}

pub fn message_role(raw: &str) -> Result<String, AppError> {
    match raw {
        "user" | "assistant" => Ok(raw.to_string()),
        _ => Err(AppError::Validation(
            "role must be 'user' or 'assistant'".into(),
        )),
    }
}

pub fn base64_field(raw: &str, field: &str, max_decoded: usize) -> Result<Vec<u8>, AppError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| AppError::Validation(format!("{field} must be valid base64")))?;
    if bytes.is_empty() {
        return Err(AppError::Validation(format!("{field} must not be empty")));
    }
    if bytes.len() > max_decoded {
        return Err(AppError::Validation(format!(
            "{field} exceeds the maximum size of {max_decoded} bytes"
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalizes_and_validates() {
        assert_eq!(email("  User@Example.COM ").unwrap(), "user@example.com");
        assert!(email("missing-at").is_err());
        assert!(email("@nodomain").is_err());
        assert!(email("user@").is_err());
        assert!(email("user@nodot").is_err());
        assert!(email("user@.leading").is_err());
        assert!(email("has space@example.com").is_err());
    }

    #[test]
    fn password_length_bounds() {
        assert!(password("short").is_err());
        assert!(password(&"x".repeat(MIN_PASSWORD_LEN)).is_ok());
        assert!(password(&"x".repeat(MAX_PASSWORD_LEN + 1)).is_err());
    }

    #[test]
    fn role_whitelist() {
        assert!(message_role("user").is_ok());
        assert!(message_role("assistant").is_ok());
        assert!(message_role("system").is_err());
        assert!(message_role("USER").is_err());
    }

    #[test]
    fn base64_bounds() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        assert!(base64_field(&b64.encode([1, 2, 3]), "f", 10).is_ok());
        assert!(base64_field("!!!not-base64!!!", "f", 10).is_err());
        assert!(base64_field("", "f", 10).is_err());
        assert!(base64_field(&b64.encode([0u8; 11]), "f", 10).is_err());
    }
}
