//! Authentication flows: register, login, refresh-token rotation, logout.

use chrono::{Duration as ChronoDuration, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::crypto::{password, tokens};
use crate::domain::dto::{RegisterRequest, TokenResponse};
use crate::domain::models::User;
use crate::domain::validate;
use crate::error::{AppError, AppResult};
use crate::repositories::{sessions, users};
use crate::state::AppState;

use super::audit;

/// Client metadata attached to sessions and audit events.
#[derive(Debug, Clone, Default)]
pub struct ClientMeta {
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

pub async fn register(
    state: &AppState,
    request: RegisterRequest,
    meta: &ClientMeta,
) -> AppResult<User> {
    let email = validate::email(&request.email)?;
    validate::password(&request.password)?;

    if users::find_by_email(&state.pool, &email).await?.is_some() {
        return Err(AppError::Conflict(
            "an account with this email already exists".into(),
        ));
    }

    let password_hash = password::hash_password(&request.password)?;
    let user = users::insert(
        &state.pool,
        &email,
        &password_hash,
        request.display_name.as_deref(),
    )
    .await?;

    audit::record(
        &state.pool,
        Some(user.id),
        "user.registered",
        json!({}),
        meta.ip_address.as_deref(),
    )
    .await;

    Ok(user)
}

pub async fn login(
    state: &AppState,
    email: &str,
    password_input: &str,
    meta: &ClientMeta,
) -> AppResult<TokenResponse> {
    let email = validate::email(email)?;
    let user = users::find_by_email(&state.pool, &email).await?;

    // Always run a password verification so response timing does not reveal
    // whether the account exists.
    const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$GpZ3sK/oH9p7bIfIHg6TCVGFeDXS0OGWKgcpMoQ99bs";
    let (user, valid) = match user {
        Some(user) => {
            let ok = password::verify_password(password_input, &user.password_hash);
            (Some(user), ok)
        }
        None => {
            let _ = password::verify_password(password_input, DUMMY_HASH);
            (None, false)
        }
    };

    let Some(user) = user.filter(|_| valid) else {
        audit::record(
            &state.pool,
            None,
            "auth.login_failed",
            json!({}),
            meta.ip_address.as_deref(),
        )
        .await;
        return Err(AppError::Unauthorized);
    };

    let session = sessions::create_session(
        &state.pool,
        user.id,
        meta.user_agent.as_deref(),
        meta.ip_address.as_deref(),
    )
    .await?;

    let response = issue_tokens(state, user.id, session.id).await?;

    audit::record(
        &state.pool,
        Some(user.id),
        "auth.login",
        json!({ "session_id": session.id }),
        meta.ip_address.as_deref(),
    )
    .await;

    Ok(response)
}

/// Exchange a refresh token for a new access/refresh pair (rotation).
///
/// Reuse of an already-rotated token is treated as theft: the whole session
/// is revoked and the event is audited.
pub async fn refresh(
    state: &AppState,
    refresh_token: &str,
    meta: &ClientMeta,
) -> AppResult<TokenResponse> {
    let token_hash = tokens::hash_token(refresh_token);
    let Some(record) = sessions::find_refresh_token(&state.pool, &token_hash).await? else {
        return Err(AppError::Unauthorized);
    };

    if record.rotated_at.is_some() {
        // Replay of a consumed token — revoke everything tied to the session.
        sessions::revoke_session(&state.pool, record.session_id).await?;
        audit::record(
            &state.pool,
            Some(record.user_id),
            "auth.refresh_token_reuse_detected",
            json!({ "session_id": record.session_id }),
            meta.ip_address.as_deref(),
        )
        .await;
        return Err(AppError::Unauthorized);
    }

    if record.revoked_at.is_some()
        || record.expires_at < Utc::now()
        || !sessions::is_active(&state.pool, record.session_id).await?
    {
        return Err(AppError::Unauthorized);
    }

    sessions::mark_rotated(&state.pool, record.id).await?;
    let response = issue_tokens(state, record.user_id, record.session_id).await?;

    audit::record(
        &state.pool,
        Some(record.user_id),
        "auth.token_refreshed",
        json!({ "session_id": record.session_id }),
        meta.ip_address.as_deref(),
    )
    .await;

    Ok(response)
}

pub async fn logout(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    meta: &ClientMeta,
) -> AppResult<()> {
    sessions::revoke_session(&state.pool, session_id).await?;
    audit::record(
        &state.pool,
        Some(user_id),
        "auth.logout",
        json!({ "session_id": session_id }),
        meta.ip_address.as_deref(),
    )
    .await;
    Ok(())
}

async fn issue_tokens(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
) -> AppResult<TokenResponse> {
    let access_token = state.jwt.issue(user_id, session_id)?;

    let refresh_token = tokens::generate_token();
    let token_hash = tokens::hash_token(&refresh_token);
    let expires_at = Utc::now()
        + ChronoDuration::from_std(state.config.refresh_token_ttl)
            .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    sessions::insert_refresh_token(&state.pool, session_id, user_id, &token_hash, expires_at)
        .await?;

    Ok(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in: state.jwt.ttl().as_secs(),
    })
}
