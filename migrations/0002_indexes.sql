-- Supporting indexes for foreign keys and cleanup scans.
--
-- Without these, user-scoped message/key queries and the ON DELETE CASCADE that
-- fires when a user is removed fall back to sequential scans, and the expiry
-- sweep over refresh_tokens has no index to use.

CREATE INDEX IF NOT EXISTS encrypted_messages_user_id_idx
    ON encrypted_messages (user_id);

CREATE INDEX IF NOT EXISTS api_keys_user_id_idx
    ON api_keys (user_id);

CREATE INDEX IF NOT EXISTS public_keys_user_id_idx
    ON public_keys (user_id);

CREATE INDEX IF NOT EXISTS refresh_tokens_expires_at_idx
    ON refresh_tokens (expires_at);
