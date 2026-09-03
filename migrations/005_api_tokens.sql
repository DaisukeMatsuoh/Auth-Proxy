-- API tokens for non-browser clients (Bearer authentication, Phase API-1)
CREATE TABLE IF NOT EXISTS api_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    token_hash    TEXT    NOT NULL UNIQUE,  -- SHA-256 hex digest; plaintext is never stored
    name          TEXT    NOT NULL,
    path_prefix   TEXT,                     -- reserved for Phase API-3 (R7); always NULL for now
    expires_at    TEXT,
    last_used_at  TEXT,
    revoked_at    TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id    ON api_tokens(user_id);
