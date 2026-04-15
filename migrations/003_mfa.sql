-- usersテーブルにMFA関連カラムを追加
ALTER TABLE users ADD COLUMN totp_secret_enc TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;

-- バックアップコード
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT    NOT NULL,
    used_at    TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user_id ON mfa_backup_codes(user_id);

-- MFA一時セッション (パスワード検証済み・TOTP未検証)
CREATE TABLE IF NOT EXISTS mfa_pending_sessions (
    token         TEXT    PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at    TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- デバイス記憶トークン
CREATE TABLE IF NOT EXISTS mfa_device_tokens (
    token      TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mfa_device_tokens_user_id ON mfa_device_tokens(user_id);
