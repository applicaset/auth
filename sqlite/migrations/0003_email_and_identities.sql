-- SQLite cannot drop a CHECK or add a UNIQUE column in place, so users is rebuilt. Dropping it with
-- foreign keys on would cascade into sessions, and PRAGMA foreign_keys is a no-op inside the
-- migration's transaction, so sessions is set aside and restored.
CREATE TABLE sessions_backup AS SELECT * FROM sessions;

DROP TABLE sessions;

CREATE TABLE users_new (
    id                TEXT NOT NULL PRIMARY KEY,
    username          TEXT NOT NULL UNIQUE,
    -- NULL for accounts from before emails were collected. UNIQUE lets any number of NULLs through.
    email             TEXT UNIQUE,
    email_verified_at TEXT,
    name              TEXT NOT NULL DEFAULT '',
    -- Empty for an account that signs in by email link or a provider only.
    password_hash     TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    CHECK (username = lower(username)),
    CHECK (length(username) BETWEEN 3 AND 32),
    CHECK (email = lower(email)),
    CHECK (email_verified_at IS NULL OR email IS NOT NULL)
) STRICT;

INSERT INTO users_new (id, username, name, password_hash, created_at, updated_at)
SELECT id, username, name, password_hash, created_at, updated_at FROM users;

DROP TABLE users;

ALTER TABLE users_new RENAME TO users;

CREATE TABLE sessions (
    id         TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT ''
) STRICT;

INSERT INTO sessions SELECT * FROM sessions_backup;

DROP TABLE sessions_backup;

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE tokens (
    -- SHA-256 of the secret in the mailed link. The secret itself is never stored.
    token_hash TEXT NOT NULL PRIMARY KEY,
    purpose    TEXT NOT NULL,
    -- NULL for an email-login link sent to someone with no account yet.
    user_id    TEXT REFERENCES users (id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;

CREATE INDEX tokens_user_id_idx ON tokens (user_id);

CREATE INDEX tokens_expires_at_idx ON tokens (expires_at);

CREATE TABLE identities (
    provider   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (provider, subject)
) STRICT, WITHOUT ROWID;

CREATE INDEX identities_user_id_idx ON identities (user_id);
