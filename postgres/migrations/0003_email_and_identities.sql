ALTER TABLE users DROP CONSTRAINT users_password_hash_present;

ALTER TABLE users ALTER COLUMN password_hash SET DEFAULT '';

-- NULL for accounts from before emails were collected. UNIQUE lets any number of NULLs through.
ALTER TABLE users ADD COLUMN email text COLLATE "C" UNIQUE;

ALTER TABLE users ADD COLUMN email_verified_at timestamptz;

ALTER TABLE users ADD CONSTRAINT users_email_is_lower CHECK (email = lower(email));

ALTER TABLE users ADD CONSTRAINT users_verified_needs_email
    CHECK (email_verified_at IS NULL OR email IS NOT NULL);

CREATE TABLE tokens (
    -- SHA-256 of the secret in the mailed link. The secret itself is never stored.
    token_hash text COLLATE "C" NOT NULL PRIMARY KEY,
    purpose    text NOT NULL,
    -- NULL for an email-login link sent to someone with no account yet.
    user_id    text COLLATE "C" REFERENCES users (id) ON DELETE CASCADE,
    email      text COLLATE "C" NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX tokens_user_id_idx ON tokens (user_id);

CREATE INDEX tokens_expires_at_idx ON tokens (expires_at);

CREATE TABLE identities (
    provider   text COLLATE "C" NOT NULL,
    subject    text COLLATE "C" NOT NULL,
    user_id    text COLLATE "C" NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    PRIMARY KEY (provider, subject)
);

CREATE INDEX identities_user_id_idx ON identities (user_id);
