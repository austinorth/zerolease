-- zerolease secret store schema (PostgreSQL)
-- Schema version: 1

CREATE TABLE IF NOT EXISTS secrets (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    ciphertext  BYTEA NOT NULL,
    nonce       BYTEA NOT NULL,
    algorithm   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1
);
