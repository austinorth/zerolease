-- zerolease audit log table (SQLite)
-- Schema version: 1

CREATE TABLE IF NOT EXISTS audit_events (
    event_id      TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    event         TEXT NOT NULL,
    agent         TEXT NOT NULL,
    peer_identity TEXT NOT NULL,
    outcome       TEXT NOT NULL,
    secret_name   TEXT,
    lease_id      TEXT
);
