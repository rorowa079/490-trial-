-- Hot-path index. No table in this file ever holds a plaintext plate.

CREATE TABLE IF NOT EXISTS sightings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,          -- unix seconds
    camera_id       TEXT    NOT NULL,
    track_id        INTEGER,
    plate_hash      TEXT,                      -- HMAC-SHA256, null if unreadable
    ocr_confidence  REAL,
    color           TEXT,
    body_type       TEXT,
    make            TEXT,
    model           TEXT,
    damage          TEXT,
    direction       TEXT,
    speed_kph       REAL,
    clip_id         TEXT                       -- sealed clip, if one was kept
);
CREATE INDEX IF NOT EXISTS idx_sightings_ts   ON sightings (ts);
CREATE INDEX IF NOT EXISTS idx_sightings_hash ON sightings (plate_hash);

-- Stolen-vehicle hotlist, stored only as hashes made with this device's key.
CREATE TABLE IF NOT EXISTS hotlist (
    plate_hash  TEXT PRIMARY KEY,
    case_ref    TEXT,
    color       TEXT,
    body_type   TEXT,
    make        TEXT,
    model       TEXT,
    source      TEXT,
    added_ts    REAL NOT NULL
);

-- Matches waiting for (or resolved by) a human reviewer.
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sighting_id     INTEGER NOT NULL REFERENCES sightings (id),
    hotlist_hash    TEXT    NOT NULL,
    case_ref        TEXT,
    confidence      REAL    NOT NULL,
    attr_report     TEXT    NOT NULL,          -- JSON: matching and non-matching attributes
    status          TEXT    NOT NULL DEFAULT 'pending',  -- pending | approved | dismissed
    created_ts      REAL    NOT NULL,
    reviewed_ts     REAL,
    reviewed_by     TEXT,
    justification   TEXT,
    observations    TEXT,                      -- JSON: what the reviewer saw
    snapshot_path   TEXT                       -- encrypted review image, deleted after review
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);

-- Sealed evidence clips. The file is useless once its day key is destroyed.
CREATE TABLE IF NOT EXISTS clips (
    id          TEXT PRIMARY KEY,
    ts_start    REAL NOT NULL,
    ts_end      REAL NOT NULL,
    day         TEXT NOT NULL,                 -- YYYY-MM-DD (UTC)
    key_id      TEXT NOT NULL,
    path        TEXT NOT NULL,
    frame_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clips_day ON clips (day);

CREATE TABLE IF NOT EXISTS legal_holds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_ref    TEXT NOT NULL,
    ts_start    REAL NOT NULL,
    ts_end      REAL NOT NULL,
    expires_ts  REAL NOT NULL,
    created_by  TEXT NOT NULL,
    created_ts  REAL NOT NULL,
    released_ts REAL
);

CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    pw_salt       BLOB NOT NULL,
    pw_hash       BLOB NOT NULL,                -- PBKDF2-HMAC-SHA256
    pw_iterations INTEGER NOT NULL,
    role          TEXT NOT NULL,                -- reviewer | investigator | supervisor | auditor | admin
    totp_secret   TEXT,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_ts    REAL NOT NULL
);

-- FIDO2 / WebAuthn security keys (phishing-resistant second factor).
-- Only the public key is stored; the private key never leaves the authenticator.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id BLOB PRIMARY KEY,
    username      TEXT NOT NULL REFERENCES users (username),
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    name          TEXT NOT NULL,
    created_ts    REAL NOT NULL,
    last_used_ts  REAL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials (username);

-- Daily totals for the public transparency report. Counts only: nothing here
-- identifies a vehicle, so these rows outlive the retention purge.
CREATE TABLE IF NOT EXISTS daily_stats (
    day         TEXT PRIMARY KEY,               -- YYYY-MM-DD (UTC)
    reads       INTEGER NOT NULL DEFAULT 0,     -- vehicles indexed
    plate_reads INTEGER NOT NULL DEFAULT 0,     -- of those, with a plate hash
    hits        INTEGER NOT NULL DEFAULT 0,     -- hotlist matches queued for review
    approved    INTEGER NOT NULL DEFAULT 0,
    dismissed   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS unseal_requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    clip_id      TEXT NOT NULL REFERENCES clips (id),
    case_ref     TEXT NOT NULL,
    reason       TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'awaiting_shares',  -- awaiting_shares | unsealed | failed | expired
    contributors TEXT NOT NULL DEFAULT '[]',   -- JSON list of usernames who supplied a share
    created_ts   REAL NOT NULL,
    resolved_ts  REAL
);
