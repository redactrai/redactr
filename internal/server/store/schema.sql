CREATE TABLE IF NOT EXISTS orgs (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token_hash  TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES orgs(id),
  expires_at  TIMESTAMP NOT NULL,
  max_uses    INTEGER NOT NULL,
  used_count  INTEGER NOT NULL DEFAULT 0,
  revoked     INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL REFERENCES orgs(id),
  name          TEXT NOT NULL,
  platform      TEXT NOT NULL,
  enrolled_at   TIMESTAMP NOT NULL,
  last_seen_at  TIMESTAMP,
  revoked       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_devices_org ON devices(org_id);

CREATE TABLE IF NOT EXISTS policies (
  org_id      TEXT PRIMARY KEY REFERENCES orgs(id),
  bundle_json TEXT NOT NULL,
  version     INTEGER NOT NULL,
  updated_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id                TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL REFERENCES orgs(id),
  device_id         TEXT NOT NULL,
  tool              TEXT NOT NULL,
  verdict           TEXT NOT NULL,
  reason            TEXT NOT NULL,
  direct_conn_count INTEGER NOT NULL,
  observed_at       TIMESTAMP NOT NULL,
  received_at       TIMESTAMP NOT NULL,
  uuid              TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_org ON events(org_id, received_at);

CREATE TABLE IF NOT EXISTS audit_records (
  uuid        TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  provider    TEXT NOT NULL,
  source      TEXT NOT NULL,
  detector    TEXT NOT NULL,
  category    TEXT NOT NULL,
  action      TEXT NOT NULL,
  latency_ms  INTEGER NOT NULL,
  observed_at TIMESTAMP NOT NULL,
  received_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_records(org_id, received_at);

CREATE TABLE IF NOT EXISTS images (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES orgs(id),
  tag         TEXT NOT NULL,
  ref         TEXT NOT NULL DEFAULT '',
  digest      TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL,
  created_at  TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_images_org ON images(org_id, created_at);
