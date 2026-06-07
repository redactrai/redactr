CREATE TABLE IF NOT EXISTS admins (
  email      TEXT PRIMARY KEY,
  added_by   TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  subject    TEXT NOT NULL,
  role       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX idx_sessions_expires ON sessions(expires_at);
