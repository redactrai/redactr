ALTER TABLE events ADD COLUMN uuid TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_uuid ON events(uuid);
