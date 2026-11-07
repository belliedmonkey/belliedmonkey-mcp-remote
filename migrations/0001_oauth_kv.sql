-- BEL-213 preview: OAuth provider state in D1.
-- One row per KV key. Expiry is enforced on read; no cron is required.
CREATE TABLE IF NOT EXISTS oauth_kv (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL,
  metadata TEXT,
  expires_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_oauth_kv_expires_at ON oauth_kv (expires_at);
