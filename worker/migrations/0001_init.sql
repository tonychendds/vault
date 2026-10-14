CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);

CREATE TABLE IF NOT EXISTS vault_items (
  user_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, item_id)
);

CREATE INDEX IF NOT EXISTS vault_items_user ON vault_items (user_id, updated_at);

-- One row per successful sync. Inserting the next generation makes the
-- optimistic version check atomic: a racing write fails the batch.
CREATE TABLE IF NOT EXISTS vault_claims (
  user_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY (user_id, generation)
);
