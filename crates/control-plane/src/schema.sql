PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, all_servers INTEGER NOT NULL DEFAULT 1,
 valid_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS servers (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, endpoint TEXT NOT NULL,
 public_key TEXT NOT NULL, protocol TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
 token_hash TEXT NOT NULL UNIQUE, last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS user_servers (
 user_id TEXT NOT NULL REFERENCES users(id), server_id TEXT NOT NULL REFERENCES servers(id),
 PRIMARY KEY(user_id,server_id)
);
CREATE TABLE IF NOT EXISTS devices (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL,
 platform TEXT NOT NULL, public_key TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);
CREATE TABLE IF NOT EXISTS payments (
 user_id TEXT NOT NULL REFERENCES users(id), reference TEXT NOT NULL,
 amount_rub INTEGER NOT NULL, months INTEGER NOT NULL,
 confirmed_at INTEGER NOT NULL, valid_until INTEGER NOT NULL,
 PRIMARY KEY(user_id,reference)
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS tickets (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), subject TEXT NOT NULL,
 kind TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL, user_read INTEGER NOT NULL DEFAULT 0, admin_read INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tickets_user ON tickets(user_id,updated_at);
CREATE TABLE IF NOT EXISTS ticket_messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id TEXT NOT NULL REFERENCES tickets(id),
 author TEXT NOT NULL, text TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ticket_messages_ticket ON ticket_messages(ticket_id,id);
CREATE TABLE IF NOT EXISTS payment_details (
 revision INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payment_requests (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 months INTEGER NOT NULL CHECK(months BETWEEN 1 AND 120), amount_rub INTEGER NOT NULL,
 note TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
 created_at INTEGER NOT NULL, decided_at INTEGER, admin_note TEXT NOT NULL DEFAULT '',
 valid_until INTEGER, details_revision INTEGER NOT NULL REFERENCES payment_details(revision)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_payment ON payment_requests(user_id) WHERE status='pending';
CREATE INDEX IF NOT EXISTS payment_requests_user ON payment_requests(user_id,created_at);

CREATE TABLE IF NOT EXISTS node_status (server_id TEXT PRIMARY KEY REFERENCES servers(id), online_devices INTEGER NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS device_owners (
 public_key TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL
);
INSERT OR IGNORE INTO device_owners SELECT public_key,user_id,name FROM devices;
CREATE TABLE IF NOT EXISTS usage_hourly (
 server_id TEXT NOT NULL REFERENCES servers(id), public_key TEXT NOT NULL REFERENCES device_owners(public_key),
 hour INTEGER NOT NULL, upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL,
 PRIMARY KEY(server_id,public_key,hour)
);
CREATE INDEX IF NOT EXISTS usage_time ON usage_hourly(hour);
CREATE TABLE IF NOT EXISTS connection_history (
 server_id TEXT NOT NULL REFERENCES servers(id), id TEXT NOT NULL, public_key TEXT NOT NULL REFERENCES device_owners(public_key),
 at INTEGER NOT NULL, protocol TEXT NOT NULL, PRIMARY KEY(server_id,id)
);
CREATE INDEX IF NOT EXISTS connection_time ON connection_history(at);
CREATE TABLE IF NOT EXISTS traffic_sync (
 server_id TEXT PRIMARY KEY REFERENCES servers(id), updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS lifetime_access (user_id TEXT PRIMARY KEY REFERENCES users(id), enabled INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS day_grants (
 user_id TEXT NOT NULL REFERENCES users(id), reference TEXT NOT NULL,
 days INTEGER NOT NULL CHECK(days BETWEEN 1 AND 3650), note TEXT NOT NULL,
 granted_at INTEGER NOT NULL, valid_until INTEGER NOT NULL,
 PRIMARY KEY(user_id,reference)
);
CREATE INDEX IF NOT EXISTS day_grants_user_time ON day_grants(user_id,granted_at);

CREATE TABLE IF NOT EXISTS billing_policy (
 id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL DEFAULT 0,
 min_months INTEGER NOT NULL DEFAULT 3 CHECK(min_months BETWEEN 1 AND 120)
);
INSERT OR IGNORE INTO billing_policy(id) VALUES(1);

CREATE TABLE IF NOT EXISTS invites (
 code TEXT PRIMARY KEY, note TEXT NOT NULL,
 trial_days INTEGER NOT NULL CHECK(trial_days BETWEEN 0 AND 365),
 max_signups INTEGER NOT NULL CHECK(max_signups BETWEEN 1 AND 1000),
 created_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS invite_signups (
 user_id TEXT PRIMARY KEY REFERENCES users(id), code TEXT NOT NULL REFERENCES invites(code),
 at INTEGER NOT NULL, trial_days INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS invite_signups_code ON invite_signups(code);

PRAGMA user_version=6;
