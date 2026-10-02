BEGIN IMMEDIATE;
CREATE TABLE payment_requests_v6 (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 months INTEGER NOT NULL CHECK(months BETWEEN 1 AND 120), amount_rub INTEGER NOT NULL,
 note TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
 created_at INTEGER NOT NULL, decided_at INTEGER, admin_note TEXT NOT NULL DEFAULT '',
 valid_until INTEGER, details_revision INTEGER NOT NULL REFERENCES payment_details(revision)
);
INSERT INTO payment_requests_v6 SELECT * FROM payment_requests;
DROP TABLE payment_requests;
ALTER TABLE payment_requests_v6 RENAME TO payment_requests;
CREATE UNIQUE INDEX one_pending_payment ON payment_requests(user_id) WHERE status='pending';
CREATE INDEX payment_requests_user ON payment_requests(user_id,created_at);
COMMIT;
