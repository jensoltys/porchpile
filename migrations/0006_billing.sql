-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Porch Pile authors. See LICENSE.
-- E5 billing: Stripe subscription state on users + webhook idempotency tables.
-- pro_until already exists (0001); it stays the single entitlement source —
-- NULL or past = free, future = Pro. Written from Stripe period end.

ALTER TABLE users ADD COLUMN stripe_customer_id TEXT;
ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT;
ALTER TABLE users ADD COLUMN stripe_status TEXT;
ALTER TABLE users ADD COLUMN cancel_at_period_end INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_users_stripe_customer ON users(stripe_customer_id);

-- Lock-first webhook idempotency: INSERT OR IGNORE claims the event id BEFORE
-- any side effects run, so Stripe's at-least-once delivery can't double-apply.
CREATE TABLE webhook_events (
  stripe_event_id TEXT PRIMARY KEY,
  event_type      TEXT NOT NULL,
  created_at      INTEGER NOT NULL      -- epoch seconds
);

-- Per-user audit trail of money events (amounts in cents as Stripe sends them).
CREATE TABLE payment_events (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  stripe_event_id TEXT NOT NULL UNIQUE,
  event_type      TEXT NOT NULL,
  amount          INTEGER,
  currency        TEXT,
  created_at      INTEGER NOT NULL
);
CREATE INDEX idx_payment_events_user ON payment_events(user_id);
