-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Porch Pile authors. See LICENSE.
-- Porch Pile — initial schema. Cloudflare D1 (SQLite).
-- Conventions:
--   * Every user-owned row carries user_id; every query filters WHERE user_id = ?
--   * IDs are UUID TEXT (crypto.randomUUID) unless noted
--   * Timestamps are ISO-8601 TEXT unless noted (epoch INTEGER for rate limits)
--   * Booleans are INTEGER 0/1
--   * Global session revocation via users.token_version (bumped on password reset)

PRAGMA defer_foreign_keys = TRUE;

-- ------------------------------------------------------------------ users
CREATE TABLE users (
  id             TEXT PRIMARY KEY,
  email          TEXT NOT NULL UNIQUE,          -- stored lowercase
  password_hash  TEXT NOT NULL,                 -- pbkdf2$...
  email_verified INTEGER NOT NULL DEFAULT 0,
  tz             TEXT NOT NULL DEFAULT 'America/Chicago', -- streak/follow-up date math
  pace_goal      INTEGER NOT NULL DEFAULT 100,  -- $/day goal for the Daily Pace widget
  pro_until      TEXT,                           -- ISO; NULL = free
  token_version  INTEGER NOT NULL DEFAULT 0,    -- bump to invalidate all sessions
  created_at     TEXT NOT NULL,
  last_login_at  TEXT
);

-- ---------------------------------------------------------- email verify / reset
-- Email verification uses a 6-digit CODE, not a magic link: a tokenized
-- verify-link to a young domain reads as phishing to Gmail, which accepts then
-- silently drops it. We store only sha256(user_id:code), never the code.
CREATE TABLE email_verifications (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,        -- sha256(user_id + ':' + code)
  expires_at INTEGER NOT NULL,     -- epoch seconds
  used       INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_emailverif_user ON email_verifications(user_id);

CREATE TABLE reset_tokens (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,        -- sha256(token); raw token only ever emailed
  expires_at INTEGER NOT NULL,     -- epoch seconds
  used       INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_reset_hash ON reset_tokens(token_hash);

-- ------------------------------------------------------------------ items
-- The pile. Status pipeline: received → queued → filmed → posted → linked.
CREATE TABLE items (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  brand         TEXT,
  asin          TEXT,                    -- optional free text
  source        TEXT NOT NULL DEFAULT 'storefront_pick',
                -- storefront_pick | brand_deal | creator_connections | purchased_myself
  date_received TEXT,                    -- YYYY-MM-DD
  est_value     REAL,                    -- estimated $ value
  category      TEXT,                    -- user-managed list value
  photo         TEXT,                    -- not used yet: always NULL
  status        TEXT NOT NULL DEFAULT 'received',
                -- received | queued | filmed | posted | linked
  notes         TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX idx_items_user ON items(user_id);
CREATE INDEX idx_items_user_status ON items(user_id, status);

-- ------------------------------------------------------------------ videos
CREATE TABLE videos (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title        TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'idea',
               -- idea | to_film | filmed | edited | posted
  posted_date  TEXT,                     -- YYYY-MM-DD (user tz)
  platforms    TEXT,                     -- JSON array: ["amazon","youtube","tiktok","instagram"]
  urls         TEXT,                     -- JSON array of strings
  notes        TEXT,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE INDEX idx_videos_user ON videos(user_id);
CREATE INDEX idx_videos_user_status ON videos(user_id, status);

-- many-to-many: one video features several items; one item can have several videos
CREATE TABLE video_items (
  video_id  TEXT NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  item_id   TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  user_id   TEXT NOT NULL,
  PRIMARY KEY (video_id, item_id)
);
CREATE INDEX idx_videoitems_item ON video_items(item_id);
CREATE INDEX idx_videoitems_user ON video_items(user_id);

-- ------------------------------------------------------------------ brand deals
CREATE TABLE brand_deals (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  brand          TEXT NOT NULL,
  contact_name   TEXT,
  contact_handle TEXT,                   -- email or @handle
  channel        TEXT,                   -- email | instagram | tiktok | levanta | creator_connections | other
  deal_type      TEXT,                   -- free_product | flat_fee | commission_boost | cc_campaign
  amount         TEXT,                   -- free text rate/amount ("$150", "10% boost")
  status         TEXT NOT NULL DEFAULT 'inquiry',
                 -- inquiry | negotiating | agreed | product_incoming | content_due | delivered | paid | dead
  next_follow_up TEXT,                   -- YYYY-MM-DD
  deliverables   TEXT,
  dead_reason    TEXT,
  notes          TEXT,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);
CREATE INDEX idx_deals_user ON brand_deals(user_id);
CREATE INDEX idx_deals_user_status ON brand_deals(user_id, status);

CREATE TABLE deal_items (
  deal_id  TEXT NOT NULL REFERENCES brand_deals(id) ON DELETE CASCADE,
  item_id  TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  user_id  TEXT NOT NULL,
  PRIMARY KEY (deal_id, item_id)
);
CREATE INDEX idx_dealitems_user ON deal_items(user_id);

-- ------------------------------------------------------------------ coupons
CREATE TABLE coupons (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code       TEXT NOT NULL,
  brand      TEXT,
  deal_id    TEXT REFERENCES brand_deals(id) ON DELETE SET NULL,
  discount   TEXT,                       -- free text ("20%", "$5 off")
  expires    TEXT,                       -- YYYY-MM-DD
  purpose    TEXT,
  used       INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_coupons_user ON coupons(user_id);

-- ------------------------------------------------------------------ income
-- Hand-typed monthly totals, one row per user+month. The three-stream AIP
-- vocabulary plus off-Amazon brand fees and other.
CREATE TABLE income_months (
  id                  TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  month               TEXT NOT NULL,     -- YYYY-MM
  commissions         REAL NOT NULL DEFAULT 0,
  creator_connections REAL NOT NULL DEFAULT 0,
  bounties_spc        REAL NOT NULL DEFAULT 0,
  brand_fees          REAL NOT NULL DEFAULT 0,   -- off-Amazon
  other               REAL NOT NULL DEFAULT 0,
  notes               TEXT,
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL,
  UNIQUE(user_id, month)
);
CREATE INDEX idx_income_user ON income_months(user_id);

-- ------------------------------------------------------------ gamification
CREATE TABLE achievements (
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key         TEXT NOT NULL,
  unlocked_at TEXT NOT NULL,
  PRIMARY KEY (user_id, key)             -- idempotent unlocks by construction
);

-- ------------------------------------------------------------------ rate limits
CREATE TABLE rate_limits (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  key        TEXT NOT NULL,        -- e.g. 'failed-login:<email>', 'signup-ip:<ip>'
  created_at INTEGER NOT NULL      -- epoch seconds
);
CREATE INDEX idx_rate_limits_key_created ON rate_limits(key, created_at);
