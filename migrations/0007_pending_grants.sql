-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Porch Pile authors. See LICENSE.
-- Affiliate free-Pro grants for emails with no account yet.
-- Applied + deleted when the email signs up.
CREATE TABLE pending_grants (
  email      TEXT PRIMARY KEY,
  months     INTEGER NOT NULL,
  lifetime   INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
