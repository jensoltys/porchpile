-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Porch Pile authors. See LICENSE.
-- Spreadsheet import. One row per import so a 200-row mistake is one undo
-- rather than 200 deletions. next_index makes a retried chunk a no-op.
CREATE TABLE import_batches (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename    TEXT,
  row_count   INTEGER NOT NULL DEFAULT 0,
  next_index  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL,
  closed_at   TEXT
);
CREATE INDEX idx_import_batches_user ON import_batches(user_id, created_at);

ALTER TABLE items ADD COLUMN import_batch_id TEXT;
CREATE INDEX idx_items_batch ON items(import_batch_id);
