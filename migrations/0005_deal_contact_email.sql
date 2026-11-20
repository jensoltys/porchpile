-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Porch Pile authors. See LICENSE.
-- Email-the-links feature: deals get a dedicated contact
-- email (creator trackers often have a Brand Contact Email; contact_handle stays for @handles)
-- and a stamp for when the finished-links email was drafted. Emails that were
-- living in contact_handle move over (contains @ + dot, doesn't start with @).

ALTER TABLE brand_deals ADD COLUMN contact_email TEXT;
ALTER TABLE brand_deals ADD COLUMN links_sent_at TEXT;

UPDATE brand_deals SET contact_email = contact_handle, contact_handle = NULL
  WHERE contact_handle LIKE '%@%.%' AND contact_handle NOT LIKE '@%';
