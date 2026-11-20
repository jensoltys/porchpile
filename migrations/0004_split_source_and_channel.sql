-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Porch Pile authors. See LICENSE.
-- Two-axis sourcing: creator trackers separate Lead (the channel a
-- deal came through) from Review Type (how the creator physically got the item), and a
-- brand usually sends THROUGH Creator Connections — so channel is not a peer of
-- "brand sent it". Items now carry:
--   source  = sent_for_review | purchased | already_owned   (how you got it)
--   channel = creator_connections | levanta | email | social | facebook_group
--             | other | NULL                                 (came through)

ALTER TABLE items ADD COLUMN channel TEXT;

UPDATE items SET channel = 'creator_connections', source = 'sent_for_review' WHERE source = 'creator_connections';
UPDATE items SET source = 'sent_for_review' WHERE source = 'brand_deal';
UPDATE items SET source = 'purchased' WHERE source = 'purchased_myself';
