-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Porch Pile authors. See LICENSE.
-- Retire the "storefront_pick" source value. It was invented
-- vocabulary that real creators didn't recognize. New enum:
-- brand_deal | creator_connections | purchased_myself | already_owned,
-- default brand_deal. Existing rows only ever had storefront_pick via the old
-- default, so they map to the new default. The stale DDL default on items.source
-- is harmless — the worker always sets source explicitly on INSERT.

UPDATE items SET source = 'brand_deal' WHERE source = 'storefront_pick';
