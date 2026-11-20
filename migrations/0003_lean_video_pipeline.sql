-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Porch Pile authors. See LICENSE.
-- Lean video pipeline: to_film -> in_review -> posted.
-- "idea" folds into to_film; "filmed"/"edited" fold into in_review (in a real
-- creator workflow a filmed video is uploaded and sitting in Amazon's review).

UPDATE videos SET status = 'to_film' WHERE status = 'idea';
UPDATE videos SET status = 'in_review' WHERE status IN ('filmed', 'edited');
