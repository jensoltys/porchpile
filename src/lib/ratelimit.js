// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Sliding-window cap on the D1 rate_limits table: true when `key` was already hit `max` times in the last `windowS`
// seconds. The current hit is recorded first, atomically, so a script hammering a
// capped route stays capped. Lives in D1, so it survives a Worker restart or
// a new isolate (an in-memory Map would not). Fail-open on a D1 error so an
// outage never locks real people out of signup or reset.
export async function overLimit(env, key, max, windowS) {
  try {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare('DELETE FROM rate_limits WHERE key = ? AND created_at < ?').bind(key, now - windowS).run();
    // Record THEN count, in one D1 batch (a single transaction). Counting first and
    // inserting after let a burst of parallel requests all read "under the cap"
    // before any of them was recorded.
    const [, counted] = await env.DB.batch([
      env.DB.prepare('INSERT INTO rate_limits (key, created_at) VALUES (?, ?)').bind(key, now),
      env.DB.prepare('SELECT COUNT(*) AS n FROM rate_limits WHERE key = ? AND created_at >= ?').bind(key, now - windowS),
    ]);
    const n = counted?.results?.[0]?.n ?? 0;
    return n > max;
  } catch (e) {
    console.error('rate_limits overLimit failed:', (e && e.message) || e);
    return false;
  }
}
