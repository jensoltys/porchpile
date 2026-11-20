// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Spreadsheet import. The browser has already parsed, mapped and validated
// the file; this receives clean rows in chunks. Every row still goes through
// collectItemFields, because the server never trusts the client.
export const MAX_IMPORT_ROWS = 5000;
export const MAX_CHUNK_ROWS = 500;

export async function importItems(user, request, env, deps) {
  const { res, badReq, readJson, isProRow, billingRow, collectItemFields } = deps;

  if (!isProRow(await billingRow(env, user.id))) {
    return res({
      error: 'Importing a spreadsheet is a Pro feature. Go Pro to bring your history over.',
      code: 'pro_required',
    }, 403);
  }

  const body = await readJson(request);
  if (!body) return badReq();

  const batchId = body.batch_id;
  if (typeof batchId !== 'string' || !/^[0-9a-f-]{36}$/.test(batchId)) return badReq('Invalid batch id.');
  const rows = Array.isArray(body.rows) ? body.rows : null;
  if (!rows) return badReq('No rows to import.');
  const startIndex = Number.isInteger(body.start_index) ? body.start_index : 0;
  // Ceiling first: a whole-file overrun gets the 5,000 message, not the chunk one.
  if (startIndex < 0 || startIndex + rows.length > MAX_IMPORT_ROWS) {
    return badReq('One import can bring in up to 5,000 rows. Split the file and import it in two goes.');
  }
  if (rows.length > MAX_CHUNK_ROWS) return badReq(`Send at most ${MAX_CHUNK_ROWS} rows at a time.`);

  const now = new Date().toISOString();
  let batch = await env.DB.prepare('SELECT id, next_index, row_count FROM import_batches WHERE id = ? AND user_id = ?')
    .bind(batchId, user.id).first();
  if (!batch) {
    // OR IGNORE, then read back as this user: a batch id that already belongs to
    // another account is a plain 400, never a crash and never a shared batch.
    await env.DB.prepare('INSERT OR IGNORE INTO import_batches (id, user_id, filename, row_count, next_index, created_at) VALUES (?, ?, ?, 0, 0, ?)')
      .bind(batchId, user.id, String(body.filename || '').slice(0, 200) || null, now).run();
    batch = await env.DB.prepare('SELECT id, next_index, row_count FROM import_batches WHERE id = ? AND user_id = ?')
      .bind(batchId, user.id).first();
    if (!batch) return badReq('Invalid batch id.');
  }

  // A retried chunk after a dropped connection is acknowledged, not reapplied.
  if (startIndex < (batch.next_index || 0)) {
    return res({ inserted: 0, updated: 0, skipped: rows.length, failed: 0, errors: [], batch_id: batchId, replayed: true });
  }

  // ONE narrow read for the whole chunk. Never one query per row.
  const existing = await env.DB.prepare('SELECT id, asin, name, date_received FROM items WHERE user_id = ?')
    .bind(user.id).all();
  const byKey = new Map();
  for (const e of existing.results || []) {
    const k = keyOf(e);
    if (k && !byKey.has(k)) byKey.set(k, e.id);
  }

  const stmts = [];
  let inserted = 0, updated = 0, skipped = 0, failed = 0;
  const errors = [];
  const updateExisting = body.update_existing === true;

  rows.forEach((raw, i) => {
    const c = collectItemFields(raw || {}, false);
    if (c.error) { failed++; if (errors.length < 20) errors.push({ row: startIndex + i + 2, message: c.error }); return; }
    const s = c.sets;
    const k = keyOf(s);
    const hit = k ? byKey.get(k) : undefined;

    if (hit) {
      if (!updateExisting) { skipped++; return; }
      const keys = Object.keys(s);
      // sec-ok(5): column names come only from collectItemFields()'s fixed field list; values are bound with ?
      stmts.push(env.DB.prepare(
        `UPDATE items SET ${keys.map(x => `${x} = ?`).join(', ')}, updated_at = ? WHERE id = ? AND user_id = ?`,
      ).bind(...keys.map(x => s[x]), now, hit, user.id));
      updated++;
      return;
    }

    const id = crypto.randomUUID();
    stmts.push(env.DB.prepare(
      `INSERT INTO items (id, user_id, name, brand, asin, source, channel, date_received, est_value, category, photo, status, notes, import_batch_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`,
    ).bind(
      id, user.id, s.name, s.brand ?? null, s.asin ?? null,
      s.source || 'sent_for_review', s.channel ?? null, s.date_received ?? null,
      s.est_value ?? null, s.category ?? null, s.status || 'received', s.notes ?? null,
      batchId, now, now,
    ));
    inserted++;
    if (k) byKey.set(k, id); // guards duplicates inside this same chunk
  });

  if (stmts.length) await env.DB.batch(stmts);

  const nextIndex = startIndex + rows.length;
  await env.DB.prepare('UPDATE import_batches SET next_index = ?, row_count = row_count + ?, closed_at = ? WHERE id = ? AND user_id = ?')
    .bind(nextIndex, inserted + updated, body.final === true ? now : null, batchId, user.id).run();

  return res({ inserted, updated, skipped, failed, errors, batch_id: batchId });
}

export async function recentImport(user, env, deps) {
  const { res } = deps;
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const row = await env.DB.prepare(
    'SELECT id, filename, row_count, created_at FROM import_batches WHERE user_id = ? AND created_at > ? AND row_count > 0 ORDER BY created_at DESC LIMIT 1',
  ).bind(user.id, cutoff).first();
  return res({ batch: row || null });
}

// Deletes only rows the person has not touched since importing. An edited row
// represents work, and undoing an import should never throw that away.
export async function undoImport(user, batchId, env, deps) {
  const { res, badReq } = deps;
  if (typeof batchId !== 'string' || !/^[0-9a-f-]{36}$/.test(batchId)) return badReq('Invalid batch id.');

  const counts = await env.DB.prepare(
    'SELECT COUNT(*) AS total, SUM(CASE WHEN updated_at = created_at THEN 1 ELSE 0 END) AS fresh FROM items WHERE user_id = ? AND import_batch_id = ?',
  ).bind(user.id, batchId).first();

  const deleted = Number(counts?.fresh || 0);
  const kept = Number(counts?.total || 0) - deleted;

  await env.DB.batch([
    env.DB.prepare('DELETE FROM items WHERE user_id = ? AND import_batch_id = ? AND updated_at = created_at').bind(user.id, batchId),
    env.DB.prepare('DELETE FROM import_batches WHERE user_id = ? AND id = ?').bind(user.id, batchId),
  ]);

  return res({ deleted, kept });
}

// Must stay identical in behaviour to dedupeKey() in public/import-lib.js.
function keyOf(item) {
  const asin = String(item.asin || '').trim().toUpperCase();
  if (asin) return 'a:' + asin;
  const name = String(item.name || '').trim().toLowerCase().replace(/\s+/g, ' ');
  const date = String(item.date_received || '').trim();
  if (!name || !date) return null;
  return 'n:' + name + '|' + date;
}
