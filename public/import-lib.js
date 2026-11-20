// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Porch Pile spreadsheet import — pure logic, no DOM, no dependencies.
// Imported by public/app.html in the browser AND by tests/import-lib.test.mjs
// in Node, which is why nothing here may touch window or document.

// Hand-rolled because a Worker app does not take a dependency to read a CSV.
// Handles: quoted fields, commas and newlines inside quotes, "" escapes,
// a leading BOM, and both CRLF and LF line endings.
export function parseCsv(text) {
  if (typeof text !== 'string' || !text.trim()) {
    throw new Error('That file looks empty.');
  }
  let s = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  s = s.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  const lines = [];
  let field = '', row = [], inQuotes = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQuotes) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); lines.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field !== '' || row.length) { row.push(field); lines.push(row); }

  const cleaned = lines
    .map(r => r.map(v => v.trim()))
    .filter(r => r.some(v => v !== ''));
  if (!cleaned.length) throw new Error('That file looks empty.');

  const headers = cleaned[0];
  const width = headers.length;
  const rows = cleaned.slice(1).map(r => {
    const out = r.slice(0, width);
    while (out.length < width) out.push('');
    return out;
  });
  if (!rows.length) throw new Error('That file has column names but no rows in it.');
  return { headers, rows };
}

export const PILE_FIELDS = [
  'name', 'brand', 'asin', 'date_received', 'est_value',
  'category', 'notes', 'source', 'channel', 'status',
];

const norm = h => String(h || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

// Ordered: fields earlier in this list claim their header first. Within one
// field, the earliest matching column wins, so ['Name', 'Title'] maps name to
// column 0 even though 'title' sits earlier in the synonym list.
// "Brand Notes" is deliberately NOT a brand synonym — in real creator trackers it is
// a multiline prose field, and brand caps at 120 characters.
const SYNONYMS = [
  ['name', ['product name', 'item name', 'item', 'title', 'name', 'product', 'description']],
  ['asin', ['asin', 'amazon id', 'amazon asin', 'product id', 'sku']],
  ['date_received', ['date received', 'received', 'date in', 'arrived', 'arrival date', 'received on', 'date']],
  ['est_value', ['product price', 'est value', 'estimated value', 'price', 'value', 'retail', 'retail price', 'cost', 'msrp']],
  ['status', ['item status', 'video status', 'status', 'stage', 'progress']],
  ['source', ['review type', 'source', 'how i got it', 'acquisition']],
  ['channel', ['lead', 'channel', 'platform', 'came from', 'where from']],
  ['brand', ['brand name', 'brand', 'company', 'vendor', 'seller', 'manufacturer']],
  ['category', ['category', 'product type', 'type', 'niche']],
  ['notes', ['my notes', 'notes', 'note', 'comments', 'details']],
];

export function guessColumns(headers) {
  const normed = (headers || []).map(norm);
  const out = {}, taken = new Set();
  for (const [field, syns] of SYNONYMS) {
    let best = -1;
    for (const syn of syns) {
      const idx = normed.findIndex((h, i) => h === syn && !taken.has(i));
      if (idx !== -1 && (best === -1 || idx < best)) best = idx;
    }
    if (best !== -1) { out[field] = best; taken.add(best); }
  }
  return out;
}

// Kept in step with src/worker.js:574-580. If those lists change, change these.
export const ITEM_STATUSES = ['sending', 'received', 'queued', 'filmed', 'posted', 'linked'];
export const ITEM_SOURCES = ['sent_for_review', 'purchased', 'already_owned'];
export const ITEM_CHANNELS = ['creator_connections', 'levanta', 'email', 'social', 'facebook_group', 'other'];

const MAX_LEN = { name: 200, brand: 120, asin: 20, category: 60, notes: 2000 };

// Value guesses. Keys are normalised (lowercase, punctuation to spaces).
// The channel and source tables carry values from a real creator tracker, the
// reference for creator vocabulary.
const VALUE_GUESS = {
  source: {
    'sent for review': 'sent_for_review', 'sent': 'sent_for_review', 'review': 'sent_for_review',
    'gifted': 'sent_for_review', 'pr': 'sent_for_review',
    'purchased': 'purchased', 'bought': 'purchased', 'bought it myself': 'purchased',
    'already owned': 'already_owned', 'owned': 'already_owned', 'had in house': 'already_owned',
  },
  channel: {
    'creator connections': 'creator_connections', 'cc': 'creator_connections',
    'levanta': 'levanta',
    'email': 'email',
    'instagram': 'social', 'social': 'social', 'social dm': 'social', 'tiktok': 'social', 'dm': 'social',
    'facebook group': 'facebook_group', 'fb group': 'facebook_group',
    'logie': 'other', 'other platform': 'other', 'other': 'other',
  },
  status: {
    'sending': 'sending', 'shipped': 'sending', 'on the way': 'sending', 'in transit': 'sending',
    'received': 'received', 'arrived': 'received', 'in hand': 'received', 'have it': 'received',
    'queued': 'queued', 'to film': 'queued', 'to do': 'queued', 'ready': 'queued', 'ready to film': 'queued',
    'filmed': 'filmed', 'recorded': 'filmed', 'shot': 'filmed', 'in review': 'filmed', 'editing': 'filmed',
    'posted': 'posted', 'published': 'posted', 'live': 'posted', 'uploaded': 'posted',
    'linked': 'linked', 'done': 'linked', 'complete': 'linked', 'completed': 'linked', 'finished': 'linked',
  },
};

// A `Lead` column often mixes origin channel with how the creator got the thing, so a
// value mapped to a channel usually implies a source as well.
const CHANNEL_IMPLIES_SOURCE = {
  'creator connections': 'sent_for_review', 'levanta': 'sent_for_review',
  'email': 'sent_for_review', 'instagram': 'sent_for_review',
  'facebook group': 'sent_for_review', 'logie': 'sent_for_review',
  'other platform': 'sent_for_review',
  'bought': 'purchased',
  'had in house': 'already_owned', 'gift': 'already_owned', 'borrowed': 'already_owned',
};

const nv = v => String(v || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

export function distinctValues(rows, colIndex) {
  const seen = new Set(), out = [];
  for (const r of rows || []) {
    const v = (r[colIndex] || '').trim();
    if (v && !seen.has(v)) { seen.add(v); out.push(v); }
  }
  return out;
}

export function guessValue(field, raw) {
  const table = VALUE_GUESS[field];
  if (!table) return null;
  return table[nv(raw)] || null;
}

export function guessSourceFromChannelValue(raw) {
  return CHANNEL_IMPLIES_SOURCE[nv(raw)] || null;
}

// Accepts YYYY-MM-DD, M/D/YYYY, MM/DD/YYYY and ISO timestamps. Anything else
// is dropped rather than failing the row: a missing date is recoverable, a
// lost row is not.
function toDate(raw) {
  const s = String(raw || '').trim();
  if (!s) return undefined;
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (m) return `${m[3]}-${String(m[1]).padStart(2, '0')}-${String(m[2]).padStart(2, '0')}`;
  return undefined;
}

// "$24.99", "1,299.00", "24.99 USD" all become a number. Junk is dropped.
function toMoney(raw) {
  const s = String(raw || '').replace(/[^0-9.\-]/g, '');
  if (!s) return undefined;
  const n = Number(s);
  if (!Number.isFinite(n) || n < 0 || n > 1000000) return undefined;
  return Math.round(n * 100) / 100;
}

export function buildRows(parsed, mapping, valueMaps, defaults) {
  const rows = [], errors = [];
  const vm = valueMaps || {};
  const cell = (r, field) => mapping[field] === undefined ? '' : (r[mapping[field]] || '').trim();

  (parsed.rows || []).forEach((r, i) => {
    const rowNum = i + 2; // header occupies row 1

    const name = cell(r, 'name').slice(0, MAX_LEN.name);
    if (!name) { errors.push({ row: rowNum, message: 'No item name in this row, so I skipped it.' }); return; }

    const out = { name };

    for (const f of ['brand', 'asin', 'category', 'notes']) {
      const v = cell(r, f);
      if (v) out[f] = v.slice(0, MAX_LEN[f]);
    }

    const d = toDate(cell(r, 'date_received'));
    if (d !== undefined) out.date_received = d;

    const money = toMoney(cell(r, 'est_value'));
    if (money !== undefined) out.est_value = money;

    // channel first, because it can supply the source
    let source;
    const rawChannel = cell(r, 'channel');
    if (rawChannel) {
      const ch = (vm.channel || {})[rawChannel];
      if (ch && ITEM_CHANNELS.includes(ch)) out.channel = ch;
      const implied = guessSourceFromChannelValue(rawChannel);
      if (implied) source = implied;
    }

    const rawSource = cell(r, 'source');
    if (rawSource) {
      const s = (vm.source || {})[rawSource];
      if (s && ITEM_SOURCES.includes(s)) source = s;
    }
    out.source = source || defaults.source || 'sent_for_review';

    const rawStatus = cell(r, 'status');
    const st = rawStatus ? (vm.status || {})[rawStatus] : null;
    out.status = st && ITEM_STATUSES.includes(st) ? st : (defaults.status || 'received');

    rows.push(out);
  });

  return { rows, errors };
}

// Two independent key spaces. An ASIN row is only ever compared to other ASIN
// rows: different products genuinely share names, so letting a name match beat
// a missing ASIN would merge unrelated items. A row with neither an ASIN nor a
// date has no reliable identity and is always treated as new.
export function dedupeKey(item) {
  const asin = String(item.asin || '').trim().toUpperCase();
  if (asin) return 'a:' + asin;
  const name = String(item.name || '').trim().toLowerCase().replace(/\s+/g, ' ');
  const date = String(item.date_received || '').trim();
  if (!name || !date) return null;
  return 'n:' + name + '|' + date;
}

export function findDuplicates(incoming, existing) {
  const byKey = new Map();
  for (const e of existing || []) {
    const k = dedupeKey(e);
    if (k && !byKey.has(k)) byKey.set(k, e.id);
  }
  const dupIndexes = new Set(), existingIdByIndex = new Map();
  const seenInFile = new Set();
  (incoming || []).forEach((row, i) => {
    const k = dedupeKey(row);
    if (!k) return;
    if (byKey.has(k)) { dupIndexes.add(i); existingIdByIndex.set(i, byKey.get(k)); return; }
    if (seenInFile.has(k)) { dupIndexes.add(i); return; }
    seenInFile.add(k);
  });
  return { dupIndexes, existingIdByIndex };
}
