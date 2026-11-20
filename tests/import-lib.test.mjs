// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCsv } from '../public/import-lib.js';

test('parses a plain file', () => {
  const r = parseCsv('Name,Brand\nLantern,GlowCo\nMug,PotCo\n');
  assert.deepEqual(r.headers, ['Name', 'Brand']);
  assert.deepEqual(r.rows, [['Lantern', 'GlowCo'], ['Mug', 'PotCo']]);
});

test('handles commas inside quotes', () => {
  const r = parseCsv('Name,Notes\n"Lantern, solar","big, heavy"\n');
  assert.deepEqual(r.rows, [['Lantern, solar', 'big, heavy']]);
});

test('handles newlines inside quotes', () => {
  const r = parseCsv('Name,Notes\n"Lantern","line one\nline two"\n');
  assert.equal(r.rows.length, 1);
  assert.equal(r.rows[0][1], 'line one\nline two');
});

test('handles escaped double quotes', () => {
  const r = parseCsv('Name\n"He said ""hi"""\n');
  assert.equal(r.rows[0][0], 'He said "hi"');
});

test('strips a BOM and handles CRLF', () => {
  const r = parseCsv('﻿Name,Brand\r\nLantern,GlowCo\r\n');
  assert.deepEqual(r.headers, ['Name', 'Brand']);
  assert.deepEqual(r.rows, [['Lantern', 'GlowCo']]);
});

test('pads short rows and truncates long ones', () => {
  const r = parseCsv('A,B,C\n1\n1,2,3,4\n');
  assert.deepEqual(r.rows, [['1', '', ''], ['1', '2', '3']]);
});

test('skips fully blank lines', () => {
  const r = parseCsv('A,B\n1,2\n\n3,4\n');
  assert.equal(r.rows.length, 2);
});

test('rejects an empty file', () => {
  assert.throws(() => parseCsv('   '), /empty/i);
});

test('rejects a header-only file', () => {
  assert.throws(() => parseCsv('Name,Brand\n'), /no rows/i);
});

import { guessColumns } from '../public/import-lib.js';

test('guesses the headers of a real creator tracker', () => {
  const g = guessColumns([
    'Product Name', 'ASIN', 'Product Price', 'Product URL', 'Lead',
    'Review Type', 'Coupon Code', 'Brand Notes', 'Brand Contact Email',
    'Date Received', 'My Notes', 'Videos', 'Video Count',
  ]);
  assert.equal(g.name, 0);
  assert.equal(g.asin, 1);
  assert.equal(g.est_value, 2);
  assert.equal(g.channel, 4);
  assert.equal(g.source, 5);
  assert.equal(g.date_received, 9);
  assert.equal(g.notes, 10);
});

test('Brand Notes does not become the brand column', () => {
  // A real creator Products table can have no brand column at all. "Brand Notes" is prose
  // about the brand, so mapping it to brand would put a paragraph in a
  // 120-character field.
  const g = guessColumns(['Product Name', 'Brand Notes']);
  assert.equal(g.brand, undefined);
});

test('guesses a totally different Sheets-style header row', () => {
  const g = guessColumns(['Item', 'Company', 'Arrived', 'Retail', 'Stage', 'Comments']);
  assert.equal(g.name, 0);
  assert.equal(g.brand, 1);
  assert.equal(g.date_received, 2);
  assert.equal(g.est_value, 3);
  assert.equal(g.status, 4);
  assert.equal(g.notes, 5);
});

test('is case and punctuation insensitive', () => {
  const g = guessColumns(['  PRODUCT_NAME ', 'date-received']);
  assert.equal(g.name, 0);
  assert.equal(g.date_received, 1);
});

test('earlier column wins a tie and no header maps twice', () => {
  const g = guessColumns(['Name', 'Title']);
  assert.equal(g.name, 0);
  assert.equal(Object.values(g).filter(i => i === 1).length, 0);
});

test('returns no name when nothing matches', () => {
  const g = guessColumns(['Sku Ref', 'Widget Count']);
  assert.equal(g.name, undefined);
});

import { distinctValues, guessValue, guessSourceFromChannelValue, buildRows } from '../public/import-lib.js';

test('distinctValues keeps first-seen order and drops blanks', () => {
  const rows = [['a'], [''], ['b'], ['a']];
  assert.deepEqual(distinctValues(rows, 0), ['a', 'b']);
});

test('guesses real Review Type values', () => {
  assert.equal(guessValue('source', 'Sent for Review'), 'sent_for_review');
  assert.equal(guessValue('source', 'Purchased'), 'purchased');
  assert.equal(guessValue('source', 'Already Owned'), 'already_owned');
  assert.equal(guessValue('source', "Dad's House"), null);
  assert.equal(guessValue('source', 'Blog Review'), null);
});

test('guesses real Lead values as channels', () => {
  assert.equal(guessValue('channel', 'Creator Connections'), 'creator_connections');
  assert.equal(guessValue('channel', 'Levanta'), 'levanta');
  assert.equal(guessValue('channel', 'Facebook Group'), 'facebook_group');
  assert.equal(guessValue('channel', 'Instagram'), 'social');
  assert.equal(guessValue('channel', 'Logie'), 'other');
  assert.equal(guessValue('channel', 'Bought'), null);
});

test('Lead values also imply a source', () => {
  assert.equal(guessSourceFromChannelValue('Creator Connections'), 'sent_for_review');
  assert.equal(guessSourceFromChannelValue('Bought'), 'purchased');
  assert.equal(guessSourceFromChannelValue('Had in House'), 'already_owned');
  assert.equal(guessSourceFromChannelValue('Gift'), 'already_owned');
  assert.equal(guessSourceFromChannelValue('Borrowed'), 'already_owned');
});

test('guesses status synonyms', () => {
  assert.equal(guessValue('status', 'To Film'), 'queued');
  assert.equal(guessValue('status', 'Published'), 'posted');
  assert.equal(guessValue('status', 'Done'), 'linked');
  assert.equal(guessValue('status', 'In Transit'), 'sending');
  assert.equal(guessValue('status', 'Whatever'), null);
});

test('buildRows applies mapping, defaults and cleanup', () => {
  const parsed = {
    headers: ['Product Name', 'Product Price', 'Date Received', 'Lead'],
    rows: [['Solar Lantern', '$24.99', '2026-03-04', 'Creator Connections']],
  };
  const out = buildRows(
    parsed,
    { name: 0, est_value: 1, date_received: 2, channel: 3 },
    { channel: { 'Creator Connections': 'creator_connections' } },
    { status: 'linked', source: 'sent_for_review' },
  );
  assert.equal(out.errors.length, 0);
  assert.deepEqual(out.rows[0], {
    name: 'Solar Lantern',
    est_value: 24.99,
    date_received: '2026-03-04',
    channel: 'creator_connections',
    source: 'sent_for_review',
    status: 'linked',
  });
});

test('buildRows normalises common date formats', () => {
  const mk = d => buildRows(
    { headers: ['Name', 'Date'], rows: [['X', d]] },
    { name: 0, date_received: 1 }, {}, { status: 'received', source: 'sent_for_review' },
  ).rows[0].date_received;
  assert.equal(mk('2026-03-04'), '2026-03-04');
  assert.equal(mk('3/4/2026'), '2026-03-04');
  assert.equal(mk('03/04/2026'), '2026-03-04');
  assert.equal(mk('2026-03-04T11:02:00.000Z'), '2026-03-04');
});

test('buildRows drops an unreadable date instead of failing the row', () => {
  const out = buildRows(
    { headers: ['Name', 'Date'], rows: [['X', 'sometime last spring']] },
    { name: 0, date_received: 1 }, {}, { status: 'received', source: 'sent_for_review' },
  );
  assert.equal(out.errors.length, 0);
  assert.equal(out.rows[0].date_received, undefined);
});

test('buildRows reports rows with no name and keeps its row numbers', () => {
  const out = buildRows(
    { headers: ['Name'], rows: [['Good'], [''], ['Also good']] },
    { name: 0 }, {}, { status: 'received', source: 'sent_for_review' },
  );
  assert.equal(out.rows.length, 2);
  assert.equal(out.errors.length, 1);
  assert.equal(out.errors[0].row, 3); // header is row 1, so the blank is row 3
});

test('buildRows truncates over-long text rather than losing the row', () => {
  const out = buildRows(
    { headers: ['Name', 'Brand'], rows: [['X', 'B'.repeat(300)]] },
    { name: 0, brand: 1 }, {}, { status: 'received', source: 'sent_for_review' },
  );
  assert.equal(out.rows[0].brand.length, 120);
  assert.equal(out.errors.length, 0);
});

test('buildRows never emits a value the worker would reject', () => {
  const out = buildRows(
    { headers: ['Name', 'Status'], rows: [['X', 'nonsense']] },
    { name: 0, status: 1 }, { status: {} }, { status: 'received', source: 'sent_for_review' },
  );
  assert.equal(out.rows[0].status, 'received');
});

import { dedupeKey, findDuplicates } from '../public/import-lib.js';

test('ASIN wins when both sides have one', () => {
  const inc = [{ name: 'Renamed Lantern', asin: 'b0abc12345' }];
  const ex = [{ id: 'x1', name: 'Solar Lantern', asin: 'B0ABC12345' }];
  const r = findDuplicates(inc, ex);
  assert.ok(r.dupIndexes.has(0));
  assert.equal(r.existingIdByIndex.get(0), 'x1');
});

test('falls back to name plus date when there is no ASIN', () => {
  const inc = [{ name: ' solar LANTERN ', date_received: '2026-03-04' }];
  const ex = [{ id: 'x2', name: 'Solar Lantern', date_received: '2026-03-04' }];
  assert.ok(findDuplicates(inc, ex).dupIndexes.has(0));
});

test('same name but a different date is not a duplicate', () => {
  const inc = [{ name: 'Solar Lantern', date_received: '2026-03-05' }];
  const ex = [{ id: 'x3', name: 'Solar Lantern', date_received: '2026-03-04' }];
  assert.equal(findDuplicates(inc, ex).dupIndexes.size, 0);
});

test('an ASIN row never matches a no-ASIN row by name', () => {
  // Different products can share a name; the ASIN is the stronger claim, and
  // mixing the two rules would merge unrelated items.
  const inc = [{ name: 'Solar Lantern', asin: 'B0ABC12345' }];
  const ex = [{ id: 'x4', name: 'Solar Lantern' }];
  assert.equal(findDuplicates(inc, ex).dupIndexes.size, 0);
});

test('collisions inside one file are flagged, first wins', () => {
  const inc = [{ name: 'Mug', asin: 'B01' }, { name: 'Mug again', asin: 'B01' }];
  const r = findDuplicates(inc, []);
  assert.equal(r.dupIndexes.has(0), false);
  assert.equal(r.dupIndexes.has(1), true);
});

test('rows with no ASIN and no date are never duplicates of each other', () => {
  const inc = [{ name: 'Mug' }, { name: 'Mug' }];
  assert.equal(findDuplicates(inc, []).dupIndexes.size, 0);
});
