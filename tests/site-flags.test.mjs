// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// /api/me tells the pages what this server has switched on (billing, feedback),
// so a copy without Stripe shows no prices and a copy without a feedback webhook
// shows no Feedback button. Also covers the STRIPE_AUTOMATIC_TAX setting.
// Run: node --test --test-force-exit tests/site-flags.test.mjs
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import worker, { fillShareUrls } from '../src/worker.js';
import { automaticTaxOn, createCheckoutSession } from '../src/lib/stripe.js';

const ORIGIN = 'https://example.com';
const MIG = new URL('../migrations/', import.meta.url);
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

function d1(db) {
  const stmt = (q, args = []) => ({
    bind: (...a) => stmt(q, a),
    first: async () => db.prepare(q).get(...args) ?? null,
    all: async () => ({ results: db.prepare(q).all(...args) }),
    run: async () => { const r = db.prepare(q).run(...args); return { success: true, meta: { changes: Number(r.changes) } }; },
  });
  return { prepare: q => stmt(q), batch: async list => Promise.all(list.map(s => s.run())) };
}
function makeEnv(extra = {}) {
  const db = new DatabaseSync(':memory:');
  for (const f of readdirSync(MIG).filter(f => f.endsWith('.sql')).sort()) db.exec(readFileSync(new URL(f, MIG), 'utf8'));
  return { DB: d1(db), APP_URL: ORIGIN, PP_SESSION_SECRET: 'x'.repeat(40), ...extra };
}
async function me(env) {
  const r = await worker.fetch(new Request(ORIGIN + '/api/me'), env, { waitUntil() {} });
  assert.equal(r.status, 200);
  return r.json();
}

test('logged-out /api/me reports billing on only when Stripe is configured', async () => {
  const off = await me(makeEnv({ FEEDBACK_WEBHOOK: 'https://hooks.example.com/f' }));
  assert.equal(off.user, null);
  assert.equal(off.billing, false);
  const on = await me(makeEnv({ STRIPE_SECRET_KEY: 'sk_test_x', STRIPE_PRICE_MONTHLY: 'price_M', FEEDBACK_WEBHOOK: 'https://hooks.example.com/f' }));
  assert.equal(on.billing, true);
  assert.equal(on.feedback, true);
});

test('a key without a price is not billing', async () => {
  const d = await me(makeEnv({ STRIPE_SECRET_KEY: 'sk_test_x' }));
  assert.equal(d.billing, false);
});

test('automatic tax: off by default on a copy, on only when set to true', () => {
  assert.equal(automaticTaxOn({}), false);
  assert.equal(automaticTaxOn({ STRIPE_AUTOMATIC_TAX: 'true' }), true);
  assert.equal(automaticTaxOn({ STRIPE_AUTOMATIC_TAX: 'false' }), false);
  assert.equal(automaticTaxOn({ STRIPE_AUTOMATIC_TAX: 'TRUE' }), true);
});

test('checkout sends the automatic tax setting to Stripe', async () => {
  const sent = [];
  globalThis.fetch = async (url, init) => { sent.push(String(init.body)); return new Response('{"id":"cs_1","url":"https://checkout.stripe.com/x"}', { status: 200 }); };
  const args = { customerEmail: 'a@example.com', priceId: 'price_M', successUrl: ORIGIN + '/s', cancelUrl: ORIGIN + '/c', clientReferenceId: 'u1' };
  await createCheckoutSession({ STRIPE_SECRET_KEY: 'sk_test_x', STRIPE_AUTOMATIC_TAX: 'true' }, args);
  await createCheckoutSession({ STRIPE_SECRET_KEY: 'sk_test_x' }, args);
  assert.match(decodeURIComponent(sent[0]), /automatic_tax\[enabled\]=true/);
  assert.match(decodeURIComponent(sent[1]), /automatic_tax\[enabled\]=false/);
});

// Link previews need full addresses. A copy whose pages say content="/og.png"
// gets APP_URL put in front at serve time. Full addresses are never touched.
test('relative share tags get APP_URL, absolute ones stay as they are', async () => {
  const page = '<meta property="og:url" content="/">\n<meta property="og:image" content="/og.png?v=1">\n<meta name="twitter:image" content="/og.png?v=1">\n<link rel="icon" href="/favicon.svg">';
  const out = fillShareUrls(page, { APP_URL: 'https://pp.example.com/' });
  assert.ok(out.includes('<meta property="og:url" content="https://pp.example.com/">'));
  assert.ok(out.includes('<meta property="og:image" content="https://pp.example.com/og.png?v=1">'));
  assert.ok(out.includes('<meta name="twitter:image" content="https://pp.example.com/og.png?v=1">'));
  assert.ok(out.includes('href="/favicon.svg"'), 'other tags untouched');
  const live = '<meta property="og:image" content="https://porchpile.com/og.png?v=ps1">';
  assert.equal(fillShareUrls(live, { APP_URL: 'https://porchpile.com' }), live);
  assert.equal(fillShareUrls(page, {}), page, 'no APP_URL leaves the page as is');
  assert.equal(fillShareUrls('<meta property="og:image" content="//cdn.example.com/x.png">', { APP_URL: 'https://pp.example.com' }),
    '<meta property="og:image" content="//cdn.example.com/x.png">');
});

test('served HTML pages get their share tags filled, other files pass through', async () => {
  const files = {
    '/': ['<meta property="og:image" content="/og.png">', 'text/html; charset=utf-8'],
    '/live': ['<meta property="og:image" content="https://porchpile.com/og.png">', 'text/html; charset=utf-8'],
    '/x.js': ['const a = \'<meta property="og:image" content="/og.png">\';', 'application/javascript'],
  };
  const env = makeEnv({ APP_URL: 'https://pp.example.com', ASSETS: { fetch: async req => {
    const [body, type] = files[new URL(req.url).pathname];
    return new Response(body, { status: 200, headers: { 'Content-Type': type, 'Content-Length': String(body.length) } });
  } } });
  const get = async p => worker.fetch(new Request('https://pp.example.com' + p), env, { waitUntil() {} });
  let r = await get('/');
  assert.equal(await r.text(), '<meta property="og:image" content="https://pp.example.com/og.png">');
  assert.ok(r.headers.get('Content-Security-Policy'), 'CSP still set');
  r = await get('/live');
  assert.equal(await r.text(), files['/live'][0]);
  r = await get('/x.js');
  assert.equal(await r.text(), files['/x.js'][0]);
});
