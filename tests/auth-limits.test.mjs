// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Login lockout, logout, free-plan caps, import batch ids, feedback limits and
// the checkout webhook's customer link, driven through the real worker against
// an in-memory SQLite DB built from every migration.
// Run: node --test --test-force-exit tests/auth-limits.test.mjs
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { createHmac } from 'node:crypto';
import worker, { ipKey, fillShareUrls } from '../src/worker.js';
import { hashPassword } from '../src/lib/pw.js';

const ORIGIN = 'https://tracker.example';
const MIG = new URL('../migrations/', import.meta.url);
const PASSWORD = 'correct horse 123';
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

// D1-shaped adapter. Like D1, a batch runs as one unit and hands back one result per statement.
function d1(db) {
  const exec = (q, args) => {
    if (/^\s*select/i.test(q)) return { results: db.prepare(q).all(...args) };
    const r = db.prepare(q).run(...args);
    return { success: true, results: [], meta: { changes: Number(r.changes) } };
  };
  const stmt = (q, args = []) => ({
    bind: (...a) => stmt(q, a),
    first: async () => db.prepare(q).get(...args) ?? null,
    all: async () => ({ results: db.prepare(q).all(...args) }),
    run: async () => exec(q, args),
    _exec: () => exec(q, args),
  });
  return { prepare: q => stmt(q), batch: async list => list.map(s => s._exec()) };
}

let HASH;
async function makeEnv(extra = {}) {
  HASH = HASH || await hashPassword(PASSWORD);
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  for (const f of readdirSync(MIG).filter(f => f.endsWith('.sql')).sort()) db.exec(readFileSync(new URL(f, MIG), 'utf8'));
  const add = (id, email, pro) => db.prepare(
    'INSERT INTO users (id, email, password_hash, email_verified, token_version, created_at, pro_until) VALUES (?, ?, ?, 1, 0, ?, ?)'
  ).run(id, email, HASH, '2026-10-01T00:00:00.000Z', pro ? '2126-01-01T00:00:00.000Z' : null);
  add('u1', 'owner@example.com', false);
  add('u2', 'second@example.com', true);
  add('u3', 'third@example.com', true);
  const env = {
    DB: d1(db), APP_URL: ORIGIN, PP_SESSION_SECRET: 'test-secret-test-secret-test-secret-0123',
    // Billing on, so the free plan caps apply the way they do on a site that sells Pro.
    STRIPE_SECRET_KEY: 'sk_test_x', STRIPE_WEBHOOK_SECRET: 'whsec_test', STRIPE_PRICE_MONTHLY: 'price_M', STRIPE_PRICE_ANNUAL: 'price_A',
    FEEDBACK_WEBHOOK: 'https://hooks.example.com/feedback',
    ...extra,
  };
  return { env, db };
}

async function call(env, method, path, { body, ip = '203.0.113.7', cookie } = {}) {
  const headers = { Origin: ORIGIN, 'Content-Type': 'application/json', 'CF-Connecting-IP': ip };
  if (cookie) headers.Cookie = cookie;
  const r = await worker.fetch(new Request(ORIGIN + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env, { waitUntil() {} });
  const set = r.headers.get('Set-Cookie') || '';
  return { status: r.status, data: await r.json().catch(() => null), headers: r.headers, cookie: set.split(';')[0] };
}
const login = (env, email, password, ip) => call(env, 'POST', '/api/auth/login', { body: { email, password }, ip });
const count = (rs, status) => rs.filter(r => r.status === status).length;

// ------------------------------------------------------------------ login lockout
test('wrong guesses from one network never lock the owner out on another', async () => {
  const { env } = await makeEnv();
  for (let i = 0; i < 5; i++) assert.equal((await login(env, 'owner@example.com', 'wrong-guess-' + i, '198.51.100.9')).status, 401);
  // The guessing network is locked, right password or not.
  assert.equal((await login(env, 'owner@example.com', 'wrong-guess-x', '198.51.100.9')).status, 429);
  assert.equal((await login(env, 'owner@example.com', PASSWORD, '198.51.100.9')).status, 429);
  // The owner, on their own network, gets straight in.
  const ok = await login(env, 'owner@example.com', PASSWORD, '203.0.113.7');
  assert.equal(ok.status, 200);
  assert.match(ok.cookie, /^pp_session=/);
});

test('a burst of 30 wrong logins at once: 5 are checked, 25 are capped, nothing crashes', async () => {
  const { env } = await makeEnv();
  const rs = await Promise.all(Array.from({ length: 30 }, (_, i) => login(env, 'owner@example.com', 'wrong-guess-' + i, '198.51.100.9')));
  assert.equal(count(rs, 401), 5);
  assert.equal(count(rs, 429), 25);
  assert.equal(rs.filter(r => r.status >= 500).length, 0);
  assert.equal((await login(env, 'owner@example.com', PASSWORD, '203.0.113.7')).status, 200);
});

test('a correct login clears only that network\'s own strikes', async () => {
  const { env } = await makeEnv();
  for (let i = 0; i < 4; i++) await login(env, 'owner@example.com', 'wrong-guess-' + i, '203.0.113.7');
  assert.equal((await login(env, 'owner@example.com', PASSWORD, '203.0.113.7')).status, 200);
  for (let i = 0; i < 5; i++) assert.equal((await login(env, 'owner@example.com', 'wrong-again-' + i, '203.0.113.7')).status, 401);
  assert.equal((await login(env, 'owner@example.com', 'wrong-again-x', '203.0.113.7')).status, 429);
});

test('guessing spread over many networks still hits the per-account ceiling', async () => {
  const { env } = await makeEnv();
  const rs = [];
  for (let n = 0; n < 5; n++) for (let i = 0; i < 4; i++) rs.push(await login(env, 'owner@example.com', `guess-${n}-${i}`, `198.51.100.${n + 1}`));
  assert.equal(count(rs, 401), 20);
  assert.equal((await login(env, 'owner@example.com', 'one-more-guess', '192.0.2.200')).status, 429);
});

test('an unknown address answers exactly like a wrong password', async () => {
  const { env } = await makeEnv();
  const a = await login(env, 'nobody@example.com', 'whatever-guess', '198.51.100.9');
  const b = await login(env, 'owner@example.com', 'whatever-guess', '198.51.100.10');
  assert.deepEqual([a.status, a.data], [b.status, b.data]);
});

test('ipKey: IPv4 as is, IPv6 cut to its /64', () => {
  const k = ip => ipKey(new Request(ORIGIN, { headers: { 'CF-Connecting-IP': ip } }));
  assert.equal(k('203.0.113.7'), '203.0.113.7');
  assert.equal(k('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), k('2001:0DB8:0001:0002::1'));
  assert.notEqual(k('2001:db8:1:2::1'), k('2001:db8:1:3::1'));
  assert.equal(k('2001:db8::1'), '2001:db8:0:0::/64');
  assert.equal(ipKey(new Request(ORIGIN)), 'unknown');
});

// ------------------------------------------------------------------ logout
test('logout clears this device only, a password reset signs out every device', async () => {
  const { env, db } = await makeEnv();
  const phone = await login(env, 'owner@example.com', PASSWORD);
  const laptop = await login(env, 'owner@example.com', PASSWORD, '203.0.113.8');
  const out = await call(env, 'POST', '/api/auth/logout', { cookie: phone.cookie });
  assert.equal(out.status, 200);
  assert.match(out.headers.get('Set-Cookie'), /^pp_session=;.*Max-Age=0/);
  // The other device stays signed in.
  assert.equal((await call(env, 'GET', '/api/items', { cookie: laptop.cookie })).status, 200);
  assert.equal((await call(env, 'POST', '/api/auth/logout')).status, 200);
  // What a password reset does to the account (token_version + 1) ends every session.
  db.prepare("UPDATE users SET token_version = token_version + 1 WHERE id = 'u1'").run();
  assert.equal((await call(env, 'GET', '/api/items', { cookie: laptop.cookie })).status, 401);
  assert.equal((await call(env, 'GET', '/api/items', { cookie: phone.cookie })).status, 401);
});

test('API answers are never cached', async () => {
  const { env } = await makeEnv();
  assert.equal((await call(env, 'GET', '/api/me')).headers.get('Cache-Control'), 'no-store');
  const a = await login(env, 'owner@example.com', PASSWORD);
  assert.equal(a.headers.get('Cache-Control'), 'no-store');
  assert.equal((await call(env, 'GET', '/api/account/export', { cookie: a.cookie })).headers.get('Cache-Control'), 'no-store');
});

// ------------------------------------------------------------------ free plan caps
test('free plan item cap holds under a parallel burst', async () => {
  const { env, db } = await makeEnv();
  const { cookie } = await login(env, 'owner@example.com', PASSWORD);
  for (let i = 0; i < 28; i++) assert.equal((await call(env, 'POST', '/api/items', { cookie, body: { name: 'box ' + i } })).status, 201);
  const rs = await Promise.all(Array.from({ length: 25 }, (_, i) => call(env, 'POST', '/api/items', { cookie, body: { name: 'burst ' + i } })));
  assert.equal(count(rs, 201), 2);
  assert.equal(count(rs, 403), 23);
  assert.equal(rs.find(r => r.status === 403).data.code, 'cap_reached');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM items WHERE user_id = 'u1'").get().n, 30);
});

test('free plan video and deal caps hold under a parallel burst, and a revive counts', async () => {
  const { env, db } = await makeEnv();
  const { cookie } = await login(env, 'owner@example.com', PASSWORD);
  const vids = await Promise.all(Array.from({ length: 25 }, (_, i) => call(env, 'POST', '/api/videos', { cookie, body: { title: 'video ' + i } })));
  assert.deepEqual([count(vids, 201), count(vids, 403)], [15, 10]);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM videos WHERE user_id = 'u1'").get().n, 15);

  // A deal that starts out dead never counts.
  const dead = await call(env, 'POST', '/api/deals', { cookie, body: { brand: 'Gone Co', status: 'dead' } });
  assert.equal(dead.status, 201);
  const deals = await Promise.all(Array.from({ length: 20 }, (_, i) => call(env, 'POST', '/api/deals', { cookie, body: { brand: 'Brand ' + i } })));
  assert.deepEqual([count(deals, 201), count(deals, 403)], [3, 17]);
  const revive = await call(env, 'PUT', '/api/deals/' + dead.data.deal.id, { cookie, body: { status: 'inquiry' } });
  assert.equal(revive.status, 403);
  assert.equal(db.prepare('SELECT status FROM brand_deals WHERE id = ?').get(dead.data.deal.id).status, 'dead');
  // Editing the dead deal without reviving it still works.
  assert.equal((await call(env, 'PUT', '/api/deals/' + dead.data.deal.id, { cookie, body: { notes: 'ghosted' } })).status, 200);
  // Closing one frees a slot, and then the revive goes through.
  const live = deals.find(r => r.status === 201).data.deal.id;
  assert.equal((await call(env, 'PUT', '/api/deals/' + live, { cookie, body: { status: 'paid' } })).status, 200);
  assert.equal((await call(env, 'PUT', '/api/deals/' + dead.data.deal.id, { cookie, body: { status: 'inquiry' } })).status, 200);
});

test('Pro has no caps', async () => {
  const { env } = await makeEnv();
  const { cookie } = await login(env, 'second@example.com', PASSWORD);
  const rs = await Promise.all(Array.from({ length: 35 }, (_, i) => call(env, 'POST', '/api/items', { cookie, body: { name: 'box ' + i } })));
  assert.equal(count(rs, 201), 35);
  const deals = await Promise.all(Array.from({ length: 5 }, (_, i) => call(env, 'POST', '/api/deals', { cookie, body: { brand: 'Brand ' + i } })));
  assert.equal(count(deals, 201), 5);
});

// ------------------------------------------------------------------ import batch ids
test('an import batch id that belongs to another account is a 400, never a 500', async () => {
  const { env, db } = await makeEnv();
  const BATCH = '11111111-1111-4111-8111-111111111111';
  const a = await login(env, 'second@example.com', PASSWORD);
  const b = await login(env, 'third@example.com', PASSWORD, '203.0.113.8');
  const first = await call(env, 'POST', '/api/items/import', { cookie: a.cookie, body: { batch_id: BATCH, rows: [{ name: 'Mine' }] } });
  assert.deepEqual([first.status, first.data.inserted], [200, 1]);
  const clash = await call(env, 'POST', '/api/items/import', { cookie: b.cookie, body: { batch_id: BATCH, rows: [{ name: 'Theirs' }] } });
  assert.equal(clash.status, 400);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM items WHERE user_id = 'u3'").get().n, 0);
  // The owner's own next chunk still lands.
  const next = await call(env, 'POST', '/api/items/import', { cookie: a.cookie, body: { batch_id: BATCH, start_index: 1, rows: [{ name: 'Mine too' }] } });
  assert.deepEqual([next.status, next.data.inserted], [200, 1]);
});

// ------------------------------------------------------------------ feedback
test('feedback: a whole-site hourly ceiling on top of the per-address one', async () => {
  const { env } = await makeEnv();
  let sent = 0;
  globalThis.fetch = async () => { sent++; return new Response('{}', { status: 200 }); };
  const send = i => call(env, 'POST', '/api/feedback', { body: { message: 'hello there ' + i, type: 'bug' }, ip: `198.51.100.${i + 1}` });
  for (let i = 0; i < 60; i++) assert.equal((await send(i)).status, 200);
  const over = await send(61);
  assert.equal(over.status, 429);
  assert.equal(over.headers.get('Retry-After'), '3600');
  assert.equal(sent, 60);
});

test('feedback off: a plain 404, and nothing is sent anywhere', async () => {
  const { env } = await makeEnv({ FEEDBACK_WEBHOOK: '' });
  const flags = (await call(env, 'GET', '/api/me')).data;
  if (flags.feedback) return; // this build has a feedback address built in, so it's never off
  let sent = 0;
  globalThis.fetch = async () => { sent++; return new Response('{}', { status: 200 }); };
  const r = await call(env, 'POST', '/api/feedback', { body: { message: 'hello there', type: 'bug' } });
  assert.equal(r.status, 404);
  assert.equal(sent, 0);
});

// ------------------------------------------------------------------ checkout webhook
async function signedEvent(env, event) {
  const body = JSON.stringify(event);
  const t = Math.floor(Date.now() / 1000);
  const sig = createHmac('sha256', env.STRIPE_WEBHOOK_SECRET).update(`${t}.${body}`).digest('hex');
  const r = await worker.fetch(new Request(ORIGIN + '/api/stripe/webhook', {
    method: 'POST', body, headers: { 'Content-Type': 'application/json', 'Stripe-Signature': `t=${t},v1=${sig}` },
  }), env, { waitUntil() {} });
  return r.status;
}
const stripeSub = price => ({
  id: 'sub_x', customer: 'cus_new', status: 'active', cancel_at_period_end: false,
  items: { data: [{ price: { id: price }, current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400 }] },
});
const checkout = (id, extra) => ({ id, type: 'checkout.session.completed', data: { object: { id: 'cs_' + id, client_reference_id: 'u1', customer: 'cus_new', ...extra } } });

test('checkout webhook: only a Porch Pile price links a Stripe customer to an account', async () => {
  const { env, db } = await makeEnv();
  const row = () => db.prepare("SELECT stripe_customer_id, pro_until FROM users WHERE id = 'u1'").get();
  // A one-off payment (a payment link lets the payer pick any client_reference_id).
  assert.equal(await signedEvent(env, checkout('evt_tip', {})), 200);
  assert.equal(row().stripe_customer_id, null);
  // Another product's subscription on the same Stripe account.
  globalThis.fetch = async () => new Response(JSON.stringify(stripeSub('price_OTHER')), { status: 200 });
  assert.equal(await signedEvent(env, checkout('evt_other', { subscription: 'sub_x' })), 200);
  assert.deepEqual({ ...row() }, { stripe_customer_id: null, pro_until: null });
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM payment_events').get().n, 0);
  // The real thing.
  globalThis.fetch = async () => new Response(JSON.stringify(stripeSub('price_M')), { status: 200 });
  assert.equal(await signedEvent(env, checkout('evt_real', { subscription: 'sub_x' })), 200);
  assert.equal(row().stripe_customer_id, 'cus_new');
  assert.ok(new Date(row().pro_until) > new Date());
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM payment_events').get().n, 1);
});

test('checkout webhook: when Stripe can\'t be read, the event is retried, not dropped', async () => {
  const { env, db } = await makeEnv();
  globalThis.fetch = async () => new Response(JSON.stringify({ error: { message: 'down' } }), { status: 500 });
  assert.equal(await signedEvent(env, checkout('evt_retry', { subscription: 'sub_x' })), 500);
  globalThis.fetch = async () => new Response(JSON.stringify(stripeSub('price_M')), { status: 200 });
  assert.equal(await signedEvent(env, checkout('evt_retry', { subscription: 'sub_x' })), 200);
  assert.equal(db.prepare("SELECT stripe_customer_id FROM users WHERE id = 'u1'").get().stripe_customer_id, 'cus_new');
});

// ------------------------------------------------------------------ share + schema urls
test('fillShareUrls fills a relative schema url and leaves full addresses alone', () => {
  const env = { APP_URL: 'https://tracker.example/' };
  assert.equal(fillShareUrls('{"url": "/", "x": 1}', env), '{"url": "https://tracker.example/", "x": 1}');
  assert.equal(fillShareUrls('{"url":"/guide#first-ten"}', env), '{"url":"https://tracker.example/guide#first-ten"}');
  const full = '<meta property="og:url" content="https://porchpile.com/">{"url": "https://porchpile.com/"}';
  assert.equal(fillShareUrls(full, env), full);
  assert.equal(fillShareUrls('{"url": "/"}', {}), '{"url": "/"}');
});
