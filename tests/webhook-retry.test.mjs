// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// A webhook that 500s must release its idempotency lock, or Stripe's retry
// hits "duplicate" and a paying customer stays on free for good.
// Drives the real worker against an in-memory SQLite DB built from every
// migration. Run: node --test --test-force-exit tests/webhook-retry.test.mjs
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { createHmac } from 'node:crypto';
import worker from '../src/worker.js';

const ORIGIN = 'https://porchpile.com';
const MIG = new URL('../migrations/', import.meta.url);
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

// D1-shaped adapter. failOnce: a regex; the first run() whose SQL matches throws.
function d1(db, opts = {}) {
  const stmt = (q, args = []) => ({
    bind: (...a) => stmt(q, a),
    first: async () => db.prepare(q).get(...args) ?? null,
    all: async () => ({ results: db.prepare(q).all(...args) }),
    run: async () => {
      if (opts.failOnce && opts.failOnce.test(q)) { opts.failOnce = null; throw new Error('D1 down (test)'); }
      const r = db.prepare(q).run(...args);
      return { success: true, meta: { changes: Number(r.changes) } };
    },
  });
  return { prepare: q => stmt(q), batch: async list => Promise.all(list.map(s => s.run())) };
}

function makeEnv(opts = {}) {
  const db = new DatabaseSync(':memory:');
  for (const f of readdirSync(MIG).filter(f => f.endsWith('.sql')).sort()) db.exec(readFileSync(new URL(f, MIG), 'utf8'));
  db.prepare(
    'INSERT INTO users (id, email, password_hash, email_verified, token_version, created_at, stripe_customer_id) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run('u1', 'buyer@example.com', 'x', 1, 0, '2026-10-01T00:00:00.000Z', 'cus_1');
  const env = {
    DB: d1(db, opts), APP_URL: ORIGIN, STRIPE_SECRET_KEY: 'sk_test_x', STRIPE_WEBHOOK_SECRET: 'whsec_test',
    STRIPE_PRICE_MONTHLY: 'price_M', STRIPE_PRICE_ANNUAL: 'price_A',
  };
  return { env, row: () => db.prepare('SELECT * FROM users WHERE id = ?').get('u1') };
}

async function signedEvent(env, event) {
  const body = JSON.stringify(event);
  const t = Math.floor(Date.now() / 1000);
  const sig = createHmac('sha256', env.STRIPE_WEBHOOK_SECRET).update(`${t}.${body}`).digest('hex');
  const r = await worker.fetch(new Request(ORIGIN + '/api/stripe/webhook', {
    method: 'POST', body, headers: { 'Content-Type': 'application/json', 'Stripe-Signature': `t=${t},v1=${sig}` },
  }), env, { waitUntil() {} });
  return { status: r.status, data: await r.json().catch(() => null) };
}

const subEvent = id => ({
  id, type: 'customer.subscription.updated',
  data: { object: {
    id: 'sub_1', customer: 'cus_1', status: 'active', cancel_at_period_end: false,
    current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400,
    items: { data: [{ price: { id: 'price_M' }, current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400 }] },
  } },
});

test('a failed grant releases the lock so Stripe\'s retry grants', async () => {
  const { env, row } = makeEnv({ failOnce: /UPDATE users SET pro_until/ });
  globalThis.fetch = async () => new Response('{}', { status: 200 });
  const e = subEvent('evt_retry');
  assert.equal((await signedEvent(env, e)).status, 500);
  assert.equal(row().pro_until, null);
  const retry = await signedEvent(env, e);
  assert.equal(retry.status, 200);
  assert.notEqual(retry.data?.duplicate, true);
  assert.ok(row().pro_until, 'retry should grant Pro');
});

test('a delivered event is still deduped', async () => {
  const { env } = makeEnv();
  globalThis.fetch = async () => new Response('{}', { status: 200 });
  const e = subEvent('evt_once');
  assert.equal((await signedEvent(env, e)).status, 200);
  const again = await signedEvent(env, e);
  assert.equal(again.status, 200);
  assert.equal(again.data?.duplicate, true);
});

// Orphan checkout: the account was deleted while its Checkout page was still
// open, then the page got paid. The new subscription must be canceled at once
// (Porch Pile prices only) and flagged for the operator. Never refunded by code.
const checkoutEvent = (id, uid) => ({
  id, type: 'checkout.session.completed',
  data: { object: { id: 'cs_1', client_reference_id: uid, customer: 'cus_new', subscription: 'sub_new', amount_total: 900, currency: 'usd' } },
});
function stripeStub(priceId) {
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url); calls.push({ url: u, method: init.method || 'GET', body: init.body });
    if (u.includes('/subscriptions/sub_new') && (init.method || 'GET') === 'GET') {
      return new Response(JSON.stringify({ id: 'sub_new', status: 'active', customer: 'cus_new', items: { data: [{ price: { id: priceId } }] } }), { status: 200 });
    }
    return new Response('{}', { status: 200 });
  };
  return calls;
}
const alertEnv = env => Object.assign(env, { ALERT_WEBHOOK_URL: 'https://alerts.test/hook', ALERT_TOKEN: 't' });

test('a paid checkout for a deleted account cancels the subscription and flags it, no refund', async () => {
  const { env } = makeEnv(); alertEnv(env);
  const calls = stripeStub('price_M');
  const r = await signedEvent(env, checkoutEvent('evt_orphan', 'gone-user'));
  assert.equal(r.status, 200);
  assert.ok(calls.some(c => c.method === 'DELETE' && c.url.endsWith('/subscriptions/sub_new')), 'subscription canceled');
  assert.ok(!calls.some(c => c.url.includes('/refunds')), 'never refunds');
  const alert = calls.find(c => c.url === 'https://alerts.test/hook');
  assert.ok(alert, 'the operator is flagged');
  assert.match(JSON.parse(alert.body).message, /sub_new/);
});

test('an orphan checkout for another product is left alone', async () => {
  const { env } = makeEnv(); alertEnv(env);
  const calls = stripeStub('price_other_app');
  assert.equal((await signedEvent(env, checkoutEvent('evt_other', 'gone-user'))).status, 200);
  assert.ok(!calls.some(c => c.method === 'DELETE'));
  assert.ok(!calls.some(c => c.url === 'https://alerts.test/hook'));
});

test('a checkout for a live account still grants and cancels nothing', async () => {
  const { env, row } = makeEnv(); alertEnv(env);
  const calls = stripeStub('price_M');
  assert.equal((await signedEvent(env, checkoutEvent('evt_live', 'u1'))).status, 200);
  assert.ok(!calls.some(c => c.method === 'DELETE'));
  assert.ok(!calls.some(c => c.url === 'https://alerts.test/hook'));
  assert.equal(row().stripe_subscription_id, 'sub_new');
});
