// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// overLimit against a real SQLite table built from migrations/0001_initial.sql's
// rate_limits definition, wrapped in a tiny D1-shaped adapter.
// Run: node --test --test-force-exit tests/ratelimit.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { overLimit } from '../src/lib/ratelimit.js';

const SCHEMA = (() => {
  const sql = readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8');
  const table = sql.match(/CREATE TABLE rate_limits[\s\S]*?\);/)[0];
  const index = sql.match(/CREATE INDEX idx_rate_limits_key_created[^;]*;/)[0];
  return table + '\n' + index;
})();

function d1(db) {
  return {
    prepare(q) {
      let args = [];
      const stmt = {
        bind(...a) { args = a; return stmt; },
        async first() { return db.prepare(q).get(...args) ?? null; },
        async run() { db.prepare(q).run(...args); return { success: true }; },
        _exec() { return /^\s*select/i.test(q) ? { results: db.prepare(q).all(...args) } : (db.prepare(q).run(...args), { results: [] }); },
      };
      return stmt;
    },
    // Like D1: the whole batch runs as one unit, with no other request in between.
    async batch(stmts) { return stmts.map(st => st._exec()); },
  };
}

function freshEnv() {
  const db = new DatabaseSync(':memory:');
  db.exec(SCHEMA);
  return { env: { DB: d1(db) }, db };
}

test('allows up to max hits in the window, then blocks', async () => {
  const { env } = freshEnv();
  for (let i = 0; i < 3; i++) assert.equal(await overLimit(env, 'reset-email:a@b.co', 3, 900), false);
  assert.equal(await overLimit(env, 'reset-email:a@b.co', 3, 900), true);
  assert.equal(await overLimit(env, 'reset-email:a@b.co', 3, 900), true);
});

test('keys are independent', async () => {
  const { env } = freshEnv();
  assert.equal(await overLimit(env, 'vr:a@b.co', 1, 60), false);
  assert.equal(await overLimit(env, 'vr:a@b.co', 1, 60), true);
  assert.equal(await overLimit(env, 'vr:c@d.co', 1, 60), false);
});

test('hits older than the window fall off and get cleaned up', async () => {
  const { env, db } = freshEnv();
  const old = Math.floor(Date.now() / 1000) - 1000;
  for (let i = 0; i < 5; i++) db.prepare('INSERT INTO rate_limits (key, created_at) VALUES (?, ?)').run('checkout:u1', old);
  assert.equal(await overLimit(env, 'checkout:u1', 3, 900), false);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM rate_limits WHERE key = ?').get('checkout:u1').n, 1);
});

test('fails open when D1 throws', async () => {
  const env = { DB: { prepare() { throw new Error('D1 down'); } } };
  const orig = console.error; console.error = () => {};
  try { assert.equal(await overLimit(env, 'signup-ip:1.2.3.4', 1, 60), false); }
  finally { console.error = orig; }
});

test('a burst of parallel requests cannot slip past the cap', async () => {
  const { env } = freshEnv();
  const results = await Promise.all(Array.from({ length: 20 }, () => overLimit(env, 'vc:burst@b.co', 3, 60)));
  assert.equal(results.filter(over => !over).length, 3, 'exactly 3 of 20 parallel attempts should get through');
});
