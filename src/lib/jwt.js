// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Porch Pile session JWT (HS256, Web Crypto). Signed with PP_SESSION_SECRET.
// Carries token_version (tv): a session is valid only while its tv matches the
// user's current users.token_version — so a password reset (which bumps tv)
// invalidates every outstanding session at once.

const enc = new TextEncoder();

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlStr(s) { return b64url(enc.encode(s)); }
function b64urlDecodeStr(s) {
  const pad = s + '='.repeat((4 - s.length % 4) % 4);
  return atob(pad.replace(/-/g, '+').replace(/_/g, '/'));
}

function requireSecret(secret) {
  // Refuse to sign or check logins without a real secret. A missing one would turn into the
  // word 'undefined', and anyone could forge a session.
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('PP_SESSION_SECRET must be set to a random string of 32+ characters.');
}
async function hmac(secret, msg) {
  requireSecret(secret);
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return crypto.subtle.sign('HMAC', key, enc.encode(msg));
}
async function hmacVerify(secret, msg, sigB64) {
  requireSecret(secret);
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const pad = sigB64 + '='.repeat((4 - sigB64.length % 4) % 4);
  const raw = atob(pad.replace(/-/g, '+').replace(/_/g, '/'));
  const sig = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) sig[i] = raw.charCodeAt(i);
  return crypto.subtle.verify('HMAC', key, sig, enc.encode(msg));
}

const EXP_SECONDS = 30 * 24 * 60 * 60; // 30 days

export async function signSessionJWT({ sub, email, tv }, secret) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64urlStr(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64urlStr(JSON.stringify({
    sub, email, tv: tv || 0, iat: now, exp: now + EXP_SECONDS, iss: 'porchpile',
    jti: crypto.randomUUID(),
  }));
  const sig = b64url(await hmac(secret, `${header}.${payload}`));
  return `${header}.${payload}.${sig}`;
}

export async function verifySessionJWT(token, secret) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  let payload;
  try { payload = JSON.parse(b64urlDecodeStr(p)); } catch { return null; }
  if (payload.iss !== 'porchpile') return null;
  if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) return null;
  const ok = await hmacVerify(secret, `${h}.${p}`, s);
  if (!ok) return null;
  return payload;
}
