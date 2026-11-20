// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Porch Pile — Cloudflare Worker + D1.
//
// Security posture (secure from commit #1):
//   - All D1 access via prepared statements + .bind()
//   - Every endpoint validates input shape + length before any DB call
//   - user_id comes from the session JWT, never the request body
//   - Every user-owned query is scoped WHERE user_id = ?
//   - Sessions: HS256 JWT in an HttpOnly/Secure/SameSite=Lax cookie, carrying
//     token_version; a session is valid only while tv == users.token_version,
//     so a password reset invalidates every session at once
//   - Generic auth errors (no account-existence enumeration); constant-time pw
//   - Per-account login lockout (5 fails / 15 min); signup Turnstile + IP throttle
//   - CSRF: SameSite cookie + Origin/Referer allowlist on mutations
//   - 64 KB body cap; HSTS + CSP + anti-clickjacking headers on every response
//   - GDPR: authed export + password-gated hard delete
//   - Any 5xx fires an email beacon (alert.js)

import { signSessionJWT, verifySessionJWT } from './lib/jwt.js';
import { hashPassword, verifyPassword } from './lib/pw.js';
import { reportServerError, alertPayloadFor, stripAlertHeader } from './lib/alert.js';
import { importItems, recentImport, undoImport } from './lib/import.js';
import { overLimit } from './lib/ratelimit.js';
import {
  verifyWebhook, isPorchPileSub, invoiceIsPorchPile, periodEndOf,
  createCheckoutSession, createPortalSession, retrieveSubscription,
  retrieveInvoice, retrieveCharge, listCustomerSubscriptions, cancelAllSubscriptions, cancelSubscription,
} from './lib/stripe.js';

// ------------------------------------------------------------- config
const COOKIE = 'pp_session';
const SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days, matches JWT exp

function allowedOrigins(env) {
  // workers.dev preview + custom domain (once live). APP_URL var can add more.
  // Your app's address comes from APP_URL. EXTRA_ORIGINS adds more, comma separated.
  const list = (env.EXTRA_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (env.APP_URL && !list.includes(env.APP_URL)) list.push(env.APP_URL);
  return list;
}

// ------------------------------------------------------------- headers
function securityHeaders() {
  return {
    'Strict-Transport-Security': 'max-age=15552000; includeSubDomains', // 6mo, NO preload (per rules)
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(self)',
  };
}
// CSP for a vanilla single-page app with inline styles/scripts + Turnstile widget.
function cspHeader() {
  return [
    "default-src 'self'",
    // static.cloudflareinsights.com = Cloudflare's zone-injected Web Analytics
    // beacon; without the allowance it just spams the console with CSP blocks.
    "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://static.cloudflareinsights.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    // Feedback goes through the Worker's /api/feedback relay now, so the
    // browser never talks to the feedback webhook directly.
    "connect-src 'self' https://cloudflareinsights.com",
    "frame-src https://challenges.cloudflare.com",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}

function res(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    // no-store: API answers hold account data and must never sit in a shared or browser cache.
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...securityHeaders(), ...extraHeaders },
  });
}
function badReq(msg = 'Invalid request') { return res({ error: msg }, 400); }
function unauth() { return res({ error: 'Unauthorized' }, 401); }
function notFound() { return res({ error: 'Not found' }, 404); }

// ------------------------------------------------------------- validators
const isEmail = v => typeof v === 'string' && v.length > 3 && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const isTz = v => typeof v === 'string' && v.length <= 64 && /^[A-Za-z0-9_+\-/]+$/.test(v);

async function sha256Hex(input) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// One structured line per auth event, read in Workers Logs ([observability]
// in wrangler.toml). Never a raw password, token or email: email and IP are
// sha256 hashes, uid is the opaque account id.
async function authLog(request, type, { uid, email } = {}) {
  try {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const line = { evt: 'auth', type, ip_hash: (await sha256Hex('ip:' + ip)).slice(0, 16) };
    if (uid) line.uid = uid;
    else if (email) line.email_hash = (await sha256Hex(String(email).trim().toLowerCase())).slice(0, 16);
    console.log(JSON.stringify(line));
  } catch {}
}

const MAX_BODY_BYTES = 64 * 1024;
async function readJson(request, maxBytes = MAX_BODY_BYTES) {
  const cl = request.headers.get('Content-Length');
  if (cl && Number(cl) > maxBytes) return null;
  try {
    const text = await request.text();
    if (!text || text.length > maxBytes) return null;
    return JSON.parse(text);
  } catch { return null; }
}

// Import chunks carry up to 500 rows with notes fields, so the default 64KB
// body cap would reject legitimate chunks. Only /api/items/import gets this.
const MAX_IMPORT_BODY_BYTES = 1024 * 1024;

// ------------------------------------------------------------- cookies / session
function parseCookies(request) {
  const raw = request.headers.get('Cookie') || '';
  const out = {};
  raw.split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
function sessionCookie(token) {
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_MAX_AGE}`;
}
function clearCookie() {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

// Resolve the authed user from the session cookie. Verifies signature, expiry,
// and that the token_version still matches (global revocation).
async function getUser(request, env) {
  const token = parseCookies(request)[COOKIE];
  if (!token) return null;
  const payload = await verifySessionJWT(token, env.PP_SESSION_SECRET);
  if (!payload || !payload.sub) return null;
  const row = await env.DB.prepare('SELECT id, email, token_version FROM users WHERE id = ?')
    .bind(payload.sub).first();
  if (!row) return null;
  if ((payload.tv || 0) !== row.token_version) return null; // stale after reset
  return { id: row.id, email: row.email };
}

async function mintSession(user, env) {
  const token = await signSessionJWT({ sub: user.id, email: user.email, tv: user.token_version || 0 }, env.PP_SESSION_SECRET);
  return sessionCookie(token);
}

// CSRF: same-origin required on mutating requests.
function checkOrigin(request, env) {
  const m = request.method;
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return true;
  const origins = allowedOrigins(env);
  const origin = request.headers.get('Origin') || '';
  const referer = request.headers.get('Referer') || '';
  if (origin && origins.includes(origin)) return true;
  if (referer && origins.some(o => referer.startsWith(o + '/'))) return true;
  return false;
}

// ------------------------------------------------------------- rate limits
// overLimit (the D1 sliding-window cap) lives in ./lib/ratelimit.js so it can
// be unit-tested under plain node.
const tooMany = (msg, retryS) => res({ error: msg }, 429, { 'Retry-After': String(retryS) });
async function rlClear(env, key) {
  try { await env.DB.prepare('DELETE FROM rate_limits WHERE key = ?').bind(key).run(); } catch {}
}
const LOGIN_MAX = 5, LOGIN_WINDOW = 900;
// Ceiling on wrong-password tries against ONE account from every network added
// together, so guessing spread across many networks stays slow (20 per 15
// minutes). Above one network's 5 so a single guesser can't lock the owner out,
// and a password reset always gets the owner back in.
const LOGIN_ALL_MAX = 20;

// A caller's network, for rate-limit keys: an IPv4 address as is, an IPv6
// address cut to its /64 (one home or phone network), so hopping between
// addresses inside one network doesn't hand out a fresh allowance each time.
export function ipKey(request) {
  const ip = (request.headers.get('CF-Connecting-IP') || 'unknown').toLowerCase();
  if (!ip.includes(':')) return ip;
  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : h;
  return groups.slice(0, 4).map(g => g.replace(/^0+(?=.)/, '')).join(':') + '::/64';
}

// ------------------------------------------------------------- Turnstile
// Verifies the signup challenge. If TURNSTILE_SECRET is unset (preview before
// keys are added), verification is skipped so the flow still works.
async function turnstileOk(request, env, token) {
  if (!env.TURNSTILE_SECRET) return true;
  if (typeof token !== 'string' || token.length < 10 || token.length > 4096) return false;
  try {
    const form = new FormData();
    form.append('secret', env.TURNSTILE_SECRET);
    form.append('response', token);
    const ip = request.headers.get('CF-Connecting-IP');
    if (ip) form.append('remoteip', ip);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
    const d = await r.json().catch(() => null);
    return !!(d && d.success);
  } catch { return false; }
}

// ------------------------------------------------- affiliate comp access
// Internal endpoints to gift/revoke Pro (POST /api/internal/comp-access and
// /api/internal/revoke-access with an X-Internal-Secret: COMP_SECRET header).
// Extend-only, stores
// a pending grant when the account doesn't exist yet, never touches a paying
// customer. Auth = X-Internal-Secret (COMP_SECRET), constant-time compared.
function timingSafeEqual(a, b) {
  const ab = new TextEncoder().encode(String(a));
  const bb = new TextEncoder().encode(String(b));
  if (ab.length !== bb.length) return false;
  let out = 0;
  for (let i = 0; i < ab.length; i++) out |= ab[i] ^ bb[i];
  return out === 0;
}
const LIFETIME_ISO = '2126-01-01T00:00:00.000Z';
function compAuthorized(request, env) {
  const secret = request.headers.get('X-Internal-Secret') || '';
  return !!env.COMP_SECRET && timingSafeEqual(secret, env.COMP_SECRET);
}
async function compGrant(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await overLimit(env, `comp:${ip}`, 20, 60)) return res({ error: 'Too many requests' }, 429);
  if (!compAuthorized(request, env)) return res({ error: 'Unauthorized' }, 401);
  const body = await readJson(request) || {};
  const email = String(body.email || '').trim().toLowerCase();
  const months = Number.isInteger(body.months) ? Math.min(Math.max(body.months, 1), 24) : 6;
  const lifetime = body.lifetime === true;
  if (!isEmail(email)) return badReq('email required');
  const user = await env.DB.prepare('SELECT id, pro_until, stripe_subscription_id FROM users WHERE email = ?').bind(email).first();
  if (!user) {
    await env.DB.prepare(
      'INSERT INTO pending_grants (email, months, lifetime, created_at) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(email) DO UPDATE SET months = MAX(months, excluded.months), lifetime = MAX(lifetime, excluded.lifetime)'
    ).bind(email, months, lifetime ? 1 : 0, new Date().toISOString()).run();
    return res({ ok: true, granted: true, pending: true, account_exists: false, months, coupon_code: null });
  }
  if (user.stripe_subscription_id) {
    return res({ ok: true, granted: false, account_exists: true, reason: 'paying_customer', coupon_code: null });
  }
  const base = user.pro_until && user.pro_until > new Date().toISOString() ? new Date(user.pro_until) : new Date();
  const until = lifetime ? LIFETIME_ISO : new Date(base.setMonth(base.getMonth() + months)).toISOString();
  await env.DB.prepare('UPDATE users SET pro_until = ? WHERE id = ?').bind(until, user.id).run();
  return res({ ok: true, granted: true, account_exists: true, plan_expires: until, months, coupon_code: null });
}
async function compRevoke(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await overLimit(env, `comp:${ip}`, 20, 60)) return res({ error: 'Too many requests' }, 429);
  if (!compAuthorized(request, env)) return res({ error: 'Unauthorized' }, 401);
  const body = await readJson(request) || {};
  const email = String(body.email || '').trim().toLowerCase();
  if (!isEmail(email)) return badReq('email required');
  await env.DB.prepare('DELETE FROM pending_grants WHERE email = ?').bind(email).run();
  const user = await env.DB.prepare('SELECT id, stripe_subscription_id FROM users WHERE email = ?').bind(email).first();
  if (!user) return res({ ok: true, revoked: false, account_exists: false });
  if (user.stripe_subscription_id) return res({ ok: true, revoked: false, account_exists: true, reason: 'paying_customer' });
  await env.DB.prepare('UPDATE users SET pro_until = NULL WHERE id = ?').bind(user.id).run();
  return res({ ok: true, revoked: true, account_exists: true });
}
// Applies (and clears) a pending grant the moment the account gets created.
async function applyPendingGrant(env, userId, email) {
  try {
    const g = await env.DB.prepare('SELECT months, lifetime FROM pending_grants WHERE email = ?').bind(email).first();
    if (!g) return;
    const until = g.lifetime ? LIFETIME_ISO : new Date(new Date().setMonth(new Date().getMonth() + g.months)).toISOString();
    await env.DB.prepare('UPDATE users SET pro_until = ? WHERE id = ?').bind(until, userId).run();
    await env.DB.prepare('DELETE FROM pending_grants WHERE email = ?').bind(email).run();
  } catch (e) { console.error('applyPendingGrant failed', e && e.message); }
}

// Optional operator signup notification (SIGNUP_WEBHOOK_URL). Never throws, never fails
// a signup; bounded so a hung webhook can't stall the response.
// Feedback widget relay. The Worker forwards a message to FEEDBACK_WEBHOOK after a
// per-IP cap, a honeypot and type/length checks.
// Optional: set FEEDBACK_WEBHOOK to any URL that accepts a JSON POST. Unset = feedback is turned off.
const FEEDBACK_WEBHOOK = '';
const FEEDBACK_HOURLY_MAX = 60; // messages per hour, every sender added together
async function feedback(request, env) {
  // No webhook set = feedback is off here. A plain 404, not a server error.
  if (!(env.FEEDBACK_WEBHOOK || FEEDBACK_WEBHOOK)) return res({ error: 'Feedback is turned off here.' }, 404);
  const body = await readJson(request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) return badReq('Invalid request body.');
  // Honeypot: a hidden field people never see. Bots fill it; answer as if sent.
  if (body.website) return res({ ok: true });
  const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
  const message = str(body.message, 2000);
  if (message.length < 3) return badReq('Please write a bit more so I know what you mean.');
  const email = str(body.email, 200);
  if (email && !isEmail(email)) return badReq("That email doesn't look right. Fix it or leave it blank.");
  const type = ['bug', 'feature', 'other'].includes(body.type) ? body.type : 'other';
  const r = await fetch(env.FEEDBACK_WEBHOOK || FEEDBACK_WEBHOOK, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // JSON payload your webhook receives.
    body: JSON.stringify({
      app: 'Porch Pile',
      type,
      message,
      email,
      url: str(body.url, 500),
      user_agent: (request.headers.get('User-Agent') || '').slice(0, 500),
    }),
    signal: AbortSignal.timeout(8000),
  }).catch(() => null);
  if (!r || !r.ok) return res({ error: "Couldn't send that. Try again in a minute." }, 502);
  return res({ ok: true });
}

async function notifySignup(env, email) {
  // Optional: SIGNUP_WEBHOOK_URL + SIGNUP_WEBHOOK_SECRET ping you on each signup.
  if (!env.SIGNUP_WEBHOOK_SECRET || !env.SIGNUP_WEBHOOK_URL) return;
  try {
    await fetch(env.SIGNUP_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Signup-Secret': env.SIGNUP_WEBHOOK_SECRET },
      body: JSON.stringify({
        app_name: 'porch-pile',
        email: (email || '').toLowerCase(),
        timestamp: new Date().toISOString(),
      }),
      signal: AbortSignal.timeout(5000),
    });
  } catch {}
}

// ------------------------------------------------------------- email (Resend)
const FROM = env => env.EMAIL_FROM || 'Porch Pile <noreply@example.com>'; // set EMAIL_FROM to an address on a domain you verified in Resend
const FOOTER = 'Sent by Porch Pile · Not affiliated with or endorsed by Amazon. Amazon and the Amazon logo are trademarks of Amazon.com, Inc. or its affiliates.';

async function sendVerificationEmail(userId, email, env) {
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  const codeHash = await sha256Hex(userId + ':' + code);
  const now = Math.floor(Date.now() / 1000);
  try {
    await env.DB.prepare('DELETE FROM email_verifications WHERE user_id = ? AND used = 0').bind(userId).run();
    await env.DB.prepare('INSERT INTO email_verifications (user_id, code_hash, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)')
      .bind(userId, codeHash, now + 1800, now).run(); // 30 min
  } catch (e) { console.error('verify token store failed', e && e.message); return false; }
  if (!env.RESEND_API_KEY) {
    // Local testing only: DEV_LOG_CODES=true prints the code to your terminal instead of emailing it.
    if (env.DEV_LOG_CODES === 'true') console.log(`[dev] verification code for ${email.replace(/^(.).*@/, '$1***@')}: ${code}`);
    else console.error('RESEND_API_KEY not set');
    return false;
  }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: FROM(env), to: email,
        subject: `Your Porch Pile code is ${code}`,
        text: `Your Porch Pile verification code is: ${code}\n\nEnter it on the sign-in screen to finish setting up your account. It expires in 30 minutes.\n\nIf you didn't sign up for Porch Pile, ignore this email.\n\n${FOOTER}`,
        html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;background:#F2F6F1;color:#1D2A22"><h2 style="color:#C2255C">Your verification code</h2><p>Enter this code on the sign-in screen to finish setting up your Porch Pile account:</p><div style="font-size:34px;font-weight:bold;letter-spacing:8px;color:#1D2A22;background:#fff;border:2px solid #F2A93B;border-radius:12px;padding:18px 0;text-align:center;margin:16px 0">${code}</div><p style="color:#8A6F4E;font-size:0.85em">This code expires in 30 minutes. If you didn't sign up for Porch Pile, ignore this email.</p><p style="font-size:12px;color:#888;margin-top:24px;text-align:center;border-top:1px solid #e6dcc8;padding-top:12px">${FOOTER}</p></div>`,
      }),
    });
    if (!r.ok) { console.error('Resend verify FAIL', r.status, await r.text()); return false; }
    return true;
  } catch (e) { console.error('verify email threw', e && e.message); return false; }
}

async function sendAlreadyRegisteredEmail(email, env) {
  if (!env.RESEND_API_KEY) return false;
  const appUrl = env.APP_URL;
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: FROM(env), to: email,
        subject: 'You already have a Porch Pile account',
        text: `Someone (probably you) tried to sign up for Porch Pile with this email, but you already have an account.\n\nLog in here: ${appUrl}/app\n\nForgot your password? Use "Forgot password" on the login screen.\n\nIf this wasn't you, you can ignore this email. No new account was created.\n\n${FOOTER}`,
        html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;background:#F2F6F1;color:#1D2A22"><h2 style="color:#C2255C">You already have an account</h2><p>Someone (probably you) tried to sign up for Porch Pile with this email, but you already have an account. No new account was created.</p><a href="${appUrl}" style="display:inline-block;background:#C2255C;color:#fff;padding:13px 24px;border-radius:10px;text-decoration:none;font-weight:bold;margin:16px 0">Log in</a><p style="color:#8A6F4E;font-size:0.85em">Forgot your password? Use "Forgot password" on the login screen. If this wasn't you, ignore this email.</p><p style="font-size:12px;color:#888;margin-top:24px;text-align:center;border-top:1px solid #e6dcc8;padding-top:12px">${FOOTER}</p></div>`,
      }),
    });
    if (!r.ok) { console.error('Resend already-registered FAIL', r.status, await r.text()); return false; }
    return true;
  } catch (e) { console.error('already-registered email threw', e && e.message); return false; }
}

// ------------------------------------------------------------- auth handlers
async function signup(request, env) {
  const body = await readJson(request);
  if (!body || !isEmail(body.email) || typeof body.password !== 'string'
      || body.password.length < 10 || body.password.length > 200) {
    return badReq('Email is required and password must be 10–200 characters.');
  }
  const email = body.email.trim().toLowerCase();
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await turnstileOk(request, env, body.turnstile_token))) {
    return res({ error: 'Human check failed. Please try again.' }, 400);
  }
  // Signup IP throttle: 10 per hour. Each signup costs a PBKDF2 hash, a D1 row and a Resend email.
  if (await overLimit(env, `signup-ip:${ip}`, 10, 3600)) {
    return tooMany("Too many signups from this network. Try again in an hour.", 3600);
  }

  const tz = isTz(body.tz) ? body.tz : 'America/Chicago';
  const existing = await env.DB.prepare('SELECT id, email_verified FROM users WHERE email = ?').bind(email).first();
  if (existing) {
    if (!existing.email_verified) {
      // Nobody has proved they own this address yet. The newest signer-up takes
      // over the credentials (old sessions die with the token_version bump) and
      // gets a fresh code; entering that code together with this password is
      // what proves ownership (verifyCode checks both). Before this, a row
      // squatted by someone else kept ITS password after the real owner
      // verified (pre-hijack account takeover).
      const hash = await hashPassword(body.password);
      await env.DB.prepare('UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?').bind(hash, existing.id).run();
      const sent = await sendVerificationEmail(existing.id, email, env);
      return res({ ok: true, awaiting_verification: true, email, email_sent: sent, message: 'Check your inbox for a 6-digit code to verify your email.' });
    }
    await hashPassword(body.password); // burn cycles; don't leak existence
    // The response is identical to a fresh signup, but the INBOX must not go
    // silent: the owner gets a "you already have an account" pointer to log in
    // or reset. Only the address owner sees which branch ran. email_sent
    // reports Resend's answer, which does not depend on whether the account
    // exists (every branch sends), so it leaks nothing.
    const sent = await sendAlreadyRegisteredEmail(email, env);
    return res({ ok: true, awaiting_verification: true, email, email_sent: sent, message: 'Check your inbox for a 6-digit code to verify your email.' });
  }
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const hash = await hashPassword(body.password);
  await env.DB.prepare('INSERT INTO users (id, email, password_hash, tz, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(id, email, hash, tz, now).run();
  await applyPendingGrant(env, id, email);
  const sent = await sendVerificationEmail(id, email, env);
  await notifySignup(env, email);
  return res({ ok: true, awaiting_verification: true, email, email_sent: sent, message: 'Check your inbox for a 6-digit code to verify your email before logging in.' });
}

async function verifyCode(request, env) {
  const body = await readJson(request);
  const email = body && isEmail(body.email) ? body.email.trim().toLowerCase() : '';
  const code = String((body && body.code) || '').replace(/\D/g, '');
  const password = body && typeof body.password === 'string' ? body.password : '';
  if (!email || code.length !== 6) return res({ error: 'Enter the 6-digit code from your email.' }, 400);
  if (!password || password.length > 200) return res({ error: 'Enter your password along with the code.' }, 400);
  const now = Math.floor(Date.now() / 1000);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  // Low-entropy code → throttle: 8/min per email, 30/min per IP.
  // Every attempt is recorded and counted in one step (overLimit), so a burst of
  // parallel requests can't all read "under the cap" first.
  if (await overLimit(env, `vc:${email}`, 8, 60)) return res({ error: 'Too many attempts. Wait a minute.' }, 429);
  if (await overLimit(env, `vc-ip:${ip}`, 30, 60)) return res({ error: 'Too many requests. Try again later.' }, 429);
  // Daily cap: 20 code attempts per email per day. The per-minute limit alone
  // allowed ~11,500 guesses a day at a 6-digit code.
  if (await overLimit(env, `vcd:${email}`, 20, 86400)) return res({ error: 'Too many tries today. Try again tomorrow or request a new code then.' }, 429);

  const user = await env.DB.prepare('SELECT id, email, email_verified, token_version, password_hash FROM users WHERE email = ?').bind(email).first();
  if (!user) return res({ error: 'That code is invalid or expired.' }, 400);
  // Same 400 as an unknown address: a distinct "already verified" answer told
  // anyone which emails have accounts.
  if (user.email_verified) return res({ error: 'That code is invalid or expired.' }, 400);
  const codeHash = await sha256Hex(user.id + ':' + code);
  const row = await env.DB.prepare('SELECT rowid FROM email_verifications WHERE user_id = ? AND code_hash = ? AND used = 0 AND expires_at > ?')
    .bind(user.id, codeHash, now).first();
  if (!row) return res({ error: 'That code is invalid or expired.' }, 400);
  // The code proves the inbox; the password proves this is whoever set the
  // row's credentials (a signup on an unverified row replaces them). Without
  // both, someone who re-signed-up on the owner's address could ride the
  // owner's code into an account whose password they chose.
  if (!(await verifyPassword(password, user.password_hash))) return res({ error: 'That password does not match this account.' }, 400);
  // One batch, conditional on the exact state just checked: still unverified,
  // same password hash, same token_version, and this code still live and
  // unused. A signup that swapped the password (or a second verify) in between
  // makes a statement change 0 rows, and then nothing is granted: generic 400,
  // no session.
  const [upd, used] = await env.DB.batch([
    env.DB.prepare('UPDATE users SET email_verified = 1, last_login_at = ? WHERE id = ? AND email_verified = 0 AND password_hash = ? AND COALESCE(token_version,0) = ? AND EXISTS (SELECT 1 FROM email_verifications WHERE user_id = ? AND code_hash = ? AND used = 0 AND expires_at > ?)')
      .bind(new Date().toISOString(), user.id, user.password_hash, user.token_version ?? 0, user.id, codeHash, now),
    env.DB.prepare('UPDATE email_verifications SET used = 1 WHERE user_id = ? AND code_hash = ? AND used = 0 AND expires_at > ?').bind(user.id, codeHash, now),
  ]);
  if (!(upd?.meta?.changes > 0) || !(used?.meta?.changes > 0)) return res({ error: 'That code is invalid or expired.' }, 400);
  // Any other live codes for this account are dead now too.
  await env.DB.prepare('UPDATE email_verifications SET used = 1 WHERE user_id = ? AND used = 0').bind(user.id).run();
  const cookie = await mintSession(user, env);
  return res({ ok: true, user: { id: user.id, email: user.email } }, 200, { 'Set-Cookie': cookie });
}

async function resendVerification(request, env) {
  const body = await readJson(request);
  if (!body || !isEmail(body.email)) return res({ ok: true });
  const email = body.email.trim().toLowerCase();
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await overLimit(env, `vr:${email}`, 1, 60)) return tooMany('Please wait a minute before requesting another email.', 60);
  if (await overLimit(env, `vr-ip:${ip}`, 10, 60)) return tooMany("Too many requests from this network. Try again in a minute.", 60);
  const user = await env.DB.prepare('SELECT id, email_verified FROM users WHERE email = ?').bind(email).first();
  // Unknown or already-verified email still reads as sent (no enumeration);
  // only a real send that failed reports email_sent:false.
  let sent = true;
  if (user && !user.email_verified) sent = await sendVerificationEmail(user.id, email, env);
  return res({ ok: true, email_sent: sent, message: sent
    ? 'If that account exists and needs verification, an email has been sent.'
    : "We couldn't send your code right now. Try again in a minute, or email support@example.com." });
}

async function login(request, env) {
  const body = await readJson(request);
  if (!body || !isEmail(body.email) || typeof body.password !== 'string'
      || body.password.length < 1 || body.password.length > 200) return badReq();
  const email = body.email.trim().toLowerCase();
  // Per-IP cap on top of the per-account lockout below, so one network can't
  // spray passwords across many accounts. Counted in D1 (overLimit).
  const net = ipKey(request);
  if (await overLimit(env, `login-ip:${net}`, 30, 900)) {
    return tooMany('Too many login attempts from this network. Try again in 15 minutes.', 900);
  }
  // Wrong-password lockout, keyed by account AND network. Someone guessing at an
  // address locks out their own network only, so the real owner (on another
  // network) still gets in with the right password. The attempt is recorded
  // BEFORE the password check (atomically), and a correct password clears it.
  // Recording only after a failure let parallel guesses race past.
  const lockKey = `failed-login:${email}|${net}`;
  if (await overLimit(env, lockKey, LOGIN_MAX, LOGIN_WINDOW)) {
    return res({ error: 'Too many failed attempts. Try again in 15 minutes.' }, 429, { 'Retry-After': String(LOGIN_WINDOW) });
  }
  // Backstop for guessing spread over many networks: every network added together
  // gets LOGIN_ALL_MAX tries at one account per window. Never cleared by a login.
  if (await overLimit(env, `failed-login-all:${email}`, LOGIN_ALL_MAX, LOGIN_WINDOW)) {
    return res({ error: 'Too many failed attempts. Try again in 15 minutes.' }, 429, { 'Retry-After': String(LOGIN_WINDOW) });
  }
  const row = await env.DB.prepare('SELECT id, email, password_hash, email_verified, token_version FROM users WHERE email = ?').bind(email).first();
  const stored = row?.password_hash || 'pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
  const ok = await verifyPassword(body.password, stored);
  if (!ok || !row) {
    await authLog(request, 'login_fail', { email });
    return res({ error: 'Invalid credentials' }, 401);
  }
  if (!row.email_verified) {
    await rlClear(env, lockKey); // right password, just unverified
    return res({ error: 'Please verify your email before logging in.', code: 'email_not_verified', email: row.email }, 403);
  }
  await rlClear(env, lockKey);
  await authLog(request, 'login_ok', { uid: row.id });
  await env.DB.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').bind(new Date().toISOString(), row.id).run();
  const cookie = await mintSession(row, env);
  return res({ ok: true, user: { id: row.id, email: row.email } }, 200, { 'Set-Cookie': cookie });
}

function logout() {
  return res({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}

async function resetRequest(request, env) {
  const body = await readJson(request);
  if (!body || !isEmail(body.email)) return res({ ok: true });
  const email = body.email.trim().toLowerCase();
  // Reset mail is the one email anybody can aim at any address. 3 per address
  // per 15 min and 10 per IP per hour stops inbox-bombing and Resend burn.
  // Checked BEFORE the user lookup, so a 429 says nothing about whether the
  // address has an account.
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await overLimit(env, `reset-email:${email}`, 3, 900)) return tooMany("A reset email was sent recently. Check your inbox, then try again in 15 minutes.", 900);
  if (await overLimit(env, `reset-ip:${ip}`, 10, 3600)) return tooMany("Too many reset requests from this network. Try again in an hour.", 3600);
  const row = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (!row) return res({ ok: true }); // don't leak existence
  const rawToken = [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, '0')).join('');
  const tokenHash = await sha256Hex(rawToken);
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare('INSERT INTO reset_tokens (user_id, token_hash, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)')
    .bind(row.id, tokenHash, now + 3600, now).run();
  if (env.RESEND_API_KEY) {
    const appUrl = env.APP_URL;
    // PATH segment, not ?reset= . Quoted-printable encoding eats the `=` plus the
    // next two characters in transit, so a `?reset=<hex>` link arrives with no `=`
    // at all, the token never parses, and the reset screen never opens. Proven on
    // more than one app.
    const resetUrl = `${appUrl}/reset/${rawToken}`;
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: FROM(env), to: email,
        subject: 'Reset your Porch Pile password',
        html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;background:#F2F6F1;color:#1D2A22"><h2 style="color:#C2255C">Reset your password</h2><p>Click below to set a new password. This link expires in 1 hour.</p><a href="${resetUrl}" style="display:inline-block;background:#C2255C;color:#fff;padding:13px 24px;border-radius:10px;text-decoration:none;font-weight:bold;margin:16px 0">Reset Password</a><p style="color:#8A6F4E;font-size:0.85em">If you didn't request this, ignore this email.</p><p style="font-size:12px;color:#888;margin-top:24px;text-align:center;border-top:1px solid #e6dcc8;padding-top:12px">${FOOTER}</p></div>`,
      }),
    }).catch(() => {});
  } else if (env.DEV_LOG_CODES === 'true') {
    // Local testing only: DEV_LOG_CODES=true prints the reset link to your terminal instead of emailing it.
    console.log(`[dev] reset link for ${email.replace(/^(.).*@/, '$1***@')}: ${env.APP_URL}/reset/${rawToken}`);
  }
  return res({ ok: true });
}

async function resetConfirm(request, env) {
  const body = await readJson(request);
  if (!body || typeof body.token !== 'string' || body.token.length < 16 || body.token.length > 256
      || typeof body.password !== 'string' || body.password.length < 10 || body.password.length > 200) {
    return badReq('Password must be 10–200 characters.');
  }
  const tokenHash = await sha256Hex(body.token);
  const now = Math.floor(Date.now() / 1000);
  const rt = await env.DB.prepare('SELECT rowid, user_id FROM reset_tokens WHERE token_hash = ? AND used = 0 AND expires_at > ?')
    .bind(tokenHash, now).first();
  if (!rt) return res({ error: 'Invalid or expired reset link' }, 400);
  const hash = await hashPassword(body.password);
  // Bump token_version so every existing session dies; verify email in case the
  // user never confirmed (proves inbox control).
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET password_hash = ?, email_verified = 1, token_version = token_version + 1 WHERE id = ?').bind(hash, rt.user_id),
    env.DB.prepare('UPDATE reset_tokens SET used = 1 WHERE user_id = ? AND used = 0').bind(rt.user_id), // kill every other live reset link too
  ]);
  const user = await env.DB.prepare('SELECT id, email, token_version FROM users WHERE id = ?').bind(rt.user_id).first();
  await authLog(request, 'password_reset', { uid: rt.user_id });
  const cookie = await mintSession(user, env);
  return res({ ok: true, user: { id: user.id, email: user.email } }, 200, { 'Set-Cookie': cookie });
}

// ------------------------------------------------------------- entitlement + free caps
// pro_until is the single entitlement source: NULL or past = free tier.
// Caps are enforced HERE, not in the UI — the UI copy is a courtesy.
const FREE_CAPS = { items: 30, videos: 15, deals: 3 };
const DEAL_DONE = ['dead', 'paid']; // deals not counted against the active cap

function isProRow(row) { return !!(row && (row.no_billing || (row.pro_until && new Date(row.pro_until) > new Date()))); }

async function billingRow(env, userId) {
  const row = await env.DB.prepare('SELECT pro_until, tz FROM users WHERE id = ?').bind(userId).first();
  // No billing on this copy (see siteFlags) means nobody can buy Pro here, so nothing is
  // held back: no item, video or deal caps, full income history and the spreadsheet import.
  if (row && !siteFlags(env).billing) row.no_billing = true;
  return row;
}

function capRes(cap, error) { return res({ error, code: 'cap_reached', cap }, 403); }

// INSERT one row, holding a free-plan cap inside the statement itself: the count
// and the write are a single SQL statement, so a burst of parallel requests can't
// all read "under the cap" first. cap = null means no cap (Pro). Returns false
// when the cap stopped the insert.
async function cappedInsert(env, table, cols, vals, cap) {
  const marks = vals.map(() => '?').join(', ');
  if (!cap) {
    // sec-ok(5): table and column names are fixed strings at every call site; values are bound with ?
    await env.DB.prepare(`INSERT INTO ${table} (${cols}) VALUES (${marks})`).bind(...vals).run();
    return true;
  }
  // sec-ok(5): table, column names and the count query are fixed strings at every call site; values are bound with ?
  const r = await env.DB.prepare(`INSERT INTO ${table} (${cols}) SELECT ${marks} WHERE (${cap.count}) < ?`)
    .bind(...vals, ...cap.binds, cap.max).run();
  return !!(r.meta && r.meta.changes > 0);
}

// Current + previous YYYY-MM in the user's timezone — the free income window.
function freeIncomeMonths(tz) {
  const cur = todayInTz(tz).slice(0, 7);
  const [y, m] = cur.split('-').map(Number);
  const prev = m === 1 ? `${y - 1}-12` : `${y}-${String(m - 1).padStart(2, '0')}`;
  return [prev, cur];
}

// ------------------------------------------------------------- account
// What this server has switched on, so the pages can hide what isn't there:
// no prices or Go Pro without billing, no Feedback button without a webhook.
function siteFlags(env) {
  return {
    billing: !!(env.STRIPE_SECRET_KEY && env.STRIPE_PRICE_MONTHLY),
    feedback: !!(env.FEEDBACK_WEBHOOK || FEEDBACK_WEBHOOK),
  };
}

async function me(user, env) {
  const row = await env.DB.prepare('SELECT id, email, tz, pace_goal, pro_until, cancel_at_period_end, stripe_status, stripe_customer_id, created_at FROM users WHERE id = ?')
    .bind(user.id).first();
  return res({ ...siteFlags(env), user: {
    id: row.id, email: row.email, tz: row.tz, pace_goal: row.pace_goal,
    pro: isProRow(row), pro_until: row.pro_until,
    cancel_at_period_end: !!row.cancel_at_period_end,
    has_billing: !!row.stripe_customer_id,
    created_at: row.created_at,
  } });
}

async function updateSettings(user, request, env) {
  const body = await readJson(request);
  if (!body) return badReq();
  const sets = [], binds = [];
  if (body.tz !== undefined) { if (!isTz(body.tz)) return badReq('Invalid timezone'); sets.push('tz = ?'); binds.push(body.tz); }
  if (body.pace_goal !== undefined) {
    const n = Number(body.pace_goal);
    if (!Number.isInteger(n) || n < 0 || n > 100000) return badReq('Invalid pace goal');
    sets.push('pace_goal = ?'); binds.push(n);
  }
  if (!sets.length) return badReq('Nothing to update');
  binds.push(user.id);
  await env.DB.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).bind(...binds).run();
  return me(user, env);
}

async function exportAccount(user, env) {
  // Every table keyed by user_id, billing history and import batches included.
  const tables = ['items', 'videos', 'video_items', 'brand_deals', 'deal_items', 'coupons', 'income_months', 'achievements', 'payment_events', 'import_batches'];
  const out = { exported_at: new Date().toISOString() };
  const u = await env.DB.prepare('SELECT id, email, tz, pace_goal, pro_until, created_at FROM users WHERE id = ?').bind(user.id).first();
  out.account = u;
  for (const t of tables) {
    const r = await env.DB.prepare(`SELECT * FROM ${t} WHERE user_id = ?`).bind(user.id).all();
    out[t] = r.results || [];
  }
  return res(out, 200, { 'Content-Disposition': 'attachment; filename="porch-pile-export.json"' });
}

async function deleteAccount(user, request, env) {
  const body = await readJson(request);
  if (!body || typeof body.password !== 'string') return badReq('Password required to delete your account.');
  // Same lockout as login: without it a stolen session could use this
  // endpoint as a password oracle at the 120/min write throttle.
  if (await overLimit(env, `failed-delete:${user.id}`, LOGIN_MAX, LOGIN_WINDOW)) {
    return res({ error: 'Too many failed attempts. Try again in 15 minutes.' }, 429, { 'Retry-After': String(LOGIN_WINDOW) });
  }
  const row = await env.DB.prepare('SELECT password_hash, stripe_customer_id, stripe_subscription_id FROM users WHERE id = ?').bind(user.id).first();
  // 400, not 401/403: the front end treats a 401 as "session ended" and a
  // wrong password here must keep the user logged in.
  if (!row || !(await verifyPassword(body.password, row.password_hash))) {
    return res({ error: 'Password is incorrect.' }, 400);
  }
  // Stop billing BEFORE deleting. If Stripe can't confirm, keep the account:
  // deleting it would leave a live subscription with no account to cancel from.
  if (row.stripe_customer_id || row.stripe_subscription_id) {
    try {
      await cancelAllSubscriptions(env, row.stripe_customer_id, row.stripe_subscription_id);
    } catch (e) {
      console.error('delete-account: subscription cancel failed', user.id, e.message);
      return res({ error: "We couldn't cancel your subscription, so your account wasn't deleted. Try again, or email privacy@example.com and we'll take care of it." }, 502);
    }
  }
  // ON DELETE CASCADE clears all child rows.
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();
  await authLog(request, 'account_delete', { uid: user.id });
  return res({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}

// ------------------------------------------------------------- items
// "sending" is an optional pre-stage: brand said it's on
// the way; one tap to Received when the box lands. Default stays received.
const ITEM_STATUSES = ['sending', 'received', 'queued', 'filmed', 'posted', 'linked'];
// Two axes, mirroring a real creator tracker (Review Type + Lead): source = how the
// item was physically acquired; channel = where a sent-for-review item came
// through (a brand usually sends THROUGH Creator Connections — the channel is
// not a peer of "sent for review").
const ITEM_SOURCES = ['sent_for_review', 'purchased', 'already_owned'];
const ITEM_CHANNELS = ['creator_connections', 'levanta', 'email', 'social', 'facebook_group', 'other'];
// Lean AIP pipeline: film + upload, Amazon reviews, it's live.
// "Idea"/"Filmed"/"Edited" were retired — the film queue covers what's next.
const VIDEO_STATUSES = ['to_film', 'in_review', 'posted'];
const PLATFORMS = ['amazon', 'youtube', 'tiktok', 'instagram'];

const isDateStr = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);
const isUuid = v => typeof v === 'string' && /^[0-9a-f-]{36}$/.test(v);

// Today's date in the user's timezone (streaks/posted dates must never be UTC).
function todayInTz(tz) {
  try {
    return new Intl.DateTimeFormat('en-CA', { timeZone: tz || 'America/Chicago', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
  } catch { return new Date().toISOString().slice(0, 10); }
}

// Validate one optional text field: undefined = not provided, null/'' = clear.
// Returns { skip } | { value } | { error }.
function optText(body, key, max) {
  if (body[key] === undefined) return { skip: true };
  if (body[key] === null || body[key] === '') return { value: null };
  if (typeof body[key] !== 'string' || body[key].length > max) return { error: `${key} is too long (max ${max} characters).` };
  return { value: body[key].trim() || null };
}

// Shared collector for create/update. partial=true skips absent fields.
function collectItemFields(body, partial) {
  const sets = {}, err = m => ({ error: m });
  if (!partial || body.name !== undefined) {
    if (typeof body.name !== 'string' || !body.name.trim() || body.name.trim().length > 200) return err('Item name is required (max 200 characters).');
    sets.name = body.name.trim();
  }
  for (const [key, max] of [['brand', 120], ['asin', 20], ['category', 60], ['notes', 2000]]) {
    const t = optText(body, key, max);
    if (t.error) return err(t.error);
    if (!t.skip) sets[key] = t.value;
  }
  if (body.source !== undefined) {
    if (!ITEM_SOURCES.includes(body.source)) return err('Invalid source.');
    sets.source = body.source;
  }
  if (body.channel !== undefined) {
    if (body.channel === null || body.channel === '') sets.channel = null;
    else if (!ITEM_CHANNELS.includes(body.channel)) return err('Invalid channel.');
    else sets.channel = body.channel;
  }
  if (body.status !== undefined) {
    if (!ITEM_STATUSES.includes(body.status)) return err('Invalid status.');
    sets.status = body.status;
  }
  if (body.date_received !== undefined) {
    if (body.date_received === null || body.date_received === '') sets.date_received = null;
    else if (!isDateStr(body.date_received)) return err('Date received must be YYYY-MM-DD.');
    else sets.date_received = body.date_received;
  }
  if (body.est_value !== undefined) {
    if (body.est_value === null || body.est_value === '') sets.est_value = null;
    else {
      const n = Number(body.est_value);
      if (!Number.isFinite(n) || n < 0 || n > 1000000) return err('Estimated value must be between 0 and 1,000,000.');
      sets.est_value = Math.round(n * 100) / 100;
    }
  }
  return { sets };
}

async function listItems(user, env) {
  const r = await env.DB.prepare('SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC').bind(user.id).all();
  return res({ items: r.results || [] });
}

async function createItem(user, request, env) {
  const body = await readJson(request);
  if (!body) return badReq();
  const c = collectItemFields(body, false);
  if (c.error) return badReq(c.error);
  const pro = isProRow(await billingRow(env, user.id));
  const now = new Date().toISOString();
  const item = {
    id: crypto.randomUUID(), user_id: user.id,
    name: c.sets.name, brand: c.sets.brand ?? null, asin: c.sets.asin ?? null,
    source: c.sets.source || 'sent_for_review', channel: c.sets.channel ?? null,
    date_received: c.sets.date_received ?? null, est_value: c.sets.est_value ?? null,
    category: c.sets.category ?? null, photo: null,
    status: c.sets.status || 'received', notes: c.sets.notes ?? null,
    created_at: now, updated_at: now,
  };
  const inserted = await cappedInsert(env, 'items',
    'id, user_id, name, brand, asin, source, channel, date_received, est_value, category, photo, status, notes, created_at, updated_at',
    [item.id, item.user_id, item.name, item.brand, item.asin, item.source, item.channel, item.date_received,
      item.est_value, item.category, item.photo, item.status, item.notes, item.created_at, item.updated_at],
    pro ? null : { count: 'SELECT COUNT(*) FROM items WHERE user_id = ?', binds: [user.id], max: FREE_CAPS.items });
  if (!inserted) return capRes('items', `The free tier holds ${FREE_CAPS.items} items. Go Pro for an unlimited pile.`);
  return res({ item }, 201);
}

async function updateItem(user, itemId, request, env) {
  const body = await readJson(request);
  if (!body) return badReq();
  const c = collectItemFields(body, true);
  if (c.error) return badReq(c.error);
  const keys = Object.keys(c.sets);
  if (!keys.length) return badReq('Nothing to update');
  // Optimistic-concurrency guard for one-tap advances: the client says what
  // status it thinks the row has; if the row moved on (double-tap, stale tab),
  // the write is skipped and stale:true tells the client to just re-sync.
  const expected = body.expected_status;
  if (expected !== undefined && !ITEM_STATUSES.includes(expected)) return badReq('Invalid expected_status.');
  const cond = expected !== undefined ? ' AND status = ?' : '';
  const condBinds = expected !== undefined ? [expected] : [];
  const binds = keys.map(k => c.sets[k]);
  // sec-ok(5): column names come only from the fixed field list in the collect*Fields() validator; values are bound with ?
  const r = await env.DB.prepare(`UPDATE items SET ${keys.map(k => `${k} = ?`).join(', ')}, updated_at = ? WHERE id = ? AND user_id = ?${cond}`)
    .bind(...binds, new Date().toISOString(), itemId, user.id, ...condBinds).run();
  const item = await env.DB.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?').bind(itemId, user.id).first();
  if (!item) return notFound();
  const stale = expected !== undefined && !(r.meta && r.meta.changes);
  return res({ item, stale });
}

async function deleteItem(user, itemId, env) {
  const r = await env.DB.prepare('DELETE FROM items WHERE id = ? AND user_id = ?').bind(itemId, user.id).run();
  if (!r.meta || !r.meta.changes) return notFound();
  return res({ ok: true });
}

// ------------------------------------------------------------- videos
function collectVideoFields(body, partial) {
  const sets = {}, err = m => ({ error: m });
  if (!partial || body.title !== undefined) {
    if (typeof body.title !== 'string' || !body.title.trim() || body.title.trim().length > 200) return err('Video title is required (max 200 characters).');
    sets.title = body.title.trim();
  }
  if (body.status !== undefined) {
    if (!VIDEO_STATUSES.includes(body.status)) return err('Invalid status.');
    sets.status = body.status;
  }
  if (body.posted_date !== undefined) {
    if (body.posted_date === null || body.posted_date === '') sets.posted_date = null;
    else if (!isDateStr(body.posted_date)) return err('Posted date must be YYYY-MM-DD.');
    else sets.posted_date = body.posted_date;
  }
  if (body.platforms !== undefined) {
    if (!Array.isArray(body.platforms) || body.platforms.some(p => !PLATFORMS.includes(p))) return err('Invalid platforms.');
    sets.platforms = JSON.stringify([...new Set(body.platforms)]);
  }
  if (body.urls !== undefined) {
    if (!Array.isArray(body.urls) || body.urls.length > 6) return err('Up to 6 URLs.');
    const urls = body.urls.map(u => typeof u === 'string' ? u.trim() : '').filter(Boolean);
    if (urls.some(u => u.length > 500 || !/^https?:\/\/\S+$/i.test(u))) return err('URLs must start with http(s):// (max 500 characters each).');
    sets.urls = JSON.stringify(urls);
  }
  const t = optText(body, 'notes', 2000);
  if (t.error) return err(t.error);
  if (!t.skip) sets.notes = t.value;
  return { sets };
}

// Of the requested ids, which items actually belong to this user.
async function ownedItemIds(env, userId, ids) {
  const uniq = [...new Set((ids || []).filter(isUuid))].slice(0, 100);
  if (!uniq.length) return [];
  const r = await env.DB.prepare(`SELECT id FROM items WHERE user_id = ? AND id IN (${uniq.map(() => '?').join(',')})`)
    .bind(userId, ...uniq).all();
  return (r.results || []).map(x => x.id);
}

function videoOut(row, itemIds) {
  const parse = (s, fb) => { try { const v = JSON.parse(s); return Array.isArray(v) ? v : fb; } catch { return fb; } };
  return { ...row, platforms: parse(row.platforms, []), urls: parse(row.urls, []), item_ids: itemIds || [] };
}

async function videoWithItems(env, userId, videoId) {
  const row = await env.DB.prepare('SELECT * FROM videos WHERE id = ? AND user_id = ?').bind(videoId, userId).first();
  if (!row) return null;
  const links = await env.DB.prepare('SELECT item_id FROM video_items WHERE video_id = ? AND user_id = ?').bind(videoId, userId).all();
  return videoOut(row, (links.results || []).map(x => x.item_id));
}

async function listVideos(user, env) {
  const [vids, links] = await Promise.all([
    env.DB.prepare('SELECT * FROM videos WHERE user_id = ? ORDER BY created_at DESC').bind(user.id).all(),
    env.DB.prepare('SELECT video_id, item_id FROM video_items WHERE user_id = ?').bind(user.id).all(),
  ]);
  const byVideo = {};
  (links.results || []).forEach(l => { (byVideo[l.video_id] = byVideo[l.video_id] || []).push(l.item_id); });
  return res({ videos: (vids.results || []).map(v => videoOut(v, byVideo[v.id])) });
}

// Advance freshly-linked items out of "received" (linking = it's queued for a
// video now), and — on posted — push every linked item to "posted".
// Returns the ids it advanced to posted so the UI can ask "linked on the
// product page yet?".
async function advanceLinkedToQueued(env, userId, itemIds) {
  if (!itemIds.length) return;
  await env.DB.prepare(`UPDATE items SET status = 'queued', updated_at = ? WHERE user_id = ? AND status = 'received' AND id IN (${itemIds.map(() => '?').join(',')})`)
    .bind(new Date().toISOString(), userId, ...itemIds).run();
}
async function advanceLinkedToPosted(env, userId, videoId) {
  const r = await env.DB.prepare(`SELECT i.id FROM items i JOIN video_items vi ON vi.item_id = i.id
    WHERE vi.video_id = ? AND i.user_id = ? AND i.status IN ('received','queued','filmed')`)
    .bind(videoId, userId).all();
  const ids = (r.results || []).map(x => x.id);
  if (ids.length) {
    await env.DB.prepare(`UPDATE items SET status = 'posted', updated_at = ? WHERE user_id = ? AND id IN (${ids.map(() => '?').join(',')})`)
      .bind(new Date().toISOString(), userId, ...ids).run();
  }
  return ids;
}

async function createVideo(user, request, env) {
  const body = await readJson(request);
  if (!body) return badReq();
  const c = collectVideoFields(body, false);
  if (c.error) return badReq(c.error);
  const pro = isProRow(await billingRow(env, user.id));
  const status = c.sets.status || 'to_film';
  let postedDate = c.sets.posted_date ?? null;
  if (status === 'posted' && !postedDate) {
    const u = await env.DB.prepare('SELECT tz FROM users WHERE id = ?').bind(user.id).first();
    postedDate = todayInTz(u && u.tz);
  }
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  const inserted = await cappedInsert(env, 'videos',
    'id, user_id, title, status, posted_date, platforms, urls, notes, created_at, updated_at',
    [id, user.id, c.sets.title, status, postedDate, c.sets.platforms || '[]', c.sets.urls || '[]', c.sets.notes ?? null, now, now],
    pro ? null : { count: 'SELECT COUNT(*) FROM videos WHERE user_id = ?', binds: [user.id], max: FREE_CAPS.videos });
  if (!inserted) return capRes('videos', `The free tier holds ${FREE_CAPS.videos} videos. Go Pro for unlimited videos.`);
  const linked = await ownedItemIds(env, user.id, body.item_ids);
  if (linked.length) {
    await env.DB.batch(linked.map(itemId =>
      env.DB.prepare('INSERT OR IGNORE INTO video_items (video_id, item_id, user_id) VALUES (?, ?, ?)').bind(id, itemId, user.id)));
    await advanceLinkedToQueued(env, user.id, linked);
  }
  const advanced = status === 'posted' ? await advanceLinkedToPosted(env, user.id, id) : [];
  return res({ video: await videoWithItems(env, user.id, id), advanced_to_posted: advanced }, 201);
}

async function updateVideo(user, videoId, request, env) {
  const body = await readJson(request);
  if (!body) return badReq();
  const existing = await env.DB.prepare('SELECT * FROM videos WHERE id = ? AND user_id = ?').bind(videoId, user.id).first();
  if (!existing) return notFound();
  // Same optimistic guard as items: a stale one-tap advance becomes a no-op.
  if (body.expected_status !== undefined) {
    if (!VIDEO_STATUSES.includes(body.expected_status)) return badReq('Invalid expected_status.');
    if (existing.status !== body.expected_status) {
      return res({ video: await videoWithItems(env, user.id, videoId), advanced_to_posted: [], stale: true });
    }
  }
  const c = collectVideoFields(body, true);
  if (c.error) return badReq(c.error);

  const becomingPosted = c.sets.status === 'posted' && existing.status !== 'posted';
  if (becomingPosted && c.sets.posted_date === undefined && !existing.posted_date) {
    const u = await env.DB.prepare('SELECT tz FROM users WHERE id = ?').bind(user.id).first();
    c.sets.posted_date = todayInTz(u && u.tz);
  }
  const keys = Object.keys(c.sets);
  if (keys.length) {
    // sec-ok(5): column names come only from the fixed field list in the collect*Fields() validator; values are bound with ?
    await env.DB.prepare(`UPDATE videos SET ${keys.map(k => `${k} = ?`).join(', ')}, updated_at = ? WHERE id = ? AND user_id = ?`)
      .bind(...keys.map(k => c.sets[k]), new Date().toISOString(), videoId, user.id).run();
  }
  if (body.item_ids !== undefined) {
    if (!Array.isArray(body.item_ids)) return badReq('item_ids must be an array.');
    const linked = await ownedItemIds(env, user.id, body.item_ids);
    await env.DB.prepare('DELETE FROM video_items WHERE video_id = ? AND user_id = ?').bind(videoId, user.id).run();
    if (linked.length) {
      await env.DB.batch(linked.map(itemId =>
        env.DB.prepare('INSERT OR IGNORE INTO video_items (video_id, item_id, user_id) VALUES (?, ?, ?)').bind(videoId, itemId, user.id)));
      await advanceLinkedToQueued(env, user.id, linked);
    }
  }
  const advanced = becomingPosted ? await advanceLinkedToPosted(env, user.id, videoId) : [];
  if (!keys.length && body.item_ids === undefined) return badReq('Nothing to update');
  return res({ video: await videoWithItems(env, user.id, videoId), advanced_to_posted: advanced });
}

async function deleteVideo(user, videoId, env) {
  const r = await env.DB.prepare('DELETE FROM videos WHERE id = ? AND user_id = ?').bind(videoId, user.id).run();
  if (!r.meta || !r.meta.changes) return notFound();
  return res({ ok: true });
}

// ------------------------------------------------------------- brand deals
const DEAL_STATUSES = ['inquiry', 'negotiating', 'agreed', 'product_incoming', 'content_due', 'delivered', 'paid', 'dead'];
const DEAL_CHANNELS = ['email', 'instagram', 'tiktok', 'facebook_group', 'levanta', 'creator_connections', 'other'];
const DEAL_TYPES = ['free_product', 'flat_fee', 'commission_boost', 'cc_campaign'];

function collectDealFields(body, partial) {
  const sets = {}, err = m => ({ error: m });
  if (!partial || body.brand !== undefined) {
    if (typeof body.brand !== 'string' || !body.brand.trim() || body.brand.trim().length > 120) return err('Brand name is required (max 120 characters).');
    sets.brand = body.brand.trim();
  }
  for (const [key, max] of [['contact_name', 120], ['contact_handle', 200], ['amount', 120], ['deliverables', 2000], ['dead_reason', 500], ['notes', 2000]]) {
    const t = optText(body, key, max);
    if (t.error) return err(t.error);
    if (!t.skip) sets[key] = t.value;
  }
  if (body.contact_email !== undefined) {
    if (body.contact_email === null || body.contact_email === '') sets.contact_email = null;
    else if (!isEmail(body.contact_email)) return err('Contact email looks invalid.');
    else sets.contact_email = body.contact_email.trim().toLowerCase();
  }
  // Client asks the server to stamp "links emailed" — timestamps stay server-set.
  if (body.mark_links_sent === true) sets.links_sent_at = new Date().toISOString();
  for (const [key, list] of [['channel', DEAL_CHANNELS], ['deal_type', DEAL_TYPES]]) {
    if (body[key] !== undefined) {
      if (body[key] === null || body[key] === '') sets[key] = null;
      else if (!list.includes(body[key])) return err(`Invalid ${key}.`);
      else sets[key] = body[key];
    }
  }
  if (body.status !== undefined) {
    if (!DEAL_STATUSES.includes(body.status)) return err('Invalid status.');
    sets.status = body.status;
  }
  if (body.next_follow_up !== undefined) {
    if (body.next_follow_up === null || body.next_follow_up === '') sets.next_follow_up = null;
    else if (!isDateStr(body.next_follow_up)) return err('Follow-up date must be YYYY-MM-DD.');
    else sets.next_follow_up = body.next_follow_up;
  }
  return { sets };
}

async function replaceDealItems(env, userId, dealId, ids) {
  const linked = await ownedItemIds(env, userId, ids);
  await env.DB.prepare('DELETE FROM deal_items WHERE deal_id = ? AND user_id = ?').bind(dealId, userId).run();
  if (linked.length) {
    await env.DB.batch(linked.map(itemId =>
      env.DB.prepare('INSERT OR IGNORE INTO deal_items (deal_id, item_id, user_id) VALUES (?, ?, ?)').bind(dealId, itemId, userId)));
  }
}

async function dealWithItems(env, userId, dealId) {
  const row = await env.DB.prepare('SELECT * FROM brand_deals WHERE id = ? AND user_id = ?').bind(dealId, userId).first();
  if (!row) return null;
  const links = await env.DB.prepare('SELECT item_id FROM deal_items WHERE deal_id = ? AND user_id = ?').bind(dealId, userId).all();
  return { ...row, item_ids: (links.results || []).map(x => x.item_id) };
}

async function listDeals(user, env) {
  const [deals, links] = await Promise.all([
    env.DB.prepare('SELECT * FROM brand_deals WHERE user_id = ? ORDER BY created_at DESC').bind(user.id).all(),
    env.DB.prepare('SELECT deal_id, item_id FROM deal_items WHERE user_id = ?').bind(user.id).all(),
  ]);
  const byDeal = {};
  (links.results || []).forEach(l => { (byDeal[l.deal_id] = byDeal[l.deal_id] || []).push(l.item_id); });
  return res({ deals: (deals.results || []).map(d => ({ ...d, item_ids: byDeal[d.id] || [] })) });
}

// Deals in play (not dead, not paid) — what the free cap counts. Binds: user id, then DEAL_DONE.
const ACTIVE_DEALS_SQL = `SELECT COUNT(*) FROM brand_deals WHERE user_id = ? AND status NOT IN (${DEAL_DONE.map(() => '?').join(',')})`;

async function createDeal(user, request, env) {
  const body = await readJson(request);
  if (!body) return badReq();
  const c = collectDealFields(body, false);
  if (c.error) return badReq(c.error);
  const newStatus = c.sets.status || 'inquiry';
  // A deal created already dead/paid isn't in play, so it never counts against the cap.
  const capped = !DEAL_DONE.includes(newStatus) && !isProRow(await billingRow(env, user.id));
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  const inserted = await cappedInsert(env, 'brand_deals',
    'id, user_id, brand, contact_name, contact_email, contact_handle, channel, deal_type, amount, status, next_follow_up, deliverables, dead_reason, notes, created_at, updated_at',
    [id, user.id, c.sets.brand, c.sets.contact_name ?? null, c.sets.contact_email ?? null, c.sets.contact_handle ?? null,
      c.sets.channel ?? null, c.sets.deal_type ?? null, c.sets.amount ?? null,
      c.sets.status || 'inquiry', c.sets.next_follow_up ?? null,
      c.sets.deliverables ?? null, c.sets.dead_reason ?? null, c.sets.notes ?? null, now, now],
    capped ? { count: ACTIVE_DEALS_SQL, binds: [user.id, ...DEAL_DONE], max: FREE_CAPS.deals } : null);
  if (!inserted) return capRes('deals', `The free tier tracks ${FREE_CAPS.deals} deals in play at once. Go Pro for unlimited deals.`);
  if (Array.isArray(body.item_ids)) await replaceDealItems(env, user.id, id, body.item_ids);
  return res({ deal: await dealWithItems(env, user.id, id) }, 201);
}

async function updateDeal(user, dealId, request, env) {
  const body = await readJson(request);
  if (!body) return badReq();
  const existing = await env.DB.prepare('SELECT * FROM brand_deals WHERE id = ? AND user_id = ?').bind(dealId, user.id).first();
  if (!existing) return notFound();
  if (body.expected_status !== undefined) {
    if (!DEAL_STATUSES.includes(body.expected_status)) return badReq('Invalid expected_status.');
    if (existing.status !== body.expected_status) {
      return res({ deal: await dealWithItems(env, user.id, dealId), stale: true });
    }
  }
  const c = collectDealFields(body, true);
  if (c.error) return badReq(c.error);
  // Reviving a dead/paid deal puts it back in play — that counts against the
  // free cap the same as creating one, or the cap would be trivial to sidestep.
  // The cap rides inside the UPDATE itself (count and write in one statement), so
  // parallel revives can't all read "under the cap" first.
  const reviving = !!c.sets.status && DEAL_DONE.includes(existing.status) && !DEAL_DONE.includes(c.sets.status)
      && !isProRow(await billingRow(env, user.id));
  const keys = Object.keys(c.sets);
  if (keys.length) {
    const capSql = reviving ? ` AND (${ACTIVE_DEALS_SQL}) < ?` : '';
    const capBinds = reviving ? [user.id, ...DEAL_DONE, FREE_CAPS.deals] : [];
    // sec-ok(5): column names come only from the fixed field list in the collect*Fields() validator; values are bound with ?
    const r = await env.DB.prepare(`UPDATE brand_deals SET ${keys.map(k => `${k} = ?`).join(', ')}, updated_at = ? WHERE id = ? AND user_id = ?${capSql}`)
      .bind(...keys.map(k => c.sets[k]), new Date().toISOString(), dealId, user.id, ...capBinds).run();
    if (reviving && !(r.meta && r.meta.changes > 0)) {
      return capRes('deals', `The free tier tracks ${FREE_CAPS.deals} deals in play at once. Go Pro for unlimited deals.`);
    }
  }
  if (body.item_ids !== undefined) {
    if (!Array.isArray(body.item_ids)) return badReq('item_ids must be an array.');
    await replaceDealItems(env, user.id, dealId, body.item_ids);
  }
  if (!keys.length && body.item_ids === undefined) return badReq('Nothing to update');
  return res({ deal: await dealWithItems(env, user.id, dealId) });
}

async function deleteDeal(user, dealId, env) {
  const r = await env.DB.prepare('DELETE FROM brand_deals WHERE id = ? AND user_id = ?').bind(dealId, user.id).run();
  if (!r.meta || !r.meta.changes) return notFound();
  return res({ ok: true });
}

// ------------------------------------------------------------- coupons
function collectCouponFields(body, partial) {
  const sets = {}, err = m => ({ error: m });
  if (!partial || body.code !== undefined) {
    if (typeof body.code !== 'string' || !body.code.trim() || body.code.trim().length > 60) return err('Coupon code is required (max 60 characters).');
    sets.code = body.code.trim();
  }
  for (const [key, max] of [['brand', 120], ['discount', 60], ['purpose', 200]]) {
    const t = optText(body, key, max);
    if (t.error) return err(t.error);
    if (!t.skip) sets[key] = t.value;
  }
  if (body.expires !== undefined) {
    if (body.expires === null || body.expires === '') sets.expires = null;
    else if (!isDateStr(body.expires)) return err('Expiry date must be YYYY-MM-DD.');
    else sets.expires = body.expires;
  }
  if (body.used !== undefined) sets.used = body.used ? 1 : 0;
  return { sets };
}

// deal_id must reference the user's own deal (or be null).
async function resolveDealId(env, userId, dealId) {
  if (dealId === undefined) return { skip: true };
  if (dealId === null || dealId === '') return { value: null };
  if (!isUuid(dealId)) return { error: 'Invalid deal.' };
  const row = await env.DB.prepare('SELECT id FROM brand_deals WHERE id = ? AND user_id = ?').bind(dealId, userId).first();
  return row ? { value: row.id } : { error: 'Invalid deal.' };
}

async function listCoupons(user, env) {
  const r = await env.DB.prepare('SELECT * FROM coupons WHERE user_id = ? ORDER BY created_at DESC').bind(user.id).all();
  return res({ coupons: r.results || [] });
}

async function createCoupon(user, request, env) {
  const body = await readJson(request);
  if (!body) return badReq();
  const c = collectCouponFields(body, false);
  if (c.error) return badReq(c.error);
  const deal = await resolveDealId(env, user.id, body.deal_id);
  if (deal.error) return badReq(deal.error);
  const id = crypto.randomUUID();
  await env.DB.prepare(`INSERT INTO coupons (id, user_id, code, brand, deal_id, discount, expires, purpose, used, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, user.id, c.sets.code, c.sets.brand ?? null, deal.skip ? null : deal.value,
      c.sets.discount ?? null, c.sets.expires ?? null, c.sets.purpose ?? null, c.sets.used ?? 0,
      new Date().toISOString()).run();
  const row = await env.DB.prepare('SELECT * FROM coupons WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  return res({ coupon: row }, 201);
}

async function updateCoupon(user, couponId, request, env) {
  const body = await readJson(request);
  if (!body) return badReq();
  const c = collectCouponFields(body, true);
  if (c.error) return badReq(c.error);
  const deal = await resolveDealId(env, user.id, body.deal_id);
  if (deal.error) return badReq(deal.error);
  const sets = { ...c.sets };
  if (!deal.skip) sets.deal_id = deal.value;
  const keys = Object.keys(sets);
  if (!keys.length) return badReq('Nothing to update');
  // sec-ok(5): column names come only from the fixed field list in the collect*Fields() validator; values are bound with ?
  await env.DB.prepare(`UPDATE coupons SET ${keys.map(k => `${k} = ?`).join(', ')} WHERE id = ? AND user_id = ?`)
    .bind(...keys.map(k => sets[k]), couponId, user.id).run();
  const row = await env.DB.prepare('SELECT * FROM coupons WHERE id = ? AND user_id = ?').bind(couponId, user.id).first();
  if (!row) return notFound();
  return res({ coupon: row });
}

async function deleteCoupon(user, couponId, env) {
  const r = await env.DB.prepare('DELETE FROM coupons WHERE id = ? AND user_id = ?').bind(couponId, user.id).run();
  if (!r.meta || !r.meta.changes) return notFound();
  return res({ ok: true });
}

// ------------------------------------------------------------- income
// Hand-typed monthly totals, one row per user+month, upserted by month.
const INCOME_STREAMS = ['commissions', 'creator_connections', 'bounties_spc', 'brand_fees', 'other'];
const isMonthStr = v => typeof v === 'string' && /^\d{4}-(0[1-9]|1[0-2])$/.test(v);

async function listIncome(user, env) {
  const r = await env.DB.prepare('SELECT * FROM income_months WHERE user_id = ? ORDER BY month').bind(user.id).all();
  const rows = r.results || [];
  const u = await billingRow(env, user.id);
  if (isProRow(u)) return res({ months: rows });
  // Free window: current + previous month only. Older rows stay in the DB
  // (they come back on upgrade) but are not served.
  const win = freeIncomeMonths(u && u.tz);
  const visible = rows.filter(m => win.includes(m.month));
  return res({ months: visible, locked_months: rows.length - visible.length });
}

async function upsertIncome(user, request, env) {
  const body = await readJson(request);
  if (!body || !isMonthStr(body.month)) return badReq('Month must be YYYY-MM.');
  const u = await billingRow(env, user.id);
  if (!isProRow(u) && !freeIncomeMonths(u && u.tz).includes(body.month)) {
    return capRes('income', 'The free tier logs the current and previous month. Go Pro for your full income history.');
  }
  const vals = {};
  for (const k of INCOME_STREAMS) {
    if (body[k] === undefined || body[k] === null || body[k] === '') { vals[k] = 0; continue; }
    const n = Number(body[k]);
    if (!Number.isFinite(n) || n < 0 || n > 10000000) return badReq('Amounts must be between 0 and 10,000,000.');
    vals[k] = Math.round(n * 100) / 100;
  }
  const t = optText(body, 'notes', 1000);
  if (t.error) return badReq(t.error);
  const notes = t.skip ? null : t.value;
  const now = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO income_months (id, user_id, month, commissions, creator_connections, bounties_spc, brand_fees, other, notes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, month) DO UPDATE SET
      commissions = excluded.commissions, creator_connections = excluded.creator_connections,
      bounties_spc = excluded.bounties_spc, brand_fees = excluded.brand_fees, other = excluded.other,
      notes = excluded.notes, updated_at = excluded.updated_at`)
    .bind(crypto.randomUUID(), user.id, body.month, vals.commissions, vals.creator_connections,
      vals.bounties_spc, vals.brand_fees, vals.other, notes, now, now).run();
  const row = await env.DB.prepare('SELECT * FROM income_months WHERE user_id = ? AND month = ?').bind(user.id, body.month).first();
  return res({ month: row });
}

async function deleteIncome(user, incomeId, env) {
  const r = await env.DB.prepare('DELETE FROM income_months WHERE id = ? AND user_id = ?').bind(incomeId, user.id).run();
  if (!r.meta || !r.meta.changes) return notFound();
  return res({ ok: true });
}

// ------------------------------------------------------------- achievements
// Unlocks are computed HERE from real data and stored INSERT OR IGNORE with
// PK(user_id, key) — idempotent by construction, survive logout, and the
// response's `new` array only ever contains keys inserted by THIS call, so a
// celebration can fire exactly once per key.
const ACHIEVEMENT_KEYS = [
  'first_item', 'items_10', 'items_50', 'items_100',
  'first_video_posted', 'videos_10', 'videos_50', 'videos_100',
  'first_linked', 'queue_cleared', 'fresh_pile',
  'first_deal', 'deal_agreed', 'first_deal_paid', 'deals_paid_5',
  'first_coupon', 'first_income_month', 'income_3_row', 'month_100', 'month_1k',
  'streak_4', 'streak_12',
];

function weekStartStr(dstr) {
  const [y, m, d] = dstr.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  dt.setUTCDate(dt.getUTCDate() - (dt.getUTCDay() + 6) % 7);
  return dt.toISOString().slice(0, 10);
}
function shiftDateStr(dstr, days) {
  const [y, m, d] = dstr.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d + days)).toISOString().slice(0, 10);
}
function postingStreakWeeks(postedDates, todayStr) {
  const weeks = new Set(postedDates.filter(Boolean).map(weekStartStr));
  if (!weeks.size) return 0;
  let cur = weekStartStr(todayStr);
  if (!weeks.has(cur)) cur = shiftDateStr(cur, -7); // last-week grace
  let n = 0;
  while (weeks.has(cur)) { n++; cur = shiftDateStr(cur, -7); }
  return n;
}
function consecutiveMonths(months) {
  const set = new Set(months);
  let best = 0;
  for (const m of set) {
    const [y, mo] = m.split('-').map(Number);
    const prev = mo === 1 ? `${y - 1}-12` : `${y}-${String(mo - 1).padStart(2, '0')}`;
    if (set.has(prev)) continue; // only start runs at their beginning
    let run = 0, cy = y, cm = mo;
    while (set.has(`${cy}-${String(cm).padStart(2, '0')}`)) {
      run++; cm++; if (cm > 12) { cm = 1; cy++; }
    }
    best = Math.max(best, run);
  }
  return best;
}

async function syncAchievements(user, env) {
  const u = await env.DB.prepare('SELECT tz FROM users WHERE id = ?').bind(user.id).first();
  const today = todayInTz(u && u.tz);
  const [items, postedVids, deals, couponCount, income] = await Promise.all([
    env.DB.prepare('SELECT status, date_received, created_at FROM items WHERE user_id = ?').bind(user.id).all(),
    env.DB.prepare("SELECT posted_date FROM videos WHERE user_id = ? AND status = 'posted'").bind(user.id).all(),
    env.DB.prepare('SELECT status FROM brand_deals WHERE user_id = ?').bind(user.id).all(),
    env.DB.prepare('SELECT COUNT(*) AS n FROM coupons WHERE user_id = ?').bind(user.id).first(),
    env.DB.prepare('SELECT month, commissions + creator_connections + bounties_spc + brand_fees + other AS total FROM income_months WHERE user_id = ?').bind(user.id).all(),
  ]);
  const it = items.results || [], vids = postedVids.results || [], dls = deals.results || [], inc = income.results || [];
  const itemCount = it.length;
  const queue = it.filter(r => r.status === 'received' || r.status === 'queued');
  const cutoff = shiftDateStr(today, -30);
  const stale = queue.filter(r => {
    const start = r.date_received || (r.created_at || '').slice(0, 10);
    return /^\d{4}-\d{2}-\d{2}$/.test(start) && start < cutoff;
  });
  const postedCount = vids.length;
  const streak = postingStreakWeeks(vids.map(v => v.posted_date), today);
  const AGREED_PLUS = ['agreed', 'product_incoming', 'content_due', 'delivered', 'paid'];
  const paidCount = dls.filter(d => d.status === 'paid').length;
  const maxMonth = inc.reduce((m, r) => Math.max(m, Number(r.total) || 0), 0);

  const earned = {
    first_item: itemCount >= 1, items_10: itemCount >= 10, items_50: itemCount >= 50, items_100: itemCount >= 100,
    first_video_posted: postedCount >= 1, videos_10: postedCount >= 10, videos_50: postedCount >= 50, videos_100: postedCount >= 100,
    first_linked: it.some(r => r.status === 'linked'),
    queue_cleared: itemCount >= 1 && queue.length === 0,
    fresh_pile: itemCount >= 1 && stale.length === 0,
    first_deal: dls.length >= 1,
    deal_agreed: dls.some(d => AGREED_PLUS.includes(d.status)),
    first_deal_paid: paidCount >= 1, deals_paid_5: paidCount >= 5,
    first_coupon: (couponCount && couponCount.n) >= 1,
    first_income_month: inc.length >= 1,
    income_3_row: consecutiveMonths(inc.map(r => r.month)) >= 3,
    month_100: maxMonth >= 100, month_1k: maxMonth >= 1000,
    streak_4: streak >= 4, streak_12: streak >= 12,
  };

  const existing = await env.DB.prepare('SELECT key, unlocked_at FROM achievements WHERE user_id = ?').bind(user.id).all();
  const have = new Set((existing.results || []).map(r => r.key));
  const now = new Date().toISOString();
  const fresh = ACHIEVEMENT_KEYS.filter(k => earned[k] && !have.has(k));
  if (fresh.length) {
    await env.DB.batch(fresh.map(k =>
      env.DB.prepare('INSERT OR IGNORE INTO achievements (user_id, key, unlocked_at) VALUES (?, ?, ?)').bind(user.id, k, now)));
  }
  const all = await env.DB.prepare('SELECT key, unlocked_at FROM achievements WHERE user_id = ?').bind(user.id).all();
  return res({
    unlocked: all.results || [],
    new: fresh,
    posted_count: postedCount,
    streak_weeks: streak,
  });
}

// ------------------------------------------------------------- billing
// Entitlement rule (learned from a $0-subscription race): the event that
// grants access must be the one that ALWAYS carries the user identity —
// checkout.session.completed with client_reference_id. subscription.* events
// key on stripe_customer_id, which that same handler writes, so their order
// can't be trusted. /api/stripe/sync self-heals anything missed.

// Write a Stripe subscription's state onto the user row. Product-guarded:
// unknown prices never touch entitlement (Stripe fans events account-wide).
async function applySubscriptionToUser(env, userId, sub) {
  if (!userId || !sub || !isPorchPileSub(sub, env)) return false;
  const active = sub.status === 'active' || sub.status === 'trialing';
  const end = periodEndOf(sub);
  const proUntil = active && end ? new Date(end * 1000).toISOString() : null;
  await env.DB.prepare(
    'UPDATE users SET pro_until = ?, stripe_subscription_id = ?, stripe_status = ?, cancel_at_period_end = ? WHERE id = ?'
  ).bind(proUntil, sub.id, sub.status, sub.cancel_at_period_end ? 1 : 0, userId).run();
  return true;
}

function pickPlanSubscription(subs, env) {
  const mine = (subs || []).filter(s => isPorchPileSub(s, env));
  if (!mine.length) return null;
  const live = mine.filter(s => s.status === 'active' || s.status === 'trialing');
  const pool = live.length ? live : mine;
  return pool.reduce((a, b) => ((b.created || 0) > (a.created || 0) ? b : a));
}

// POST /api/stripe/create-checkout  { interval: 'monthly' | 'annual', ref? }
async function stripeCreateCheckout(user, request, env) {
  // No Stripe on this copy: say so plainly instead of a checkout that can't work.
  if (!env.STRIPE_SECRET_KEY || !env.STRIPE_PRICE_MONTHLY) return res({ error: "Paid plans aren't set up on this copy of Porch Pile." }, 404);
  const body = await readJson(request);
  const interval = body && (body.interval === 'annual' ? 'annual' : body.interval === 'monthly' ? 'monthly' : null);
  if (!interval) return badReq('Pick monthly or annual.');
  // Price IDs come from env only — never from the client.
  const priceId = interval === 'annual' ? env.STRIPE_PRICE_ANNUAL : env.STRIPE_PRICE_MONTHLY;
  if (!priceId) return res({ error: 'Pricing not configured yet. Try again in a few minutes.' }, 503);
  // 10 checkout sessions per user per hour, held in D1.
  if (await overLimit(env, `checkout:${user.id}`, 10, 3600)) return tooMany("Too many checkout attempts. Try again in an hour.", 3600);
  // Affiliate referral (from ?ref, persisted client-side) rides the
  // subscription metadata so every paid invoice can be attributed.
  const affRef = String((body && body.ref) || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 40);
  const row = await env.DB.prepare('SELECT stripe_customer_id, email FROM users WHERE id = ?').bind(user.id).first();
  const base = env.APP_URL;
  if (!base) return res({ error: 'Billing needs APP_URL set on this server.' }, 503);
  try {
    const session = await createCheckoutSession(env, {
      customerId: row.stripe_customer_id || null,
      customerEmail: row.stripe_customer_id ? null : row.email,
      priceId,
      successUrl: `${base}/app?upgraded=1`,
      cancelUrl: `${base}/app?canceled=1`,
      clientReferenceId: user.id,
      affRef: affRef || undefined,
    });
    return res({ url: session.url });
  } catch (e) {
    console.error('checkout create failed', e.stripe || e.message);
    return res({ error: 'Could not start checkout. Try again in a minute.' }, 502);
  }
}

// POST /api/stripe/portal — manage/cancel in the Stripe customer portal.
async function stripePortal(user, env) {
  if (!env.STRIPE_SECRET_KEY) return res({ error: "Billing isn't set up on this copy of Porch Pile." }, 404);
  const row = await env.DB.prepare('SELECT stripe_customer_id FROM users WHERE id = ?').bind(user.id).first();
  if (!row || !row.stripe_customer_id) return res({ error: 'No subscription yet.' }, 412);
  const base = env.APP_URL;
  if (!base) return res({ error: 'Billing needs APP_URL set on this server.' }, 503);
  try {
    const session = await createPortalSession(env, { customerId: row.stripe_customer_id, returnUrl: `${base}/app` });
    return res({ url: session.url });
  } catch (e) {
    console.error('portal create failed', e.stripe || e.message);
    return res({ error: 'Could not open the billing portal. Try again in a minute.' }, 502);
  }
}

// POST /api/stripe/sync — reconcile the caller's plan straight from Stripe.
// Self-heals missed/out-of-order webhooks; safe on every return-from-checkout.
async function stripeSync(user, env) {
  const row = await env.DB.prepare('SELECT stripe_customer_id, stripe_subscription_id, pro_until FROM users WHERE id = ?').bind(user.id).first();
  if (!row || !row.stripe_customer_id) return res({ pro: isProRow(row), synced: false });
  try {
    const subs = await listCustomerSubscriptions(env, row.stripe_customer_id);
    const sub = pickPlanSubscription(subs, env);
    if (sub) {
      await applySubscriptionToUser(env, user.id, sub);
    } else if (row.stripe_subscription_id) {
      // Entitlement came from Stripe and Stripe has no sub left → free. (A
      // manually comped account has no stripe_subscription_id and is left alone.)
      await env.DB.prepare(
        "UPDATE users SET pro_until = NULL, stripe_status = 'canceled', cancel_at_period_end = 0 WHERE id = ?"
      ).bind(user.id).run();
    }
    const fresh = await env.DB.prepare('SELECT pro_until FROM users WHERE id = ?').bind(user.id).first();
    return res({ pro: isProRow(fresh), synced: true });
  } catch (e) {
    console.error('stripe sync failed', e.stripe || e.message);
    return res({ pro: isProRow(row), synced: false });
  }
}

// POST /api/stripe/webhook — raw body, Stripe signature, NO cookie auth and
// NO origin check (Stripe sends no Origin header; the HMAC is the auth).
async function stripeWebhook(request, env) {
  const rawBody = await request.text();
  const v = await verifyWebhook(env, rawBody, request.headers.get('Stripe-Signature'));
  if (!v.ok) {
    console.error('stripe webhook verify failed:', v.reason);
    return res({ error: 'Invalid signature' }, 400); // 4xx: Stripe stops retrying
  }
  const event = v.event;
  const type = event.type;

  // Lock-first idempotency: claim the event id BEFORE any side effects, so
  // at-least-once delivery (and concurrent replays) can't double-apply.
  try {
    const lock = await env.DB.prepare(
      'INSERT OR IGNORE INTO webhook_events (stripe_event_id, event_type, created_at) VALUES (?, ?, ?)'
    ).bind(event.id, type, Math.floor(Date.now() / 1000)).run();
    if (!lock.meta || lock.meta.changes === 0) return res({ received: true, duplicate: true });
  } catch (e) {
    console.error('webhook idempotency lock failed', e.message);
    return res({ error: 'Internal' }, 500); // 5xx → Stripe retries; don't drop the event
  }

  let userId = null, amount = null, currency = null;
  try {
    if (type === 'checkout.session.completed') {
      const session = event.data.object;
      userId = session.client_reference_id || null;
      // Orphan checkout: the account was deleted while this Checkout page was
      // still open, then it got paid. The first checkout uses customer_email,
      // so account delete had no Stripe customer to list it under. Cancel the
      // new subscription now (Porch Pile prices only, in case the Stripe account
      // sells other things too) and flag the payment for the operator. Never auto-refund: a person decides.
      // Only a checkout for a Porch Pile price may touch a user row. Every other
      // checkout on the Stripe account lands here too, and a payment link lets
      // the payer type any client_reference_id they like. If Stripe can't be
      // read, this throws: the lock is released and Stripe sends the event again.
      let sub = null;
      if (userId && session.subscription) {
        sub = await retrieveSubscription(env, session.subscription);
        if (!isPorchPileSub(sub, env)) sub = null;
      }
      if (!sub) userId = null; // not ours: no customer link, no grant, no payment_events row
      else {
        const exists = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
        if (!exists) {
          userId = null; // no row to attach payment_events to
          if (sub.status !== 'canceled' && sub.status !== 'incomplete_expired') await cancelSubscription(env, sub.id);
          const note = `Paid checkout for a deleted account. Subscription ${sub.id} canceled. Decide on a refund in Stripe: customer ${session.customer || '?'}, session ${session.id}, amount ${session.amount_total ?? '?'} ${session.currency || ''}`.trim();
          console.error('checkout.completed ORPHAN:', note);
          await reportServerError(env, null, { path: '/api/stripe/webhook', method: 'POST', status: 'refund?', message: note });
        } else if (session.customer) {
          await env.DB.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?')
            .bind(session.customer, userId).run();
          // Grant HERE — this event always carries our user id. Waiting for
          // subscription.created loses the race on $0 (promo-code) checkouts.
          try { await applySubscriptionToUser(env, userId, sub); }
          catch (e) { console.error('checkout.completed: sub apply failed', e.stripe || e.message); }
        }
      }
    }
    else if (type === 'customer.subscription.created' || type === 'customer.subscription.updated') {
      const sub = event.data.object;
      const u = await env.DB.prepare('SELECT id FROM users WHERE stripe_customer_id = ?').bind(sub.customer).first();
      if (u) { userId = u.id; await applySubscriptionToUser(env, userId, sub); }
      // No user row yet → the customer link hasn't been written; the
      // checkout.session.completed handler grants instead. Skip, don't orphan.
    }
    else if (type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      if (isPorchPileSub(sub, env)) {
        const u = await env.DB.prepare('SELECT id FROM users WHERE stripe_customer_id = ?').bind(sub.customer).first();
        if (u) {
          userId = u.id;
          await env.DB.prepare(
            "UPDATE users SET pro_until = NULL, stripe_status = ?, cancel_at_period_end = 0 WHERE id = ?"
          ).bind(sub.status || 'canceled', userId).run();
        }
      }
    }
    else if (type === 'invoice.paid') {
      const inv = event.data.object;
      amount = inv.amount_paid || null;
      currency = inv.currency || null;
      // Newer API versions moved the subscription ref off the invoice top
      // level; resolve from all known locations.
      const subId = inv.subscription
        || inv.parent?.subscription_details?.subscription
        || inv.lines?.data?.[0]?.parent?.subscription_item_details?.subscription;
      const u = await env.DB.prepare('SELECT id FROM users WHERE stripe_customer_id = ?').bind(inv.customer).first();
      if (u) userId = u.id;
      // Guard is subId alone, NOT userId && subId: on a first purchase
      // invoice.paid can beat checkout.session.completed, and gating on the
      // user row silently dropped the affiliate's first commission.
      if (subId) {
        const sub = await retrieveSubscription(env, subId);
        // Product guard FIRST — the only thing stopping this endpoint from
        // recording a conversion for another product's sale.
        if (!isPorchPileSub(sub, env)) return res({ received: true, ignored: 'not-porch-pile' });
        if (userId) await applySubscriptionToUser(env, userId, sub);
        const affRef = sub.metadata?.aff_ref;
        // Optional affiliate tracking: set AFFILIATE_API_URL to your own platform. Unset = skipped.
        if (affRef && env.AFFILIATE_API_URL && (inv.amount_paid || 0) > 0) {
          try {
            const rc = await fetch(env.AFFILIATE_API_URL + '/record-conversion', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'X-Webhook-Secret': env.CONVERSION_WEBHOOK_SECRET || '' },
              body: JSON.stringify({
                referral_code: affRef,
                product_slug: 'porch-pile',
                sale_amount_cents: inv.amount_paid,
                currency: inv.currency,
                stripe_invoice_id: inv.id,
                stripe_charge_id: inv.charge,
                stripe_subscription_id: sub.id,
                customer_email: inv.customer_email || '',
                attribution_method: 'referral_code',
                status: 'pending',
              }),
            });
            // Read the answer: fire-and-forget made a dropped commission
            // indistinguishable from success. Log either way.
            const out = await rc.json().catch(() => null);
            if (rc.ok && out?.created) console.log('record-conversion ok', inv.id, out.created);
            else console.error('record-conversion NOT recorded', rc.status, inv.id, JSON.stringify(out));
          } catch (e) { console.error('record-conversion call failed', e.message); }
        }
      }
    }
    else if (type === 'charge.refunded') {
      // Reverse the affiliate commission for a refunded payment. Must prove
      // the charge is OURS first (this fires for every refund on the account).
      // No email+amount fallback — two products on one Stripe account can share a price point, so
      // the platform only gets ids; an unmatched refund is logged, not guessed.
      const charge = event.data.object;
      try {
        let invoiceId = charge.invoice || '';
        if (!invoiceId && charge.id) {
          try {
            const full = await retrieveCharge(env, charge.id); // pinned: default version drops .invoice
            invoiceId = full?.invoice || '';
          } catch (e) { console.error('charge.refunded: retrieveCharge failed', e.stripe || e.message); }
        }
        if (!invoiceId) {
          console.error('charge.refunded: UNRESOLVED — no invoice id for charge', charge.id,
            '— affiliate commission NOT reversed, check manually');
        } else {
          const invoice = await retrieveInvoice(env, invoiceId);
          if (env.AFFILIATE_API_URL && invoiceIsPorchPile(invoice, env)) {
            const r = await fetch(env.AFFILIATE_API_URL + '/reverse-conversion', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'X-Webhook-Secret': env.CONVERSION_WEBHOOK_SECRET || '' },
              body: JSON.stringify({
                stripe_invoice_id: invoiceId,
                stripe_charge_id: charge.id || '',
                stripe_payment_intent: charge.payment_intent || '',
                amount_refunded_cents: charge.amount_refunded ?? charge.amount ?? null,
                reason: 'Stripe charge.refunded (porch-pile)',
              }),
            });
            const out = await r.json().catch(() => null);
            if (r.ok && out?.skipped === 'not_found') {
              console.log('charge.refunded: no affiliate conversion for invoice', invoiceId);
            } else if (!r.ok || !(out?.reversed || out?.skipped === 'already_reversed')) {
              console.error('charge.refunded: reverse-conversion did not reverse for invoice', invoiceId, JSON.stringify(out));
            }
          }
        }
      } catch (e) { console.error('reverse-conversion call failed', e.stripe || e.message); }
    }
    else if (type === 'invoice.payment_failed') {
      // No entitlement change — Stripe retries; subscription.updated/deleted
      // carry any eventual downgrade. Logged in payment_events below.
      const inv = event.data.object;
      const u = await env.DB.prepare('SELECT id FROM users WHERE stripe_customer_id = ?').bind(inv.customer).first();
      if (u) userId = u.id;
    }

    if (userId) {
      try {
        await env.DB.prepare(
          'INSERT INTO payment_events (id, user_id, stripe_event_id, event_type, amount, currency, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).bind(crypto.randomUUID(), userId, event.id, type, amount, currency, Math.floor(Date.now() / 1000)).run();
      } catch (e) {
        if (!String(e.message || '').includes('UNIQUE')) console.error('payment_events insert failed', e.message);
      }
    }
  } catch (e) {
    console.error(`stripe webhook ${type} failed`, e.stack || e.message);
    // Release the lock so Stripe's retry runs the handler again. Without this
    // the retry hits "duplicate" and the failure is permanent. Every side
    // effect is safe to repeat: UPDATEs, the platform dedupes on the Stripe id,
    // payment_events has a UNIQUE event id.
    try { await env.DB.prepare('DELETE FROM webhook_events WHERE stripe_event_id = ?').bind(event.id).run(); }
    catch (e2) { console.error('webhook lock release failed', event.id, e2.message); }
    return res({ error: 'Internal' }, 500); // Stripe retries
  }
  return res({ received: true });
}

// ------------------------------------------------------------- daily purge
// Cron (wrangler.toml [triggers]). Deletes rate-limit rows past every window
// (the longest is one day) and verification codes / reset
// tokens that expired or were used more than 7 days ago.
// Link-preview scrapers skip relative URLs, so a share tag written as
// content="/og.png" gets this site's APP_URL put in front of it at serve time.
// Tags that already hold a full address are left alone.
const SHARE_URL_TAG = /(<meta\s+(?:property|name)="(?:og:url|og:image|og:image:secure_url|twitter:image)"\s+content=")\/(?!\/)/g;
// Same for a relative "url" in the page's schema.org data.
const SCHEMA_URL = /("url":\s*")\/(?!\/)/g;
export function fillShareUrls(html, env) {
  const base = String(env.APP_URL || '').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(base)) return html;
  return html.replace(SHARE_URL_TAG, `$1${base}/`).replace(SCHEMA_URL, `$1${base}/`);
}

export async function purgeExpired(env, nowS = Math.floor(Date.now() / 1000)) {
  const weekAgo = nowS - 7 * 86400;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM rate_limits WHERE created_at < ?').bind(nowS - 86400),
    env.DB.prepare('DELETE FROM email_verifications WHERE expires_at < ? OR (used = 1 AND created_at < ?)').bind(weekAgo, weekAgo),
    env.DB.prepare('DELETE FROM reset_tokens WHERE expires_at < ? OR (used = 1 AND created_at < ?)').bind(weekAgo, weekAgo),
  ]);
}

// ------------------------------------------------------------- router
export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(purgeExpired(env).catch(e => console.error('daily purge failed', (e && e.message) || e)));
  },

  async fetch(request, env, ctx) {
    // A THROW out of handle() has to become a Response before the 5xx branch
    // below can see it. Without this catch the exception escaped the worker,
    // the runtime turned it into its own 500, and NO alert email was sent —
    // silent on exactly the crash class the beacon exists for.
    let response;
    let errDetail = '';
    try {
      response = await this.handle(request, env, ctx);
    } catch (e) {
      console.error('unhandled route error', request.method, new URL(request.url).pathname, (e && e.stack) || e);
      response = new Response(JSON.stringify({ error: 'Server error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      });
      // The message the beacon reads comes off this body, so name the cause.
      errDetail = String((e && e.message) || e).slice(0, 200);
    }
    try {
      if (response && response.status >= 500) {
        // The message is read off a clone of the response body inside
        // waitUntil, so it never delays the client. Responses tagged by
        // markNoAlert() are skipped.
        const job = alertPayloadFor(request, response, errDetail)
          .then(info => (info ? reportServerError(env, null, info) : null))
          .catch(() => {});
        if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(job);
      }
    } catch {}
    return stripAlertHeader(response);
  },

  async handle(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      if (method === 'OPTIONS') return new Response(null, { status: 204, headers: securityHeaders() });

      // Non-API: serve static assets with CSP layered on top.
      if (!path.startsWith('/api/')) {
        // /reset/<token> is a virtual route — there is no such file, so ASSETS
        // would 404 it. Serve the app shell and let the front end read the token
        // off the path.
        const resetPath = path.match(/^\/reset\/([a-f0-9]{64})\/?$/);
        const assetRequest = resetPath
          // '/app', not '/app.html' — Workers static assets normalises the .html
          // form with a 307, and a redirect here would throw the token off the URL
          // before the front end ever reads it.
          ? new Request(new URL('/app', url).toString(), request)
          : request;
        const assetRes = await env.ASSETS.fetch(assetRequest);
        const h = new Headers(assetRes.headers);
        Object.entries(securityHeaders()).forEach(([k, v]) => h.set(k, v));
        const isHtml = (h.get('Content-Type') || '').includes('text/html');
        if (isHtml) h.set('Content-Security-Policy', cspHeader());
        // Share tags written as relative paths get APP_URL in front, so link
        // previews find the image. Tags that are already full addresses are left
        // alone, so a page that has only those comes out byte for byte the same.
        if (isHtml && assetRes.status === 200) {
          const html = await assetRes.text();
          const filled = fillShareUrls(html, env);
          if (filled !== html) h.delete('Content-Length');
          return new Response(filled, { status: assetRes.status, headers: h });
        }
        return new Response(assetRes.body, { status: assetRes.status, headers: h });
      }

      if (path === '/api/health' && method === 'GET') return res({ ok: true, app: 'porch-pile' });

      // Stripe webhook comes BEFORE the CSRF gate: Stripe sends no Origin
      // header — the HMAC signature is the authentication.
      if (path === '/api/stripe/webhook' && method === 'POST') return stripeWebhook(request, env);

      // Internal comp calls: the secret header is the auth, no Origin.
      if (path === '/api/internal/comp-access' && method === 'POST') return compGrant(request, env);
      if (path === '/api/internal/revoke-access' && method === 'POST') return compRevoke(request, env);

      // CSRF gate on mutations.
      if (!checkOrigin(request, env)) return res({ error: 'Bad origin' }, 403);

      // Setup check, before any signup, code or login is written: with no real session
      // secret nobody could be logged in anyway, so say what to fix.
      if (path.startsWith('/api/auth/') && path !== '/api/auth/logout'
          && !(typeof env.PP_SESSION_SECRET === 'string' && env.PP_SESSION_SECRET.length >= 32)) {
        return res({ error: "Server isn't set up: set PP_SESSION_SECRET to 32+ random characters." }, 503);
      }

      // Public auth endpoints.
      if (path === '/api/auth/signup' && method === 'POST') return signup(request, env);
      if (path === '/api/auth/verify-code' && method === 'POST') return verifyCode(request, env);
      if (path === '/api/auth/resend-verification' && method === 'POST') return resendVerification(request, env);
      if (path === '/api/auth/login' && method === 'POST') return login(request, env);
      if (path === '/api/auth/logout' && method === 'POST') return logout();
      if (path === '/api/auth/reset-request' && method === 'POST') return resetRequest(request, env);
      if (path === '/api/auth/reset-confirm' && method === 'POST') return resetConfirm(request, env);

      // Feedback relay: open to logged-out callers (the CSRF gate above still
      // requires same-origin). 5 per IP per 10 min, counted in D1.
      if (path === '/api/feedback' && method === 'POST') {
        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (await overLimit(env, `feedback-ip:${ip}`, 5, 600)) return tooMany('Too many messages from this connection. Try again in a few minutes.', 600);
        // Whole-site ceiling, so a script hopping between addresses can't flood the inbox.
        if (await overLimit(env, 'feedback-all', FEEDBACK_HOURLY_MAX, 3600)) return tooMany('Feedback is busy right now. Try again in an hour.', 3600);
        return feedback(request, env);
      }

      // Everything below needs a session.
      const user = await getUser(request, env);
      if (!user) {
        // The SPA boots by asking "who am I". Logged out is a normal answer,
        // not an error — a 401 here logs a console resource error on every
        // first visit (and fails the zero-console-errors bar).
        if (path === '/api/me' && method === 'GET') return res({ user: null, ...siteFlags(env) });
        return unauth();
      }

      // Per-user write throttle: 120 mutations / min. Cheap backstop against a
      // runaway client or a stolen session hammering the endpoints.
      if (method !== 'GET' && method !== 'HEAD') {
        if (await overLimit(env, `writes:${user.id}`, 120, 60)) {
          return res({ error: 'Slow down a moment. Too many changes at once.' }, 429);
        }
      }

      if (path === '/api/me' && method === 'GET') return me(user, env);
      if (path === '/api/me' && method === 'DELETE') return deleteAccount(user, request, env);
      if (path === '/api/settings' && method === 'PUT') return updateSettings(user, request, env);
      if (path === '/api/account/export' && method === 'GET') return exportAccount(user, env);

      // ---- billing
      if (path === '/api/stripe/create-checkout' && method === 'POST') return stripeCreateCheckout(user, request, env);
      if (path === '/api/stripe/portal' && method === 'POST') return stripePortal(user, env);
      if (path === '/api/stripe/sync' && method === 'POST') return stripeSync(user, env);

      // ---- items
      if (path === '/api/items' && method === 'GET') return listItems(user, env);
      if (path === '/api/items' && method === 'POST') return createItem(user, request, env);

      // ---- spreadsheet import — before the :id routes so 'import' is never an item id
      if (path === '/api/items/import' && method === 'POST') {
        return importItems(user, request, env, {
          res, badReq, isProRow, billingRow, collectItemFields,
          readJson: r => readJson(r, MAX_IMPORT_BODY_BYTES),
        });
      }
      if (path === '/api/items/import/recent' && method === 'GET') {
        return recentImport(user, env, { res });
      }
      if (path.startsWith('/api/items/import/') && method === 'DELETE') {
        return undoImport(user, path.slice('/api/items/import/'.length), env, { res, badReq });
      }
      const itemM = path.match(/^\/api\/items\/([0-9a-f-]{36})$/);
      if (itemM && method === 'PUT') return updateItem(user, itemM[1], request, env);
      if (itemM && method === 'DELETE') return deleteItem(user, itemM[1], env);

      // ---- videos
      if (path === '/api/videos' && method === 'GET') return listVideos(user, env);
      if (path === '/api/videos' && method === 'POST') return createVideo(user, request, env);
      const videoM = path.match(/^\/api\/videos\/([0-9a-f-]{36})$/);
      if (videoM && method === 'PUT') return updateVideo(user, videoM[1], request, env);
      if (videoM && method === 'DELETE') return deleteVideo(user, videoM[1], env);

      // ---- brand deals
      if (path === '/api/deals' && method === 'GET') return listDeals(user, env);
      if (path === '/api/deals' && method === 'POST') return createDeal(user, request, env);
      const dealM = path.match(/^\/api\/deals\/([0-9a-f-]{36})$/);
      if (dealM && method === 'PUT') return updateDeal(user, dealM[1], request, env);
      if (dealM && method === 'DELETE') return deleteDeal(user, dealM[1], env);

      // ---- coupons
      if (path === '/api/coupons' && method === 'GET') return listCoupons(user, env);
      if (path === '/api/coupons' && method === 'POST') return createCoupon(user, request, env);
      const couponM = path.match(/^\/api\/coupons\/([0-9a-f-]{36})$/);
      if (couponM && method === 'PUT') return updateCoupon(user, couponM[1], request, env);
      if (couponM && method === 'DELETE') return deleteCoupon(user, couponM[1], env);

      // ---- income
      if (path === '/api/income' && method === 'GET') return listIncome(user, env);
      if (path === '/api/income' && method === 'POST') return upsertIncome(user, request, env);
      const incomeM = path.match(/^\/api\/income\/([0-9a-f-]{36})$/);
      if (incomeM && method === 'DELETE') return deleteIncome(user, incomeM[1], env);

      // ---- achievements
      if (path === '/api/achievements/sync' && method === 'POST') return syncAchievements(user, env);

      return notFound();
    } catch (e) {
      console.error('unhandled', e && e.stack || e);
      return res({ error: 'Server error' }, 500);
    }
  },
};
