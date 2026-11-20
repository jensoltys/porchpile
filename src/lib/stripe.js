// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Stripe helpers — webhook signature verification + thin API wrapper.
// No Stripe SDK (heavy for Workers); a few fetch calls cover us. Pattern
// proven on other small Workers apps.
//
// Webhook security: Stripe signs every webhook with HMAC-SHA256 over
// `<timestamp>.<raw body>` using STRIPE_WEBHOOK_SECRET. We verify the
// signature AND a 5-minute timestamp skew so replays can't reuse an old
// signed event.

const STRIPE_API = 'https://api.stripe.com/v1';
const MAX_WEBHOOK_AGE_SEC = 5 * 60;

const enc = new TextEncoder();

// Constant-time string equality — prevents byte-at-a-time signature probing.
export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
  return [...sig].map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseSignatureHeader(header) {
  const out = { t: null, v1: [] };
  if (!header) return out;
  for (const part of header.split(',')) {
    const [k, v] = part.split('=');
    if (k === 't') out.t = v;
    else if (k === 'v1') out.v1.push(v);
  }
  return out;
}

// Verify webhook signature + recency. `rawBody` MUST be the exact string
// Stripe signed — never re-stringify parsed JSON.
export async function verifyWebhook(env, rawBody, sigHeader) {
  if (!env.STRIPE_WEBHOOK_SECRET) return { ok: false, reason: 'webhook-secret-not-configured' };
  if (!sigHeader) return { ok: false, reason: 'missing-signature' };
  const parsed = parseSignatureHeader(sigHeader);
  if (!parsed.t || parsed.v1.length === 0) return { ok: false, reason: 'malformed-signature' };
  const ts = parseInt(parsed.t, 10);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(ts) || Math.abs(now - ts) > MAX_WEBHOOK_AGE_SEC) {
    return { ok: false, reason: 'timestamp-skew' };
  }
  const expected = await hmacSha256Hex(env.STRIPE_WEBHOOK_SECRET, `${parsed.t}.${rawBody}`);
  if (!parsed.v1.some(v => timingSafeEqual(v, expected))) return { ok: false, reason: 'signature-mismatch' };
  let event;
  try { event = JSON.parse(rawBody); }
  catch { return { ok: false, reason: 'invalid-json' }; }
  return { ok: true, event };
}

function ppPriceIds(env) {
  return [env.STRIPE_PRICE_MONTHLY, env.STRIPE_PRICE_ANNUAL].filter(Boolean);
}

// Explicit product guard: is this Stripe subscription a PORCH PILE one?
// Stripe fans every event out to EVERY endpoint on the account, so if your Stripe
// account sells anything else, those events land here too.
// Affiliate attribution runs without a local user lookup (a first purchase may
// have no linked row yet), so this price check is the only thing stopping
// Porch Pile from recording a conversion for another product's sale. Fails
// CLOSED when the price env vars are missing. Never remove it.
export function isPorchPileSub(sub, env) {
  const ids = ppPriceIds(env);
  if (!ids.length) return false;
  const items = sub?.items?.data || [];
  return items.some(it => ids.includes(it?.price?.id) || ids.includes(it?.plan?.id))
    || ids.includes(sub?.plan?.id);
}

// Same guard for the refund path, applied to the invoice a refunded charge
// points at (a Charge carries no line items).
export function invoiceIsPorchPile(invoice, env) {
  const ids = ppPriceIds(env);
  if (!ids.length) return false;
  const lines = invoice?.lines?.data || [];
  return lines.some(l => ids.includes(l?.price?.id)
    || ids.includes(l?.plan?.id)
    || ids.includes(l?.pricing?.price_details?.price));
}

// Stripe moved current_period_end off the Subscription top level onto each
// subscription item (Basil, 2025-03-31+). Read the item first; keep the
// top-level fallback for pinned calls and replayed events.
export function periodEndOf(sub) {
  return Number(sub?.items?.data?.[0]?.current_period_end)
    || Number(sub?.current_period_end)
    || null;
}

// Flatten nested params into Stripe's bracket notation, to ANY depth —
// a shallow flattener serializes subscription_data.metadata.aff_ref as
// "[object Object]" and Stripe rejects the whole checkout.
export function buildFormBody(params, body = new URLSearchParams(), prefix = '') {
  for (const [k, v] of Object.entries(params)) {
    const key = prefix ? `${prefix}[${k}]` : k;
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      v.forEach((item, i) => {
        if (item === undefined || item === null) return;
        if (typeof item === 'object') buildFormBody(item, body, `${key}[${i}]`);
        else body.append(`${key}[${i}]`, String(item));
      });
    } else if (typeof v === 'object') {
      buildFormBody(v, body, key);
    } else {
      body.append(key, String(v));
    }
  }
  return body;
}

async function stripeApi(env, method, path, params = {}, opts = {}) {
  if (!env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY not configured');
  const body = buildFormBody(params);
  const headers = {
    'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (opts.apiVersion) headers['Stripe-Version'] = opts.apiVersion;
  const resp = await fetch(`${STRIPE_API}${path}`, {
    method,
    headers,
    body: method === 'GET' ? undefined : body.toString(),
  });
  const json = await resp.json();
  if (!resp.ok) {
    const err = new Error(json?.error?.message || `Stripe API ${resp.status}`);
    err.stripe = json;
    throw err;
  }
  return json;
}

// Stripe Tax on checkout. Off unless STRIPE_AUTOMATIC_TAX is 'true'. Turn it on
// only after Stripe Tax is set up in the account (head office, default tax
// code, a tax_code on the product).
export function automaticTaxOn(env) {
  return String(env.STRIPE_AUTOMATIC_TAX ?? '').toLowerCase() === 'true';
}

export async function createCheckoutSession(env, { customerId, customerEmail, priceId, successUrl, cancelUrl, clientReferenceId, affRef }) {
  // automatic_tax (see automaticTaxOn) needs Stripe Tax active in this mode.
  // payment_method_collection 'if_required' skips the card form when a
  // 100%-off promo code brings the total to $0.
  const params = {
    mode: 'subscription',
    customer: customerId || undefined,
    customer_email: customerId ? undefined : customerEmail,
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: successUrl,
    cancel_url: cancelUrl,
    client_reference_id: clientReferenceId,
    allow_promotion_codes: 'true',
    automatic_tax: { enabled: automaticTaxOn(env) ? 'true' : 'false' },
    payment_method_collection: 'if_required',
  };
  // Affiliate referral rides the subscription so every paid invoice can be
  // attributed, renewals included.
  if (affRef) params.subscription_data = { metadata: { aff_ref: affRef } };
  return stripeApi(env, 'POST', '/checkout/sessions', params);
}

export async function createPortalSession(env, { customerId, returnUrl }) {
  return stripeApi(env, 'POST', '/billing_portal/sessions', {
    customer: customerId,
    return_url: returnUrl,
    configuration: env.STRIPE_PORTAL_CONFIG || undefined,
  });
}

export async function retrieveSubscription(env, subscriptionId) {
  return stripeApi(env, 'GET', `/subscriptions/${encodeURIComponent(subscriptionId)}`);
}

// Pinned reads for the refund path: at the account's default API version a
// Charge no longer exposes `invoice` (and vice versa), so a refund loses the
// id that ties it back to the conversion row. 2024-06-20 still carries both.
export async function retrieveInvoice(env, invoiceId) {
  return stripeApi(env, 'GET', `/invoices/${encodeURIComponent(invoiceId)}`, {}, { apiVersion: '2024-06-20' });
}
export async function retrieveCharge(env, chargeId) {
  return stripeApi(env, 'GET', `/charges/${encodeURIComponent(chargeId)}`, {}, { apiVersion: '2024-06-20' });
}

// Reconcile source: list a customer's subscriptions straight from Stripe when
// a webhook was missed or arrived out of order.
export async function listCustomerSubscriptions(env, customerId) {
  const out = await stripeApi(
    env, 'GET',
    `/subscriptions?customer=${encodeURIComponent(customerId)}&status=all&limit=10`
  );
  return out?.data || [];
}

// Immediate cancel (no period-end grace) — used by account-delete so a user
// can't keep being charged for a row that no longer exists.
// Cancel, effective now, every Porch Pile subscription that could still bill this
// customer. Account delete runs this first and stops if it throws. Lists by customer
// so a past_due or older subscription can't survive, but only touches Porch Pile
// prices, in case the Stripe account sells other things too.
const ENDED_SUB_STATUSES = new Set(['canceled', 'incomplete_expired']);

export async function cancelAllSubscriptions(env, customerId, subscriptionId) {
  const ids = new Set(subscriptionId ? [subscriptionId] : []);
  if (customerId) {
    if (!ppPriceIds(env).length) throw new Error('No Stripe prices configured');
    try {
      const list = await stripeApi(env, 'GET', `/subscriptions?customer=${encodeURIComponent(customerId)}&status=all&limit=100`);
      for (const sub of list?.data || []) {
        if (ENDED_SUB_STATUSES.has(sub.status)) ids.delete(sub.id);
        else if (isPorchPileSub(sub, env)) ids.add(sub.id);
      }
    } catch (e) {
      if (e.stripe?.error?.code !== 'resource_missing') throw e;
    }
  }
  for (const id of ids) await cancelSubscription(env, id);
}

export async function cancelSubscription(env, subscriptionId) {
  try {
    return await stripeApi(env, 'DELETE', `/subscriptions/${encodeURIComponent(subscriptionId)}`);
  } catch (e) {
    if (e.stripe?.error?.code === 'resource_missing') return { ok: true, missing: true };
    throw e;
  }
}
