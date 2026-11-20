// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Security regression gate — Porch Pile. Run: node scripts/test-security.mjs
//
// Every future audit finding gets a check here so it can't silently regress.
// App-specific allowances (documented, deliberate):
//   - CSP script-src 'unsafe-inline': family-standard vanilla SPA with inline
//     script; XSS defense is esc() on every user-derived string (checked below).
//   - Inline on* handlers: allowed because CSP permits inline (same family call).
//   - SELECT * on user-scoped CONTENT tables (items/videos/deals/coupons/
//     income_months): scoped by user_id, no secret columns. SELECT * on users
//     is still flagged HIGH (password_hash/salt live there).
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');

function listFiles(dir, exts, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith('.')) continue;
    const full = join(dir, entry);
    const s = statSync(full);
    if (s.isDirectory()) {
      if (['vendor', 'node_modules', '.wrangler', 'dist', 'build', 'fonts'].includes(entry)) continue;
      listFiles(full, exts, out);
    } else if (exts.some(e => entry.endsWith(e))) {
      out.push(full);
    }
  }
  return out;
}

const findings = [];
function flag(severity, file, line, rule, detail) {
  findings.push({ severity, file: relative(repoRoot, file), line, rule, detail });
}

const CONTENT_TABLES = /\bFROM\s+(\$\{t\}|items\b|videos\b|video_items\b|brand_deals\b|deal_items\b|coupons\b|income_months\b|achievements\b)/i;

// ── Source code checks (src/) ──────────────────────────────────────────────
const srcFiles = listFiles(join(repoRoot, 'src'), ['.js', '.ts', '.mjs']);
for (const f of srcFiles) {
  const content = readFileSync(f, 'utf8');
  const lines = content.split('\n');
  lines.forEach((line, idx) => {
    const ln = idx + 1;
    // SELECT * on users = credential-column leak risk. Content tables exempted (see header).
    if (/\bSELECT\s+\*/i.test(line) && !CONTENT_TABLES.test(line)) {
      flag('HIGH', f, ln, 'SELECT * outside content-table allowlist', 'List columns explicitly (users carries password_hash/salt).');
    }
    if (/Access-Control-Allow-Origin['"\s:,]+\*/.test(line)) flag('HIGH', f, ln, 'CORS wildcard', 'Origin allowlist required with credentials.');
    if (/sk-ant-api03-[A-Za-z0-9_-]{20,}/.test(line)) flag('HIGH', f, ln, 'hardcoded ANTHROPIC key', 'Move to wrangler secret.');
    if (/\bre_[A-Za-z0-9]{20,}/.test(line)) flag('HIGH', f, ln, 'hardcoded RESEND key', 'Move to wrangler secret.');
    if (/sk_(live|test)_[A-Za-z0-9]{20,}/.test(line)) flag('HIGH', f, ln, 'hardcoded STRIPE key', 'Move to wrangler secret.');
    if (/whsec_[A-Za-z0-9]{20,}/.test(line)) flag('HIGH', f, ln, 'hardcoded Stripe webhook secret', 'Move to wrangler secret.');
    if (/ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}/.test(line)) flag('HIGH', f, ln, 'hardcoded GitHub PAT', 'Move to secret store.');
    if (/console\.(log|error|warn|info|debug)\s*\([^)]*\b(password|passwordHash|jwt|apiKey|api_key|authorization|req\.body|request\.body)\b/i.test(line)) {
      flag('MEDIUM', f, ln, 'PII / secret in console log', 'Log identifiers, never the data.');
    }
    if (/(localStorage|sessionStorage)\.setItem\s*\(\s*['"`][^'"`]*(password|token|jwt|secret|apiKey|api_key|credit|card|ssn)/i.test(line)) {
      flag('HIGH', f, ln, 'sensitive data in browser storage', 'Auth state lives in the HttpOnly cookie.');
    }
    if (/(\beval\s*\(|new\s+Function\s*\()/.test(line)) flag('HIGH', f, ln, 'eval/new Function', 'Never eval dynamic strings.');
    if (/'unsafe-eval'/.test(line)) flag('HIGH', f, ln, "CSP allows 'unsafe-eval'", 'Remove unsafe-eval from CSP.');
  });
  // JWT revocation + dummy-hash timing guard must stay present in the worker.
  if (/worker\.js$/.test(f)) {
    if (!/token_version/.test(content)) flag('HIGH', f, 0, 'token_version missing from worker', 'JWT revocation depends on it.');
    if (!/pbkdf2\$100000\$/.test(content)) flag('MEDIUM', f, 0, 'login dummy-hash guard missing', 'Constant-time unknown-email path (enumeration).');
    if (!/MAX_BODY_BYTES/.test(content)) flag('HIGH', f, 0, 'request body cap missing', '64KB cap prevents payload abuse.');
    if (!/checkOrigin/.test(content)) flag('HIGH', f, 0, 'CSRF origin gate missing', 'Mutations must verify Origin.');
    // Unverified-signup pre-hijack: a signup on an
    // unverified row must replace its credentials, and code entry must also
    // check the password, or a squatter's password survives the owner's verify.
    const signupSrc = (content.match(/async function signup\([\s\S]*?\n\}\n/) || [''])[0];
    if (!/email_verified[\s\S]*UPDATE users SET password_hash = \?, token_version = token_version \+ 1/.test(signupSrc)) {
      flag('HIGH', f, 0, 'signup keeps a squatter password on an unverified row', 'Replace password_hash and bump token_version when the existing row is unverified.');
    }
    const verifySrc = (content.match(/async function verifyCode\([\s\S]*?\n\}\n/) || [''])[0];
    if (!/verifyPassword\(/.test(verifySrc)) {
      flag('HIGH', f, 0, 'verify-code mints a session without the password', 'The code proves the inbox; the password proves who set the credentials.');
    }
  }
}

// ── HTML asset checks (public/) ──────────────────────────────────────────
const htmlFiles = listFiles(join(repoRoot, 'public'), ['.html']);
for (const f of htmlFiles) {
  const content = readFileSync(f, 'utf8');
  const lines = content.split('\n');
  lines.forEach((line, idx) => {
    const ln = idx + 1;
    const matches = line.match(/<a\b[^>]*\btarget\s*=\s*["']_blank["'][^>]*>/gi);
    if (matches) for (const tag of matches) {
      if (!/\brel\s*=\s*["'][^"']*\bnoopener\b/i.test(tag)) flag('MEDIUM', f, ln, 'target=_blank without rel=noopener', tag.slice(0, 80));
    }
    // XSS sinks fed dynamic data must run it through esc() on the same line
    // (family templating style). Static-only innerHTML is fine.
    if (/(\.innerHTML\s*=|insertAdjacentHTML\s*\()/.test(line) && /\$\{(?!esc\()/.test(line)) {
      const expr = line.match(/\$\{(?!esc\()[^}]*\}/g) || [];
      // allow interpolations that are function calls building already-escaped html,
      // numeric/known-safe locals, or ternary class toggles — flag raw state fields
      if (expr.some(e => /\b(name|title|brand|note|email|url|text|msg)\b/i.test(e))) {
        flag('MEDIUM', f, ln, 'XSS sink: interpolated user-ish field without esc()', expr[0].slice(0, 60));
      }
    }
    const cdnScript = line.match(/<script[^>]+src\s*=\s*["']https:\/\/[^"']+["'][^>]*>/gi);
    if (cdnScript) for (const tag of cdnScript) {
      if (!/\bintegrity\s*=/i.test(tag)) flag('MEDIUM', f, ln, 'external script without SRI', tag.slice(0, 80));
    }
    const checkboxMatches = line.match(/<input\b[^>]*\btype\s*=\s*["']checkbox["'][^>]*>/gi);
    if (checkboxMatches) for (const tag of checkboxMatches) {
      if (/\b(newsletter|marketing|subscribe|opt[-_]?in|promo)\b/i.test(tag) && /\bchecked\b/i.test(tag)) {
        flag('HIGH', f, ln, 'consent checkbox default-checked', 'GDPR/ePrivacy: default unchecked.');
      }
    }
    if (/price_[A-Za-z0-9]{14,}/.test(line)) flag('HIGH', f, ln, 'Stripe price_id in HTML', 'Server chooses price by interval name; never trust client.');
  });
  // Landing + app must link the privacy policy.
  if (/(index|app)\.html$/.test(f) && !/href\s*=\s*["'][^"']*(privacy|legal)/i.test(content)) {
    flag('MEDIUM', f, 0, 'no privacy policy link', 'Every collection point needs a reachable privacy notice.');
  }
}

// ── Migrations ────────────────────────────────────────────────────────────
const migrationsDir = join(repoRoot, 'migrations');
if (existsSync(migrationsDir)) {
  const all = readdirSync(migrationsDir).filter(x => x.endsWith('.sql'))
    .map(x => readFileSync(join(migrationsDir, x), 'utf8')).join('\n');
  if (/CREATE TABLE users/i.test(all) && !/token_version/i.test(all)) {
    flag('HIGH', migrationsDir, 0, 'users.token_version missing', 'JWT revocation requires it.');
  }
}

// ── Feedback relay ───────────────────────────────
// The widget must post to the Worker's rate-limited /api/feedback relay,
// never straight to a webhook URL.
{
  const widget = join(repoRoot, 'public', 'feedback-widget.js');
  if (existsSync(widget)) {
    const w = readFileSync(widget, 'utf8');
    if (/https?:\/\/[^'"`\s]*webhook/i.test(w) || !/ENDPOINT\s*=\s*'\/api\/feedback'/.test(w)) {
      flag('HIGH', widget, 0, 'feedback widget bypasses relay', "ENDPOINT must be '/api/feedback'.");
    }
    if (!/name="website"/.test(w)) flag('HIGH', widget, 0, 'feedback honeypot missing', 'Keep the hidden website field.');
  }
  const worker = readFileSync(join(repoRoot, 'src', 'worker.js'), 'utf8');
  if (!/overLimit\(env, `feedback-ip:\$\{ip\}`, 5, 600\)/.test(worker)) {
    flag('HIGH', join(repoRoot, 'src', 'worker.js'), 0, 'feedback relay limit missing', '/api/feedback needs its 5 per 10 min per-IP cap.');
  }
}

// ── Report ────────────────────────────────────────────────────────────────
if (findings.length === 0) {
  console.log(`   scanned ${srcFiles.length} src + ${htmlFiles.length} html files, no security regressions found`);
  process.exit(0);
}
const high = findings.filter(x => x.severity === 'HIGH');
console.error(`   ✗ security scan: ${high.length} HIGH, ${findings.filter(x => x.severity === 'MEDIUM').length} MEDIUM`);
for (const x of findings) console.error(`     [${x.severity}] ${x.file}${x.line ? ':' + x.line : ''}  '${x.rule}' — ${x.detail}`);
if (high.length > 0) process.exit(1);
console.error('   (warnings only — deploy continues)');
process.exit(0);
