// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Promo/help separation and disclosure rules for the in-app nudges.
// The rules:
//   1. App help and promos are separate. Help never occupies a promo slot.
//   2. No Amazon links anywhere in here — Associates needs publicly viewable
//      content and this app is behind a login.
//   3. Paid links are free-tier only, and never in a celebration popup.
//   4. The creator's own products carry NUDGE_OWN ("Built by Porch Pile's creator."), never sponsored/nofollow.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const html = readFileSync('public/app.html', 'utf8');
function grab(startMarker, endMarker) {
  const i = html.indexOf(startMarker);
  const j = html.indexOf(endMarker, i);
  assert.ok(i > -1 && j > i, 'could not slice ' + startMarker);
  return html.slice(i, j + endMarker.length);
}
const src = [
  grab('const TIPS = [', '\n];'),
  grab('const NUDGE_DISC =', '\n];'),
  grab('function isAff(url)', '\n}'),
  grab('function dayIndex(offset)', '\n}'),
  grab('function nudgePool(ctx)', '\n}'),
  grab('function nudgeBody(nudge, actAttr)', '\n}'),
  grab('function appTipCard()', '\n}'),
  grab('function promoCard(ctx)', '\n}'),
  grab('function toolsIUseCard()', '\n}'),
].join('\n');

const S = { user: { pro: false }, tab: 'today' };
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const fn = new Function('S', 'esc', src + '\nreturn { TIPS, NUDGES, NUDGE_DISC, NUDGE_OWN, isAff, nudgePool, nudgeBody, appTipCard, promoCard, toolsIUseCard };');
const M = fn(S, esc);

const labelOf = (out) => {
  const m = out.match(/<div class="tip-disc">([^<]*)<\/div>/);
  return m ? m[1] : null;
};
const TABS = ['pile', 'videos', 'deals', 'income', 'settings', 'coupons'];
let pass = 0; const fail = [];
const t = (name, f) => { try { f(); pass++; } catch (e) { fail.push(name + ': ' + e.message); } };

t('1. TIPS are app help only: no links, nothing to disclose', () => {
  assert.ok(M.TIPS.length >= 4, 'need real help content, got ' + M.TIPS.length);
  for (const tip of M.TIPS) {
    assert.equal(tip.href, undefined, 'a TIP must not carry a link: ' + tip.cta);
    assert.equal(tip.aff, undefined, 'a TIP is never an affiliate: ' + tip.cta);
    assert.equal(labelOf(M.nudgeBody(tip, 'data-act')), null, 'a TIP must render no label: ' + tip.cta);
  }
});

t('2. NUDGES are promos only: every one is a real link', () => {
  assert.ok(M.NUDGES.length >= 10); // public copy: 7 own-product tips + 3 affiliate
  for (const n of M.NUDGES) {
    assert.match(n.href || '', /^https:\/\/\S+$/, 'promo without a link: ' + n.cta);
    assert.ok(n.name, 'promo needs a name for the Tools I use list: ' + n.cta);
  }
});

t('3. no Amazon links anywhere', () => {
  const bad = M.NUDGES.filter(n => /amazon\.|amzn\./i.test(n.href || ''));
  assert.equal(bad.length, 0, JSON.stringify(bad.map(b => b.href)));
});

t('4. Pro sees zero paid links, on every tab', () => {
  S.user.pro = true;
  for (const tab of TABS.concat([undefined])) {
    const pool = M.nudgePool(tab);
    assert.equal(pool.filter(n => n.aff).length, 0, (tab || 'any') + ' leaked a paid link to Pro');
    assert.equal(pool.filter(n => M.isAff(n.href)).length, 0, (tab || 'any') + ' leaked a third-party link to Pro');
    assert.ok(pool.length > 0, (tab || 'any') + ' left Pro with nothing');
  }
  S.user.pro = false;
});

t('5. free tier sees the paid links', () => {
  assert.ok(M.nudgePool().filter(n => n.aff).length >= 1); // the public copy ships one affiliate tip; add your own
});

t('6. tagged promos never leak across tabs; untagged appear everywhere', () => {
  const untagged = M.NUDGES.filter(n => !n.ctx).map(n => n.href);
  for (const tab of TABS) {
    const pool = M.nudgePool(tab);
    assert.equal(pool.filter(n => n.ctx && n.ctx !== tab).length, 0, tab + ' leaked a foreign promo');
    for (const u of untagged) assert.ok(pool.map(n => n.href).includes(u), u + ' missing from ' + tab);
  }
});

t('7. every paid link: sponsored + nofollow and an earning label', () => {
  for (const n of M.NUDGES.filter(x => x.aff)) {
    const out = M.nudgeBody(n, 'data-act');
    assert.match(out, /rel="noopener noreferrer sponsored nofollow"/, n.name + ' bad rel');
    assert.match(labelOf(out) || '', /(commission|account credit)/, n.name + ' label says nothing about earning');
  }
});

t('8. the creator\'s own products: NUDGE_OWN label, never sponsored', () => {
  const own = M.NUDGES.filter(x => !x.aff);
  assert.ok(own.length >= 5, 'expected the creator\'s own products, got ' + own.length);
  for (const n of own) {
    const out = M.nudgeBody(n, 'data-act');
    assert.equal(labelOf(out), M.NUDGE_OWN, n.name + ' wrong label');
    assert.ok(!/sponsored|nofollow/.test(out), n.name + ' wrongly marked sponsored');
    assert.equal(M.isAff(n.href), false, n.href + ' not recognized as an own domain');
  }
});

t('9. the Today card is app help, never a promo, on every day of the year', () => {
  const texts = new Set(M.NUDGES.map(n => n.text));
  for (let d = 0; d < 366; d++) {
    const tip = M.TIPS[d % M.TIPS.length];
    assert.ok(!texts.has(tip.text), 'day ' + d + ' put a promo in the help slot');
  }
  assert.ok(!M.appTipCard().includes('tip-disc'), 'the Today card must carry no disclosure');
});

t('10. every tab with promos renders one, and it is a real promo', () => {
  for (const tab of ['pile', 'videos', 'deals', 'income']) {
    const out = M.promoCard(tab);
    assert.ok(out.includes('promo-card'), tab + ' rendered no promo card');
    assert.ok(out.includes('tip-disc'), tab + ' promo has no label');
    assert.ok(/href="https:\/\//.test(out), tab + ' promo has no link');
  }
});

t('11. promo rotation stays inside the tab, all year', () => {
  for (const tab of ['pile', 'videos', 'deals', 'income']) {
    const pool = M.nudgePool(tab);
    for (let d = 0; d < 366; d++) {
      const n = pool[d % pool.length];
      assert.ok(!n.ctx || n.ctx === tab, tab + ' day ' + d + ' showed a ' + n.ctx + ' promo');
    }
  }
});

// Tools I use lists the AIP tools for EVERYONE, Pro included (this list
// only). Popups and tip cards stay free-tier only; test 13 and nudgePool cover those.
t('12. Tools I use lists every promo for free AND Pro, AIP tools first, paid rows labelled', () => {
  for (const pro of [false, true]) {
    S.user.pro = pro;
    const out = M.toolsIUseCard();
    for (const n of M.NUDGES) assert.ok(out.includes(n.href), n.name + ' missing from Tools I use (pro=' + pro + ')');
    const firstPaid = Math.min(...M.NUDGES.filter(x => x.aff).map(x => out.indexOf(x.href)));
    const firstMine = Math.min(...M.NUDGES.filter(x => !x.aff).map(x => out.indexOf(x.href)));
    assert.ok(firstPaid < firstMine, 'AIP tools must come before the creator\'s own products');
    for (const n of M.NUDGES.filter(x => x.aff)) {
      const i = out.indexOf(n.href);
      assert.ok(out.slice(Math.max(0, i - 200), i + n.href.length + 80).includes('sponsored nofollow'), n.name + ' needs sponsored/nofollow');
    }
  }
  S.user.pro = false;
});
t('12b. promo cards still hide paid links from Pro', () => {
  S.user.pro = true;
  for (const tab of [undefined, 'pile', 'videos', 'deals', 'income', 'settings'])
    assert.equal(M.nudgePool(tab).filter(n => n.aff).length, 0, 'Pro saw a paid promo on ' + tab);
  S.user.pro = false;
});

t('13. celebration pool excludes paid links entirely', () => {
  const celebPool = M.TIPS.concat(M.NUDGES.filter(n => !n.aff));
  assert.equal(celebPool.filter(n => n.href && M.isAff(n.href)).length, 0,
    'a celebration popup must never carry a paid link');
  assert.ok(celebPool.length > M.TIPS.length, 'celebrations should still show the creator\'s own products');
});

t('14. every TIP action has a handler in the app', () => {
  const handled = new Set(['goqueue', 'goincome', 'godeals', 'gopile', 'gosettings']);
  for (const tip of M.TIPS) {
    if (!tip.act) continue;
    assert.ok(handled.has(tip.act), tip.act + ' has no handler');
    assert.ok(html.includes(`act === '${tip.act}'`), tip.act + ' missing from the data-act router');
    assert.ok(html.includes(`a === '${tip.act}'`) || tip.act === 'goincome',
      tip.act + ' missing from the celebration router');
  }
});


t('15. every tab renders its promo in the EMPTY state too, not just when it has data', () => {
  // A brand-new account is the empty state on every tab, and Videos + Income both
  // early-return there. That branch shipped without a promo the first time, so a
  // new user saw nothing. Invariant: on these tabs the promo sits immediately
  // before the floating action button, so every path that ends in a FAB must
  // carry a promoCard. Counting is enough and does not need a JS parser.
  const bodyOf = (name) => {
    const i = html.indexOf('function ' + name + '()');
    assert.ok(i > -1, name + ' not found');
    return html.slice(i, html.indexOf('\n}', i));
  };
  const count = (str, needle) => str.split(needle).length - 1;
  for (const tab of ['tabPile', 'tabVideos', 'tabDeals', 'tabIncome']) {
    const body = bodyOf(tab);
    const promos = count(body, 'promoCard(');
    const fabs = count(body, 'fabHTML(');
    assert.ok(promos >= 1, tab + ' renders no promo at all');
    assert.ok(promos >= fabs,
      tab + ' has ' + fabs + ' render paths but only ' + promos + ' promos, so one path (likely the empty state) shows nothing');
  }
});

console.log(`\n${pass} passed, ${fail.length} failed`);
fail.forEach(f => console.log('  FAIL ' + f));
process.exit(fail.length ? 1 : 0);
