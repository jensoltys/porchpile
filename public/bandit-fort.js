// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Porch Pile: Bandit the raccoon, Box Fort version.
// Each draw(rank 0-8, pal, opts) returns one self-contained SVG string.
// Rank shows on the drawing: Box Fort grows a fort of boxes, Courier upgrades
// his hat and satchel, Wagon's load piles higher.
// opts.ids (default true) adds lid-l, lid-r, mouth, iris-l, iris-r for the live copy.
// Every <defs> id is suffixed per call so several copies never collide.
(function (root) {
  let SEQ = 0;
  const DEF = { primary: '#2F5BEA', second: '#FFC93C', kraft: '#D2A56C', ink: '#1E2433' };
  const F = { hi: '#C3C9D6', mid: '#9AA2B6', lo: '#6C748B', line: '#4B526A', mask: '#2F3445', white: '#F6F7FB', belly: '#E3E6EE', paw: '#3E4456', pink: '#FF8FA3', nose: '#1F2230' };

  const hx = h => { h = h.replace('#', ''); if (h.length === 3) h = h.split('').map(c => c + c).join(''); return [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16)); };
  const mix = (a, b, t) => { const A = hx(a), B = hx(b); return '#' + A.map((v, i) => Math.round(v + (B[i] - v) * t).toString(16).padStart(2, '0')).join(''); };
  const dk = (c, t) => mix(c, '#000000', t), lt = (c, t) => mix(c, '#ffffff', t);

  function ctx(pal, opts) {
    const P = Object.assign({}, DEF, pal || {});
    const o = Object.assign({ ids: true }, opts || {});
    const u = o.u || ('b' + (++SEQ).toString(36));
    const id = n => (o.ids ? ` id="${n}"` : '');
    return { P, o, u, id };
  }

  // Shared defs: fur, muzzle, gold, shine overlays, kraft.
  function defs(c) {
    const { P, u } = c;
    return `<radialGradient id="fur${u}" cx=".38" cy=".3" r=".85"><stop offset="0" stop-color="${F.hi}"/><stop offset=".55" stop-color="${F.mid}"/><stop offset="1" stop-color="${F.lo}"/></radialGradient>
<radialGradient id="bel${u}" cx=".45" cy=".3" r=".8"><stop offset="0" stop-color="#FFFFFF"/><stop offset="1" stop-color="${F.belly}"/></radialGradient>
<radialGradient id="mz${u}" cx=".45" cy=".3" r=".8"><stop offset="0" stop-color="#FFFFFF"/><stop offset="1" stop-color="#DADEE8"/></radialGradient>
<radialGradient id="iris${u}" cx=".5" cy=".35" r=".7"><stop offset="0" stop-color="#5A4E7A"/><stop offset="1" stop-color="#1C1A2C"/></radialGradient>
<linearGradient id="gold${u}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FFE789"/><stop offset=".5" stop-color="#FFC73A"/><stop offset="1" stop-color="#E39A12"/></linearGradient>
<linearGradient id="shine${u}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".45"/><stop offset=".5" stop-color="#fff" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity=".14"/></linearGradient>
<linearGradient id="kr${u}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${lt(P.kraft, .18)}"/><stop offset="1" stop-color="${dk(P.kraft, .12)}"/></linearGradient>
<radialGradient id="halo${u}" cx=".5" cy=".5" r=".5"><stop offset="0" stop-color="${P.second}" stop-opacity=".55"/><stop offset="1" stop-color="${P.second}" stop-opacity="0"/></radialGradient>
<clipPath id="ecl${u}"><circle cx="34" cy="44" r="13.5"/></clipPath>
<clipPath id="ecr${u}"><circle cx="70" cy="44" r="13.5"/></clipPath>`;
  }

  // Raccoon head in a 104 x 92 local space (ears ~y2, chin ~y90). Eyes at (34,44) and (70,44), r 13.
  function head(c, x, y, s) {
    const { u, id } = c;
    const eye = (ex, side) => `<circle cx="${ex}" cy="44" r="13.5" fill="#fff"/>
<circle cx="${ex + 1}" cy="45.5" r="10" fill="url(#iris${u})"${id('iris-' + side)}/>
<circle cx="${ex + 1}" cy="46" r="5" fill="#0F0E18"/>
<circle cx="${ex + 4.6}" cy="40.6" r="4" fill="#fff"/>
<circle cx="${ex - 3}" cy="50" r="1.9" fill="#fff" opacity=".9"/>
<rect${id('lid-' + side)} x="${ex - 14}" y="30.5" width="28" height="0" fill="#454B60" clip-path="url(#ec${side}${u})"/>`;
    return `<g transform="translate(${x} ${y}) scale(${s})">
<path d="M10 40 Q0 8 20 2 Q34 2 40 22 Z" fill="${F.lo}" stroke="${F.line}" stroke-width="2" stroke-linejoin="round"/>
<path d="M14 34 Q8 12 21 8 Q30 9 33 22 Z" fill="${F.mask}"/>
<path d="M94 40 Q104 8 84 2 Q70 2 64 22 Z" fill="${F.lo}" stroke="${F.line}" stroke-width="2" stroke-linejoin="round"/>
<path d="M90 34 Q96 12 83 8 Q74 9 71 22 Z" fill="${F.mask}"/>
<path d="M52 13 C80 13 97 28 99 48 Q104 56 108 62 Q101 63 97 66 C90 82 72 90 52 90 C32 90 14 82 7 66 Q3 63 -4 62 Q0 56 5 48 C7 28 24 13 52 13 Z" fill="url(#fur${u})" stroke="${F.line}" stroke-width="2.2" stroke-linejoin="round"/>
<ellipse cx="38" cy="26" rx="13" ry="7" fill="${F.white}" opacity=".95" transform="rotate(-8 38 26)"/>
<ellipse cx="66" cy="26" rx="13" ry="7" fill="${F.white}" opacity=".95" transform="rotate(8 66 26)"/>
<path d="M52 13 Q56 24 55 36 L49 36 Q48 24 52 13 Z" fill="${F.lo}"/>
<path d="M3 46 C8 32 24 28 38 32 Q46 34 52 40 Q58 34 66 32 C80 28 96 32 101 46 C98 58 86 62 74 60 Q62 58 56 62 L52 64 L48 62 Q42 58 30 60 C18 62 6 58 3 46 Z" fill="${F.mask}"/>
<ellipse cx="52" cy="70" rx="19" ry="14" fill="url(#mz${u})"/>
${eye(34, 'l')}${eye(70, 'r')}
<path d="M44.5 62 Q52 57.5 59.5 62 Q58 68.5 52 69.5 Q46 68.5 44.5 62 Z" fill="${F.nose}"/>
<ellipse cx="49.5" cy="61.6" rx="2.6" ry="1.3" fill="#fff" opacity=".55"/>
<path${id('mouth')} d="M45 74 Q48.5 78 52 74 Q55.5 78 59 74" fill="none" stroke="${F.mask}" stroke-width="2.2" stroke-linecap="round"/>
<ellipse cx="22" cy="69" rx="6.5" ry="3.8" fill="${F.pink}" opacity=".6"/>
<ellipse cx="82" cy="69" rx="6.5" ry="3.8" fill="${F.pink}" opacity=".6"/>
<ellipse cx="34" cy="20" rx="8" ry="3.5" fill="#fff" opacity=".35" transform="rotate(-15 34 20)"/>
</g>`;
  }

  // Ringed tail along a path: light base, dark dashes make the rings, dark tip.
  function tail(c, d, tipX, tipY, w) {
    w = w || 17;
    return `<path d="${d}" fill="none" stroke="${F.line}" stroke-width="${w + 4}" stroke-linecap="round"/>
<path d="${d}" fill="none" stroke="${F.hi}" stroke-width="${w}" stroke-linecap="round"/>
<path d="${d}" fill="none" stroke="${F.mask}" stroke-width="${w}" stroke-dasharray="7 7" stroke-dashoffset="3"/>
<circle cx="${tipX}" cy="${tipY}" r="${w / 2}" fill="${F.mask}"/>
<path d="${d}" fill="none" stroke="#fff" stroke-width="3" stroke-opacity=".25" stroke-linecap="round" transform="translate(-3 -2)"/>`;
  }

  const paw = (x, y, r) => `<ellipse cx="${x}" cy="${y}" rx="${r * 1.2}" ry="${r}" fill="${F.paw}" stroke="${F.line}" stroke-width="1.2"/>
<path d="M${x - r * .6} ${y - r * .55} v${r * .45} M${x} ${y - r * .75} v${r * .5} M${x + r * .6} ${y - r * .55} v${r * .45}" stroke="#6B7188" stroke-width="1.1" stroke-linecap="round"/>`;

  const sparkle = (x, y, r, col) => `<path d="M${x} ${y - r} Q${x + r * .18} ${y - r * .18} ${x + r} ${y} Q${x + r * .18} ${y + r * .18} ${x} ${y + r} Q${x - r * .18} ${y + r * .18} ${x - r} ${y} Q${x - r * .18} ${y - r * .18} ${x} ${y - r} Z" fill="${col}"/>`;

  function crown(c, x, y, w, jewels) {
    const { P, u } = c, h = w * .62;
    return `<g transform="translate(${x - w / 2} ${y - h})"><path d="M0 ${h} L${w * .02} ${h * .28} L${w * .27} ${h * .58} L${w * .5} 0 L${w * .73} ${h * .58} L${w * .98} ${h * .28} L${w} ${h} Z" fill="url(#gold${u})" stroke="#C98410" stroke-width="1.6" stroke-linejoin="round"/>
<rect x="0" y="${h * .8}" width="${w}" height="${h * .2}" fill="#E8A21C"/>
<circle cx="${w * .5}" cy="0" r="${w * .06}" fill="#FFF3C4"/><circle cx="${w * .02}" cy="${h * .28}" r="${w * .05}" fill="#FFF3C4"/><circle cx="${w * .98}" cy="${h * .28}" r="${w * .05}" fill="#FFF3C4"/>
${jewels ? `<circle cx="${w * .5}" cy="${h * .66}" r="${w * .08}" fill="${P.primary}" stroke="#fff" stroke-width=".8"/><circle cx="${w * .22}" cy="${h * .78}" r="${w * .05}" fill="#E0457B"/><circle cx="${w * .78}" cy="${h * .78}" r="${w * .05}" fill="#E0457B"/>` : ''}
<path d="M${w * .12} ${h * .5} L${w * .2} ${h * .72}" stroke="#fff" stroke-width="1.4" stroke-opacity=".6" stroke-linecap="round"/></g>`;
  }

  // Bandana tied around the neck. cx/y is the knot line, w the width.
  const bandana = (c, cx, y, w) => {
    const { P, u } = c;
    return `<path d="M${cx - w / 2} ${y - 3} Q${cx} ${y + 6} ${cx + w / 2} ${y - 3} L${cx + w / 2 - 3} ${y + 4} Q${cx} ${y + 13} ${cx - w / 2 + 3} ${y + 4} Z" fill="${P.primary}" stroke="${dk(P.primary, .3)}" stroke-width="1.2"/>
<path d="M${cx - 9} ${y + 6} L${cx} ${y + 20} L${cx + 9} ${y + 6} Z" fill="${P.primary}" stroke="${dk(P.primary, .3)}" stroke-width="1.2" stroke-linejoin="round"/>
<circle cx="${cx - 2}" cy="${y + 10}" r="1.3" fill="#fff" opacity=".8"/><circle cx="${cx + 3}" cy="${y + 13}" r="1.1" fill="#fff" opacity=".8"/><circle cx="${cx - w / 4}" cy="${y + 4}" r="1.2" fill="#fff" opacity=".8"/><circle cx="${cx + w / 4}" cy="${y + 4}" r="1.2" fill="#fff" opacity=".8"/>`;
  };

  // A parcel: front face, tape, optional label / fragile arrow / gold.
  function parcel(c, x, y, w, h, o) {
    const { P, u } = c;
    o = o || {};
    const base = o.gold ? `url(#gold${u})` : `url(#kr${u})`;
    const edge = o.gold ? '#C98410' : dk(P.kraft, .32);
    const tape = o.gold ? '#FFF1B8' : o.goldTape ? `url(#gold${u})` : lt(P.kraft, .45);
    const rot = o.rot ? ` transform="rotate(${o.rot} ${x + w / 2} ${y + h / 2})"` : '';
    let s = `<g${rot}><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="3" fill="${base}" stroke="${edge}" stroke-width="1.5"/>
<rect x="${x}" y="${y}" width="${w}" height="${Math.min(5, h * .18)}" rx="2" fill="${edge}" opacity=".35"/>`;
    if (o.tape !== false) s += `<rect x="${x + w / 2 - w * .09}" y="${y}" width="${w * .18}" height="${h}" fill="${tape}" opacity="${o.goldTape ? 1 : .85}"/>`;
    if (o.label) s += `<rect x="${x + w * .08}" y="${y + h * .3}" width="${w * .26}" height="${h * .26}" rx="1.5" fill="#FFFDF7" stroke="${edge}" stroke-width=".6"/><path d="M${x + w * .11} ${y + h * .38} h${w * .18} M${x + w * .11} ${y + h * .47} h${w * .12}" stroke="${P.ink}" stroke-width="1" opacity=".5"/>`;
    if (o.fragile) { const fx = x + w * .78, fy = y + h * .62; s += `<path d="M${fx} ${fy + 8} v-10 M${fx - 4} ${fy - 1} l4 -5 l4 5" stroke="#D9463B" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/><path d="M${fx + 5} ${fy + 8} v-10 M${fx + 1} ${fy - 1} l4 -5 l4 5" stroke="#D9463B" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" transform="translate(${-w * .0} 0)" opacity="0"/>`; }
    if (o.ribbon) s += `<rect x="${x}" y="${y + h / 2 - 2.5}" width="${w}" height="5" fill="${P.primary}"/><rect x="${x + w / 2 - 2.5}" y="${y}" width="5" height="${h}" fill="${P.primary}"/><path d="M${x + w / 2} ${y} q-10 -9 -12 -2 q2 5 12 2 q10 -9 12 -2 q-2 5 -12 2 Z" fill="${P.primary}" stroke="${dk(P.primary, .3)}" stroke-width="1"/>`;
    if (o.star) s += sparkle(x + w / 2, y + h / 2, Math.min(w, h) * .26, '#FFF6D0');
    s += `<rect x="${x + 2}" y="${y + 2}" width="${w - 4}" height="${h * .35}" rx="2" fill="#fff" opacity=".12"/></g>`;
    return s;
  }

  const pennant = (c, x, y, len, col, flip) => {
    const { P } = c, d = flip ? -1 : 1;
    return `<path d="M${x} ${y + len} V${y}" stroke="${P.ink}" stroke-width="2.4" stroke-linecap="round"/>
<path d="M${x} ${y + 1} L${x + d * 24} ${y + 7} L${x} ${y + 14} Z" fill="${col}" stroke="${dk(col, .25)}" stroke-width="1.2" stroke-linejoin="round"/>
<path d="M${x + d * 3} ${y + 5} L${x + d * 14} ${y + 7.5}" stroke="#fff" stroke-width="1.6" stroke-opacity=".6" stroke-linecap="round"/>
<circle cx="${x}" cy="${y - 1}" r="2.6" fill="${P.second}" stroke="${dk(P.second, .3)}" stroke-width=".8"/>`;
  };

  const wrap = (c, vb, body, label) => `<svg width="100%" height="100%" viewBox="${vb}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${label}"><defs>${defs(c)}</defs>${body}</svg>`;

  // ---------- 1. BOX FORT ----------
  function fort(rank, pal, opts) {
    const c = ctx(pal, opts), { P, u } = c;
    const r = Math.max(0, Math.min(8, rank | 0));
    const gold = r >= 8;
    let s = '';
    s += `<ellipse cx="85" cy="178" rx="${r >= 4 ? 80 : r >= 3 ? 66 : 52}" ry="5.5" fill="${P.ink}" opacity=".12"/>`;
    if (gold) s += `<circle cx="85" cy="92" r="84" fill="url(#halo${u})"/>`;
    // back stacks (behind everything)
    const sideL = r >= 3, sideR = r >= 4, stackL = r >= 5, stackR = r >= 6, merlons = r >= 6;
    if (stackL) s += parcel(c, 6, 100, 36, 38, { label: r >= 6, gold: gold && false });
    if (stackR) s += parcel(c, 128, 100, 36, 38, { fragile: true });
    if (merlons) {
      s += parcel(c, 6, 87, 13, 14, { tape: false }) + parcel(c, 29, 87, 13, 14, { tape: false });
      s += parcel(c, 128, 87, 13, 14, { tape: false }) + parcel(c, 151, 87, 13, 14, { tape: false });
    }
    if (stackL) s += pennant(c, merlons ? 24 : 24, merlons ? 58 : 70, merlons ? 30 : 30, gold ? P.primary : P.second, true);
    if (stackR) s += pennant(c, 146, 58, 30, gold ? P.primary : P.second, false);
    if (sideL) s += parcel(c, 2, 136, 44, 40, { label: true });
    if (sideR) s += parcel(c, 124, 136, 44, 40, { fragile: true });
    // tail pokes over the right rim
    s += tail(c, 'M122 126 C144 124 154 110 150 90', 150, 90, 15);
    // box interior back wall
    s += `<path d="M40 112 L46 102 L124 102 L130 112 Z" fill="${dk(P.kraft, .45)}"/>`;
    // Bandit's head
    s += head(c, 37, 26, 0.92);
    if (r >= 2) s += bandana(c, 85, 102, 50);
    if (r >= 7) s += crown(c, 85, 32, gold ? 40 : 32, gold);
    // main box front
    s += parcel(c, 38, 112, 94, 64, { label: r >= 1, fragile: r >= 2, tape: r >= 1, goldTape: gold });
    if (r === 0) s += `<path d="M48 126 l10 6 M116 160 l8 -5" stroke="${dk(P.kraft, .35)}" stroke-width="1.4" stroke-linecap="round"/>`;
    if (gold) s += `<circle cx="85" cy="150" r="10" fill="url(#gold${u})" stroke="#C98410" stroke-width="1.4"/>` + sparkle(85, 150, 6, '#fff');
    // flaps
    const fl = dk(P.kraft, .08);
    s += `<path d="M38 112 L20 ${r >= 1 ? 100 : 104} L24 ${r >= 1 ? 94 : 98} L46 104 Z" fill="${fl}" stroke="${dk(P.kraft, .32)}" stroke-width="1.4" stroke-linejoin="round"/>`;
    s += `<path d="M132 112 L150 ${r >= 1 ? 100 : 104} L146 ${r >= 1 ? 94 : 98} L124 104 Z" fill="${fl}" stroke="${dk(P.kraft, .32)}" stroke-width="1.4" stroke-linejoin="round"/>`;
    // paws over the rim
    s += paw(62, 113, 7) + paw(108, 113, 7);
    if (gold) s += sparkle(20, 40, 6, P.second) + sparkle(152, 34, 5, P.second) + sparkle(160, 128, 4, '#fff');
    return wrap(c, '0 0 170 185', s, 'Bandit the raccoon in a box fort');
  }

  // Logo mark: Bandit's face on a rounded tile (favicon, headers, og).
  function mark(pal, opts) {
    const c = ctx(pal, Object.assign({ ids: false }, opts));
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 104 104" aria-hidden="true"><defs>${defs(c)}</defs><rect width="104" height="104" rx="24" fill="${c.P.primary}"/>${head(c, 7, 10, 0.86)}</svg>`;
  }

  root.PP_BANDIT = { draw: fort, mark: mark };
})(typeof window !== 'undefined' ? window : globalThis);
