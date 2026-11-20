// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Porch Pile authors. See LICENSE.
// Porch Pile feedback widget — login-only, posts to the Worker's /api/feedback
// relay, which rate-limits and forwards to FEEDBACK_WEBHOOK. Styled to the
// Porch Pile palette. Sits bottom-LEFT because
// the app's + FAB owns bottom-right.
(function () {
  var ENDPOINT = '/api/feedback';

  // Logged-in users only. /api/me returns 200 with {user:null} when logged
  // out, so gate on the body, not the status. feedback:false = no webhook set
  // on this server, so there's nowhere to send it: no button.
  fetch('/api/me', { credentials: 'include' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) { if (d && d.user && d.feedback !== false) initWidget(); })
    .catch(function () { /* logged out or offline - no widget */ });

  function initWidget() {
  var css = [
    '.fbw-btn{position:fixed;bottom:22px;left:22px;z-index:250;background:linear-gradient(135deg,#C2255C,#A01D4B);color:#fff;border:0;border-radius:999px;padding:10px 18px;min-height:40px;font:600 13px Fredoka,system-ui,sans-serif;cursor:pointer;box-shadow:0 4px 14px rgba(194,37,92,.35)}',
    '.fbw-btn:hover{transform:translateY(-1px)}',
    '@media (max-width:760px){.fbw-btn{bottom:16px;left:16px;padding:9px 14px}}',
    '.fbw-overlay{position:fixed;inset:0;background:rgba(29,42,34,.42);backdrop-filter:blur(3px);z-index:460;display:none;align-items:center;justify-content:center;padding:16px}',
    '.fbw-overlay.fbw-open{display:flex}',
    '.fbw-modal{background:#FFFFFF;border:1px solid rgba(255,255,255,.85);border-radius:20px;padding:24px;width:100%;max-width:460px;font:14px Nunito,system-ui,sans-serif;color:#1D2A22;box-shadow:0 20px 60px rgba(29,42,34,.35);box-sizing:border-box;max-height:90vh;overflow-y:auto}',
    '.fbw-modal h3{margin:0 0 6px;font:600 18px Fredoka,system-ui,sans-serif;color:#1D2A22}',
    '.fbw-modal p.fbw-lede{margin:0 0 16px;color:#526357;font-size:13px;font-weight:600;line-height:1.4}',
    '.fbw-row{margin-bottom:14px}',
    '.fbw-row label.fbw-label{display:block;font:500 11px Fredoka,system-ui,sans-serif;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;color:#526357}',
    '.fbw-types{display:flex;gap:8px}',
    '.fbw-types label{flex:1;padding:9px;text-align:center;border:1.5px solid rgba(29,42,34,.13);border-radius:999px;cursor:pointer;font:500 13px Fredoka,system-ui,sans-serif;user-select:none;color:#526357}',
    '.fbw-types input{position:absolute;opacity:0;pointer-events:none}',
    '.fbw-types label.fbw-on{border-color:#C2255C;background:#C2255C;color:#fff}',
    '.fbw-modal textarea,.fbw-modal input[type=email]{width:100%;padding:10px 12px;border:1.5px solid rgba(29,42,34,.13);border-radius:12px;font:inherit;box-sizing:border-box;color:#1D2A22;background:#fff}',
    '.fbw-modal textarea{resize:vertical;min-height:90px}',
    '.fbw-modal textarea:focus,.fbw-modal input[type=email]:focus{outline:0;border-color:#C2255C;box-shadow:0 0 0 3px rgba(194,37,92,.15)}',
    '.fbw-modal small{color:#526357;display:block;margin-top:4px;font-size:11px;font-weight:700}',
    '.fbw-actions{display:flex;gap:8px;margin-top:18px}',
    '.fbw-actions button{flex:1;padding:12px;border:0;border-radius:12px;font:600 13px Fredoka,system-ui,sans-serif;cursor:pointer}',
    '.fbw-cancel{background:rgba(29,42,34,.07);color:#1D2A22}',
    '.fbw-submit{background:linear-gradient(135deg,#C2255C,#A01D4B);color:#fff;box-shadow:0 4px 14px rgba(194,37,92,.3)}',
    '.fbw-submit:disabled{opacity:.5;cursor:default}',
    '.fbw-status{margin-top:12px;font-size:13px;font-weight:600;padding:10px;border-radius:11px;display:none}',
    '.fbw-status.fbw-ok{background:rgba(47,125,69,.15);color:#2F7D45;display:block}',
    '.fbw-status.fbw-err{background:rgba(180,35,24,.13);color:#B42318;display:block}'
  ].join('');
  var s = document.createElement('style');
  s.textContent = css;
  document.head.appendChild(s);

  var btn = document.createElement('button');
  btn.className = 'fbw-btn';
  btn.type = 'button';
  btn.textContent = 'Feedback';
  btn.setAttribute('aria-label', 'Report a bug or suggest a feature');
  document.body.appendChild(btn);

  var overlay = document.createElement('div');
  overlay.className = 'fbw-overlay';
  overlay.innerHTML =
    '<div class="fbw-modal" role="dialog" aria-label="Feedback form">' +
      '<h3>Report a bug or suggest a feature</h3>' +
      '<p class="fbw-lede">Your feedback shapes this app. Email is optional and only used if you want a follow-up. Never added to a mailing list.</p>' +
      '<form class="fbw-form" novalidate>' +
        '<div class="fbw-row">' +
          '<label class="fbw-label">Type</label>' +
          '<div class="fbw-types">' +
            '<label class="fbw-on"><input type="radio" name="type" value="bug" checked>Bug</label>' +
            '<label><input type="radio" name="type" value="feature">Feature idea</label>' +
            '<label><input type="radio" name="type" value="other">Other</label>' +
          '</div>' +
        '</div>' +
        '<div class="fbw-row">' +
          '<label class="fbw-label" for="fbw-msg">What\'s on your mind?</label>' +
          '<textarea id="fbw-msg" name="message" required maxlength="2000" placeholder="Describe what you saw, what you expected, or what you\'d like to see..."></textarea>' +
          '<small><span class="fbw-count">0</span> / 2000</small>' +
        '</div>' +
        '<div class="fbw-row">' +
          '<label class="fbw-label" for="fbw-email">Email (optional)</label>' +
          '<input type="email" id="fbw-email" name="email" maxlength="200" placeholder="you@example.com">' +
        '</div>' +
        '<div class="fbw-hp" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">' +
          '<label>Leave this empty<input type="text" name="website" tabindex="-1" autocomplete="off"></label>' +
        '</div>' +
        '<div class="fbw-actions">' +
          '<button type="button" class="fbw-cancel">Cancel</button>' +
          '<button type="submit" class="fbw-submit">Send</button>' +
        '</div>' +
        '<div class="fbw-status" role="status" aria-live="polite"></div>' +
      '</form>' +
    '</div>';
  document.body.appendChild(overlay);

  var form = overlay.querySelector('.fbw-form');
  var msgEl = overlay.querySelector('#fbw-msg');
  var countEl = overlay.querySelector('.fbw-count');
  var statusEl = overlay.querySelector('.fbw-status');
  var submitEl = overlay.querySelector('.fbw-submit');

  msgEl.addEventListener('input', function () {
    countEl.textContent = String(msgEl.value.length);
  });

  Array.prototype.forEach.call(overlay.querySelectorAll('.fbw-types input'), function (input) {
    input.addEventListener('change', function () {
      Array.prototype.forEach.call(overlay.querySelectorAll('.fbw-types label'), function (l) {
        l.classList.toggle('fbw-on', l.contains(input) && input.checked);
      });
    });
  });

  // The form is an overlay, so it gets one history entry: Back closes it and
  // leaves the user on the app instead of leaving the site (back-button
  // rule). The app's own view state rides along so a refresh still lands on
  // the same tab.
  btn.addEventListener('click', function () {
    try { history.pushState(Object.assign({}, history.state || {}, { fbw: 1 }), ''); } catch (e) { /* ignore */ }
    overlay.classList.add('fbw-open');
    setTimeout(function () { msgEl.focus(); }, 50);
  });
  window.addEventListener('popstate', function () {
    if (overlay.classList.contains('fbw-open') && !(history.state && history.state.fbw)) close(true);
  });
  overlay.querySelector('.fbw-cancel').addEventListener('click', function () { close(); });
  overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && overlay.classList.contains('fbw-open')) close();
  });

  // A user-initiated close routes through history.back() so the entry pushed
  // on open is consumed; popstate then calls close(true) to do the DOM work.
  function close(fromHistory) {
    if (!fromHistory && history.state && history.state.fbw) { history.back(); return; }
    overlay.classList.remove('fbw-open');
    form.reset();
    statusEl.className = 'fbw-status';
    statusEl.textContent = '';
    countEl.textContent = '0';
    submitEl.disabled = false;
    Array.prototype.forEach.call(overlay.querySelectorAll('.fbw-types label'), function (l, i) {
      l.classList.toggle('fbw-on', i === 0);
    });
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    var message = msgEl.value.trim();
    if (message.length < 3) {
      statusEl.className = 'fbw-status fbw-err';
      statusEl.textContent = 'Please write a bit more so I know what you mean.';
      return;
    }
    submitEl.disabled = true;
    statusEl.className = 'fbw-status';
    statusEl.textContent = '';
    var data = new FormData(form);
    var payload = {
      app: 'Porch Pile',
      type: String(data.get('type') || 'other'),
      message: message.slice(0, 2000),
      email: String(data.get('email') || '').trim().slice(0, 200),
      url: location.href.slice(0, 500),
      website: String(data.get('website') || '')
    };
    try {
      var r = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload)
      });
      if (r.status === 429) {
        statusEl.className = 'fbw-status fbw-err';
        statusEl.textContent = 'That\'s a lot of messages in a row. Try again in a few minutes.';
        submitEl.disabled = false;
        return;
      }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      statusEl.className = 'fbw-status fbw-ok';
      statusEl.textContent = 'Got it. Thank you.';
      setTimeout(function () { close(); }, 2200);
    } catch (err) {
      statusEl.className = 'fbw-status fbw-err';
      statusEl.textContent = 'Could not send. Try again, or email support@example.com.';
      submitEl.disabled = false;
    }
  });
  }
})();
