// Meridian · Portal UI helpers
(() => {
  'use strict';

  // --- CSRF double-submit: wrap fetch so every unsafe call echoes the
  // meridian_csrf cookie into the X-CSRF-Token header. The CsrfMiddleware
  // rejects unsafe calls whose header doesn't match the cookie.
  function readCookie(name) {
    const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[.$?*|{}()[\]\\/+^]/g, '\\$&') + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : '';
  }
  const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  const _origFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    init = init || {};
    const method = ((init.method || (typeof input === 'object' && input.method) || 'GET') + '').toUpperCase();
    if (UNSAFE.has(method)) {
      const token = readCookie('meridian_csrf');
      if (token) {
        const headers = new Headers(init.headers || {});
        if (!headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', token);
        init.headers = headers;
      }
    }
    const p = _origFetch(input, init);
    // Reset any submit buttons currently stuck in their "... Running"
    // state whenever a fetch resolves (success or failure). Paired with
    // the generic "disable on submit" wiring in dns_tools.html, this
    // means every tool's Run button automatically re-enables as soon as
    // the backing fetch comes back, without needing to patch each
    // inline submit handler individually.
    p.finally(() => {
      try {
        document.querySelectorAll('form button[type="submit"]').forEach(btn => {
          if (btn.disabled && btn.dataset.origText !== undefined) {
            btn.disabled = false;
            btn.textContent = btn.dataset.origText;
          }
        });
      } catch(_){}
    });
    return p.then(r => {
      // 401 => session gone; redirect to login.
      try {
        if (r && r.status === 401 && !location.pathname.startsWith('/ui/login')) {
          const next = location.pathname + location.search + location.hash;
          location.href = '/ui/login?next=' + encodeURIComponent(next);
        }
      } catch(_){}
      return r;
    });
  };
  // ----- Idle countdown / auto-logout -------------------------------
  // The topbar renders an `#idle-countdown` chip with a data-idle-min
  // attribute. Reset on any user activity; when it hits 0, redirect to
  // login. This is client-side only and is the complement to the 401
  // redirect above (the server will also expire the session on its end).
  function wireIdleTimer() {
    const el = document.getElementById('idle-countdown');
    if (!el) return;
    const minutes = Number(el.dataset.idleMin || 0);
    if (!minutes || minutes <= 0) return;
    const totalMs = minutes * 60 * 1000;
    const valEl = document.getElementById('idle-countdown-val');
    let last = Date.now();
    // Only meaningful interactions keep a session alive -- clicks (links,
    // tabs, buttons, any real control press) and keydown (typing, tab
    // navigation). Mousemove / scroll / touchstart do NOT reset the
    // timer because server-side the session is only extended by actual
    // API calls that the user triggers, and passive viewing behaviour
    // isn't server-side activity.
    const bump = () => { last = Date.now(); };
    ['click','keydown','submit'].forEach(ev =>
      window.addEventListener(ev, bump, {capture:true, passive:true}));
    function tick() {
      const remaining = totalMs - (Date.now() - last);
      if (remaining <= 0) {
        // Client-side nudge; server cookie may already be stale. Include
        // ?next so the user lands back here after re-login.
        const next = location.pathname + location.search + location.hash;
        location.href = '/ui/login?next=' + encodeURIComponent(next);
        return;
      }
      // Ceil so that just-resumed activity shows "30:00" (the admin-
      // configured max) instead of "29:59" due to first-tick drift.
      const totalSeconds = Math.ceil(remaining / 1000);
      const mins = Math.floor(totalSeconds / 60);
      const secs = totalSeconds % 60;
      const txt = (mins < 10 ? '0' : '') + mins + ':' + (secs < 10 ? '0' : '') + secs;
      if (valEl) valEl.textContent = txt;
      // Recolour the pill as the time approaches expiry.
      if (remaining < 60 * 1000) {
        el.style.color = 'var(--danger, #e06060)';
        el.style.borderColor = 'var(--danger, #e06060)';
      } else if (remaining < 5 * 60 * 1000) {
        el.style.color = 'var(--warn, #eab308)';
        el.style.borderColor = 'var(--warn, #eab308)';
      }
    }
    tick();
    setInterval(tick, 1000);
  }

  // For <form method="post"> submissions, inject a hidden field as well.
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    if ((form.method || 'get').toLowerCase() === 'get') return;
    if (form.querySelector('input[name="_csrf"]')) return;
    const token = readCookie('meridian_csrf');
    if (!token) return;
    const h = document.createElement('input');
    h.type = 'hidden'; h.name = '_csrf'; h.value = token;
    form.appendChild(h);
  }, true);

  // --- MFA auto-advance ---
  function wireMfa() {
    const inputs = document.querySelectorAll('.mfa-in');
    inputs.forEach((el, i) => {
      el.addEventListener('input', () => {
        if (el.value && i < inputs.length - 1) inputs[i + 1].focus();
      });
      el.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !el.value && i > 0) inputs[i - 1].focus();
      });
    });
    const form = document.querySelector('[data-form="login"]');
    if (form) {
      form.addEventListener('submit', () => {
        const code = [...inputs].map(i => i.value).join('');
        const hidden = form.querySelector('input[name="mfa_code"]');
        if (hidden) hidden.value = code;
      });
    }
  }

  // --- Content-level tabs (data-tabs group) ---
  // Tabs are deep-linkable: /ui/dns-tools#propagation activates the
  // Propagation tab on load; clicking a tab updates the URL hash so the
  // current view is bookmark/shareable/refresh-safe. `?wizard_key=…` style
  // query strings from wizard deeplinks are also honored — we look there
  // first, then the hash.
  function wireTabs() {
    document.querySelectorAll('[data-tabs]').forEach(group => {
      const tabs   = [...group.querySelectorAll('[data-tab]')];
      const panels = [...document.querySelectorAll(`[data-panel][data-group="${group.dataset.tabs}"]`)];
      if (!tabs.length) return;

      const activate = (key, {scroll = false, updateHash = true} = {}) => {
        const target = tabs.find(t => t.dataset.tab === key);
        if (!target) return false;
        tabs.forEach(x => x.classList.toggle('active', x === target));
        panels.forEach(p => p.classList.toggle('hidden', p.dataset.panel !== key));
        if (updateHash) {
          // Use replaceState so tab switches don't spam the browser history
          // (Back button still goes to the previous *page*, not the previous tab).
          try {
            history.replaceState(null, '', '#' + key);
          } catch (_) { /* file:// etc. */ }
        }
        if (scroll) target.scrollIntoView({block: 'nearest', inline: 'nearest'});
        return true;
      };

      tabs.forEach(t => t.addEventListener('click', (e) => {
        // Let the label behave like a link to its own hash — enables "open in
        // new tab" / "copy link address" on every tab button.
        activate(t.dataset.tab);
      }));

      // Honor an incoming hash / query string on first load.
      const fromQuery = new URLSearchParams(location.search).get('tab');
      const fromHash  = (location.hash || '').replace(/^#/, '');
      const initial   = fromQuery || fromHash;
      if (initial) {
        activate(initial, {updateHash: false});
      }

      // Also react to hash changes while the user is on the page (manual
      // address-bar edits, Back/Forward from another in-page link).
      window.addEventListener('hashchange', () => {
        const h = (location.hash || '').replace(/^#/, '');
        if (h) activate(h, {updateHash: false});
      });
    });
  }

  // --- Chip toggles (dig flags) ---
  function wireChips() {
    document.querySelectorAll('[data-chip-group]').forEach(group => {
      group.querySelectorAll('.chip[data-value]').forEach(chip => {
        chip.addEventListener('click', () => {
          chip.classList.toggle('active');
          const hidden = document.querySelector(`[data-chip-output="${group.dataset.chipGroup}"]`);
          if (hidden) {
            const active = [...group.querySelectorAll('.chip.active[data-value]')].map(c => c.dataset.value);
            hidden.value = JSON.stringify(active);
          }
        });
      });
    });
  }

  // --- Tool form submit (AJAX to /api/v1/...) ---
  async function submitTool(form) {
    const endpoint = form.dataset.endpoint;
    const outEl = document.querySelector(form.dataset.output);
    const btn = form.querySelector('[data-submit]');
    // Only capture origText the FIRST time we touch the button. A second
    // caller (e.g. the page-level generic "Running" binding) may have
    // already changed btn.textContent -- clobbering that would lose the
    // real label and leave the button stuck at "... Running" forever.
    if (btn) {
      btn.disabled = true;
      if (!btn.dataset.origText) btn.dataset.origText = btn.textContent;
      btn.textContent = 'Running…';
    }
    outEl.classList.remove('empty');
    outEl.textContent = '';

    const payload = {};
    [...form.querySelectorAll('[name]')].forEach(el => {
      if (el.type === 'hidden' && el.name.endsWith('_json')) {
        try { payload[el.name.replace('_json','')] = JSON.parse(el.value || '[]'); }
        catch { payload[el.name.replace('_json','')] = []; }
      } else if (el.type === 'number') {
        payload[el.name] = el.value === '' ? null : Number(el.value);
      } else if (el.type === 'checkbox') {
        payload[el.name] = el.checked;
      } else if (el.value !== '') {
        payload[el.name] = el.value;
      }
    });

    try {
      const r = await fetch(endpoint, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const msg = typeof data.error === 'string' ? data.error
                  : typeof data.detail === 'string' ? data.detail
                  : Array.isArray(data.detail)
                      ? data.detail.map(e => (e.loc ? e.loc.join('.') + ': ' : '') + (e.msg || JSON.stringify(e))).join('; ')
                  : r.statusText;
        outEl.textContent = `HTTP ${r.status}: ${msg}`;
        return;
      }
      const rendered = renderResult(endpoint, data);
      if (rendered && typeof rendered === 'object' && rendered.html) {
        outEl.innerHTML = rendered.html;
      } else {
        outEl.textContent = rendered;
      }
    } catch (e) {
      outEl.textContent = `Network error: ${e.message}`;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = btn.dataset.origText || '▸ Run'; }
    }
  }

  function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function renderResult(endpoint, data) {
    if (endpoint.includes('/dns/propagation')) {
      const sorted = [...(data.rows || [])].sort((a, b) =>
        a.provider.localeCompare(b.provider) || a.resolver_ip.localeCompare(b.resolver_ip)
      );
      const rows = sorted.map(r => `
        <tr>
          <td style="padding:4px 8px;">${escHtml(r.provider)}</td>
          <td class="mono" style="padding:4px 8px;">${escHtml(r.resolver_ip)}</td>
          <td class="mono" style="padding:4px 8px;">${r.ok ? escHtml(r.answer || '—') : `<span style="color:var(--danger,#e06060);">${escHtml(r.error || 'error')}</span>`}</td>
          <td class="mono" style="padding:4px 8px;text-align:right;">${r.duration_ms} ms</td>
          <td style="padding:4px 8px;">${r.ok ? '✓' : '✗'}</td>
        </tr>`).join('');
      const banner = data.divergence
        ? `<div style="padding:8px 12px;background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.3);border-radius:6px;margin-bottom:10px;">Divergence detected — ${(data.unique_answers||[]).length} distinct answers across resolvers.</div>`
        : `<div style="padding:8px 12px;background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.25);border-radius:6px;margin-bottom:10px;">Consistent across all resolvers.</div>`;
      return {html: `${banner}
        <table data-sortable style="width:100%;border-collapse:collapse;font-size:12px;">
          <thead><tr style="text-align:left;color:var(--text-dim);border-bottom:1px solid var(--border);">
            <th data-sort="string" data-col="0" style="padding:6px 8px;cursor:pointer;user-select:none;">Provider ⇅</th>
            <th data-sort="string" data-col="1" style="padding:6px 8px;cursor:pointer;user-select:none;">Resolver ⇅</th>
            <th data-sort="string" data-col="2" style="padding:6px 8px;cursor:pointer;user-select:none;">Answer ⇅</th>
            <th data-sort="num"    data-col="3" style="padding:6px 8px;text-align:right;cursor:pointer;user-select:none;">RTT ⇅</th>
            <th data-sort="string" data-col="4" style="padding:6px 8px;cursor:pointer;user-select:none;">OK ⇅</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>`};
    }
    if (endpoint.includes('/dns/axfr')) {
      const rows = (data.rows || []).map(r => `
        <tr>
          <td class="mono" style="padding:4px 8px;">${escHtml(r.nameserver)}</td>
          <td style="padding:4px 8px;"><span style="color:${r.exposed ? 'var(--danger,#e06060)' : 'var(--accent,#20c896)'};font-family:var(--mono);font-weight:600;">${r.exposed ? 'EXPOSED' : 'REFUSED'}</span></td>
          <td class="mono" style="padding:4px 8px;color:var(--text-dim);">${escHtml(r.detail || '')}</td>
        </tr>`).join('') || '<tr><td colspan="3" style="padding:12px;color:var(--text-dim);">No authoritative nameservers found for this domain.</td></tr>';
      const banner = data.any_exposed
        ? `<div style="padding:8px 12px;background:rgba(224,96,96,.1);border:1px solid rgba(224,96,96,.4);border-radius:6px;margin-bottom:10px;"><strong>Zone transfer exposed</strong> — one or more nameservers accepted AXFR. This is a misconfiguration.</div>`
        : `<div style="padding:8px 12px;background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.25);border-radius:6px;margin-bottom:10px;">All nameservers refused AXFR (expected for production zones).</div>`;
      return {html: `${banner}
        <table style="width:100%;border-collapse:collapse;font-size:12px;">
          <thead><tr style="text-align:left;color:var(--text-dim);border-bottom:1px solid var(--border);">
            <th style="padding:6px 8px;">Nameserver</th>
            <th style="padding:6px 8px;">Result</th>
            <th style="padding:6px 8px;">Detail</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>`};
    }
    if (endpoint.includes('/network/http-test')) {
      const kv = (label, val) => `<div><span style="color:var(--text-dim);">${label}</span> <span class="mono" style="color:var(--text);">${escHtml(val)}</span></div>`;
      const chain = (data.chain || []).map(s => `
        <tr>
          <td class="mono" style="padding:4px 8px;">${s.status}</td>
          <td class="mono" style="padding:4px 8px;color:var(--text-dim);">${escHtml(s.reason || '')}</td>
          <td class="mono" style="padding:4px 8px;">${escHtml(s.url)}</td>
          <td class="mono" style="padding:4px 8px;text-align:right;">${s.duration_ms} ms</td>
        </tr>`).join('');
      const hdrs = Object.entries(data.response_headers || {}).map(([k,v]) => `
        <tr><td class="mono" style="padding:2px 8px;color:var(--text-dim);">${escHtml(k)}</td><td class="mono" style="padding:2px 8px;">${escHtml(v)}</td></tr>`).join('');
      return {html: `
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;padding:10px 12px;background:rgba(255,255,255,.02);border-radius:6px;margin-bottom:10px;font-size:12px;">
          ${kv('Final status', data.final_status)}
          ${kv('Total', (data.total_ms||0) + ' ms')}
          ${kv('Redirects', data.redirect_count)}
          ${kv('Content-Type', data.content_type || '—')}
          ${kv('Content-Length', data.content_length ?? '—')}
        </div>
        ${data.chain && data.chain.length ? `
        <div style="font-family:var(--mono);font-size:10px;color:var(--text-dimmer);margin:6px 0;">Request chain</div>
        <table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:10px;">
          <thead><tr style="text-align:left;color:var(--text-dim);border-bottom:1px solid var(--border);">
            <th style="padding:6px 8px;">Status</th>
            <th style="padding:6px 8px;">Reason</th>
            <th style="padding:6px 8px;">URL</th>
            <th style="padding:6px 8px;text-align:right;">Duration</th>
          </tr></thead>
          <tbody>${chain}</tbody>
        </table>` : ''}
        <details style="margin-top:8px;">
          <summary style="cursor:pointer;color:var(--text-dim);font-family:var(--mono);font-size:11px;">Response headers (${Object.keys(data.response_headers||{}).length})</summary>
          <table style="width:100%;border-collapse:collapse;font-size:11px;margin-top:6px;"><tbody>${hdrs}</tbody></table>
        </details>
        ${data.body_preview ? `<details style="margin-top:8px;"><summary style="cursor:pointer;color:var(--text-dim);font-family:var(--mono);font-size:11px;">Body preview</summary><pre style="background:rgba(0,0,0,.3);padding:10px;border-radius:4px;margin-top:6px;overflow-x:auto;font-size:11px;">${escHtml(data.body_preview)}</pre></details>` : ''}`};
    }
    if (endpoint.includes('/network/traceroute')) {
      const hops = (data.hops || []).map(h => {
        const rtts = h.rtts_ms && h.rtts_ms.length
          ? h.rtts_ms.map(r => r.toFixed(1) + ' ms').join('  ')
          : '<span style="color:var(--text-dimmer);">* * *</span>';
        const host = h.host || h.ip || '<span style="color:var(--text-dimmer);">(no response)</span>';
        const ip = h.ip && h.host && h.ip !== h.host ? ` <span style="color:var(--text-dim);">(${escHtml(h.ip)})</span>` : '';
        return `<tr>
          <td class="mono" style="padding:4px 10px;text-align:right;color:var(--text-dim);">${h.ttl}</td>
          <td class="mono" style="padding:4px 10px;">${escHtml(host)}${ip}</td>
          <td class="mono" style="padding:4px 10px;">${rtts}</td>
        </tr>`;
      }).join('');
      return {html: `
        <div style="font-family:var(--mono);font-size:10px;color:var(--text-dimmer);margin-bottom:6px;">$ ${escHtml(data.command || '')}</div>
        <table style="width:100%;border-collapse:collapse;font-size:12px;">
          <thead><tr style="text-align:left;color:var(--text-dim);border-bottom:1px solid var(--border);">
            <th style="padding:6px 10px;text-align:right;">Hop</th>
            <th style="padding:6px 10px;">Host</th>
            <th style="padding:6px 10px;">RTTs</th>
          </tr></thead>
          <tbody>${hops}</tbody>
        </table>`};
    }
    if (endpoint.includes('/dns/reverse')) {
      // Reverse lookup: show the target IP + the arpa name + a PTR table.
      const recs = (data.records || []);
      const rowsHtml = recs.map(r => `
        <tr>
          <td style="padding:4px 8px;font-family:var(--mono);">${escHtml(r.owner || '')}</td>
          <td style="padding:4px 8px;font-family:var(--mono);">${escHtml(r.ptr || '')}</td>
        </tr>`).join('')
        || `<tr><td colspan="2" style="padding:12px;color:var(--text-dim);font-style:italic;">No PTR records returned for ${escHtml(data.ip || '')}.</td></tr>`;
      const banner = recs.length
        ? `<div style="padding:8px 12px;background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.25);border-radius:6px;margin-bottom:10px;">
             Resolved <span class="mono">${escHtml(data.ip)}</span> → ${recs.length} PTR record${recs.length === 1 ? '' : 's'}.
           </div>`
        : `<div style="padding:8px 12px;background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.3);border-radius:6px;margin-bottom:10px;">
             No PTR records returned (NXDOMAIN or empty zone).
           </div>`;
      return { html: `${banner}
        <div style="font-size:11px;color:var(--text-dim);margin-bottom:6px;">
          Reverse zone: <span class="mono">${escHtml(data.reverse_zone || '')}</span>
        </div>
        <table data-sortable style="width:100%;border-collapse:collapse;font-size:12px;">
          <thead><tr style="text-align:left;color:var(--text-dim);border-bottom:1px solid var(--border);">
            <th data-sort="string" data-col="0" style="padding:6px 8px;cursor:pointer;user-select:none;">Owner (arpa) ⇅</th>
            <th data-sort="string" data-col="1" style="padding:6px 8px;cursor:pointer;user-select:none;">PTR ⇅</th>
          </tr></thead>
          <tbody>${rowsHtml}</tbody>
        </table>
        ${data.raw ? `<details style="margin-top:10px;"><summary style="cursor:pointer;font-size:11px;color:var(--text-dim);">Show raw dig output</summary><pre style="font-size:11px;color:var(--text-dim);white-space:pre;overflow:auto;user-select:text;">${escHtml(data.raw)}</pre></details>` : ''}
      ` };
    }
    if (endpoint.includes('/dns/dig')) {
      const lines = [];
      lines.push(`$ ${data.command}`);
      lines.push('');
      if (data.stdout) lines.push(data.stdout.trimEnd());
      if (data.stderr && data.returncode !== 0) lines.push(`\n[stderr]\n${data.stderr}`);
      lines.push(`\n── exit=${data.returncode} · ${data.duration_ms}ms${data.truncated ? ' · TRUNCATED' : ''}${data.timed_out ? ' · TIMED OUT' : ''}`);
      return lines.join('\n');
    }
    if (endpoint.includes('/network/ping')) {
      const lines = [];
      lines.push(`$ ${data.command}`);
      lines.push('');
      if (data.stdout) lines.push(data.stdout.trimEnd());
      const s = data.stats || {};
      if (s.transmitted) {
        lines.push(`\n── ${s.transmitted} tx / ${s.received} rx · ${s.loss_pct}% loss · rtt min/avg/max = ${s.rtt_min}/${s.rtt_avg}/${s.rtt_max} ms · jitter ${s.jitter} ms`);
      }
      return lines.join('\n');
    }
    return JSON.stringify(data, null, 2);
  }

  function wireForms() {
    document.querySelectorAll('form[data-endpoint]').forEach(form => {
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        submitTool(form);
      });
    });
  }

  // Delegated sort-on-header-click for any table tagged data-sortable.
  // Tables rendered by renderResult() come and go, so delegation beats
  // per-render rebinding.
  document.addEventListener('click', (e) => {
    const th = e.target.closest('table[data-sortable] thead th[data-col]');
    if (!th) return;
    const table = th.closest('table');
    const tbody = table.querySelector('tbody');
    const col = Number(th.dataset.col);
    const kind = th.dataset.sort || 'string';
    const asc = table.dataset.sortCol === String(col) && table.dataset.sortDir === 'asc' ? false : true;
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {
      const av = (a.children[col]?.textContent || '').trim();
      const bv = (b.children[col]?.textContent || '').trim();
      if (kind === 'num') return (parseFloat(av) || 0) - (parseFloat(bv) || 0);
      return av.localeCompare(bv);
    });
    if (!asc) rows.reverse();
    rows.forEach(r => tbody.appendChild(r));
    table.dataset.sortCol = String(col);
    table.dataset.sortDir = asc ? 'asc' : 'desc';
  });

  // --- Timestamp formatting ---------------------------------------------
  // Everything is stored UTC. Display follows the precedence:
  //   user.preferences.timezone → branding.timezone → server default (install.sh)
  //   → browser TZ → UTC fallback.
  // The effective TZ is exposed as `body[data-tz]`. Pages call `fmt.ts(iso)`
  // where they'd otherwise drop a raw UTC string.
  const _pageTz = () => (
    (document.body && document.body.dataset && document.body.dataset.tz) ||
    Intl.DateTimeFormat().resolvedOptions().timeZone ||
    'UTC'
  );
  function _fmt(iso, opts) {
    if (!iso) return '';
    const d = (iso instanceof Date) ? iso : new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    try {
      return new Intl.DateTimeFormat(undefined, Object.assign({timeZone: _pageTz()}, opts || {})).format(d);
    } catch {
      return d.toISOString();
    }
  }
  const fmt = {
    tz: _pageTz,
    ts(iso)        { return _fmt(iso, {year:'numeric',month:'short',day:'2-digit',
                                        hour:'2-digit',minute:'2-digit',second:'2-digit',
                                        timeZoneName:'short'}); },
    tsShort(iso)   { return _fmt(iso, {month:'short',day:'2-digit',
                                        hour:'2-digit',minute:'2-digit'}); },
    date(iso)      { return _fmt(iso, {year:'numeric',month:'short',day:'2-digit'}); },
    time(iso)      { return _fmt(iso, {hour:'2-digit',minute:'2-digit',second:'2-digit',
                                        timeZoneName:'short'}); },
    // Relative form: "3m ago" / "2h ago" — falls back to tsShort beyond 48h.
    rel(iso) {
      if (!iso) return '';
      const d = (iso instanceof Date) ? iso : new Date(iso);
      if (isNaN(d.getTime())) return String(iso);
      const diff = Math.round((Date.now() - d.getTime()) / 1000);
      if (diff < 60)            return `${diff}s ago`;
      if (diff < 3600)          return `${Math.round(diff/60)}m ago`;
      if (diff < 48 * 3600)     return `${Math.round(diff/3600)}h ago`;
      return fmt.tsShort(iso);
    },
    // Dual-display for forensic/audit views: "14:22:05 CDT · 19:22:05 UTC".
    tsAudit(iso) {
      if (!iso) return '';
      const d = new Date(iso);
      if (isNaN(d.getTime())) return String(iso);
      const local = new Intl.DateTimeFormat(undefined, {
        timeZone: _pageTz(), hour:'2-digit', minute:'2-digit', second:'2-digit',
        timeZoneName: 'short',
      }).format(d);
      const utc = new Intl.DateTimeFormat(undefined, {
        timeZone: 'UTC', hour:'2-digit', minute:'2-digit', second:'2-digit',
      }).format(d);
      return `${local} · ${utc} UTC`;
    },
  };
  window.fmt = fmt;

  // Auto-convert <time datetime="ISO" data-fmt="ts|rel|date|time|tsShort|tsAudit">
  // on page load. Pages rendering through JS call fmt.* directly.
  function formatTimeElements(root) {
    (root || document).querySelectorAll('time[datetime]').forEach(el => {
      const kind = el.dataset.fmt || 'ts';
      const fn = fmt[kind];
      if (typeof fn === 'function') el.textContent = fn(el.getAttribute('datetime'));
    });
  }
  window.formatTimeElements = formatTimeElements;

  // --- Boot ---
  document.addEventListener('DOMContentLoaded', () => {
    wireMfa();
    wireTabs();
    wireChips();
    wireForms();
    wireIdleTimer();
    formatTimeElements();
  });
})();
