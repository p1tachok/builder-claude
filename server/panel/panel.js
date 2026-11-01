'use strict';
/* Админ-панель Pitachok HUD. Без внешних зависимостей; все данные экранируются; токены хранятся только в памяти вкладки. */
(function (root) {
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const dt = (iso) => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d) ? '—' : d.toLocaleString('ru-RU'); };
  const badge = (cls, text) => `<span class="badge ${esc(cls)}">${esc(text)}</span>`;
  const STATUS_RU = { active: 'работает', revoked: 'отключён', blocked: 'заблокирован платформой' };
  const TYPE_RU = { free: 'бесплатный', paid: 'платный' };

  // ---------- чистые функции отрисовки (покрыты тестами) ----------
  function renderHudList(huds, role) {
    if (!huds.length) return '<div class="card muted">HUD пока нет. Создайте первый в конструкторе.</div>';
    const rows = huds.map((h) => {
      const st = h.stats || {};
      const off = h.status !== 'active';
      return `<tr>
        <td><a class="link" data-act="open" data-id="${esc(h.hudId)}">${esc(h.hudId)}</a></td>
        <td>${esc(h.name)}</td>
        <td>${badge(h.type, TYPE_RU[h.type] || h.type)}</td>
        <td>${badge(h.status, STATUS_RU[h.status] || h.status)}</td>
        <td>${esc(h.currentVersion || '—')}</td>
        ${role === 'owner' ? `<td class="muted">${esc(h.developerId)}</td>` : ''}
        <td>${h.type === 'paid' ? `ключей: ${esc(st.licenses)}${st.flaggedLicenses ? ' ' + badge('flag', 'подозрительных: ' + st.flaggedLicenses) : ''}` : `установок: ${esc(st.installs)} (за 24ч: ${esc(st.activeLast24h)})`}</td>
        <td>${h.status === 'blocked' && role !== 'owner' ? '' : `<button class="${off ? 'ok' : 'danger'}" data-act="toggle-hud" data-id="${esc(h.hudId)}" data-to="${off ? 'active' : 'revoked'}">${off ? 'Включить' : 'Отключить'}</button>`}</td>
      </tr>`;
    }).join('');
    return `<div class="card"><table><thead><tr><th>ID</th><th>Название</th><th>Тип</th><th>Статус</th><th>Версия</th>${role === 'owner' ? '<th>Разработчик</th>' : ''}<th>Пользователи</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderLicenseRow(l) {
    const pcs = (l.activations || []).map((a) => `<div><span class="pc">${esc(a.pc)}</span> <span class="muted">с ${esc(dt(a.firstSeenAt))}, был ${esc(dt(a.lastSeenAt))}</span></div>`).join('') || '<span class="muted">ещё не активирован</span>';
    const att = (l.attempts || []).map((a) => `<div><span class="pc">${esc(a.pc)}</span> × ${esc(a.count)} <span class="muted">последняя ${esc(dt(a.lastAt))}</span></div>`).join('');
    const revoked = l.status === 'revoked';
    return `<tr>
      <td>${esc(l.label)}<div class="muted pc">${esc(l.licenseId)} · ${esc(l.keyPrefix)}…</div></td>
      <td>${badge(l.status, revoked ? 'отключён' : 'работает')}${revoked && l.revokeReason ? `<div class="muted">${esc(l.revokeReason)}</div>` : ''}</td>
      <td>${pcs}<div class="muted">${esc(l.devices)} из ${esc(l.maxDevices)}</div></td>
      <td>${l.deviceAttempts ? `${badge('flag', 'попыток с других ПК: ' + l.deviceAttempts)}${att}` : '<span class="muted">нет</span>'}</td>
      <td><div class="row">
        <button class="${revoked ? 'ok' : 'danger'}" data-act="${revoked ? 'restore-lic' : 'revoke-lic'}" data-id="${esc(l.licenseId)}">${revoked ? 'Включить' : 'Отключить ключ'}</button>
        <button class="ghost" data-act="reset-lic" data-id="${esc(l.licenseId)}">Сбросить ПК</button>
        <button class="ghost" data-act="rotate-lic" data-id="${esc(l.licenseId)}">Новый ключ</button>
      </div></td></tr>`;
  }

  function renderHudDetail(h, licenses, role) {
    const st = h.stats || {};
    const off = h.status !== 'active';
    const head = `<div class="card">
      <div class="row"><h2 class="m0f1">${esc(h.name)} <span class="muted pc">${esc(h.hudId)}</span></h2>
        <button class="ghost" data-act="back">← К списку</button>
        ${h.status === 'blocked' && role !== 'owner' ? '' : `<button class="${off ? 'ok' : 'danger'}" data-act="toggle-hud" data-id="${esc(h.hudId)}" data-to="${off ? 'active' : 'revoked'}">${off ? 'Включить HUD' : 'Отключить HUD'}</button>`}
      </div>
      <div class="row mt8">${badge(h.type, TYPE_RU[h.type] || h.type)} ${badge(h.status, STATUS_RU[h.status] || h.status)} <span class="muted">версия: ${esc(h.currentVersion || 'не опубликована')} · разработчик ${esc(h.developerId)}</span></div>
      <div class="stats"><div><b>${esc(st.installs)}</b>установок</div><div><b>${esc(st.activeLast24h)}</b>активных за 24 ч</div>${h.type === 'paid' ? `<div><b>${esc(st.licenses)}</b>ключей</div><div><b>${esc(st.flaggedLicenses)}</b>подозрительных</div>` : ''}</div></div>`;
    if (h.type !== 'paid') {
      return head + `<div class="card"><p>Бесплатный HUD: ключи и привязка к ПК не используются, скачать может любое число людей.</p><button data-act="dl-build" data-id="${esc(h.hudId)}">Скачать общий HudLoader.build</button></div>`;
    }
    const rows = (licenses || []).map(renderLicenseRow).join('') || '<tr><td colspan="5" class="muted">Ключей пока нет — выдайте первый покупателю.</td></tr>';
    return head + `<div class="card"><h3 class="mt0">Выдать ключ покупателю</h3>
      <div class="row"><input id="lic-label" placeholder="Кому (ник/заметка)" maxlength="64"><select id="lic-max"><option value="1">1 ПК</option><option value="2">2 ПК</option><option value="3">3 ПК</option></select><button data-act="issue" data-id="${esc(h.hudId)}">Выдать</button></div>
      <div id="issued"></div></div>
      <div class="card"><h3 class="mt0">Покупатели</h3><table><thead><tr><th>Покупатель</th><th>Статус</th><th>Привязанные ПК</th><th>Попытки с других ПК</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderIssued(l) {
    return `<div class="mt12"><div class="muted">Ключ показывается один раз:</div><div class="key">${esc(l.licenseKey)}</div>
      <p class="muted">Отправьте покупателю файл <b>${esc(l.buildFileName)}</b> (он уже содержит ключ) вместе с loader. ПК привяжется сам при первом запуске игры.</p>
      <button data-act="dl-issued">Скачать ${esc(l.buildFileName)}</button></div>`;
  }

  function renderAudit(logs) {
    const rows = logs.map((l) => `<tr><td class="muted">${esc(dt(l.ts))}</td><td>${esc(l.actor)}</td><td>${esc(l.action)}</td><td class="pc">${esc(l.target)}</td></tr>`).join('');
    return `<div class="card"><h3 class="mt0">Журнал событий</h3><table><thead><tr><th>Время</th><th>Кто</th><th>Действие</th><th>Объект</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  const api = { esc, dt, renderHudList, renderLicenseRow, renderHudDetail, renderIssued, renderAudit };
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; return; }

  // ---------- приложение (только в браузере) ----------
  const $ = (s) => document.querySelector(s);
  const app = $('#app');
  let tokens = null, me = null, issued = null, view = { name: 'list' };

  function toast(msg, isErr) { const t = $('#toast'); t.textContent = msg; t.className = 'show' + (isErr ? ' err' : ''); clearTimeout(toast.t); toast.t = setTimeout(() => { t.className = ''; }, 3500); }

  async function call(method, path, body, retry = true) {
    const r = await fetch('/api/v1' + path, { method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(tokens ? { Authorization: 'Bearer ' + tokens.accessToken } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
    if (r.status === 401 && tokens && retry) {
      const rr = await fetch('/api/v1/auth/refresh', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refreshToken: tokens.refreshToken }) });
      if (rr.ok) { tokens = await rr.json(); return call(method, path, body, false); }
      tokens = null; me = null; showLogin(); throw new Error('Сессия истекла, войдите снова');
    }
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.message || ('Ошибка ' + r.status));
    return data;
  }
  const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

  function showLogin() {
    $('#logout').hidden = true; $('#who').textContent = '';
    app.innerHTML = `<form class="card login" id="login-form"><h2 class="mt0">Вход</h2>
      <label>Логин</label><input id="l-login" autocomplete="username" required>
      <label>Пароль</label><input id="l-pass" type="password" autocomplete="current-password" required>
      <div class="mt14"><button type="submit">Войти</button></div></form>`;
    $('#login-form').addEventListener('submit', guard(async (e) => {
      e.preventDefault();
      const r = await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ login: $('#l-login').value, password: $('#l-pass').value }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.message || 'Ошибка входа');
      tokens = d; me = d.account; $('#l-pass').value = '';
      await showList();
    }));
  }

  async function showList() {
    view = { name: 'list' };
    $('#logout').hidden = false; $('#who').textContent = `${me.login} (${me.role === 'owner' ? 'владелец' : 'разработчик'})`;
    const d = await call('GET', me.role === 'owner' ? '/admin/huds' : '/developers/me/huds');
    app.innerHTML = `<div class="row mb12"><h2 class="m0f1">HUD</h2>${me.role === 'owner' ? '<button class="ghost" data-act="audit">Журнал</button>' : ''}<button class="ghost" data-act="refresh">Обновить</button></div>` + renderHudList(d.huds, me.role);
  }
  async function showHud(id) {
    view = { name: 'hud', id };
    const h = await call('GET', '/huds/' + encodeURIComponent(id));
    const lic = h.type === 'paid' ? (await call('GET', `/huds/${encodeURIComponent(id)}/licenses`)).licenses : [];
    app.innerHTML = renderHudDetail(h, lic, me.role);
    if (issued) { $('#issued').innerHTML = renderIssued(issued); }
  }
  const reload = () => (view.name === 'hud' ? showHud(view.id) : showList());
  function download(name, text) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }

  app.addEventListener('click', guard(async (e) => {
    const b = e.target.closest('[data-act]'); if (!b) return;
    const act = b.dataset.act, id = b.dataset.id;
    if (act === 'open') { issued = null; return showHud(id); }
    if (act === 'back' || act === 'refresh') { issued = null; return showList(); }
    if (act === 'audit') { const d = await call('GET', '/admin/audit-logs?limit=200'); app.innerHTML = '<button class="ghost" data-act="back" class="mb12">← К списку</button>' + renderAudit(d.logs); return; }
    if (act === 'toggle-hud') {
      const to = b.dataset.to;
      if (to === 'revoked' && !confirm('Отключить HUD для ВСЕХ пользователей?')) return;
      await call('POST', `/huds/${encodeURIComponent(id)}/status`, { status: to }); toast(to === 'revoked' ? 'HUD отключён' : 'HUD включён'); return reload();
    }
    if (act === 'revoke-lic') { const reason = prompt('Причина (необязательно):', 'слив худа'); if (reason === null) return; await call('POST', `/huds/${encodeURIComponent(view.id)}/licenses/${encodeURIComponent(id)}/revoke`, { reason }); toast('Ключ отключён'); return reload(); }
    if (act === 'restore-lic') { await call('POST', `/huds/${encodeURIComponent(view.id)}/licenses/${encodeURIComponent(id)}/restore`, {}); toast('Ключ включён'); return reload(); }
    if (act === 'reset-lic') { if (!confirm('Сбросить привязанные ПК? Покупатель сможет привязать новый.')) return; await call('POST', `/huds/${encodeURIComponent(view.id)}/licenses/${encodeURIComponent(id)}/reset-devices`, {}); toast('ПК сброшены'); return reload(); }
    if (act === 'rotate-lic') { if (!confirm('Выпустить новый ключ? Старый перестанет работать, ПК отвяжутся.')) return; issued = await call('POST', `/huds/${encodeURIComponent(view.id)}/licenses/${encodeURIComponent(id)}/rotate-key`, {}); return showHud(view.id); }
    if (act === 'issue') {
      const label = $('#lic-label').value.trim(); if (!label) throw new Error('Укажите, кому выдаётся ключ');
      issued = await call('POST', `/huds/${encodeURIComponent(id)}/licenses`, { label, maxDevices: Number($('#lic-max').value) }); return showHud(id);
    }
    if (act === 'dl-issued' && issued) return download(issued.buildFileName, issued.buildFile);
    if (act === 'dl-build') { const d = await call('GET', `/huds/${encodeURIComponent(id)}/build`); return download(d.buildFileName, d.buildFile); }
  }));

  $('#logout').addEventListener('click', guard(async () => { if (tokens) await call('POST', '/auth/logout', { refreshToken: tokens.refreshToken }).catch(() => {}); tokens = null; me = null; issued = null; showLogin(); }));
  showLogin();
})(typeof window !== 'undefined' ? window : globalThis);
