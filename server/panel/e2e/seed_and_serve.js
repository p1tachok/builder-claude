'use strict';
// Поднимает сервер на :18099 с тестовыми данными для проверки панели в браузере (используется e2e/panel_e2e.py)
const fs = require('fs'); const os = require('os'); const path = require('path');
const { createApp } = require('../../src/app'); const S = require('../../src/security');
const { makePng } = require('../../../tests/helpers');
(async () => {
  const keys = S.generateSigningKeys();
  const app = createApp({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-')), dbFile: ':memory:', tokenSecret: 'e2e-secret-e2e-secret', signing: { ...keys, keyId: 'k1' },
    template: fs.readFileSync(path.join(__dirname, '..', '..', '..', 'templates', 'hud.template.js'), 'utf8'), publicUrl: 'http://127.0.0.1:18099' });
  await app.createAccount({ login: 'owner', password: 'Owner-pass-12345', role: 'owner' });
  await app.listen(18099);
  const base = 'http://127.0.0.1:18099/api/v1';
  const call = async (m, p, b, t) => (await fetch(base + p, { method: m, headers: { 'Content-Type': 'application/json', ...(t ? { Authorization: 'Bearer ' + t } : {}) }, body: b ? JSON.stringify(b) : undefined })).json();
  const tok = (await call('POST', '/auth/login', { login: 'owner', password: 'Owner-pass-12345' })).accessToken;
  const cfg = { schemaVersion: 1, hudId: 'x', distribution: 'free', version: '1.0.0', status: 'draft', assets: { auth: { dataUri: 'data:image/png;base64,' + makePng(2, 2).toString('base64') }, icons: {}, logos: {}, weapons: {}, dialogBackground: null }, colors: {}, radar: {}, dialogStyle: {} };
  const mk = async (name, type) => { const h = await call('POST', '/huds', { name, type }, tok); await call('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfg }, tok); await call('POST', `/huds/${h.hudId}/publish`, { version: '1.0.0' }, tok); return h.hudId; };
  const paid = await mk('Платный HUD', 'paid'); const free = await mk('Бесплатный HUD', 'free');
  const lic = await call('POST', `/huds/${paid}/licenses`, { label: 'Вася' }, tok);
  const val = (hw) => call('POST', '/license/validate', { installationId: 'e2e-install-0000000001', hudId: paid, loaderVersion: '1.0.0', licenseKey: lic.licenseKey, hwid: hw });
  await val('hwid-vasya-pc-aaaaaaaaaaaaaa'); for (let i = 0; i < 3; i++) await val('hwid-leaker-pc-aaaaaaaaaaaaa');
  for (let i = 0; i < 5; i++) await call('POST', '/license/validate', { installationId: `e2e-free-install-00000${i}`, hudId: free, loaderVersion: '1.0.0' });
  await call('POST', `/huds/${paid}/licenses`, { label: 'Хакер &amp; Co' }, tok);
  console.log('READY', paid, free); 
})();
