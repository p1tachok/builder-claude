'use strict';
// Клиент API для конструктора: создание HUD (free/paid), загрузка и публикация версии, выдача ключей покупателям.
const fs = require('fs');
const path = require('path');
const { migrate, validate } = require('./config');
const { toDataUri } = require('./imageutil');
const { resolveInside } = require('./generator');

class ClientError extends Error {}

class ApiClient {
  constructor(baseUrl, fetchImpl = globalThis.fetch) { this.base = baseUrl.replace(/\/+$/, '') + '/api/v1'; this.f = fetchImpl; this.tokens = null; }
  async login(login, password) {
    const r = await this._raw('POST', '/auth/login', { login, password });
    this.tokens = r; return r.account;
  }
  async _raw(method, p, body, token) {
    const res = await this.f(this.base + p, { method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new ClientError(`${data.message || 'Ошибка ' + res.status} (${data.code || res.status})`);
    return data;
  }
  async request(method, p, body, retry = true) {
    if (!this.tokens) throw new ClientError('Сначала войдите (login)');
    try { return await this._raw(method, p, body, this.tokens.accessToken); }
    catch (e) {
      if (retry && /\(unauthorized\)/.test(e.message)) { this.tokens = await this._raw('POST', '/auth/refresh', { refreshToken: this.tokens.refreshToken }); return this.request(method, p, body, false); }
      throw e;
    }
  }
}

// Заменяет {file} на {dataUri}: сервер принимает только встроенные картинки
function inlineAssets(cfg, baseDir) {
  const c = structuredClone(cfg);
  const conv = (ref) => (ref && ref.file ? { dataUri: toDataUri(fs.readFileSync(resolveInside(baseDir, ref.file))).dataUri } : ref);
  c.assets.auth = conv(c.assets.auth); c.assets.dialogBackground = conv(c.assets.dialogBackground);
  for (const sec of ['icons', 'logos', 'weapons']) for (const k of Object.keys(c.assets[sec])) c.assets[sec][k] = conv(c.assets[sec][k]);
  return c;
}

const safeName = (s) => String(s).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 40) || 'buyer';
function writeBuild(outDir, buildFileName, buildFile, loaderPath) {
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, buildFileName), buildFile);
  if (loaderPath) fs.copyFileSync(loaderPath, path.join(outDir, path.basename(loaderPath)));
  return outDir;
}

/** Создаёт HUD (тип обязателен), загружает и публикует версию. Для существующего HUD тип менять нельзя. */
async function publishHud({ client, hudId, name, type, config, baseDir, version }) {
  let hud;
  if (!hudId) {
    if (type !== 'free' && type !== 'paid') throw new ClientError('Выберите тип HUD: free (бесплатный) или paid (платный)');
    if (!name) throw new ClientError('Укажите название HUD');
    hud = await client.request('POST', '/huds', { name, type });
  } else {
    hud = await client.request('GET', `/huds/${hudId}`);
    if (type && type !== hud.type) throw new ClientError(`HUD ${hudId} уже ${hud.type}; тип меняется отдельно (PATCH /huds/{id}/settings)`);
  }
  const cfg = migrate(config); cfg.distribution = hud.type;
  const v = validate(cfg); if (!v.ok) throw new ClientError('Конфигурация невалидна: ' + v.errors.map((e) => `${e.path}: ${e.message}`).join('; '));
  const created = await client.request('POST', `/huds/${hud.hudId}/versions`, { version, config: inlineAssets(cfg, baseDir) });
  const pub = await client.request('POST', `/huds/${hud.hudId}/publish`, { version });
  return { hudId: hud.hudId, type: hud.type, version, sha256: created.sha256, warnings: created.warnings, mirror: pub.mirror };
}

/** Платный HUD: ключ + персональный .build на покупателя; ПК привяжется сам при первом запуске. */
async function issueBuyerKey({ client, hudId, label, maxDevices = 1, outDir, loaderPath }) {
  const r = await client.request('POST', `/huds/${hudId}/licenses`, { label, maxDevices });
  const dir = outDir ? writeBuild(path.join(outDir, `${safeName(label)}_${r.licenseId}`), r.buildFileName, r.buildFile, loaderPath) : null;
  return { licenseId: r.licenseId, licenseKey: r.licenseKey, dir };
}
/** Бесплатный HUD: один общий .build для всех */
async function exportFreeBuild({ client, hudId, outDir, loaderPath }) {
  const r = await client.request('GET', `/huds/${hudId}/build`);
  return { dir: writeBuild(outDir, r.buildFileName, r.buildFile, loaderPath) };
}
module.exports = { ApiClient, ClientError, inlineAssets, publishHud, issueBuyerKey, exportFreeBuild };
