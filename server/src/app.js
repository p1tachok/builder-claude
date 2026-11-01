'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const S = require('./security');
const { signBlob } = require('./blob');
const { openDb } = require('./db');
const { generate } = require('../../src/generator');
const { migrate } = require('../../src/config');

class HttpError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
const bad = (code, msg) => new HttpError(400, code, msg);
const nowIso = () => new Date().toISOString();
const VERSION_RE = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/;
const HUD_ID_RE = /^HUD-[0-9A-F]{8}$/;
const LOGIN_RE = /^[A-Za-z0-9_.-]{3,32}$/;
const INSTALL_RE = /^[A-Za-z0-9-]{16,64}$/;
const HWID_RE = /^[A-Za-z0-9_.:-]{16,128}$/;
const KEY_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';   // без похожих символов
const LABEL_RE = /^[A-Za-z0-9 _.-]{1,32}$/;
const LIC_ID_RE = /^LK-[0-9A-F]{8}$/;

const DEFAULTS = {
  accessTtlSec: 900, refreshTtlSec: 30 * 86400, graceHours: 72, policyVersion: 1, minLoaderVersion: '0.0.0',
  maxBodyBytes: 64 * 1024, maxVersionBodyBytes: 40 * 1024 * 1024,
  limits: { loginIp: [20, 60000], loginAccount: [5, 300000], general: [600, 60000], license: [120, 60000] },
  trustProxy: false,
};

function createApp(options) {
  const o = { ...DEFAULTS, ...options, limits: { ...DEFAULTS.limits, ...(options.limits || {}) } };
  for (const k of ['dataDir', 'tokenSecret', 'signing', 'template']) if (!o[k]) throw new Error(`createApp: нет опции ${k}`);
  if (o.publicUrl && !/^https?:\/\/[A-Za-z0-9.:_\/-]{1,200}$/.test(o.publicUrl)) throw new Error('createApp: некорректный publicUrl');
  const db = openDb(o.dbFile || path.join(o.dataDir, 'pitachok.sqlite'));
  const limiter = new S.RateLimiter(o.now);
  const q = (sql) => db.prepare(sql);
  const artifactsRoot = path.join(o.dataDir, 'artifacts');
  fs.mkdirSync(artifactsRoot, { recursive: true });

  const audit = (actor, action, target, details) =>
    q('INSERT INTO audit_logs(ts,actor,action,target,details) VALUES(?,?,?,?,?)').run(nowIso(), actor, action, target ?? null, details ? JSON.stringify(details) : null);

  // ---------- аккаунты ----------
  const publicAccount = (a) => ({ id: a.code, login: a.login, role: a.role, status: a.status, canCreateHud: !!a.can_create_hud, mustChangePassword: !!a.must_change_password, createdAt: a.created_at });
  async function createAccount({ login, password, role }) {
    if (!LOGIN_RE.test(login || '')) throw bad('invalid_login', 'Логин: 3–32 символа (буквы, цифры, _ . -)');
    const pe = S.validatePasswordPolicy(password); if (pe) throw bad('weak_password', pe);
    if (q('SELECT 1 FROM accounts WHERE login=?').get(login)) throw new HttpError(409, 'login_taken', 'Логин уже занят');
    const hash = await S.hashPassword(password);
    const r = q('INSERT INTO accounts(login,password_hash,role,created_at) VALUES(?,?,?,?)').run(login, hash, role, nowIso());
    const id = Number(r.lastInsertRowid);
    const code = `${role === 'owner' ? 'OWNER' : 'DEV'}-${String(id).padStart(3, '0')}`;
    q('UPDATE accounts SET code=? WHERE id=?').run(code, id);
    return q('SELECT * FROM accounts WHERE id=?').get(id);
  }
  const accByCode = (code) => q('SELECT * FROM accounts WHERE code=? AND role=\'developer\'').get(String(code));

  // ---------- токены ----------
  const nowSec = () => Math.floor((o.now ? o.now() : Date.now()) / 1000);
  function issueTokens(acc, family = crypto.randomUUID()) {
    const access = S.signToken(o.tokenSecret, { sub: acc.id, role: acc.role, exp: nowSec() + o.accessTtlSec });
    const refresh = S.newRefreshToken();
    q('INSERT INTO refresh_tokens(account_id,token_hash,family,expires_at) VALUES(?,?,?,?)').run(acc.id, S.sha256hex(refresh), family, nowSec() + o.refreshTtlSec);
    return { accessToken: access, refreshToken: refresh, expiresIn: o.accessTtlSec, account: publicAccount(acc) };
  }
  const revokeAllTokens = (accId) => q('UPDATE refresh_tokens SET revoked=1 WHERE account_id=?').run(accId);

  // ---------- http утилиты ----------
  async function readJson(req, max) {
    const ct = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/json') throw new HttpError(415, 'unsupported_media_type', 'Нужен Content-Type: application/json');
    const len = Number(req.headers['content-length']);
    if (Number.isFinite(len) && len > max) throw new HttpError(413, 'payload_too_large', 'Слишком большой запрос');
    const chunks = []; let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > max) { req.destroy(); throw new HttpError(413, 'payload_too_large', 'Слишком большой запрос'); }
      chunks.push(c);
    }
    try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); if (!v || typeof v !== 'object' || Array.isArray(v)) throw 0; return v; }
    catch { throw bad('invalid_json', 'Некорректный JSON'); }
  }
  function send(res, status, body, traceId, headers = {}) {
    const isBuf = Buffer.isBuffer(body);
    const payload = isBuf ? body : Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'Content-Type': isBuf ? 'application/octet-stream' : 'application/json; charset=utf-8', 'Content-Length': payload.length,
      'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', 'X-Trace-Id': traceId, ...headers });
    res.end(payload);
  }
  const clientIp = (req) => (o.trustProxy && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress) || 'unknown';
  function throttle(key, [limit, win]) {
    const r = limiter.hit(key, limit, win);
    if (!r.ok) { const e = new HttpError(429, 'rate_limited', 'Слишком много запросов, попробуйте позже'); e.retryAfter = r.retryAfterSec; throw e; }
  }
  function authenticate(req, needRole) {
    const h = req.headers.authorization || '';
    const m = /^Bearer (.+)$/.exec(h);
    const pl = m && S.verifyToken(o.tokenSecret, m[1], nowSec());
    if (!pl) throw new HttpError(401, 'unauthorized', 'Требуется авторизация');
    const acc = q('SELECT * FROM accounts WHERE id=?').get(pl.sub);
    if (!acc || acc.role !== pl.role) throw new HttpError(401, 'unauthorized', 'Требуется авторизация');
    if (acc.status !== 'active') throw new HttpError(403, 'account_disabled', 'Доступ отключён владельцем');
    if (needRole && acc.role !== needRole) throw new HttpError(403, 'forbidden', 'Недостаточно прав');
    return acc;
  }

  // ---------- HUD ----------
  const hudView = (h, devCode) => ({ hudId: h.hud_id, name: h.name, status: h.status, developerId: devCode, currentVersion: h.current_version, minVersion: h.min_version, type: h.require_license ? 'paid' : 'free', requireLicense: !!h.require_license, createdAt: h.created_at });
  const hudStats = (h) => ({
    installs: q('SELECT COUNT(*) c FROM installations WHERE hud_id=?').get(h.hud_id).c,
    activeLast24h: q('SELECT COUNT(*) c FROM installations WHERE hud_id=? AND last_seen_at>=?').get(h.hud_id, new Date(Date.now() - 86400000).toISOString()).c,
    licenses: q('SELECT COUNT(*) c FROM licenses WHERE hud_id=?').get(h.hud_id).c,
    flaggedLicenses: q('SELECT COUNT(*) c FROM licenses WHERE hud_id=? AND flagged=1').get(h.hud_id).c,
  });
  const devCodeOf = (devId) => q('SELECT code FROM accounts WHERE id=?').get(devId).code;
  function ownedHud(acc, hudId) {   // чужой HUD неотличим от несуществующего (404)
    if (!HUD_ID_RE.test(hudId)) throw new HttpError(404, 'not_found', 'HUD не найден');
    const h = q('SELECT * FROM huds WHERE hud_id=?').get(hudId);
    if (!h || (acc.role !== 'owner' && h.developer_id !== acc.id)) throw new HttpError(404, 'not_found', 'HUD не найден');
    return h;
  }
  const versionDir = (hudId, version) => path.join(artifactsRoot, hudId, version);

  function assertNoFileRefs(cfg) {
    const refs = [cfg.assets.auth, cfg.assets.dialogBackground, ...Object.values(cfg.assets.icons), ...Object.values(cfg.assets.logos), ...Object.values(cfg.assets.weapons)];
    if (refs.some((r) => r && r.file)) throw bad('file_refs_not_allowed', 'Сервер принимает только встроенные картинки (dataUri), не пути к файлам');
  }

  function buildVersion(acc, hud, body) {
    const version = String(body.version || '');
    if (!VERSION_RE.test(version)) throw bad('invalid_version', 'Версия в формате X.Y.Z');
    const latest = q('SELECT version FROM hud_versions WHERE hud_id=?').all(hud.hud_id).map((r) => r.version).sort(S.compareSemver).pop();
    if (latest && S.compareSemver(version, latest) <= 0) throw new HttpError(409, 'version_not_increasing', `Версия должна быть выше ${latest}`);
    let cfg;
    try { cfg = migrate(body.config); } catch (e) { throw bad('invalid_config', e.message); }
    assertNoFileRefs(cfg);
    cfg.hudType = hud.require_license ? 'paid' : 'free'; cfg.hudId = hud.hud_id; cfg.developerId = devCodeOf(hud.developer_id); cfg.version = version; cfg.status = 'draft';   // не доверяем клиенту
    let gen;
    try { gen = generate({ template: o.template, config: cfg, baseDir: null, now: new Date(o.now ? o.now() : Date.now()) }); }
    catch (e) { throw bad('generation_failed', e.message); }
    const manifest = { ...gen.manifest, hudId: hud.hud_id, developerId: cfg.developerId, version };
    delete manifest.signature;
    manifest.keyId = o.signing.keyId || 'k1';
    const signature = S.signObject(o.signing.privateKey, manifest);
    const signedManifest = { ...manifest, signature };
    const files = {
      'hud.js': gen.jsBuffer,
      'config.json': Buffer.from(JSON.stringify(gen.config, null, 2)),
      'manifest.json': Buffer.from(JSON.stringify(signedManifest, null, 2)),
      'checksums.txt': Buffer.from(`${manifest.files[0].sha256}  hud.js\n`),
    };
    return { version, files, manifest: signedManifest, warnings: gen.warnings };
  }

  function storeVersion(hud, built) {
    const dir = versionDir(hud.hud_id, built.version);
    const tmp = dir + '.tmp-' + crypto.randomBytes(4).toString('hex');
    fs.mkdirSync(tmp, { recursive: true });
    try {
      for (const [n, b] of Object.entries(built.files)) fs.writeFileSync(path.join(tmp, n), b);
      fs.mkdirSync(path.dirname(dir), { recursive: true });
      if (fs.existsSync(dir)) throw new HttpError(409, 'version_exists', 'Версия уже существует');
      db.exec('BEGIN');
      try {
        q('INSERT INTO hud_versions(hud_id,version,js_sha256,js_size,manifest_json,created_at) VALUES(?,?,?,?,?,?)')
          .run(hud.hud_id, built.version, built.manifest.files[0].sha256, built.manifest.files[0].size, JSON.stringify(built.manifest), nowIso());
        fs.renameSync(tmp, dir);
        db.exec('COMMIT');
      } catch (e) { db.exec('ROLLBACK'); throw e; }
    } catch (e) {
      fs.rmSync(tmp, { recursive: true, force: true });
      if (/UNIQUE/.test(String(e.message))) throw new HttpError(409, 'version_exists', 'Версия уже существует');
      throw e;
    }
  }

  // ---------- лицензии покупателей ----------
  const hwidPepper = crypto.createHash('sha256').update('hwid:' + o.tokenSecret).digest();
  const hwidHash = (hwid) => crypto.createHmac('sha256', hwidPepper).update(hwid).digest('hex');
  const normKey = (k) => String(k || '').trim().toUpperCase();
  function newLicenseKey() {
    const part = () => Array.from(crypto.randomBytes(5), (b) => KEY_ALPHABET[b % 32]).join('');
    return `PTK-${part()}-${part()}-${part()}-${part()}`;
  }
  const pcId = (hh) => 'PC-' + hh.slice(0, 12);     // короткий неполный идентификатор устройства для показа
  const licView = (l, detail = false) => {
    const acts = q('SELECT hwid_hash,first_seen_at,last_seen_at,loader_version FROM activations WHERE lic_row=? ORDER BY first_seen_at').all(l.id);
    const v = {
      licenseId: l.lic_id, label: l.label, keyPrefix: l.key_prefix, status: l.status, revokeReason: l.revoke_reason, maxDevices: l.max_devices,
      devices: acts.length, flagged: !!l.flagged, deviceAttempts: l.device_attempts, createdAt: l.created_at, revokedAt: l.revoked_at,
    };
    if (detail) {
      v.activations = acts.map((a) => ({ pc: pcId(a.hwid_hash), firstSeenAt: a.first_seen_at, lastSeenAt: a.last_seen_at, loaderVersion: a.loader_version }));
      v.attempts = q('SELECT hwid_hash,count,first_at,last_at FROM license_attempts WHERE lic_row=? ORDER BY last_at DESC LIMIT 50').all(l.id)
        .map((a) => ({ pc: pcId(a.hwid_hash), count: a.count, firstAt: a.first_at, lastAt: a.last_at }));
    }
    return v;
  };
  // record=true — активация/проверка с записью; record=false — только проверка (скачивание артефакта)
  function checkBuyer(hud, licenseKey, hwid, record, loaderVersion, deviceLabel) {
    if (!hud.require_license) return { status: 'active', lic: null, hh: null };
    if (!licenseKey) return { status: 'license_required' };
    const lic = q('SELECT * FROM licenses WHERE key_hash=?').get(S.sha256hex(normKey(licenseKey)));
    if (!lic || lic.hud_id !== hud.hud_id) return { status: 'license_invalid' };
    if (lic.status === 'revoked') return { status: 'license_revoked', lic };
    if (!HWID_RE.test(String(hwid || ''))) throw bad('invalid_hwid', 'hwid: 16–128 символов [A-Za-z0-9_.:-]');
    const hh = hwidHash(hwid);
    const act = q('SELECT 1 FROM activations WHERE lic_row=? AND hwid_hash=?').get(lic.id, hh);
    const t = nowIso();
    if (act) { if (record) q('UPDATE activations SET last_seen_at=?, loader_version=?, device_label=COALESCE(?, device_label) WHERE lic_row=? AND hwid_hash=?').run(t, loaderVersion || null, deviceLabel || null, lic.id, hh); return { status: 'active', lic, hh }; }
    if (!record) return { status: 'not_activated', lic };
    const n = q('SELECT COUNT(*) c FROM activations WHERE lic_row=?').get(lic.id).c;
    if (n >= lic.max_devices) {
      q('UPDATE licenses SET flagged=1, device_attempts=device_attempts+1 WHERE id=?').run(lic.id);
      q(`INSERT INTO activation_attempts(lic_row,hwid_hash,device_label,attempts,first_attempt_at,last_attempt_at) VALUES(?,?,?,1,?,?)
         ON CONFLICT(lic_row,hwid_hash) DO UPDATE SET attempts=attempts+1, last_attempt_at=excluded.last_attempt_at, device_label=COALESCE(excluded.device_label, device_label)`)
        .run(lic.id, hh, deviceLabel || null, t, t);
      q(`INSERT INTO license_attempts(lic_row,hwid_hash,count,first_at,last_at) VALUES(?,?,1,?,?)
         ON CONFLICT(lic_row,hwid_hash) DO UPDATE SET count=count+1, last_at=excluded.last_at`).run(lic.id, hh, t, t);
      audit('system', 'license_device_limit', lic.lic_id, { hudId: hud.hud_id, devices: n });
      return { status: 'device_limit', lic };
    }
    q('INSERT INTO activations(lic_row,hwid_hash,first_seen_at,last_seen_at,loader_version,device_label) VALUES(?,?,?,?,?,?)').run(lic.id, hh, t, t, loaderVersion || null, deviceLabel || null);
    return { status: 'active', lic, hh };
  }

  // ---------- .build для loader ----------
  const BUILD_FILE_NAME = o.buildFileName || 'HudLoader.build';
  function makeBuildFile(hudId, licenseKey, licId) {
    if (!o.publicUrl) throw new HttpError(409, 'public_url_not_configured', 'На сервере не задан PUBLIC_URL (адрес API для loader)');
    return signBlob(o.signing.privateKey, { v: 1, hudId, server: o.publicUrl.replace(/\/+$/, ''), key: licenseKey || '', licId: licId || '', keyId: o.signing.keyId || 'k1', issuedAt: nowSec() });
  }

  // ---------- лицензия ----------
  function licenseFor(hudId, { installationId, loaderVersion, hudVersion, licenseKey, hwid, deviceLabel }) {
    const hud = q('SELECT * FROM huds WHERE hud_id=?').get(hudId);
    if (!hud) throw new HttpError(404, 'not_found', 'HUD не найден');
    const dev = q('SELECT * FROM accounts WHERE id=?').get(hud.developer_id);
    const cur = hud.current_version ? q('SELECT * FROM hud_versions WHERE hud_id=? AND version=?').get(hudId, hud.current_version) : null;
    let status = 'active';
    if (hud.status !== 'active') status = hud.status;
    else if (dev.status !== 'active') status = 'blocked';
    else if (!cur) status = 'no_release';
    else if (S.compareSemver(loaderVersion, o.minLoaderVersion) < 0 || (hud.min_version && hudVersion && S.compareSemver(hudVersion, hud.min_version) < 0)) status = 'update_required';
    let buyer = { lic: null, hh: null };
    if (status === 'active' || status === 'update_required') {
      const b = checkBuyer(hud, licenseKey, hwid, true, loaderVersion, deviceLabel);
      if (b.status !== 'active') status = b.status; else buyer = b;
    }
    const issued = nowSec();
    const lic = {
      licenseId: `LIC-${hudId}`, hudId, developerId: dev.code, installationId, status, issuedAt: issued,
      expiresAt: issued + Math.floor(o.graceHours * 3600), allowedVersion: cur ? cur.version : null, minHudVersion: hud.min_version || null,
      minLoaderVersion: o.minLoaderVersion, artifactSha256: cur ? cur.js_sha256 : null, policyVersion: o.policyVersion, keyId: o.signing.keyId || 'k1',
      buyerLicenseId: buyer.lic ? buyer.lic.lic_id : null, deviceHash: buyer.hh ? buyer.hh.slice(0, 16) : null,
    };
    return { hud, license: lic, signature: S.signObject(o.signing.privateKey, lic) };
  }

  // ---------- маршруты ----------
  const R = [];
  const route = (method, re, opts, fn) => R.push({ method, re, opts, fn });

  route('GET', /^\/api\/v1\/health$/, {}, () => ({ status: 200, body: { status: 'ok' } }));

  route('POST', /^\/api\/v1\/auth\/login$/, { public: true }, async ({ req, body }) => {
    throttle('login-ip:' + clientIp(req), o.limits.loginIp);
    const login = String(body.login || ''), password = String(body.password || '');
    if (!login || !password || login.length > 64 || password.length > 256) throw bad('invalid_credentials_format', 'Введите логин и пароль');
    throttle('login-acc:' + login.toLowerCase(), o.limits.loginAccount);
    const acc = q('SELECT * FROM accounts WHERE login=?').get(login);
    if (!acc) { await S.dummyVerify(password); audit('anonymous', 'login_failed', login); throw new HttpError(401, 'invalid_credentials', 'Неверный логин или пароль'); }
    if (!(await S.verifyPassword(password, acc.password_hash))) { audit('anonymous', 'login_failed', acc.code); throw new HttpError(401, 'invalid_credentials', 'Неверный логин или пароль'); }
    if (acc.status !== 'active') { audit(acc.code, 'login_denied_disabled', acc.code); throw new HttpError(403, 'account_disabled', 'Доступ отключён владельцем'); }
    audit(acc.code, 'login', acc.code);
    return { status: 200, body: issueTokens(acc) };
  });

  route('POST', /^\/api\/v1\/auth\/refresh$/, { public: true }, async ({ req, body }) => {
    throttle('refresh-ip:' + clientIp(req), o.limits.loginIp);
    const tok = String(body.refreshToken || '');
    const row = q('SELECT * FROM refresh_tokens WHERE token_hash=?').get(S.sha256hex(tok));
    if (!row) throw new HttpError(401, 'invalid_refresh', 'Сессия недействительна');
    if (row.revoked || row.used || row.expires_at <= nowSec()) {
      q('UPDATE refresh_tokens SET revoked=1 WHERE family=?').run(row.family);   // повторное использование = компрометация цепочки
      throw new HttpError(401, 'invalid_refresh', 'Сессия недействительна');
    }
    const acc = q('SELECT * FROM accounts WHERE id=?').get(row.account_id);
    if (!acc || acc.status !== 'active') throw new HttpError(403, 'account_disabled', 'Доступ отключён владельцем');
    q('UPDATE refresh_tokens SET used=1 WHERE id=?').run(row.id);
    return { status: 200, body: issueTokens(acc, row.family) };
  });

  route('POST', /^\/api\/v1\/auth\/logout$/, { auth: true }, ({ acc, body }) => {
    const row = q('SELECT * FROM refresh_tokens WHERE token_hash=? AND account_id=?').get(S.sha256hex(String(body.refreshToken || '')), acc.id);
    if (row) q('UPDATE refresh_tokens SET revoked=1 WHERE family=?').run(row.family);
    audit(acc.code, 'logout', acc.code);
    return { status: 200, body: { ok: true } };
  });

  route('GET', /^\/api\/v1\/auth\/me$/, { auth: true }, ({ acc }) => ({ status: 200, body: publicAccount(acc) }));

  route('POST', /^\/api\/v1\/auth\/change-password$/, { auth: true }, async ({ acc, body }) => {
    if (!(await S.verifyPassword(String(body.currentPassword || ''), acc.password_hash))) throw new HttpError(401, 'invalid_credentials', 'Неверный текущий пароль');
    const pe = S.validatePasswordPolicy(body.newPassword); if (pe) throw bad('weak_password', pe);
    q('UPDATE accounts SET password_hash=?, must_change_password=0 WHERE id=?').run(await S.hashPassword(body.newPassword), acc.id);
    revokeAllTokens(acc.id);
    audit(acc.code, 'change_password', acc.code);
    return { status: 200, body: { ok: true } };
  });

  route('GET', /^\/api\/v1\/developers\/me\/huds$/, { auth: true }, ({ acc }) => ({
    status: 200, body: { huds: q('SELECT * FROM huds WHERE developer_id=? ORDER BY id').all(acc.id).map((h) => ({ ...hudView(h, acc.code), stats: hudStats(h) })) },
  }));

  route('POST', /^\/api\/v1\/huds$/, { auth: true }, ({ acc, body }) => {
    if (acc.role !== 'owner' && !acc.can_create_hud) throw new HttpError(403, 'hud_creation_forbidden', 'Создание новых HUD запрещено владельцем');
    const name = String(body.name || '').trim();
    if (name.length < 1 || name.length > 64 || /[\u0000-\u001f<>]/.test(name)) throw bad('invalid_name', 'Название HUD: 1–64 символа без служебных символов');
    const type = body.type === undefined ? 'free' : body.type;
    if (type !== 'free' && type !== 'paid') throw bad('invalid_type', 'type: free | paid');
    const hudId = 'HUD-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    q('INSERT INTO huds(hud_id,developer_id,name,require_license,created_at) VALUES(?,?,?,?,?)').run(hudId, acc.id, name, type === 'paid' ? 1 : 0, nowIso());
    audit(acc.code, 'hud_create', hudId, { name, type });
    return { status: 201, body: hudView(q('SELECT * FROM huds WHERE hud_id=?').get(hudId), acc.code) };
  });

  route('GET', /^\/api\/v1\/huds\/([^/]+)$/, { auth: true }, ({ acc, m }) => {
    const h = ownedHud(acc, m[1]);
    const versions = q('SELECT version,status,js_sha256,js_size,mirror,created_at,published_at FROM hud_versions WHERE hud_id=? ORDER BY id').all(h.hud_id)
      .map((v) => ({ version: v.version, status: v.status, sha256: v.js_sha256, size: v.js_size, mirror: v.mirror, createdAt: v.created_at, publishedAt: v.published_at }));
    return { status: 200, body: { ...hudView(h, devCodeOf(h.developer_id)), stats: hudStats(h), versions } };
  });

  route('POST', /^\/api\/v1\/huds\/([^/]+)\/versions$/, { auth: true, maxBody: 'version' }, ({ acc, m, body }) => {
    const h = ownedHud(acc, m[1]);
    if (h.status !== 'active') throw new HttpError(403, 'hud_revoked', 'HUD отозван или заблокирован');
    const built = buildVersion(acc, h, body);
    storeVersion(h, built);
    audit(acc.code, 'version_create', h.hud_id, { version: built.version, sha256: built.manifest.files[0].sha256 });
    return { status: 201, body: { hudId: h.hud_id, version: built.version, status: 'draft', sha256: built.manifest.files[0].sha256, warnings: built.warnings, manifest: built.manifest } };
  });

  route('POST', /^\/api\/v1\/huds\/([^/]+)\/publish$/, { auth: true }, async ({ acc, m, body }) => {
    const h = ownedHud(acc, m[1]);
    if (h.status !== 'active') throw new HttpError(403, 'hud_revoked', 'HUD отозван или заблокирован');
    const version = String(body.version || '');
    if (!VERSION_RE.test(version)) throw bad('invalid_version', 'Версия в формате X.Y.Z');
    const v = q('SELECT * FROM hud_versions WHERE hud_id=? AND version=?').get(h.hud_id, version);
    if (!v) throw new HttpError(404, 'not_found', 'Версия не найдена');
    if (v.status === 'published') throw new HttpError(409, 'already_published', 'Версия уже опубликована (неизменяема)');
    const dir = versionDir(h.hud_id, version);
    const files = {}; for (const n of ['hud.js', 'config.json', 'manifest.json', 'checksums.txt']) files[n] = fs.readFileSync(path.join(dir, n));
    if (S.sha256hex(files['hud.js']) !== v.js_sha256) throw new HttpError(500, 'integrity_error', 'Хеш артефакта не совпал, публикация остановлена');
    let mirror = 'none';
    if (o.registry && h.require_license) {   // платный HUD нельзя зеркалировать в публичный репозиторий: любой скачал бы hud.js с картинками
      let priv = false;
      try { priv = typeof o.registry.isPrivate === 'function' && (await o.registry.isPrivate()) === true; }
      catch (e) { audit(acc.code, 'publish_failed', h.hud_id, { version, error: String(e.message).slice(0, 200) }); throw new HttpError(502, 'mirror_failed', 'Не удалось проверить приватность GitHub-репозитория; версия осталась черновиком'); }
      if (!priv) { audit(acc.code, 'publish_blocked_public_registry', h.hud_id, { version }); throw new HttpError(409, 'registry_public', 'Платный HUD нельзя публиковать в публичный GitHub-репозиторий. Сделайте репозиторий приватным'); }
    }
    if (o.registry) {
      try { mirror = (await o.registry.publish(h.hud_id, version, files)).mirror; }
      catch (e) { audit(acc.code, 'publish_failed', h.hud_id, { version, error: String(e.message).slice(0, 200) }); throw new HttpError(502, 'mirror_failed', 'Не удалось опубликовать в GitHub-реестр; версия осталась черновиком'); }
    }
    db.exec('BEGIN');
    try {
      q('UPDATE hud_versions SET status=\'published\', mirror=?, published_at=? WHERE id=?').run(mirror, nowIso(), v.id);
      if (!h.current_version || S.compareSemver(version, h.current_version) > 0) q('UPDATE huds SET current_version=? WHERE id=?').run(version, h.id);
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    audit(acc.code, 'version_publish', h.hud_id, { version, mirror });
    return { status: 200, body: { hudId: h.hud_id, version, status: 'published', mirror } };
  });

  const artifactGuard = (hudId, version) => {
    if (!HUD_ID_RE.test(hudId) || !VERSION_RE.test(version)) throw new HttpError(404, 'not_found', 'Не найдено');
    const h = q('SELECT * FROM huds WHERE hud_id=?').get(hudId);
    const v = h && q('SELECT * FROM hud_versions WHERE hud_id=? AND version=? AND status=\'published\'').get(hudId, version);
    if (!h || !v) throw new HttpError(404, 'not_found', 'Не найдено');
    const dev = q('SELECT status FROM accounts WHERE id=?').get(h.developer_id);
    if (h.status !== 'active' || dev.status !== 'active') throw new HttpError(403, 'hud_revoked', 'HUD отозван или заблокирован');
    return { h, v };
  };
  route('GET', /^\/api\/v1\/artifacts\/([^/]+)\/([^/]+)\/manifest$/, { public: true, bucket: 'license' }, ({ m }) => {
    const { v } = artifactGuard(m[1], m[2]); return { status: 200, body: JSON.parse(v.manifest_json) };
  });
  route('GET', /^\/api\/v1\/artifacts\/([^/]+)\/([^/]+)\/download$/, { public: true, bucket: 'license' }, ({ req, m }) => {
    const { h, v } = artifactGuard(m[1], m[2]);
    if (h.require_license) {
      const b = checkBuyer(h, req.headers['x-license-key'], req.headers['x-hwid'], false);
      if (b.status !== 'active') throw new HttpError(403, b.status, 'Нет действующей лицензии для этого устройства');
    }
    return { status: 200, body: fs.readFileSync(path.join(versionDir(m[1], m[2]), 'hud.js')), headers: { 'Content-Type': 'application/javascript; charset=utf-8', 'X-Content-Sha256': v.js_sha256 } };
  });

  route('POST', /^\/api\/v1\/license\/validate$/, { public: true, bucket: 'license' }, ({ body }) => {
    const installationId = String(body.installationId || ''), hudId = String(body.hudId || '');
    const loaderVersion = String(body.loaderVersion || ''), hudVersion = body.hudVersion == null ? null : String(body.hudVersion);
    if (!INSTALL_RE.test(installationId)) throw bad('invalid_installation_id', 'installationId: 16–64 символа [A-Za-z0-9-]');
    if (!HUD_ID_RE.test(hudId)) throw new HttpError(404, 'not_found', 'HUD не найден');
    if (!VERSION_RE.test(loaderVersion) || (hudVersion !== null && !VERSION_RE.test(hudVersion))) throw bad('invalid_version', 'Версия в формате X.Y.Z');
    const licenseKey = body.licenseKey == null ? null : String(body.licenseKey).slice(0, 64);
    const hwid = body.hwid == null ? null : String(body.hwid);
    const dl = body.deviceLabel == null ? null : String(body.deviceLabel).trim();
    const deviceLabel = dl && LABEL_RE.test(dl) ? dl : null;
    const { license, signature } = licenseFor(hudId, { installationId, loaderVersion, hudVersion, licenseKey, hwid, deviceLabel });
    const t = nowIso();
    q(`INSERT INTO installations(install_id,hud_id,loader_version,hud_version,first_seen_at,last_seen_at,last_status) VALUES(?,?,?,?,?,?,?)
       ON CONFLICT(install_id,hud_id) DO UPDATE SET loader_version=excluded.loader_version, hud_version=excluded.hud_version, last_seen_at=excluded.last_seen_at, last_status=excluded.last_status`)
      .run(installationId, hudId, loaderVersion, hudVersion, t, t, license.status);
    return { status: 200, body: { status: license.status, license, signature, blob: signBlob(o.signing.privateKey, license), graceHours: o.graceHours } };
  });

  route('POST', /^\/api\/v1\/huds\/([^/]+)\/status$/, { auth: true }, ({ acc, m, body }) => {
    const h = ownedHud(acc, m[1]);
    if (body.status !== 'active' && body.status !== 'revoked') throw bad('invalid_status', 'active | revoked');
    if (h.status === 'blocked' && acc.role !== 'owner') throw new HttpError(403, 'hud_blocked', 'HUD заблокирован владельцем платформы');
    q('UPDATE huds SET status=? WHERE id=?').run(body.status, h.id);
    audit(acc.code, body.status === 'revoked' ? 'hud_disable' : 'hud_enable', h.hud_id);
    return { status: 200, body: hudView(q('SELECT * FROM huds WHERE id=?').get(h.id), devCodeOf(h.developer_id)) };
  });
  // ---- лицензии покупателей (владелец HUD или owner) ----
  route('PATCH', /^\/api\/v1\/huds\/([^/]+)\/settings$/, { auth: true }, ({ acc, m, body }) => {
    const h = ownedHud(acc, m[1]);
    if (body.type !== undefined && body.type !== 'free' && body.type !== 'paid') throw bad('invalid_type', 'type: free | paid');
    const paid = body.type !== undefined ? body.type === 'paid' : (body.requireLicense !== undefined ? !!body.requireLicense : null);
    if (paid !== null) q('UPDATE huds SET require_license=? WHERE id=?').run(paid ? 1 : 0, h.id);
    audit(acc.code, 'hud_settings', h.hud_id, { type: paid === null ? undefined : (paid ? 'paid' : 'free') });
    return { status: 200, body: hudView(q('SELECT * FROM huds WHERE id=?').get(h.id), devCodeOf(h.developer_id)) };
  });
  route('POST', /^\/api\/v1\/huds\/([^/]+)\/licenses$/, { auth: true }, ({ acc, m, body }) => {
    const h = ownedHud(acc, m[1]);
    if (!h.require_license) throw bad('hud_is_free', 'HUD бесплатный: ключи не нужны. Переключите тип на paid, чтобы выдавать ключи');
    const label = String(body.label || '').trim();
    if (label.length < 1 || label.length > 64 || /[\u0000-\u001f<>]/.test(label)) throw bad('invalid_label', 'Метка покупателя: 1–64 символа');
    const maxDevices = body.maxDevices === undefined ? 1 : body.maxDevices;
    if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 10) throw bad('invalid_max_devices', 'maxDevices: целое 1–10');
    const key = newLicenseKey(); const licId = 'LK-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    q('INSERT INTO licenses(lic_id,hud_id,key_hash,key_prefix,label,max_devices,created_at) VALUES(?,?,?,?,?,?,?)')
      .run(licId, h.hud_id, S.sha256hex(key), key.slice(0, 9), label, maxDevices, nowIso());
    audit(acc.code, 'license_create', licId, { hudId: h.hud_id, label });
    return { status: 201, body: { ...licView(q('SELECT * FROM licenses WHERE lic_id=?').get(licId)), licenseKey: key, buildFileName: BUILD_FILE_NAME, buildFile: makeBuildFile(h.hud_id, key, licId), note: 'Ключ и .build показываются один раз' } };
  });
  route('GET', /^\/api\/v1\/huds\/([^/]+)\/licenses$/, { auth: true }, ({ acc, m }) => {
    const h = ownedHud(acc, m[1]);
    return { status: 200, body: { licenses: q('SELECT * FROM licenses WHERE hud_id=? ORDER BY id').all(h.hud_id).map((l) => licView(l, true)) } };
  });
  const licOf = (acc, hudId, licId) => {
    const h = ownedHud(acc, hudId);
    const l = LIC_ID_RE.test(licId) && q('SELECT * FROM licenses WHERE lic_id=? AND hud_id=?').get(licId, h.hud_id);
    if (!l) throw new HttpError(404, 'not_found', 'Лицензия не найдена');
    return l;
  };
  route('POST', /^\/api\/v1\/huds\/([^/]+)\/licenses\/([^/]+)\/revoke$/, { auth: true }, ({ acc, m, body }) => {
    const l = licOf(acc, m[1], m[2]);
    const reason = String(body.reason || '').slice(0, 200);
    q('UPDATE licenses SET status=\'revoked\', revoke_reason=?, revoked_at=? WHERE id=?').run(reason || null, nowIso(), l.id);
    audit(acc.code, 'license_revoke', l.lic_id, { hudId: l.hud_id, reason });
    return { status: 200, body: licView(q('SELECT * FROM licenses WHERE id=?').get(l.id)) };
  });
  route('POST', /^\/api\/v1\/huds\/([^/]+)\/licenses\/([^/]+)\/restore$/, { auth: true }, ({ acc, m }) => {
    const l = licOf(acc, m[1], m[2]);
    q('UPDATE licenses SET status=\'active\', revoke_reason=NULL, revoked_at=NULL WHERE id=?').run(l.id);
    audit(acc.code, 'license_restore', l.lic_id, { hudId: l.hud_id });
    return { status: 200, body: licView(q('SELECT * FROM licenses WHERE id=?').get(l.id)) };
  });
  route('POST', /^\/api\/v1\/huds\/([^/]+)\/licenses\/([^/]+)\/reset-devices$/, { auth: true }, ({ acc, m }) => {
    const l = licOf(acc, m[1], m[2]);
    q('DELETE FROM activations WHERE lic_row=?').run(l.id);
    q('DELETE FROM license_attempts WHERE lic_row=?').run(l.id);
    q('UPDATE licenses SET flagged=0, device_attempts=0 WHERE id=?').run(l.id);
    audit(acc.code, 'license_reset_devices', l.lic_id, { hudId: l.hud_id });
    return { status: 200, body: licView(q('SELECT * FROM licenses WHERE id=?').get(l.id)) };
  });

  route('POST', /^\/api\/v1\/huds\/([^/]+)\/licenses\/([^/]+)\/rotate-key$/, { auth: true }, ({ acc, m }) => {
    const l = licOf(acc, m[1], m[2]);
    const key = newLicenseKey();
    q('UPDATE licenses SET key_hash=?, key_prefix=? WHERE id=?').run(S.sha256hex(key), key.slice(0, 9), l.id);
    q('DELETE FROM activations WHERE lic_row=?').run(l.id);
    q('DELETE FROM license_attempts WHERE lic_row=?').run(l.id);
    q('UPDATE licenses SET flagged=0, device_attempts=0 WHERE id=?').run(l.id);
    audit(acc.code, 'license_rotate_key', l.lic_id, { hudId: l.hud_id });
    return { status: 200, body: { ...licView(q('SELECT * FROM licenses WHERE id=?').get(l.id)), licenseKey: key, buildFileName: BUILD_FILE_NAME, buildFile: makeBuildFile(l.hud_id, key, l.lic_id), note: 'Старый ключ больше не действует' } };
  });
  route('GET', /^\/api\/v1\/huds\/([^/]+)\/build$/, { auth: true }, ({ acc, m }) => {
    const h = ownedHud(acc, m[1]);
    if (h.require_license) throw bad('license_build_required', 'Для этого HUD .build выдаётся вместе с ключом покупателя');
    return { status: 200, body: { buildFileName: BUILD_FILE_NAME, buildFile: makeBuildFile(h.hud_id, '', '') } };
  });
  // ---- веб-панель администратора (статика, без секретов; вся работа идёт через API после входа) ----
  const PANEL_DIR = path.join(__dirname, '..', 'panel');
  const PANEL_FILES = { '': ['index.html', 'text/html; charset=utf-8'], 'index.html': ['index.html', 'text/html; charset=utf-8'], 'panel.js': ['panel.js', 'application/javascript; charset=utf-8'], 'panel.css': ['panel.css', 'text/css; charset=utf-8'] };
  const PANEL_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
  route('GET', /^\/panel\/?([A-Za-z.]*)$/, { public: true }, ({ m }) => {
    const f = Object.hasOwn(PANEL_FILES, m[1]) ? PANEL_FILES[m[1]] : null; if (!f) throw new HttpError(404, 'not_found', 'Не найдено');
    return { status: 200, body: fs.readFileSync(path.join(PANEL_DIR, f[0])), headers: { 'Content-Type': f[1], 'Content-Security-Policy': PANEL_CSP, 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' } };
  });

  const devicesOf = (l) => ({
    devices: q('SELECT hwid_hash,device_label,first_seen_at,last_seen_at,loader_version FROM activations WHERE lic_row=? ORDER BY first_seen_at').all(l.id)
      .map((d) => ({ deviceId: d.hwid_hash.slice(0, 12), label: d.device_label, firstSeenAt: d.first_seen_at, lastSeenAt: d.last_seen_at, loaderVersion: d.loader_version })),
    attempts: q('SELECT hwid_hash,device_label,attempts,first_attempt_at,last_attempt_at FROM activation_attempts WHERE lic_row=? ORDER BY last_attempt_at DESC').all(l.id)
      .map((d) => ({ deviceId: d.hwid_hash.slice(0, 12), label: d.device_label, attempts: d.attempts, firstAttemptAt: d.first_attempt_at, lastAttemptAt: d.last_attempt_at })),
  });
  route('GET', /^\/api\/v1\/huds\/([^/]+)\/licenses\/([^/]+)\/devices$/, { auth: true }, ({ acc, m }) => ({ status: 200, body: devicesOf(licOf(acc, m[1], m[2])) }));
  route('GET', /^\/api\/v1\/admin\/huds\/([^/]+)\/overview$/, { auth: 'owner' }, ({ m }) => {
    const h = hudByIdAdmin(m[1]);
    const inst = q('SELECT COUNT(*) c FROM installations WHERE hud_id=?').get(h.hud_id).c;
    const recent = q('SELECT install_id,loader_version,hud_version,first_seen_at,last_seen_at,last_status FROM installations WHERE hud_id=? ORDER BY last_seen_at DESC LIMIT 50').all(h.hud_id)
      .map((r) => ({ installationId: r.install_id, loaderVersion: r.loader_version, hudVersion: r.hud_version, firstSeenAt: r.first_seen_at, lastSeenAt: r.last_seen_at, lastStatus: r.last_status }));
    const versions = q('SELECT version,status,created_at,published_at FROM hud_versions WHERE hud_id=? ORDER BY id DESC').all(h.hud_id)
      .map((v) => ({ version: v.version, status: v.status, createdAt: v.created_at, publishedAt: v.published_at }));
    const licenses = q('SELECT * FROM licenses WHERE hud_id=? ORDER BY id').all(h.hud_id).map((l) => ({ ...licView(l), ...devicesOf(l) }));
    return { status: 200, body: { hud: { ...hudView(h, devCodeOf(h.developer_id)), developerLogin: q('SELECT login FROM accounts WHERE id=?').get(h.developer_id).login }, installations: { total: inst, recent }, versions, licenses } };
  });
  // ---- админ ----
  const devRow = (a) => ({ ...publicAccount(a), hudCount: q('SELECT COUNT(*) c FROM huds WHERE developer_id=?').get(a.id).c });
  route('GET', /^\/api\/v1\/admin\/developers$/, { auth: 'owner' }, () => ({ status: 200, body: { developers: q('SELECT * FROM accounts WHERE role=\'developer\' ORDER BY id').all().map(devRow) } }));
  route('POST', /^\/api\/v1\/admin\/developers$/, { auth: 'owner' }, async ({ acc, body }) => {
    const temp = body.password ? null : S.randomPassword();
    const d = await createAccount({ login: String(body.login || ''), password: body.password || temp, role: 'developer' });
    q('UPDATE accounts SET must_change_password=? WHERE id=?').run(temp ? 1 : 0, d.id);
    audit(acc.code, 'developer_create', d.code, { login: d.login });
    return { status: 201, body: { ...devRow(q('SELECT * FROM accounts WHERE id=?').get(d.id)), temporaryPassword: temp } };
  });
  route('PATCH', /^\/api\/v1\/admin\/developers\/([^/]+)\/status$/, { auth: 'owner' }, ({ acc, m, body }) => {
    const d = accByCode(m[1]); if (!d) throw new HttpError(404, 'not_found', 'Разработчик не найден');
    if (body.status !== undefined) {
      if (!['active', 'disabled', 'archived'].includes(body.status)) throw bad('invalid_status', 'active | disabled | archived');
      q('UPDATE accounts SET status=? WHERE id=?').run(body.status, d.id);
      if (body.status !== 'active') revokeAllTokens(d.id);
    }
    if (body.canCreateHud !== undefined) q('UPDATE accounts SET can_create_hud=? WHERE id=?').run(body.canCreateHud ? 1 : 0, d.id);
    audit(acc.code, 'developer_update', d.code, { status: body.status, canCreateHud: body.canCreateHud });
    return { status: 200, body: devRow(q('SELECT * FROM accounts WHERE id=?').get(d.id)) };
  });
  route('DELETE', /^\/api\/v1\/admin\/developers\/([^/]+)$/, { auth: 'owner' }, ({ acc, m }) => {   // мягкое удаление = архив
    const d = accByCode(m[1]); if (!d) throw new HttpError(404, 'not_found', 'Разработчик не найден');
    q('UPDATE accounts SET status=\'archived\' WHERE id=?').run(d.id); revokeAllTokens(d.id);
    audit(acc.code, 'developer_archive', d.code);
    return { status: 200, body: devRow(q('SELECT * FROM accounts WHERE id=?').get(d.id)) };
  });
  route('POST', /^\/api\/v1\/admin\/developers\/([^/]+)\/reset-password$/, { auth: 'owner' }, async ({ acc, m }) => {
    const d = accByCode(m[1]); if (!d) throw new HttpError(404, 'not_found', 'Разработчик не найден');
    const temp = S.randomPassword();
    q('UPDATE accounts SET password_hash=?, must_change_password=1 WHERE id=?').run(await S.hashPassword(temp), d.id);
    revokeAllTokens(d.id);
    audit(acc.code, 'developer_reset_password', d.code);
    return { status: 200, body: { id: d.code, temporaryPassword: temp } };
  });
  route('GET', /^\/api\/v1\/admin\/huds$/, { auth: 'owner' }, () => ({
    status: 200, body: { huds: q('SELECT * FROM huds ORDER BY id').all().map((h) => ({ ...hudView(h, devCodeOf(h.developer_id)), stats: hudStats(h) })) },
  }));
  const hudByIdAdmin = (id) => { const h = HUD_ID_RE.test(id) && q('SELECT * FROM huds WHERE hud_id=?').get(id); if (!h) throw new HttpError(404, 'not_found', 'HUD не найден'); return h; };
  route('PATCH', /^\/api\/v1\/admin\/huds\/([^/]+)\/status$/, { auth: 'owner' }, ({ acc, m, body }) => {
    const h = hudByIdAdmin(m[1]);
    if (body.status !== undefined) { if (!['active', 'blocked', 'revoked'].includes(body.status)) throw bad('invalid_status', 'active | blocked | revoked'); q('UPDATE huds SET status=? WHERE id=?').run(body.status, h.id); }
    if (body.minVersion !== undefined) {
      if (body.minVersion !== null && !VERSION_RE.test(String(body.minVersion))) throw bad('invalid_version', 'Версия в формате X.Y.Z');
      q('UPDATE huds SET min_version=? WHERE id=?').run(body.minVersion, h.id);
    }
    audit(acc.code, 'hud_status', h.hud_id, { status: body.status, minVersion: body.minVersion });
    return { status: 200, body: hudView(q('SELECT * FROM huds WHERE id=?').get(h.id), devCodeOf(h.developer_id)) };
  });
  route('POST', /^\/api\/v1\/admin\/huds\/([^/]+)\/revoke$/, { auth: 'owner' }, ({ acc, m }) => {
    const h = hudByIdAdmin(m[1]); q('UPDATE huds SET status=\'revoked\' WHERE id=?').run(h.id);
    audit(acc.code, 'hud_revoke', h.hud_id);
    return { status: 200, body: hudView(q('SELECT * FROM huds WHERE id=?').get(h.id), devCodeOf(h.developer_id)) };
  });
  route('GET', /^\/api\/v1\/admin\/installations$/, { auth: 'owner', query: true }, ({ url }) => {
    const hudId = url.searchParams.get('hudId');
    const rows = hudId ? q('SELECT * FROM installations WHERE hud_id=? ORDER BY last_seen_at DESC LIMIT 500').all(hudId) : q('SELECT * FROM installations ORDER BY last_seen_at DESC LIMIT 500').all();
    return { status: 200, body: { installations: rows.map((r) => ({ installationId: r.install_id, hudId: r.hud_id, loaderVersion: r.loader_version, hudVersion: r.hud_version, firstSeenAt: r.first_seen_at, lastSeenAt: r.last_seen_at, lastStatus: r.last_status })) } };
  });
  route('GET', /^\/api\/v1\/admin\/audit-logs$/, { auth: 'owner', query: true }, ({ url }) => {
    const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 1), 1000);
    return { status: 200, body: { logs: q('SELECT id,ts,actor,action,target,details FROM audit_logs ORDER BY id DESC LIMIT ?').all(limit) } };
  });

  // ---------- сервер ----------
  async function handle(req, res) {
    const traceId = crypto.randomUUID();
    try {
      const url = new URL(req.url, 'http://x');
      throttle('gen:' + clientIp(req), o.limits.general);
      const r = R.find((x) => x.method === req.method && x.re.test(url.pathname));
      if (!r) throw new HttpError(404, 'not_found', 'Не найдено');
      const m = r.re.exec(url.pathname);
      if (r.opts.bucket === 'license') throttle('lic:' + clientIp(req), o.limits.license);
      let acc = null;
      if (r.opts.auth) acc = authenticate(req, r.opts.auth === true ? null : r.opts.auth);
      let body = {};
      if (req.method === 'POST' || req.method === 'PATCH') body = await readJson(req, r.opts.maxBody === 'version' ? o.maxVersionBodyBytes : o.maxBodyBytes);
      const out = await r.fn({ req, res, acc, m: m.map(decodeURIComponent), body, url });
      send(res, out.status, out.body, traceId, out.headers);
    } catch (e) {
      if (e instanceof HttpError) {
        send(res, e.status, { code: e.code, message: e.message, traceId }, traceId, e.retryAfter ? { 'Retry-After': String(e.retryAfter) } : {});
      } else {
        console.error(`[${traceId}]`, e && e.message);
        send(res, 500, { code: 'internal_error', message: 'Внутренняя ошибка сервера', traceId }, traceId);
      }
    }
  }

  const server = http.createServer((req, res) => { handle(req, res); });
  server.requestTimeout = 120000; server.headersTimeout = 20000;
  return {
    server, db, createAccount, audit, limiter,
    listen: (port = 0, host = '127.0.0.1') => new Promise((ok) => server.listen(port, host, () => ok(server.address()))),
    close: () => new Promise((ok) => { server.close(() => { db.close(); ok(); }); server.closeAllConnections && server.closeAllConnections(); }),
  };
}
module.exports = { createApp, HttpError };
