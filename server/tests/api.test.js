'use strict';
const test = require('node:test'); const assert = require('node:assert');
const fs = require('fs'); const os = require('os'); const path = require('path');
const { createApp } = require('../src/app');
const S = require('../src/security');
const { GithubRegistry, gitBlobSha } = require('../src/registry');
const { makePng } = require('../../tests/helpers');
const { openBlob, signBlob, rawPublicKey } = require('../src/blob');

const TEMPLATE = fs.readFileSync(path.join(__dirname, '..', '..', 'templates', 'hud.template.js'), 'utf8');
const KEYS = S.generateSigningKeys();
const png = makePng(4, 4, [255, 0, 255, 255]);
const uri = (b) => `data:image/png;base64,${b.toString('base64')}`;
const INSTALL = 'a1b2c3d4-e5f6-4789-abcd-0123456789ab';

async function boot(extra = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pitachok-'));
  const app = createApp({ dataDir, dbFile: ':memory:', tokenSecret: 'test-secret-test-secret', signing: { ...KEYS, keyId: 'k1' }, template: TEMPLATE, publicUrl: 'https://api.example.com', ...extra });
  const addr = await app.listen(0);
  const base = `http://127.0.0.1:${addr.port}/api/v1`;
  const api = async (method, p, body, token, raw) => {
    const r = await fetch(base + p, { method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
    if (raw) return r;
    return { status: r.status, body: await r.json().catch(() => null), headers: r.headers };
  };
  const owner = await app.createAccount({ login: 'owner', password: 'Owner-pass-12345', role: 'owner' });
  const login = async (l, p) => (await api('POST', '/auth/login', { login: l, password: p })).body;
  const ownerTok = (await login('owner', 'Owner-pass-12345')).accessToken;
  const mkDev = async (name, canCreate = true) => {
    const r = await api('POST', '/admin/developers', { login: name, password: name + '-pass-12345' }, ownerTok);
    if (!canCreate) await api('PATCH', `/admin/developers/${r.body.id}/status`, { canCreateHud: false }, ownerTok);
    const t = await login(name, name + '-pass-12345');
    return { code: r.body.id, tok: t.accessToken, refresh: t.refreshToken };
  };
  return { app, api, base, ownerTok, mkDev, login, owner, dataDir };
}
const cfgWith = (extra = {}) => ({ schemaVersion: 1, hudId: 'HUD-EVIL', developerId: 'DEV-999', version: '9.9.9', status: 'published',
  assets: { auth: { dataUri: uri(png) }, icons: {}, logos: {}, weapons: {}, dialogBackground: null }, colors: {}, radar: { shape: 'round' }, dialogStyle: {}, ...extra });

test('аутентификация: вход, неверный пароль, пароли не хранятся открыто', async () => {
  const t = await boot();
  try {
    const ok = await t.api('POST', '/auth/login', { login: 'owner', password: 'Owner-pass-12345' });
    assert.strictEqual(ok.status, 200); assert.ok(ok.body.accessToken && ok.body.refreshToken);
    const badPw = await t.api('POST', '/auth/login', { login: 'owner', password: 'wrong-password' });
    const noUser = await t.api('POST', '/auth/login', { login: 'nobody', password: 'wrong-password' });
    assert.strictEqual(badPw.status, 401); assert.deepStrictEqual(badPw.body.message, noUser.body.message);
    assert.ok(badPw.body.traceId);
    const row = t.app.db.prepare('SELECT password_hash FROM accounts WHERE login=?').get('owner');
    assert.ok(row.password_hash.startsWith('scrypt$') && !row.password_hash.includes('Owner-pass'));
    assert.strictEqual((await t.api('GET', '/auth/me', undefined, ok.body.accessToken)).body.role, 'owner');
    assert.strictEqual((await t.api('GET', '/auth/me')).status, 401);
    assert.strictEqual((await t.api('GET', '/auth/me', undefined, ok.body.accessToken + 'x')).status, 401);
  } finally { await t.app.close(); }
});

test('refresh: ротация, повторное использование блокирует цепочку, logout отзывает', async () => {
  const t = await boot();
  try {
    const l = await t.login('owner', 'Owner-pass-12345');
    const r1 = await t.api('POST', '/auth/refresh', { refreshToken: l.refreshToken });
    assert.strictEqual(r1.status, 200); assert.notStrictEqual(r1.body.refreshToken, l.refreshToken);
    const reuse = await t.api('POST', '/auth/refresh', { refreshToken: l.refreshToken });
    assert.strictEqual(reuse.status, 401);
    assert.strictEqual((await t.api('POST', '/auth/refresh', { refreshToken: r1.body.refreshToken })).status, 401, 'цепочка отозвана');
    const l2 = await t.login('owner', 'Owner-pass-12345');
    await t.api('POST', '/auth/logout', { refreshToken: l2.refreshToken }, l2.accessToken);
    assert.strictEqual((await t.api('POST', '/auth/refresh', { refreshToken: l2.refreshToken })).status, 401);
  } finally { await t.app.close(); }
});

test('rate limit логина и ограничение размера тела', async () => {
  const t = await boot({ limits: { loginAccount: [3, 60000] } });
  try {
    for (let i = 0; i < 3; i++) assert.strictEqual((await t.api('POST', '/auth/login', { login: 'ghost', password: 'bad-bad-bad-bad' })).status, 401);
    const lim = await t.api('POST', '/auth/login', { login: 'ghost', password: 'bad-bad-bad-bad' });
    assert.strictEqual(lim.status, 429); assert.ok(lim.headers.get('retry-after'));
    const big = await fetch(t.base + '/auth/refresh', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refreshToken: 'x'.repeat(100000) }) });
    assert.strictEqual(big.status, 413);
    const wrongCt = await fetch(t.base + '/auth/refresh', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
    assert.strictEqual(wrongCt.status, 415);
  } finally { await t.app.close(); }
});

test('разработчик: создание HUD, изоляция чужих HUD (404), запрет создания', async () => {
  const t = await boot();
  try {
    const a = await t.mkDev('alice'); const b = await t.mkDev('bob'); const c = await t.mkDev('carol', false);
    const h = await t.api('POST', '/huds', { name: 'Мой HUD' }, a.tok);
    assert.strictEqual(h.status, 201); assert.match(h.body.hudId, /^HUD-[0-9A-F]{8}$/); assert.strictEqual(h.body.developerId, a.code);
    assert.strictEqual((await t.api('GET', `/huds/${h.body.hudId}`, undefined, a.tok)).status, 200);
    assert.strictEqual((await t.api('GET', `/huds/${h.body.hudId}`, undefined, b.tok)).status, 404);
    assert.strictEqual((await t.api('POST', `/huds/${h.body.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, b.tok)).status, 404);
    assert.strictEqual((await t.api('GET', `/huds/${h.body.hudId}`, undefined, t.ownerTok)).status, 200);
    const forb = await t.api('POST', '/huds', { name: 'x' }, c.tok);
    assert.strictEqual(forb.status, 403); assert.strictEqual(forb.body.code, 'hud_creation_forbidden');
    assert.strictEqual((await t.api('POST', '/huds', { name: '<script>' }, a.tok)).status, 400);
    assert.strictEqual((await t.api('GET', '/admin/developers', undefined, a.tok)).status, 403);
    assert.strictEqual((await t.api('GET', '/developers/me/huds', undefined, a.tok)).body.huds.length, 1);
  } finally { await t.app.close(); }
});

test('версия: сервер сам генерирует и подписывает; клиенту не доверяем; версии неизменяемы', async () => {
  const t = await boot();
  try {
    const a = await t.mkDev('alice');
    const h = (await t.api('POST', '/huds', { name: 'H' }, a.tok)).body;
    const v = await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok);
    assert.strictEqual(v.status, 201, JSON.stringify(v.body));
    assert.strictEqual(v.body.manifest.hudId, h.hudId); assert.strictEqual(v.body.manifest.developerId, a.code);   // не HUD-EVIL/DEV-999
    const { signature, ...unsigned } = v.body.manifest;
    assert.ok(S.verifyObject(KEYS.publicKey, unsigned, signature), 'подпись манифеста');
    assert.ok(!S.verifyObject(KEYS.publicKey, { ...unsigned, version: '9.9.9' }, signature), 'подделка не проходит');
    const js = fs.readFileSync(path.join(t.dataDir, 'artifacts', h.hudId, '1.0.0', 'hud.js'));
    assert.strictEqual(S.sha256hex(js), v.body.sha256);
    assert.ok(js.toString('utf8').includes(uri(png)));
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok)).status, 409);
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/versions`, { version: '0.9.0', config: cfgWith() }, a.tok)).status, 409);
    for (const bad of [{ version: '1.1.0', config: { ...cfgWith(), assets: { auth: { file: '../../etc/passwd' } } } },
      { version: '1.1.0', config: cfgWith({ radar: { outlineSize: 99 } }) },
      { version: '1.1.0', config: cfgWith({ assets: { auth: { dataUri: 'data:image/svg+xml;base64,PHN2Zz4=' } } }) },
      { version: 'x', config: cfgWith() }]) {
      const r = await t.api('POST', `/huds/${h.hudId}/versions`, bad, a.tok); assert.strictEqual(r.status, 400, JSON.stringify(bad).slice(0, 80));
    }
    assert.strictEqual((await t.api('GET', `/huds/${h.hudId}`, undefined, a.tok)).body.versions.length, 1);
  } finally { await t.app.close(); }
});

test('публикация: зеркало вызывается, сбой зеркала оставляет черновик, повтор запрещён', async () => {
  const calls = []; let fail = false;
  const registry = { publish: async (hudId, version, files) => { if (fail) throw new Error('boom'); calls.push({ hudId, version, names: Object.keys(files) }); return { mirror: 'github' }; } };
  const t = await boot({ registry });
  try {
    const a = await t.mkDev('alice'); const h = (await t.api('POST', '/huds', { name: 'H' }, a.tok)).body;
    await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok);
    fail = true;
    const f = await t.api('POST', `/huds/${h.hudId}/publish`, { version: '1.0.0' }, a.tok);
    assert.strictEqual(f.status, 502);
    assert.strictEqual((await t.api('GET', `/huds/${h.hudId}`, undefined, a.tok)).body.versions[0].status, 'draft');
    assert.strictEqual((await t.api('GET', `/artifacts/${h.hudId}/1.0.0/manifest`)).status, 404, 'черновик недоступен для скачивания');
    fail = false;
    const ok = await t.api('POST', `/huds/${h.hudId}/publish`, { version: '1.0.0' }, a.tok);
    assert.strictEqual(ok.status, 200); assert.strictEqual(ok.body.mirror, 'github');
    assert.deepStrictEqual(calls[0].names.sort(), ['checksums.txt', 'config.json', 'hud.js', 'manifest.json']);
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/publish`, { version: '1.0.0' }, a.tok)).status, 409);
    const info = (await t.api('GET', `/huds/${h.hudId}`, undefined, a.tok)).body;
    assert.strictEqual(info.currentVersion, '1.0.0');
    const dl = await t.api('GET', `/artifacts/${h.hudId}/1.0.0/download`, undefined, undefined, true);
    const buf = Buffer.from(await dl.arrayBuffer());
    assert.strictEqual(dl.status, 200); assert.strictEqual(S.sha256hex(buf), dl.headers.get('x-content-sha256'));
  } finally { await t.app.close(); }
});

test('лицензия: подписана, отзыв/блокировка/реактивация/min-версия действуют на сервере', async () => {
  const t = await boot({ minLoaderVersion: '1.0.0' });
  try {
    const a = await t.mkDev('alice'); const h = (await t.api('POST', '/huds', { name: 'H' }, a.tok)).body;
    const lic = (loader = '1.0.0', hv) => t.api('POST', '/license/validate', { installationId: INSTALL, hudId: h.hudId, loaderVersion: loader, hudVersion: hv });
    assert.strictEqual((await lic()).body.status, 'no_release');
    await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok);
    await t.api('POST', `/huds/${h.hudId}/publish`, { version: '1.0.0' }, a.tok);
    const act = await lic();
    assert.strictEqual(act.body.status, 'active'); assert.strictEqual(act.body.license.allowedVersion, '1.0.0');
    assert.ok(S.verifyObject(KEYS.publicKey, act.body.license, act.body.signature));
    assert.ok(!S.verifyObject(KEYS.publicKey, { ...act.body.license, status: 'active', expiresAt: act.body.license.expiresAt + 99999 }, act.body.signature));
    assert.strictEqual(act.body.license.expiresAt - act.body.license.issuedAt, 72 * 3600);
    assert.strictEqual((await lic('0.5.0')).body.status, 'update_required');
    // отзыв
    assert.strictEqual((await t.api('POST', `/admin/huds/${h.hudId}/revoke`, {}, t.ownerTok)).status, 200);
    const rev = await lic(); assert.strictEqual(rev.body.status, 'revoked'); assert.ok(S.verifyObject(KEYS.publicKey, rev.body.license, rev.body.signature));
    assert.strictEqual((await t.api('GET', `/artifacts/${h.hudId}/1.0.0/download`, undefined, undefined, true)).status, 403);
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.1.0', config: cfgWith() }, a.tok)).status, 403);
    // реактивация
    await t.api('PATCH', `/admin/huds/${h.hudId}/status`, { status: 'active' }, t.ownerTok);
    assert.strictEqual((await lic()).body.status, 'active');
    // принудительное обновление
    await t.api('PATCH', `/admin/huds/${h.hudId}/status`, { minVersion: '2.0.0' }, t.ownerTok);
    assert.strictEqual((await lic('1.0.0', '1.0.0')).body.status, 'update_required');
    // блокировка разработчика отключает его HUD и сессии
    await t.api('PATCH', `/admin/huds/${h.hudId}/status`, { minVersion: null }, t.ownerTok);
    await t.api('PATCH', `/admin/developers/${a.code}/status`, { status: 'disabled' }, t.ownerTok);
    assert.strictEqual((await lic()).body.status, 'blocked');
    assert.strictEqual((await t.api('GET', '/auth/me', undefined, a.tok)).status, 403, 'токен перестаёт работать сразу');
    const l = await t.api('POST', '/auth/login', { login: 'alice', password: 'alice-pass-12345' });
    assert.strictEqual(l.status, 403); assert.strictEqual(l.body.code, 'account_disabled');
    assert.strictEqual((await t.api('POST', '/auth/refresh', { refreshToken: a.refresh })).status, 401);
    await t.api('PATCH', `/admin/developers/${a.code}/status`, { status: 'active' }, t.ownerTok);
    assert.strictEqual((await lic()).body.status, 'active');
    // установки записаны минимально
    const ins = (await t.api('GET', `/admin/installations?hudId=${h.hudId}`, undefined, t.ownerTok)).body.installations;
    assert.strictEqual(ins.length, 1); assert.deepStrictEqual(Object.keys(ins[0]).sort(), ['firstSeenAt', 'hudId', 'hudVersion', 'installationId', 'lastSeenAt', 'lastStatus', 'loaderVersion']);
    assert.strictEqual((await t.api('POST', '/license/validate', { installationId: 'short', hudId: h.hudId, loaderVersion: '1.0.0' })).status, 400);
    assert.strictEqual((await t.api('POST', '/license/validate', { installationId: INSTALL, hudId: 'HUD-00000000', loaderVersion: '1.0.0' })).status, 404);
  } finally { await t.app.close(); }
});

test('админ: создание/сброс пароля/архив, доступ только владельцу, аудит', async () => {
  const t = await boot();
  try {
    const c = await t.api('POST', '/admin/developers', { login: 'dave' }, t.ownerTok);
    assert.strictEqual(c.status, 201); assert.ok(c.body.temporaryPassword.length >= 12); assert.ok(c.body.mustChangePassword);
    assert.strictEqual((await t.api('POST', '/admin/developers', { login: 'dave' }, t.ownerTok)).status, 409);
    assert.strictEqual((await t.api('POST', '/admin/developers', { login: 'x' }, t.ownerTok)).status, 400);
    assert.strictEqual((await t.api('POST', '/admin/developers', { login: 'weak', password: '123' }, t.ownerTok)).status, 400);
    const l = await t.login('dave', c.body.temporaryPassword);
    assert.ok(l.accessToken && l.account.mustChangePassword);
    const ch = await t.api('POST', '/auth/change-password', { currentPassword: c.body.temporaryPassword, newPassword: 'New-strong-pass-1' }, l.accessToken);
    assert.strictEqual(ch.status, 200);
    assert.strictEqual((await t.api('POST', '/auth/login', { login: 'dave', password: c.body.temporaryPassword })).status, 401);
    const rp = await t.api('POST', `/admin/developers/${c.body.id}/reset-password`, {}, t.ownerTok);
    assert.strictEqual((await t.api('POST', '/auth/login', { login: 'dave', password: 'New-strong-pass-1' })).status, 401);
    assert.strictEqual((await t.api('POST', '/auth/login', { login: 'dave', password: rp.body.temporaryPassword })).status, 200);
    assert.strictEqual((await t.api('DELETE', `/admin/developers/${c.body.id}`, undefined, t.ownerTok)).body.status, 'archived');
    assert.strictEqual((await t.api('POST', '/auth/login', { login: 'dave', password: rp.body.temporaryPassword })).status, 403);
    assert.strictEqual((await t.api('GET', '/admin/developers')).status, 401);
    const logs = (await t.api('GET', '/admin/audit-logs?limit=50', undefined, t.ownerTok)).body.logs.map((x) => x.action);
    for (const act of ['login', 'developer_create', 'change_password', 'developer_reset_password', 'developer_archive']) assert.ok(logs.includes(act), act);
    assert.ok(!JSON.stringify((await t.api('GET', '/admin/audit-logs', undefined, t.ownerTok)).body).includes('pass-12345'), 'пароли не попадают в аудит');
    const nf = await t.api('GET', '/nope'); assert.strictEqual(nf.status, 404); assert.ok(nf.body.traceId);
  } finally { await t.app.close(); }
});

test('GithubRegistry: PUT с проверкой хеша, идемпотентность, неизменяемость, ошибки', async () => {
  const store = new Map(); const log = [];
  const fetchImpl = async (url, init) => {
    const p = decodeURIComponent(new URL(url).pathname.split('/contents/')[1]); log.push([init.method, p]);
    assert.ok(init.headers.Authorization === 'Bearer tok');
    if (init.method === 'GET') return store.has(p) ? { status: 200, json: async () => ({ sha: gitBlobSha(store.get(p)) }) } : { status: 404, json: async () => ({}) };
    const buf = Buffer.from(JSON.parse(init.body).content, 'base64'); store.set(p, buf);
    return { status: 201, json: async () => ({ content: { sha: gitBlobSha(buf) } }) };
  };
  const g = new GithubRegistry({ token: 'tok', repo: 'me/reg', fetchImpl });
  const files = { 'hud.js': Buffer.from('a'), 'manifest.json': Buffer.from('b') };
  assert.strictEqual((await g.publish('HUD-AAAAAAAA', '1.0.0', files)).mirror, 'github');
  assert.ok(store.has('published/HUD-AAAAAAAA/1.0.0/hud.js'));
  const puts = log.filter((l) => l[0] === 'PUT').length;
  await g.publish('HUD-AAAAAAAA', '1.0.0', files);                                 // идемпотентно
  assert.strictEqual(log.filter((l) => l[0] === 'PUT').length, puts);
  await assert.rejects(() => g.publish('HUD-AAAAAAAA', '1.0.0', { 'hud.js': Buffer.from('CHANGED') }), /другим содержимым/);
  const g2 = new GithubRegistry({ token: 'tok', repo: 'me/reg', fetchImpl: async () => ({ status: 500, json: async () => ({}) }) });
  await assert.rejects(() => g2.publish('HUD-BBBBBBBB', '1.0.0', files), /HTTP 500/);
  const g3 = new GithubRegistry({ token: 'tok', repo: 'me/reg', fetchImpl: async (u, i) => (i.method === 'GET' ? { status: 404, json: async () => ({}) } : { status: 201, json: async () => ({ content: { sha: 'deadbeef' } }) }) });
  await assert.rejects(() => g3.publish('HUD-CCCCCCCC', '1.0.0', files), /хеш не совпал/);
  assert.throws(() => new GithubRegistry({ token: '', repo: 'x' }));
});

test('security: токены, пароли, подписи', async () => {
  const tok = S.signToken('s', { sub: 1, exp: 100 });
  assert.ok(S.verifyToken('s', tok, 50)); assert.strictEqual(S.verifyToken('s', tok, 100), null); assert.strictEqual(S.verifyToken('other', tok, 50), null);
  const [p, sg] = tok.split('.'); const forged = Buffer.from(JSON.stringify({ sub: 2, exp: 100 })).toString('base64url') + '.' + sg;
  assert.strictEqual(S.verifyToken('s', forged, 50), null);
  assert.strictEqual(S.verifyToken('s', 'a.b.c', 50), null);
  const h = await S.hashPassword('correct horse'); assert.ok(await S.verifyPassword('correct horse', h)); assert.ok(!(await S.verifyPassword('wrong', h)));
  assert.notStrictEqual(h, await S.hashPassword('correct horse'));
  assert.strictEqual(S.canonical({ b: 1, a: [2, { d: 1, c: 2 }] }), '{"a":[2,{"c":2,"d":1}],"b":1}');
  assert.strictEqual(S.compareSemver('1.10.0', '1.9.0'), 1);
});

test('лицензии покупателей: привязка к устройству, лимит, отзыв одного ключа, пометка утечки, закрытая загрузка', async () => {
  const t = await boot();
  try {
    const a = await t.mkDev('alice'); const b = await t.mkDev('bob');
    const h = (await t.api('POST', '/huds', { name: 'Paid' }, a.tok)).body;
    await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok);
    await t.api('POST', `/huds/${h.hudId}/publish`, { version: '1.0.0' }, a.tok);
    const set = await t.api('PATCH', `/huds/${h.hudId}/settings`, { requireLicense: true }, a.tok);
    assert.strictEqual(set.body.requireLicense, true);
    assert.strictEqual((await t.api('PATCH', `/huds/${h.hudId}/settings`, { requireLicense: false }, b.tok)).status, 404, 'чужой HUD');
    const HW_A = 'hwid-aaaaaaaaaaaaaaaaaaaa', HW_B = 'hwid-bbbbbbbbbbbbbbbbbbbb';
    const val = (key, hwid) => t.api('POST', '/license/validate', { installationId: INSTALL, hudId: h.hudId, loaderVersion: '1.0.0', licenseKey: key, hwid });

    assert.strictEqual((await val(undefined, HW_A)).body.status, 'license_required');
    assert.strictEqual((await val('PTK-AAAAA-AAAAA-AAAAA-AAAAA', HW_A)).body.status, 'license_invalid');

    const buyer1 = await t.api('POST', `/huds/${h.hudId}/licenses`, { label: 'buyer1' }, a.tok);
    const buyer2 = await t.api('POST', `/huds/${h.hudId}/licenses`, { label: 'buyer2', maxDevices: 2 }, a.tok);
    assert.strictEqual(buyer1.status, 201); assert.match(buyer1.body.licenseKey, /^PTK-[2-9A-HJ-NP-Z]{5}(-[2-9A-HJ-NP-Z]{5}){3}$/);
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/licenses`, { label: 'x' }, b.tok)).status, 404);
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/licenses`, { label: 'x', maxDevices: 99 }, a.tok)).status, 400);
    const K1 = buyer1.body.licenseKey, K2 = buyer2.body.licenseKey;

    // ключ не хранится открыто, в списке виден только префикс
    const dump = JSON.stringify(t.app.db.prepare('SELECT * FROM licenses').all());
    assert.ok(!dump.includes(K1) && !dump.includes(K1.slice(4)));
    const list = (await t.api('GET', `/huds/${h.hudId}/licenses`, undefined, a.tok)).body.licenses;
    assert.ok(!JSON.stringify(list).includes(K1)); assert.strictEqual(list[0].keyPrefix, K1.slice(0, 9));

    // активация и привязка к устройству
    const act = await val(K1.toLowerCase(), HW_A);      // регистр ключа не важен
    assert.strictEqual(act.body.status, 'active');
    assert.strictEqual(act.body.license.buyerLicenseId, buyer1.body.licenseId);
    assert.ok(S.verifyObject(KEYS.publicKey, act.body.license, act.body.signature));
    assert.ok(!JSON.stringify(t.app.db.prepare('SELECT * FROM activations').all()).includes(HW_A), 'сырой HWID не хранится');
    assert.strictEqual((await val(K1, HW_A)).body.status, 'active', 'повторная проверка того же устройства');
    // второе устройство на ключе с лимитом 1 — отказ и пометка
    const lim = await val(K1, HW_B);
    assert.strictEqual(lim.body.status, 'device_limit'); assert.ok(S.verifyObject(KEYS.publicKey, lim.body.license, lim.body.signature));
    let l1 = (await t.api('GET', `/huds/${h.hudId}/licenses`, undefined, a.tok)).body.licenses.find((x) => x.licenseId === buyer1.body.licenseId);
    assert.ok(l1.flagged); assert.strictEqual(l1.deviceAttempts, 1); assert.strictEqual(l1.devices, 1);
    // ключ с двумя устройствами
    assert.strictEqual((await val(K2, HW_A)).body.status, 'active'); assert.strictEqual((await val(K2, HW_B)).body.status, 'active');
    assert.strictEqual((await val(K2, 'hwid-cccccccccccccccccccc')).body.status, 'device_limit');
    assert.strictEqual((await val(K1, 'short')).status, 400);
    // ключ другого HUD не подходит
    const h2 = (await t.api('POST', '/huds', { name: 'Other' }, a.tok)).body;
    await t.api('POST', `/huds/${h2.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok);
    await t.api('POST', `/huds/${h2.hudId}/publish`, { version: '1.0.0' }, a.tok);
    await t.api('PATCH', `/huds/${h2.hudId}/settings`, { requireLicense: true }, a.tok);
    const cross = await t.api('POST', '/license/validate', { installationId: INSTALL, hudId: h2.hudId, loaderVersion: '1.0.0', licenseKey: K1, hwid: HW_A });
    assert.strictEqual(cross.body.status, 'license_invalid');

    // закрытая загрузка hud.js
    const dl = (key, hwid) => fetch(`${t.base}/artifacts/${h.hudId}/1.0.0/download`, { headers: { ...(key ? { 'X-License-Key': key } : {}), ...(hwid ? { 'X-HWID': hwid } : {}) } });
    assert.strictEqual((await dl()).status, 403);
    assert.strictEqual((await dl(K1, HW_B)).status, 403, 'устройство не активировано');
    assert.strictEqual((await dl(K1, HW_A)).status, 200);

    // отзыв одного ключа не трогает остальные
    const rv = await t.api('POST', `/huds/${h.hudId}/licenses/${buyer1.body.licenseId}/revoke`, { reason: 'слил в паблик' }, a.tok);
    assert.strictEqual(rv.body.status, 'revoked');
    const after = await val(K1, HW_A);
    assert.strictEqual(after.body.status, 'license_revoked'); assert.ok(S.verifyObject(KEYS.publicKey, after.body.license, after.body.signature));
    assert.strictEqual((await dl(K1, HW_A)).status, 403);
    assert.strictEqual((await val(K2, HW_A)).body.status, 'active');
    // владелец тоже может отзывать; чужой разработчик — нет
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/licenses/${buyer2.body.licenseId}/revoke`, {}, b.tok)).status, 404);
    // восстановление и сброс устройств
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/licenses/${buyer1.body.licenseId}/restore`, {}, t.ownerTok)).body.status, 'active');
    assert.strictEqual((await val(K1, HW_A)).body.status, 'active');
    const rs = await t.api('POST', `/huds/${h.hudId}/licenses/${buyer1.body.licenseId}/reset-devices`, {}, a.tok);
    assert.strictEqual(rs.body.devices, 0); assert.ok(!rs.body.flagged);
    assert.strictEqual((await val(K1, HW_B)).body.status, 'active');
    // отзыв HUD целиком сильнее лицензий
    await t.api('POST', `/admin/huds/${h.hudId}/revoke`, {}, t.ownerTok);
    assert.strictEqual((await val(K2, HW_A)).body.status, 'revoked');
    const logs = (await t.api('GET', '/admin/audit-logs?limit=200', undefined, t.ownerTok)).body.logs.map((x) => x.action);
    for (const act of ['license_create', 'license_revoke', 'license_restore', 'license_device_limit', 'license_reset_devices']) assert.ok(logs.includes(act), act);
    assert.ok(!JSON.stringify(logs).includes(K1));
  } finally { await t.app.close(); }
});

test('.build: подписанный файл для loader, blob лицензии, ротация ключа', async () => {
  const t = await boot();
  try {
    const a = await t.mkDev('alice');
    const h = (await t.api('POST', '/huds', { name: 'Paid' }, a.tok)).body;
    await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok);
    await t.api('POST', `/huds/${h.hudId}/publish`, { version: '1.0.0' }, a.tok);
    // HUD без обязательного ключа: общий .build без ключа
    const plain = await t.api('GET', `/huds/${h.hudId}/build`, undefined, a.tok);
    const pd = openBlob(KEYS.publicKey, plain.body.buildFile);
    assert.deepStrictEqual({ v: pd.v, hudId: pd.hudId, server: pd.server, key: pd.key }, { v: 1, hudId: h.hudId, server: 'https://api.example.com', key: '' });
    assert.strictEqual(plain.body.buildFileName, 'HudLoader.build');
    await t.api('PATCH', `/huds/${h.hudId}/settings`, { requireLicense: true }, a.tok);
    assert.strictEqual((await t.api('GET', `/huds/${h.hudId}/build`, undefined, a.tok)).status, 400);
    assert.strictEqual((await t.api('GET', `/huds/${h.hudId}/build`, undefined, (await t.mkDev('bob')).tok)).status, 404);
    // персональный .build содержит ключ и licId, подпись защищает от правок
    const lic = await t.api('POST', `/huds/${h.hudId}/licenses`, { label: 'buyer' }, a.tok);
    const d = openBlob(KEYS.publicKey, lic.body.buildFile);
    assert.strictEqual(d.key, lic.body.licenseKey); assert.strictEqual(d.licId, lic.body.licenseId);
    const [pl, sg] = lic.body.buildFile.split('.');
    const forged = Buffer.from(Buffer.from(pl, 'base64url').toString().replace(lic.body.licenseKey, 'PTK-AAAAA-AAAAA-AAAAA-AAAAA')).toString('base64url');
    assert.strictEqual(openBlob(KEYS.publicKey, forged + '.' + sg), null);
    assert.strictEqual(openBlob(S.generateSigningKeys().publicKey, lic.body.buildFile), null, 'чужой ключ');
    assert.strictEqual(openBlob(KEYS.publicKey, 'garbage'), null);
    assert.strictEqual(rawPublicKey(KEYS.publicKey).length, 32);
    // blob лицензии = подписанная копия license
    const HW = 'hwid-aaaaaaaaaaaaaaaaaaaa';
    const v = await t.api('POST', '/license/validate', { installationId: INSTALL, hudId: h.hudId, loaderVersion: '1.0.0', licenseKey: d.key, hwid: HW });
    assert.strictEqual(v.body.status, 'active');
    assert.deepStrictEqual(openBlob(KEYS.publicKey, v.body.blob), v.body.license);
    // ротация: старый ключ мёртв, новый .build рабочий, устройства сброшены
    const rot = await t.api('POST', `/huds/${h.hudId}/licenses/${lic.body.licenseId}/rotate-key`, {}, a.tok);
    assert.notStrictEqual(rot.body.licenseKey, lic.body.licenseKey);
    assert.strictEqual((await t.api('POST', '/license/validate', { installationId: INSTALL, hudId: h.hudId, loaderVersion: '1.0.0', licenseKey: d.key, hwid: HW })).body.status, 'license_invalid');
    const v2 = await t.api('POST', '/license/validate', { installationId: INSTALL, hudId: h.hudId, loaderVersion: '1.0.0', licenseKey: openBlob(KEYS.publicKey, rot.body.buildFile).key, hwid: HW });
    assert.strictEqual(v2.body.status, 'active');
    // без PUBLIC_URL .build не выдаётся
    const t2 = await boot({ publicUrl: null });
    try {
      const a2 = await t2.mkDev('carol'); const h2 = (await t2.api('POST', '/huds', { name: 'x' }, a2.tok)).body;
      assert.strictEqual((await t2.api('GET', `/huds/${h2.hudId}/build`, undefined, a2.tok)).status, 409);
    } finally { await t2.app.close(); }
    assert.throws(() => createApp({ dataDir: t.dataDir, dbFile: ':memory:', tokenSecret: 'x', signing: KEYS, template: TEMPLATE, publicUrl: 'javascript:alert(1)' }), /publicUrl/);
  } finally { await t.app.close(); }
});

test('бесплатный HUD: без ключей и привязок, тысячи установок; платный — один ПК', async () => {
  const t = await boot({ limits: { license: [100000, 60000], general: [100000, 60000] } });
  try {
    const a = await t.mkDev('alice');
    const free = (await t.api('POST', '/huds', { name: 'Free', type: 'free' }, a.tok)).body;
    const paid = (await t.api('POST', '/huds', { name: 'Paid', type: 'paid' }, a.tok)).body;
    assert.strictEqual(free.type, 'free'); assert.strictEqual(paid.type, 'paid');
    assert.strictEqual((await t.api('POST', '/huds', { name: 'x', type: 'vip' }, a.tok)).status, 400);
    for (const h of [free, paid]) { await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok); await t.api('POST', `/huds/${h.hudId}/publish`, { version: '1.0.0' }, a.tok); }

    // бесплатный: ключ не нужен, число пользователей не ограничено, hud.js скачивается без заголовков
    assert.strictEqual((await t.api('POST', `/huds/${free.hudId}/licenses`, { label: 'x' }, a.tok)).body.code, 'hud_is_free');
    const N = 1500; let active = 0;
    for (let i = 0; i < N; i += 50) {
      const batch = await Promise.all(Array.from({ length: Math.min(50, N - i) }, (_, j) => t.api('POST', '/license/validate', { installationId: `inst-${String(i + j).padStart(6, '0')}-aaaaaaaa`, hudId: free.hudId, loaderVersion: '1.0.0', hwid: `hwid-${i + j}-aaaaaaaaaaaaaaaa` })));
      active += batch.filter((r) => r.body.status === 'active').length;
    }
    assert.strictEqual(active, N);
    assert.strictEqual(t.app.db.prepare('SELECT COUNT(*) c FROM installations WHERE hud_id=?').get(free.hudId).c, N);
    assert.strictEqual((await t.api('GET', `/artifacts/${free.hudId}/1.0.0/download`, undefined, undefined, true)).status, 200);
    assert.strictEqual(S.verifyObject !== undefined && (await t.api('GET', `/huds/${free.hudId}/build`, undefined, a.tok)).status, 200, 'общий .build для всех');
    // платный: один ключ — один ПК, без ключа не скачать
    assert.strictEqual((await t.api('POST', '/license/validate', { installationId: INSTALL, hudId: paid.hudId, loaderVersion: '1.0.0', hwid: 'hwid-aaaaaaaaaaaaaaaaaaaa' })).body.status, 'license_required');
    assert.strictEqual((await t.api('GET', `/artifacts/${paid.hudId}/1.0.0/download`, undefined, undefined, true)).status, 403);
    const lic = await t.api('POST', `/huds/${paid.hudId}/licenses`, { label: 'buyer' }, a.tok);
    assert.strictEqual(lic.body.maxDevices, 1);
    const v = (hw) => t.api('POST', '/license/validate', { installationId: INSTALL, hudId: paid.hudId, loaderVersion: '1.0.0', licenseKey: lic.body.licenseKey, hwid: hw });
    assert.strictEqual((await v('hwid-pc1-aaaaaaaaaaaaaaaa')).body.status, 'active');
    assert.strictEqual((await v('hwid-pc2-aaaaaaaaaaaaaaaa')).body.status, 'device_limit');
    // смена типа
    const sw = await t.api('PATCH', `/huds/${free.hudId}/settings`, { type: 'paid' }, a.tok); assert.strictEqual(sw.body.type, 'paid');
    assert.strictEqual((await t.api('PATCH', `/huds/${free.hudId}/settings`, { type: 'x' }, a.tok)).status, 400);
  } finally { await t.app.close(); }
});

// ---------- конструктор (клиент API), панель администратора ----------
const { ApiClient, publishHud, issueBuyerKey, exportFreeBuild, ClientError } = require('../../src/client');
const { defaultConfig } = require('../../src/config');
const panel = require('../panel/panel.js');

test('конструктор: тип HUD выбирается обязательно; paid → ключ → .build покупателю; free → общий .build', async () => {
  const t = await boot();
  try {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bld-')); fs.mkdirSync(path.join(dir, 'auth'));
    fs.writeFileSync(path.join(dir, 'auth', 'auth.png'), png); fs.writeFileSync(path.join(dir, 'HudLoader.asi'), 'MZ-fake-loader');
    const cfg = defaultConfig(); cfg.assets.auth = { file: 'auth/auth.png' }; cfg.radar.shape = 'round';
    const root = t.base.replace('/api/v1', '');
    await t.api('POST', '/admin/developers', { login: 'seller', password: 'seller-pass-12345' }, t.ownerTok);
    const client = new ApiClient(root); await client.login('seller', 'seller-pass-12345');

    await assert.rejects(() => publishHud({ client, name: 'X', config: cfg, baseDir: dir, version: '1.0.0' }), /Выберите тип/);
    await assert.rejects(() => publishHud({ client, name: 'X', type: 'vip', config: cfg, baseDir: dir, version: '1.0.0' }), ClientError);

    const paid = await publishHud({ client, name: 'Платный', type: 'paid', config: cfg, baseDir: dir, version: '1.0.0' });
    assert.strictEqual(paid.type, 'paid'); assert.strictEqual(paid.warnings.length, 0);
    await assert.rejects(() => publishHud({ client, hudId: paid.hudId, type: 'free', config: cfg, baseDir: dir, version: '1.0.1' }), /уже paid/);
    const out = path.join(dir, 'buyers');
    const k = await issueBuyerKey({ client, hudId: paid.hudId, label: 'Вася / тест', outDir: out, loaderPath: path.join(dir, 'HudLoader.asi') });
    assert.deepStrictEqual(fs.readdirSync(k.dir).sort(), ['HudLoader.asi', 'HudLoader.build']);
    assert.match(path.basename(k.dir), /^[A-Za-z0-9._-]+$/, 'имя папки безопасно для файловой системы');
    const bd = openBlob(KEYS.publicKey, fs.readFileSync(path.join(k.dir, 'HudLoader.build'), 'utf8'));
    assert.strictEqual(bd.hudId, paid.hudId); assert.strictEqual(bd.key, k.licenseKey);
    // первый запуск покупателя привязывает ПК автоматически
    const first = await t.api('POST', '/license/validate', { installationId: INSTALL, hudId: paid.hudId, loaderVersion: '1.0.0', licenseKey: bd.key, hwid: 'hwid-buyer-pc-aaaaaaaaaaaa' });
    assert.strictEqual(first.body.status, 'active');
    const lics = (await client.request('GET', `/huds/${paid.hudId}/licenses`)).licenses;
    assert.strictEqual(lics[0].devices, 1); assert.match(lics[0].activations[0].pc, /^PC-[0-9a-f]{12}$/);

    const free = await publishHud({ client, name: 'Бесплатный', type: 'free', config: cfg, baseDir: dir, version: '1.0.0' });
    const fb = await exportFreeBuild({ client, hudId: free.hudId, outDir: path.join(dir, 'dist') });
    assert.strictEqual(openBlob(KEYS.publicKey, fs.readFileSync(path.join(fb.dir, 'HudLoader.build'), 'utf8')).key, '');
    await assert.rejects(() => issueBuyerKey({ client, hudId: free.hudId, label: 'x' }), /бесплатный/);
    // владелец платформы тоже может создавать HUD
    const oc = new ApiClient(root); await oc.login('owner', 'Owner-pass-12345');
    assert.strictEqual((await publishHud({ client: oc, name: 'Owner HUD', type: 'free', config: cfg, baseDir: dir, version: '1.0.0' })).type, 'free');
  } finally { await t.app.close(); }
});

test('панель: ПК и попытки с других ПК, отключение HUD/ключа, права, статика с CSP', async () => {
  const t = await boot();
  try {
    const a = await t.mkDev('alice'); const b = await t.mkDev('bob');
    const h = (await t.api('POST', '/huds', { name: 'Paid', type: 'paid' }, a.tok)).body;
    await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok);
    await t.api('POST', `/huds/${h.hudId}/publish`, { version: '1.0.0' }, a.tok);
    const lic = (await t.api('POST', `/huds/${h.hudId}/licenses`, { label: 'Покупатель' }, a.tok)).body;
    const val = (hw) => t.api('POST', '/license/validate', { installationId: INSTALL, hudId: h.hudId, loaderVersion: '1.0.0', licenseKey: lic.licenseKey, hwid: hw });
    await val('hwid-main-pc-aaaaaaaaaaaaaaaa');
    for (let i = 0; i < 3; i++) await val('hwid-thief-1-aaaaaaaaaaaaaaaa');
    await val('hwid-thief-2-aaaaaaaaaaaaaaaa');
    const l = (await t.api('GET', `/huds/${h.hudId}/licenses`, undefined, t.ownerTok)).body.licenses[0];
    assert.strictEqual(l.activations.length, 1); assert.strictEqual(l.deviceAttempts, 4); assert.strictEqual(l.attempts.length, 2);
    assert.deepStrictEqual(l.attempts.map((x) => x.count).sort(), [1, 3]);
    assert.ok(!JSON.stringify(l).includes('hwid-'), 'сырой HWID не отдаётся даже владельцу');
    const list = (await t.api('GET', '/admin/huds', undefined, t.ownerTok)).body.huds.find((x) => x.hudId === h.hudId);
    assert.strictEqual(list.type, 'paid'); assert.strictEqual(list.stats.flaggedLicenses, 1);
    assert.strictEqual((await t.api('GET', '/developers/me/huds', undefined, a.tok)).body.huds[0].stats.licenses, 1);
    // сброс ПК очищает и попытки
    await t.api('POST', `/huds/${h.hudId}/licenses/${lic.licenseId}/reset-devices`, {}, a.tok);
    const l2 = (await t.api('GET', `/huds/${h.hudId}/licenses`, undefined, a.tok)).body.licenses[0];
    assert.deepStrictEqual([l2.activations.length, l2.attempts.length, l2.flagged], [0, 0, false]);
    // кнопка «Отключить HUD»: владелец HUD и платформа; чужой — нет; blocked владельца разработчик не снимет
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/status`, { status: 'revoked' }, b.tok)).status, 404);
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/status`, { status: 'bad' }, a.tok)).status, 400);
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/status`, { status: 'revoked' }, a.tok)).body.status, 'revoked');
    assert.strictEqual((await val('hwid-main-pc-aaaaaaaaaaaaaaaa')).body.status, 'revoked');
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/status`, { status: 'active' }, a.tok)).body.status, 'active');
    await t.api('PATCH', `/admin/huds/${h.hudId}/status`, { status: 'blocked' }, t.ownerTok);
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/status`, { status: 'active' }, a.tok)).status, 403);
    assert.strictEqual((await t.api('POST', `/huds/${h.hudId}/status`, { status: 'active' }, t.ownerTok)).body.status, 'active');
    // статика панели
    const pg = await fetch(t.base.replace('/api/v1', '/panel/'));
    assert.strictEqual(pg.status, 200); assert.match(pg.headers.get('content-security-policy'), /script-src 'self'/); assert.match(await pg.text(), /Pitachok HUD/);
    for (const bad of ['/panel/..%2Fsrc', '/panel/constructor', '/panel/app.js', '/panel/%2e%2e']) assert.strictEqual((await fetch(t.base.replace('/api/v1', bad))).status, 404, bad);
    assert.strictEqual((await fetch(t.base.replace('/api/v1', '/panel/panel.js'))).status, 200);
  } finally { await t.app.close(); }
});

test('панель: отрисовка экранирует данные (XSS) и показывает нужные кнопки', () => {
  const evil = '<img src=x onerror=alert(1)>"\'';
  const html = panel.renderHudList([{ hudId: 'HUD-AAAAAAAA', name: evil, type: 'paid', status: 'active', currentVersion: '1.0.0', developerId: 'DEV-001', stats: { licenses: 2, flaggedLicenses: 1 } }], 'owner')
    + panel.renderHudDetail({ hudId: 'HUD-AAAAAAAA', name: evil, type: 'paid', status: 'revoked', developerId: 'DEV-001', stats: {} },
      [{ licenseId: 'LK-AABBCCDD', label: evil, keyPrefix: 'PTK-ABCDE', status: 'revoked', revokeReason: evil, maxDevices: 1, devices: 1, deviceAttempts: 3,
        activations: [{ pc: 'PC-0123456789ab', firstSeenAt: '2026-01-01T00:00:00Z', lastSeenAt: '2026-01-02T00:00:00Z' }], attempts: [{ pc: 'PC-ffffffffffff', count: 3, lastAt: '2026-01-03T00:00:00Z' }] }], 'owner')
    + panel.renderIssued({ licenseKey: evil, buildFileName: evil }) + panel.renderAudit([{ ts: evil, actor: evil, action: evil, target: evil }]);
  assert.ok(!/<img/.test(html), 'ни один тег из данных не попал в разметку');
  assert.ok(html.includes('&lt;img'));
  assert.match(html, /попыток с других ПК: 3/); assert.match(html, /PC-ffffffffffff/); assert.match(html, /data-act="restore-lic"/);
  assert.match(html, /Включить HUD/);                                                                    // HUD отключён → кнопка включения
  assert.match(panel.renderHudList([{ hudId: 'H', name: 'n', type: 'free', status: 'active', stats: { installs: 5, activeLast24h: 2 } }], 'developer'), /установок: 5 \(за 24ч: 2\)/);
  assert.ok(!/Отключить HUD/.test(panel.renderHudDetail({ hudId: 'H', name: 'n', type: 'free', status: 'blocked', stats: {} }, [], 'developer')), 'blocked: разработчик не видит кнопку');
});

test('платный HUD не уходит в публичный GitHub-репозиторий; бесплатному можно', async () => {
  let priv = false, published = 0, failCheck = false;
  const registry = { isPrivate: async () => { if (failCheck) throw new Error('net'); return priv; }, publish: async () => { published++; return { mirror: 'github' }; } };
  const t = await boot({ registry });
  try {
    const a = await t.mkDev('alice');
    const paid = (await t.api('POST', '/huds', { name: 'Paid', type: 'paid' }, a.tok)).body;
    const free = (await t.api('POST', '/huds', { name: 'Free', type: 'free' }, a.tok)).body;
    for (const h of [paid, free]) await t.api('POST', `/huds/${h.hudId}/versions`, { version: '1.0.0', config: cfgWith() }, a.tok);
    const blocked = await t.api('POST', `/huds/${paid.hudId}/publish`, { version: '1.0.0' }, a.tok);
    assert.strictEqual(blocked.status, 409); assert.strictEqual(blocked.body.code, 'registry_public'); assert.strictEqual(published, 0);
    assert.strictEqual((await t.api('GET', `/huds/${paid.hudId}`, undefined, a.tok)).body.versions[0].status, 'draft');
    failCheck = true;
    assert.strictEqual((await t.api('POST', `/huds/${paid.hudId}/publish`, { version: '1.0.0' }, a.tok)).status, 502);
    failCheck = false;
    assert.strictEqual((await t.api('POST', `/huds/${free.hudId}/publish`, { version: '1.0.0' }, a.tok)).status, 200, 'бесплатный — можно и в публичный');
    priv = true;
    const ok = await t.api('POST', `/huds/${paid.hudId}/publish`, { version: '1.0.0' }, a.tok);
    assert.strictEqual(ok.status, 200); assert.strictEqual(ok.body.mirror, 'github'); assert.strictEqual(published, 2);
    const logs = (await t.api('GET', '/admin/audit-logs?limit=100', undefined, t.ownerTok)).body.logs.map((l) => l.action);
    assert.ok(logs.includes('publish_blocked_public_registry'));
  } finally { await t.app.close(); }
});

test('GithubRegistry.isPrivate: только private===true; ошибки не маскируются', async () => {
  const mk = (status, data) => new GithubRegistry({ token: 't', repo: 'me/reg', fetchImpl: async (url, i) => { assert.ok(String(url).endsWith('/repos/me/reg')); assert.ok(i.headers.Authorization === 'Bearer t'); return { status, json: async () => data }; } });
  assert.strictEqual(await mk(200, { private: true }).isPrivate(), true);
  assert.strictEqual(await mk(200, { private: false }).isPrivate(), false);
  assert.strictEqual(await mk(200, {}).isPrivate(), false);
  await assert.rejects(() => mk(404, {}).isPrivate(), /HTTP 404/);
});
