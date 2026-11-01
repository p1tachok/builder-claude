#!/usr/bin/env node
'use strict';
// Запуск:  node server/src/index.js start | init --owner <login>
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createApp } = require('./app');
const S = require('./security');
const { GithubRegistry } = require('./registry');

const env = process.env;
const dataDir = path.resolve(env.PITACHOK_DATA_DIR || path.join(__dirname, '..', 'data'));
const keyDir = path.join(dataDir, 'keys');

function ensureKeys() {
  fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
  const pub = path.join(keyDir, 'signing.pub.pem'), priv = path.join(keyDir, 'signing.key.pem'), sec = path.join(keyDir, 'token.secret');
  if (!fs.existsSync(priv)) {
    const k = S.generateSigningKeys();
    fs.writeFileSync(priv, k.privateKey, { mode: 0o600 }); fs.writeFileSync(pub, k.publicKey);
    console.log('Созданы ключи подписи. Публичный ключ (для loader):', pub);
  }
  if (!fs.existsSync(sec)) fs.writeFileSync(sec, crypto.randomBytes(48).toString('base64'), { mode: 0o600 });
  return { privateKey: fs.readFileSync(priv, 'utf8'), publicKey: fs.readFileSync(pub, 'utf8'), tokenSecret: fs.readFileSync(sec, 'utf8').trim() };
}

function build() {
  const k = ensureKeys();
  const registry = env.GITHUB_TOKEN && env.GITHUB_REPO ? new GithubRegistry({ token: env.GITHUB_TOKEN, repo: env.GITHUB_REPO, branch: env.GITHUB_BRANCH || 'main' }) : null;
  return createApp({
    dataDir, tokenSecret: k.tokenSecret, signing: { privateKey: k.privateKey, publicKey: k.publicKey, keyId: 'k1' },
    template: fs.readFileSync(env.PITACHOK_TEMPLATE || path.join(__dirname, '..', '..', 'templates', 'hud.template.js'), 'utf8'),
    registry, publicUrl: env.PUBLIC_URL || null, graceHours: Number(env.OFFLINE_GRACE_HOURS || 72), minLoaderVersion: env.MIN_LOADER_VERSION || '0.0.0',
    trustProxy: env.TRUST_PROXY === '1',
  });
}

async function main() {
  const cmd = process.argv[2];
  if (cmd === 'init') {
    const i = process.argv.indexOf('--owner'); const login = i > 0 ? process.argv[i + 1] : null;
    if (!login) { console.error('Использование: init --owner <login>  (пароль: PITACHOK_OWNER_PASSWORD или будет сгенерирован)'); process.exit(1); }
    fs.mkdirSync(dataDir, { recursive: true });
    const app = build();
    const pw = env.PITACHOK_OWNER_PASSWORD || S.randomPassword() + 'Aa1';
    const acc = await app.createAccount({ login, password: pw, role: 'owner' });
    app.audit('system', 'owner_create', acc.code);
    console.log(`Владелец создан: ${acc.code} / ${login}`);
    if (!env.PITACHOK_OWNER_PASSWORD) console.log('Пароль (показан один раз):', pw);
    await app.close(); return;
  }
  if (cmd === 'start') {
    fs.mkdirSync(dataDir, { recursive: true });
    const app = build();
    const addr = await app.listen(Number(env.PORT || 8080), env.HOST || '127.0.0.1');
    console.log(`Pitachok API: http://${addr.address}:${addr.port}  (HTTPS обеспечивает reverse proxy)`);
    console.log(env.GITHUB_TOKEN ? `GitHub-реестр: ${env.GITHUB_REPO}` : 'GitHub-реестр не настроен: публикация только локально');
    return;
  }
  console.log('Команды: init --owner <login> | start');
}
main().catch((e) => { console.error('ОШИБКА:', e.message); process.exit(1); });
