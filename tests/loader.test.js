'use strict';
const test = require('node:test'); const assert = require('node:assert');
const { run } = require('../loader/test/run');
const { render } = require('../loader/tools/gen_pubkey_h');
const S = require('../server/src/security'); const { rawPublicKey } = require('../server/src/blob');

test('C-ядро loader: подпись/разбор/фаззинг под ASan+UBSan (blob выпущен Node-сервером)', (t) => {
  const r = run();
  if (r.skipped) return t.skip(r.skipped);
  assert.strictEqual(r.status, 0, r.out); assert.match(r.out, /^OK/);
});

test('gen_pubkey_h: заголовок содержит ровно публичный ключ, без секретов', () => {
  const k = S.generateSigningKeys(); const h = render(k.publicKey);
  const bytes = [...h.matchAll(/0x([0-9a-f]{2})/g)].map((m) => m[1]).join('');
  assert.strictEqual(bytes, rawPublicKey(k.publicKey).toString('hex'));
  assert.ok(!/PRIVATE/.test(h));
});

test('loader (Windows): hud.js не пишется на диск', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'loader', 'win', 'hudloader_win.c'), 'utf8');
  assert.ok(!/CACHE_|write_file|offline_fallback/.test(src));
  const opens = [...src.matchAll(/fopen\([^,]+,\s*"([a-z+]+)"\)/g)].map((m) => m[1]).sort();
  assert.deepStrictEqual(opens, ['a', 'rb'], 'допустимы только лог (a) и чтение .build (rb)');
});
