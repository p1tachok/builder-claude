'use strict';
// Собирает C-тест (gcc + libsodium.so) и проверяет blob-ы, выпущенные Node-сервером. Пропускается, если нет gcc/libsodium.
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs'); const os = require('os'); const path = require('path');
const S = require('../../server/src/security'); const { signBlob, rawPublicKey } = require('../../server/src/blob');

function findSodium() {
  for (const d of ['/usr/lib/x86_64-linux-gnu', '/usr/lib', '/usr/lib64', '/usr/local/lib']) {
    try { const f = fs.readdirSync(d).find((n) => /^libsodium\.so(\.\d+)*$/.test(n)); if (f) return path.join(d, f); } catch { /* нет каталога */ }
  }
  return null;
}
function run() {
  const so = findSodium(); const gcc = spawnSync('gcc', ['--version']);
  if (!so || gcc.status !== 0) return { skipped: 'нет gcc или libsodium' };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-')); const exe = path.join(dir, 't');
  execFileSync('gcc', ['-Wall', '-Wextra', '-Werror', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-o', exe, path.join(__dirname, 'test_hudblob.c'), path.join(__dirname, '..', 'core', 'hudblob.c'), so], { stdio: 'pipe' });
  const keys = S.generateSigningKeys();
  const blob = signBlob(keys.privateKey, { v: 1, hudId: 'HUD-0123ABCD', server: 'https://api.example.com', key: 'PTK-ABCDE-FGHJK-MNPQR-STUVW', licId: 'LK-AABBCCDD', keyId: 'k1', issuedAt: 1700000000 });
  fs.writeFileSync(path.join(dir, 'b.build'), blob);
  const r = spawnSync(exe, [rawPublicKey(keys.publicKey).toString('hex'), path.join(dir, 'b.build'), 'HUD-0123ABCD', 'PTK-ABCDE-FGHJK-MNPQR-STUVW'], { encoding: 'utf8' });
  return { status: r.status, out: r.stdout };
}
module.exports = { run };
if (require.main === module) { const r = run(); console.log(r.skipped ? 'SKIP: ' + r.skipped : r.out.trim()); process.exit(r.skipped ? 0 : r.status); }
