#!/usr/bin/env node
'use strict';
// node loader/tools/gen_pubkey_h.js server/data/keys/signing.pub.pem > loader/win/pubkey.h
const fs = require('fs');
const { rawPublicKey } = require('../../server/src/blob');
function render(pem) {
  const raw = rawPublicKey(pem);
  const bytes = Array.from(raw, (b) => '0x' + b.toString(16).padStart(2, '0'));
  const rows = []; for (let i = 0; i < 32; i += 8) rows.push('  ' + bytes.slice(i, i + 8).join(', '));
  return `/* Сгенерировано gen_pubkey_h.js. Публичный ключ подписи сервера (Ed25519). Секретов здесь нет. */\n#include <stdint.h>\nstatic const uint8_t HB_SERVER_PUBKEY[32] = {\n${rows.join(',\n')}\n};\n`;
}
module.exports = { render };
if (require.main === module) {
  if (!process.argv[2]) { console.error('Использование: gen_pubkey_h.js <signing.pub.pem>'); process.exit(1); }
  process.stdout.write(render(fs.readFileSync(process.argv[2], 'utf8')));
}
