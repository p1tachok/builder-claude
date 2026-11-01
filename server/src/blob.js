'use strict';
// Подписанный «blob» для loader: base64url(payload JSON).base64url(Ed25519-подпись по байтам payload).
// Подпись считается по сырым байтам payload (не по каноническому JSON), чтобы C-loader проверял без пересборки JSON.
const crypto = require('crypto');
const b64u = (b) => Buffer.from(b).toString('base64url');

function signBlob(privateKeyPem, obj) {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  const sig = crypto.sign(null, payload, crypto.createPrivateKey(privateKeyPem));
  return `${b64u(payload)}.${b64u(sig)}`;
}
function openBlob(publicKeyPem, text) {
  try {
    const parts = String(text).trim().split('.');
    if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
    const payload = Buffer.from(parts[0], 'base64url'), sig = Buffer.from(parts[1], 'base64url');
    if (sig.length !== 64) return null;
    if (!crypto.verify(null, payload, crypto.createPublicKey(publicKeyPem), sig)) return null;
    return JSON.parse(payload.toString('utf8'));
  } catch { return null; }
}
// Сырой публичный ключ Ed25519 (32 байта) для вшивания в loader
function rawPublicKey(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32);
}
module.exports = { signBlob, openBlob, rawPublicKey };
