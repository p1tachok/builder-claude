'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const b64u = (b) => Buffer.from(b).toString('base64url');

// ---- пароли: scrypt, соль на пользователя, сравнение за постоянное время ----
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${h.toString('base64')}`;
}
async function verifyPassword(pw, stored) {
  try {
    const [alg, N, r, p, salt, hash] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hash, 'base64');
    const got = await scrypt(pw, Buffer.from(salt, 'base64'), expected.length, { N: +N, r: +r, p: +p });
    return crypto.timingSafeEqual(got, expected);
  } catch { return false; }
}
let DUMMY = null;
async function dummyVerify(pw) { DUMMY = DUMMY || (await hashPassword('dummy-password-for-timing')); await verifyPassword(pw, DUMMY); }

function validatePasswordPolicy(pw) {
  if (typeof pw !== 'string' || pw.length < 10) return 'Пароль не короче 10 символов';
  if (pw.length > 256) return 'Пароль слишком длинный';
  return null;
}
const randomPassword = () => crypto.randomBytes(12).toString('base64url');

// ---- access-токен: payload.HMAC-SHA256 ----
function signToken(secret, payload) {
  const p = b64u(JSON.stringify(payload));
  const s = b64u(crypto.createHmac('sha256', secret).update(p).digest());
  return `${p}.${s}`;
}
function verifyToken(secret, token, nowSec = Math.floor(Date.now() / 1000)) {
  if (typeof token !== 'string' || token.length > 2048) return null;
  const [p, s, extra] = token.split('.');
  if (!p || !s || extra !== undefined) return null;
  const exp = crypto.createHmac('sha256', secret).update(p).digest();
  let got; try { got = Buffer.from(s, 'base64url'); } catch { return null; }
  if (got.length !== exp.length || !crypto.timingSafeEqual(got, exp)) return null;
  let pl; try { pl = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch { return null; }
  if (!pl || typeof pl.exp !== 'number' || pl.exp <= nowSec) return null;
  return pl;
}
const newRefreshToken = () => crypto.randomBytes(32).toString('base64url');
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---- Ed25519 подпись манифестов и лицензий ----
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
function signObject(privateKeyPem, obj) {
  return crypto.sign(null, Buffer.from(canonical(obj)), crypto.createPrivateKey(privateKeyPem)).toString('base64');
}
function verifyObject(publicKeyPem, obj, sigB64) {
  try { return crypto.verify(null, Buffer.from(canonical(obj)), crypto.createPublicKey(publicKeyPem), Buffer.from(sigB64, 'base64')); }
  catch { return false; }
}
function generateSigningKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { publicKey: publicKey.export({ type: 'spki', format: 'pem' }), privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

// ---- rate limit (фиксированное окно, в памяти процесса) ----
class RateLimiter {
  constructor(now = () => Date.now()) { this.now = now; this.m = new Map(); }
  hit(key, limit, windowMs) {
    const t = this.now(); let e = this.m.get(key);
    if (!e || e.reset <= t) { e = { n: 0, reset: t + windowMs }; this.m.set(key, e); }
    e.n++;
    if (this.m.size > 50000) for (const [k, v] of this.m) if (v.reset <= t) this.m.delete(k);
    return { ok: e.n <= limit, retryAfterSec: Math.ceil((e.reset - t) / 1000) };
  }
}

function compareSemver(a, b) {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) < (pb[i] || 0) ? -1 : 1; }
  return 0;
}

module.exports = { hashPassword, verifyPassword, dummyVerify, validatePasswordPolicy, randomPassword, signToken, verifyToken,
  newRefreshToken, sha256hex, canonical, signObject, verifyObject, generateSigningKeys, RateLimiter, compareSemver };
