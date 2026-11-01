'use strict';
const { LIMITS } = require('./constants');

class ImageError extends Error {}

function pngInfo(b) {
  if (b.length < 24 || b.toString('latin1', 12, 16) !== 'IHDR') throw new ImageError('Повреждённый PNG');
  return { mime: 'image/png', width: b.readUInt32BE(16), height: b.readUInt32BE(20) };
}
function jpegInfo(b) {
  let i = 2;
  while (i + 9 < b.length) {
    if (b[i] !== 0xff) { i++; continue; }
    const m = b[i + 1];
    if (m === 0xff) { i++; continue; }
    if (m >= 0xc0 && m <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(m)) {
      return { mime: 'image/jpeg', height: b.readUInt16BE(i + 5), width: b.readUInt16BE(i + 7) };
    }
    if (m === 0xd8 || (m >= 0xd0 && m <= 0xd7) || m === 0x01) { i += 2; continue; }
    i += 2 + b.readUInt16BE(i + 2);
  }
  throw new ImageError('Повреждённый JPEG');
}
function webpInfo(b) {
  const t = b.toString('latin1', 12, 16);
  if (t === 'VP8X' && b.length >= 30) {
    return { mime: 'image/webp', width: 1 + b.readUIntLE(24, 3), height: 1 + b.readUIntLE(27, 3) };
  }
  if (t === 'VP8L' && b.length >= 25) {
    const v = b.readUInt32LE(21);
    return { mime: 'image/webp', width: (v & 0x3fff) + 1, height: ((v >> 14) & 0x3fff) + 1 };
  }
  if (t === 'VP8 ' && b.length >= 30 && b[23] === 0x9d && b[24] === 0x01 && b[25] === 0x2a) {
    return { mime: 'image/webp', width: b.readUInt16LE(26) & 0x3fff, height: b.readUInt16LE(28) & 0x3fff };
  }
  throw new ImageError('Повреждённый WEBP');
}

// Формат определяется строго по сигнатуре (расширение файла не учитывается).
function inspectImage(buf, limits = LIMITS) {
  if (!Buffer.isBuffer(buf)) throw new ImageError('Ожидался Buffer');
  if (buf.length === 0) throw new ImageError('Пустой файл');
  if (buf.length > limits.maxImageBytes) {
    throw new ImageError(`Файл слишком большой (${buf.length} байт, максимум ${limits.maxImageBytes})`);
  }
  let info;
  if (buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) info = pngInfo(buf);
  else if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) info = jpegInfo(buf);
  else if (buf.length > 16 && buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') info = webpInfo(buf);
  else throw new ImageError('Неподдерживаемый формат (нужен PNG, JPG/JPEG или WEBP)');
  if (!(info.width > 0 && info.height > 0)) throw new ImageError('Нулевые размеры изображения');
  if (info.width > limits.maxImageDim || info.height > limits.maxImageDim) {
    throw new ImageError(`Разрешение ${info.width}x${info.height} превышает ${limits.maxImageDim}px`);
  }
  return info;
}

function toDataUri(buf, limits) {
  const info = inspectImage(buf, limits);
  return { dataUri: `data:${info.mime};base64,${buf.toString('base64')}`, ...info };
}

const DATA_URI_RE = /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
function isSafeDataUri(s) { return typeof s === 'string' && DATA_URI_RE.test(s); }

module.exports = { inspectImage, toDataUri, isSafeDataUri, ImageError };
