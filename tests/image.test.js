'use strict';
const test = require('node:test'); const assert = require('node:assert');
const { inspectImage, toDataUri, isSafeDataUri, ImageError } = require('../src/imageutil');
const { makePng, makeJpeg, makeWebpLossless } = require('./helpers');

test('PNG/JPEG/WEBP определяются по сигнатуре и размерам', () => {
  assert.deepStrictEqual(inspectImage(makePng(4, 6)), { mime: 'image/png', width: 4, height: 6 });
  assert.deepStrictEqual(inspectImage(makeJpeg(3, 5)), { mime: 'image/jpeg', width: 3, height: 5 });
  assert.deepStrictEqual(inspectImage(makeWebpLossless(7, 9)), { mime: 'image/webp', width: 7, height: 9 });
});
test('мусор, пустой файл, текст под видом png отклоняются', () => {
  assert.throws(() => inspectImage(Buffer.alloc(0)), ImageError);
  assert.throws(() => inspectImage(Buffer.from('<svg onload=alert(1)>')), ImageError);
  assert.throws(() => inspectImage(Buffer.from('not an image at all, just text')), ImageError);
});
test('лимит размера и разрешения', () => {
  assert.throws(() => inspectImage(makePng(5000, 5)), /Разрешение/);
  assert.throws(() => inspectImage(makePng(2, 2), { maxImageBytes: 10, maxImageDim: 4096 }), /слишком большой/);
});
test('data URI корректен и проходит safe-проверку; svg/javascript — нет', () => {
  const r = toDataUri(makePng());
  assert.match(r.dataUri, /^data:image\/png;base64,/);
  assert.ok(isSafeDataUri(r.dataUri));
  assert.ok(!isSafeDataUri('data:image/svg+xml;base64,PHN2Zz4='));
  assert.ok(!isSafeDataUri('javascript:alert(1)'));
  assert.ok(!isSafeDataUri('data:image/png;base64,AAAA"+alert(1)+"'));
});
