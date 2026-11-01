'use strict';
const test = require('node:test'); const assert = require('node:assert');
const { ConfigStore } = require('../src/state'); const { defaultConfig } = require('../src/config');

test('выбор без «Установить» не меняет установленное значение (preview только в preview())', () => {
  const s = new ConfigStore(defaultConfig());
  s.open('radar.shape'); s.setDraft('round');
  assert.strictEqual(s.preview().radar.shape, 'round');
  assert.strictEqual(s.installed.radar.shape, null);
  assert.ok(s.isDirty);
});
test('Установить сохраняет, Отмена/X откатывает', () => {
  const s = new ConfigStore(defaultConfig());
  s.open('radar.shape'); s.setDraft('square'); assert.ok(s.commit().ok);
  assert.strictEqual(s.installed.radar.shape, 'square'); assert.strictEqual(s.openPath, null);
  s.open('radar.shape'); s.setDraft('oval'); s.cancel();
  assert.strictEqual(s.installed.radar.shape, 'square'); assert.strictEqual(s.preview().radar.shape, 'square');
});
test('открытие другого модуля отбрасывает незавершённый черновик', () => {
  const s = new ConfigStore(defaultConfig());
  s.open('colors.hp'); s.setDraft('#112233'); s.open('radar.outlineSize');
  assert.strictEqual(s.installed.colors.hp, null); assert.strictEqual(s.preview().colors.hp, null);
});
test('невалидный черновик не устанавливается, окно остаётся открытым', () => {
  const s = new ConfigStore(defaultConfig());
  s.open('radar.outlineSize'); s.setDraft(7);
  const r = s.commit(); assert.ok(!r.ok); assert.ok(r.errors.length);
  assert.strictEqual(s.installed.radar.outlineSize, null); assert.strictEqual(s.openPath, 'radar.outlineSize');
});
test('сброс к стандартной и работа с asset-слотами', () => {
  const s = new ConfigStore(defaultConfig());
  s.open('assets.weapons.5'); s.setDraft({ file: 'w5.png' }); assert.ok(s.commit().ok);
  assert.deepStrictEqual(s.installed.assets.weapons['5'], { file: 'w5.png' });
  assert.ok(s.reset('assets.weapons.5', undefined).ok);
  assert.strictEqual(s.installed.assets.weapons['5'], undefined);
});
