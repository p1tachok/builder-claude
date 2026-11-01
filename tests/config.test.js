'use strict';
const test = require('node:test'); const assert = require('node:assert');
const { defaultConfig, migrate, validate, isValidOutlineSize } = require('../src/config');

test('конфиг по умолчанию валиден', () => assert.ok(validate(defaultConfig()).ok));
test('radar.outlineSize: 0.00..5.00 шаг 0.01', () => {
  for (const ok of [0, 0.01, 0.6, 1.23, 4.99, 5]) assert.ok(isValidOutlineSize(ok), String(ok));
  for (const bad of [-0.01, 5.01, 0.005, 1.234, NaN, Infinity, '1', null]) assert.ok(!isValidOutlineSize(bad), String(bad));
  const c = defaultConfig(); c.radar.outlineSize = 5.01;
  assert.ok(!validate(c).ok);
});
test('цвета только #RRGGBB', () => {
  const c = defaultConfig();
  for (const bad of ['FF00FF', '#FFF', '#GG0000', '#FF00FF80', 'red']) { c.colors.hp = bad; assert.ok(!validate(c).ok, bad); }
  c.colors.hp = '#FF00ff'; assert.ok(validate(c).ok);
});
test('радар: только известные формы; слоты ограничены', () => {
  const c = defaultConfig(); c.radar.shape = 'triangle'; assert.ok(!validate(c).ok);
  c.radar.shape = 'rect'; assert.ok(validate(c).ok);
  c.assets.logos['22'] = { file: 'a.png' }; assert.ok(!validate(c).ok); delete c.assets.logos['22'];
  c.assets.logos['0'] = { file: 'a.png' }; assert.ok(!validate(c).ok); delete c.assets.logos['0'];
  c.assets.weapons['49'] = { file: 'a.png' }; assert.ok(!validate(c).ok); delete c.assets.weapons['49'];
  c.assets.icons.evil = { file: 'a.png' }; assert.ok(!validate(c).ok);
});
test('кастомный диалог требует картинку; ассет только {file}|{dataUri}', () => {
  const c = defaultConfig(); c.dialogStyle.type = 'custom'; assert.ok(!validate(c).ok);
  c.assets.dialogBackground = { file: 'd.png' }; assert.ok(validate(c).ok);
  c.assets.auth = 'raw string'; assert.ok(!validate(c).ok);
  c.assets.auth = { file: 'a.png', extra: 1 }; assert.ok(!validate(c).ok);
});
test('миграция: плоская форма из ТЗ -> schemaVersion 1', () => {
  const m = migrate({ auth: { file: 'a.png' }, icons: { health: { file: 'h.png' } }, logos: { 1: { file: 'l.png' } }, weapons: { 5: { file: 'w.png' } },
    colors: { hp: '#112233', radarOutline: '#000000' }, radar: { shape: 'round', outlineSize: 1.5 }, dialogStyle: { type: 'normal', image: null } });
  assert.strictEqual(m.schemaVersion, 1);
  assert.deepStrictEqual(m.assets.auth, { file: 'a.png' });
  assert.ok(m.assets.weapons['5'] && m.assets.logos['1'] && m.assets.icons.health);
  assert.strictEqual(m.radar.outlineColor, '#000000');
  assert.ok(validate(m).ok, JSON.stringify(validate(m).errors));
});
test('миграция: новая версия схемы и мусор отклоняются', () => {
  assert.throws(() => migrate({ schemaVersion: 2 }), /новее/);
  assert.throws(() => migrate({ schemaVersion: 0 }));
  assert.throws(() => migrate(null)); assert.throws(() => migrate([]));
});
test('сериализация туда-обратно сохраняет конфиг', () => {
  const c = defaultConfig(); c.radar = { shape: 'oval', outlineSize: 2.5, outlineColor: '#FF00FF' };
  assert.deepStrictEqual(migrate(JSON.parse(JSON.stringify(c))), c);
});
