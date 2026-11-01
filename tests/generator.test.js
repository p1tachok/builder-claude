'use strict';
const test = require('node:test'); const assert = require('node:assert');
const fs = require('fs'); const os = require('os'); const path = require('path');
const { generate, extractConfig, GeneratorError, sha256 } = require('../src/generator');
const { defaultConfig } = require('../src/config');
const { configFromFolders } = require('../src/cli');
const { makePng, makeJpeg } = require('./helpers');

const TEMPLATE = fs.readFileSync(path.join(__dirname, '..', 'templates', 'hud.template.js'), 'utf8');
const NOW = new Date('2026-01-01T00:00:00Z');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hudtest-'));
const uri = (buf, mime = 'image/png') => `data:${mime};base64,${buf.toString('base64')}`;

test('шаблон: структура oldRadmirConfig соответствует ожиданиям', () => {
  const c = extractConfig(TEMPLATE);
  assert.deepStrictEqual(Object.keys(c.icons).sort(), ['active_wanted', 'armour', 'breath', 'cash', 'circle', 'health', 'hunger', 'inactive_wanted', 'radar', 'wanted_back', 'weapon_back', 'zone']);
  assert.strictEqual(Object.keys(c.logo).length, 21);
  assert.strictEqual(Object.keys(c.weapon).length, 46);
  assert.ok(!('45' in c.weapon) && !('47' in c.weapon) && !('48' in c.weapon));
});

test('пустая конфигурация: JS не меняется по смыслу и конфиг идентичен шаблону', () => {
  const r = generate({ template: TEMPLATE, config: defaultConfig(), now: NOW });
  assert.strictEqual(r.js, TEMPLATE);
  assert.deepStrictEqual(r.applied, []);
});

test('подстановка auth/icon/logo/weapon: заменено нужное, остальное не тронуто', () => {
  const dir = tmp(); const png = makePng(3, 3, [1, 2, 3, 255]);
  fs.writeFileSync(path.join(dir, 'a.png'), png);
  const jpg = makeJpeg(4, 4);
  const cfg = defaultConfig();
  cfg.assets.auth = { file: 'a.png' };
  cfg.assets.icons.health = { dataUri: uri(png) };
  cfg.assets.logos['3'] = { dataUri: uri(jpg, 'image/jpeg') };
  cfg.assets.weapons['5'] = { dataUri: uri(png) };
  const r = generate({ template: TEMPLATE, config: cfg, baseDir: dir, now: NOW });
  const base = extractConfig(TEMPLATE); const out = extractConfig(r.js);
  assert.strictEqual(out.auth.auth, uri(png));
  assert.strictEqual(out.icons.health, uri(png));
  assert.strictEqual(out.logo['3'], uri(jpg, 'image/jpeg'));
  assert.strictEqual(out.weapon['5'], uri(png));
  assert.strictEqual(out.weapon['4'], base.weapon['4']);
  assert.strictEqual(out.logo['4'], base.logo['4']);
  assert.strictEqual(out.icons.armour, base.icons.armour);
  // за пределами блока config шаблон не изменился
  const tail = (s) => s.slice(s.indexOf('// ===== ФОН АВТОРИЗАЦИИ'));
  assert.strictEqual(tail(r.js), tail(TEMPLATE));
  assert.ok(r.checks.includes('syntax: ok'));
});

test('радар: форма, обводка, цвет и цвет окон попадают в код', () => {
  const cfg = defaultConfig();
  cfg.radar = { shape: 'round', outlineSize: 2.5, outlineColor: '#ff00ff' };
  cfg.colors.radicalWindows = '#112233';
  const r = generate({ template: TEMPLATE, config: cfg, now: NOW });
  assert.match(r.js, /let currentType = "round";/);
  assert.match(r.js, /let radarColor = "#FF00FF";/);
  assert.match(r.js, /2\.50vh solid \$\{radarColor\}/);
  assert.ok(!/0\.60vh solid/.test(r.js));
  assert.match(r.js, /applyInterfaceColor\("#112233"\);/);
  // вызов стоит после объявления interfaceStyle (иначе TDZ)
  assert.ok(r.js.indexOf('applyInterfaceColor("#112233")') > r.js.indexOf('let interfaceStyle = null;'));
  assert.deepStrictEqual(r.warnings, []);
});

test('обводка без цвета даёт предупреждение (шаблонный цвет прозрачный)', () => {
  const cfg = defaultConfig(); cfg.radar.outlineSize = 1;
  assert.ok(generate({ template: TEMPLATE, config: cfg, now: NOW }).warnings.some((w) => /прозрач/.test(w)));
});

test('неподдерживаемые параметры не применяются молча — есть предупреждения', () => {
  const cfg = defaultConfig(); cfg.colors.hp = '#00FF00'; cfg.colors.chat = '#000000'; cfg.captureBoard = 'black';
  const r = generate({ template: TEMPLATE, config: cfg, now: NOW });
  assert.strictEqual(r.js, TEMPLATE);
  assert.ok(r.warnings.length === 3 && r.warnings.every((w) => /НЕ применено/.test(w)));
});

test('оружие с ID вне шаблона добавляется с предупреждением', () => {
  const cfg = defaultConfig(); cfg.assets.weapons['45'] = { dataUri: uri(makePng()) };
  const r = generate({ template: TEMPLATE, config: cfg, now: NOW });
  assert.ok('45' in extractConfig(r.js).weapon);
  assert.ok(r.warnings.some((w) => /45/.test(w)));
});

test('отклоняются: path traversal, битая/подменённая картинка, огромный файл, невалидный конфиг', () => {
  const dir = tmp(); const outside = path.join(os.tmpdir(), 'hud-outside.png'); fs.writeFileSync(outside, makePng());
  const mk = (ref) => { const c = defaultConfig(); c.assets.auth = ref; return c; };
  assert.throws(() => generate({ template: TEMPLATE, config: mk({ file: '../' + path.basename(outside) }), baseDir: dir }), /за пределы|не найден/);
  assert.throws(() => generate({ template: TEMPLATE, config: mk({ file: outside }), baseDir: dir }), /за пределы|не найден/);
  fs.symlinkSync(outside, path.join(dir, 'link.png'));
  assert.throws(() => generate({ template: TEMPLATE, config: mk({ file: 'link.png' }), baseDir: dir }), /за пределы/);
  fs.writeFileSync(path.join(dir, 'fake.png'), 'MZ this is an exe');
  assert.throws(() => generate({ template: TEMPLATE, config: mk({ file: 'fake.png' }), baseDir: dir }), /Неподдерживаемый/);
  fs.writeFileSync(path.join(dir, 'big.png'), Buffer.concat([makePng(), Buffer.alloc(3 * 1024 * 1024)]));
  assert.throws(() => generate({ template: TEMPLATE, config: mk({ file: 'big.png' }), baseDir: dir }), /слишком большой/);
  const bad = defaultConfig(); bad.radar.outlineSize = 9;
  assert.throws(() => generate({ template: TEMPLATE, config: bad }), GeneratorError);
  assert.throws(() => generate({ template: TEMPLATE, config: mk({ dataUri: 'data:image/svg+xml;base64,PHN2Zz4=' }) }), /data URI/);
});

test('шаблон-исходник не изменяется, результат детерминирован, manifest/hash верны', () => {
  const before = sha256(Buffer.from(TEMPLATE));
  const cfg = defaultConfig(); cfg.radar.shape = 'rect'; cfg.assets.auth = { dataUri: uri(makePng()) };
  const a = generate({ template: TEMPLATE, config: cfg, now: NOW });
  const b = generate({ template: TEMPLATE, config: cfg, now: NOW });
  assert.strictEqual(a.manifest.files[0].sha256, b.manifest.files[0].sha256);
  assert.strictEqual(a.manifest.files[0].sha256, sha256(a.jsBuffer));
  assert.strictEqual(a.manifest.files[0].size, a.jsBuffer.length);
  assert.strictEqual(sha256(Buffer.from(TEMPLATE)), before);
  assert.strictEqual(a.manifest.signature, null);
  assert.deepStrictEqual(a.manifest.applied.sort(), ['assets.auth', 'radar.shape']);
});

test('шаблон с изменённым якорем отклоняется, а не правится «наугад»', () => {
  const broken = TEMPLATE.replace('let currentType = "oval";', 'let currentType = "oval"; // x\nlet currentType = "oval";');
  const cfg = defaultConfig(); cfg.radar.shape = 'rect';
  assert.throws(() => generate({ template: broken, config: cfg }), /не уникален/);
  const missing = TEMPLATE.replace('let radarColor = "#F000";', '');
  const c2 = defaultConfig(); c2.radar.outlineColor = '#000000';
  assert.throws(() => generate({ template: missing, config: c2 }), /не содержит/);
});

test('загрузка из папок auth/ ikons/ logo/ weapon/ (структура рядом с Builder.exe)', () => {
  const dir = tmp();
  for (const d of ['auth', 'ikons', 'logo', 'weapon']) fs.mkdirSync(path.join(dir, d));
  const png = makePng();
  fs.writeFileSync(path.join(dir, 'auth', 'auth.png'), png);
  fs.writeFileSync(path.join(dir, 'ikons', 'health.png'), png);
  fs.writeFileSync(path.join(dir, 'ikons', 'unknown.png'), png);   // игнорируется
  fs.writeFileSync(path.join(dir, 'logo', '07.png'), png);
  fs.writeFileSync(path.join(dir, 'weapon', '30.png'), png);
  const cfg = configFromFolders(dir);
  assert.deepStrictEqual(Object.keys(cfg.assets.icons), ['health']);
  assert.deepStrictEqual(Object.keys(cfg.assets.logos), ['7']);
  assert.deepStrictEqual(Object.keys(cfg.assets.weapons), ['30']);
  const r = generate({ template: TEMPLATE, config: cfg, baseDir: dir, now: NOW });
  assert.strictEqual(extractConfig(r.js).weapon['30'], uri(png));
});
