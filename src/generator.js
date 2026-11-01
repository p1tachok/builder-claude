'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');
const { validate, migrate, HEX6 } = require('./config');
const { toDataUri, isSafeDataUri } = require('./imageutil');
const C = require('./constants');

class GeneratorError extends Error {}
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');

// ---- безопасное разрешение путей (защита от path traversal / symlink) ----
function resolveInside(baseDir, rel) {
  const base = fs.realpathSync(baseDir);
  const full = path.resolve(base, rel);
  let real;
  try { real = fs.realpathSync(full); } catch { throw new GeneratorError(`Файл не найден: ${rel}`); }
  if (real !== base && !real.startsWith(base + path.sep)) throw new GeneratorError(`Путь выходит за пределы проекта: ${rel}`);
  return real;
}

function loadAsset(ref, baseDir, label) {
  let r;
  if (ref.dataUri) {
    const m = /^data:image\/(?:png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(ref.dataUri);
    if (!m) throw new GeneratorError(`${label}: некорректный data URI`);
    r = toDataUri(Buffer.from(m[1], 'base64'));
  } else {
    if (!baseDir) throw new GeneratorError(`${label}: не задан baseDir для file`);
    r = toDataUri(fs.readFileSync(resolveInside(baseDir, ref.file)));
  }
  return r.dataUri;
}

// ---- чтение блока oldRadmirConfig из шаблона ----
function locateConfigBlock(tpl) {
  const startKey = 'const oldRadmirConfig = ';
  const s = tpl.indexOf(startKey);
  if (s < 0 || tpl.indexOf(startKey, s + 1) >= 0) throw new GeneratorError('oldRadmirConfig не найден или найден дважды');
  const litStart = s + startKey.length;
  const endRe = /\r?\n[ \t]*\};[ \t]*\r?\n[ \t]*\/\/ ===== ФОН АВТОРИЗАЦИИ/g;
  endRe.lastIndex = litStart;
  const m = endRe.exec(tpl);
  if (!m) throw new GeneratorError('Конец oldRadmirConfig не найден (шаблон изменён?)');
  const litEnd = m.index + m[0].indexOf('}') + 1;
  return { s, litStart, litEnd };
}

function extractConfig(tpl) {
  const { litStart, litEnd } = locateConfigBlock(tpl);
  const obj = vm.runInNewContext('(' + tpl.slice(litStart, litEnd) + ')', Object.create(null), { timeout: 10000 });
  const expected = ['auth', 'icons', 'weapon', 'logo'];
  const got = Object.keys(obj);
  if (got.length !== 4 || !expected.every((k) => got.includes(k))) {
    throw new GeneratorError('Неожиданные секции oldRadmirConfig: ' + got.join(','));
  }
  return JSON.parse(JSON.stringify(obj));
}

function serializeConfig(obj, eol) {
  const sec = (name) => {
    const body = Object.entries(obj[name]).map(([k, v]) => ` ${JSON.stringify(k)}: ${JSON.stringify(v)},${eol}`).join('');
    return `        ${name}:${eol}{${eol}${body} },${eol}`;
  };
  return `{${eol}${['auth', 'icons', 'weapon', 'logo'].map(sec).join('')}    }`;
}

function replaceOnce(text, find, repl, what) {
  const i = text.indexOf(find);
  if (i < 0) throw new GeneratorError(`Шаблон не содержит ожидаемый фрагмент: ${what}`);
  if (text.indexOf(find, i + 1) >= 0) throw new GeneratorError(`Фрагмент не уникален в шаблоне: ${what}`);
  return text.slice(0, i) + repl + text.slice(i + find.length);
}

const UNSUPPORTED = [
  ['colors.chat', (c) => c.colors.chat, 'цвет чата: в шаблоне нет CSS/кода для него'],
  ['colors.hp', (c) => c.colors.hp, 'цвет HP: в шаблоне нет подтверждённого селектора'],
  ['colors.armor', (c) => c.colors.armor, 'цвет Armor: в шаблоне нет подтверждённого селектора'],
  ['colors.food', (c) => c.colors.food, 'цвет Food: в шаблоне нет подтверждённого селектора'],
  ['captureBoard', (c) => c.captureBoard, 'табло капта: в шаблоне нет ресурсов и механизма переключения'],
  ['dialogStyle', (c) => c.dialogStyle.type === 'custom', 'кастомный стиль диалогов: в шаблоне нет кода рендера фонов диалогов'],
  ['assets.dialogBackground', (c) => c.assets.dialogBackground, 'фон диалога: не применяется (см. dialogStyle)'],
];

/**
 * generate({ template, config, baseDir, now })
 *  template — текст шаблона hud.js; config — конфигурация (будет migrate+validate)
 */
function generate({ template, config, baseDir = null, now = new Date() }) {
  if (typeof template !== 'string' || !template.length) throw new GeneratorError('Пустой шаблон');
  const cfg = migrate(config);
  const v = validate(cfg);
  if (!v.ok) throw new GeneratorError('Конфигурация невалидна: ' + v.errors.map((e) => `${e.path}: ${e.message}`).join('; '));

  const eol = template.includes('\r\n') ? '\r\n' : '\n';
  const warnings = [];
  const applied = [];
  let out = template;

  // 1) картинки
  const base = extractConfig(template);
  const next = structuredClone(base);
  const put = (section, key, ref, label) => {
    next[section][key] = loadAsset(ref, baseDir, label);
    applied.push(label);
  };
  if (cfg.assets.auth) put('auth', 'auth', cfg.assets.auth, 'assets.auth');
  for (const [k, ref] of Object.entries(cfg.assets.icons)) put('icons', k, ref, `assets.icons.${k}`);
  for (const [k, ref] of Object.entries(cfg.assets.logos)) put('logo', String(Number(k)), ref, `assets.logos.${k}`);
  for (const [k, ref] of Object.entries(cfg.assets.weapons)) {
    const id = String(Number(k));
    if (!(id in base.weapon)) warnings.push(`assets.weapons.${k}: ID отсутствует в стандартном шаблоне (добавлен как новый)`);
    put('weapon', id, ref, `assets.weapons.${k}`);
  }
  if (applied.length) {
    const { litStart, litEnd } = locateConfigBlock(out);
    out = out.slice(0, litStart) + serializeConfig(next, eol) + out.slice(litEnd);
  }

  // 2) радар
  const r = cfg.radar;
  if (r.shape) {
    out = replaceOnce(out, 'let currentType = "oval";', `let currentType = ${JSON.stringify(r.shape)};`, 'currentType');
    applied.push('radar.shape');
  }
  if (r.outlineColor) {
    out = replaceOnce(out, 'let radarColor = "#F000";', `let radarColor = ${JSON.stringify(r.outlineColor.toUpperCase())};`, 'radarColor');
    applied.push('radar.outlineColor');
  }
  if (r.outlineSize != null) {
    out = replaceOnce(out, '0.60vh solid ${radarColor}', `${r.outlineSize.toFixed(2)}vh solid \${radarColor}`, 'radar border width');
    applied.push('radar.outlineSize');
    if (!r.outlineColor && r.outlineSize > 0) {
      warnings.push('radar.outlineSize задан, а outlineColor нет: цвет по умолчанию в шаблоне (#F000) прозрачный — обводка не будет видна');
    }
  }

  // 3) цвет «радикальных окон» = applyInterfaceColor (единственный подтверждённый цвет в шаблоне)
  if (cfg.colors.radicalWindows) {
    const anchor = `(function () {${eol}    let hudHide = 0;`;
    out = replaceOnce(out, anchor, `applyInterfaceColor(${JSON.stringify(cfg.colors.radicalWindows.toUpperCase())});${eol}${eol}${anchor}`, 'interface color anchor');
    applied.push('colors.radicalWindows');
  }

  // 4) честные предупреждения о неподдержанных параметрах
  for (const [p, get, msg] of UNSUPPORTED) if (get(cfg)) warnings.push(`${p}: НЕ применено — ${msg}`);

  // 5) проверки результата
  const checks = [];
  try { new vm.Script(out, { filename: 'hud.js' }); checks.push('syntax: ok'); }
  catch (e) { throw new GeneratorError('Сгенерированный JS не компилируется: ' + e.message); }

  const re = extractConfig(out);
  for (const sec of Object.keys(re)) {
    for (const [k, val] of Object.entries(re[sec])) {
      const original = base[sec][k];
      if (val !== original && !isSafeDataUri(val)) throw new GeneratorError(`Некорректный data URI в ${sec}.${k}`);
      if (JSON.stringify(val) !== JSON.stringify(next[sec][k])) throw new GeneratorError(`Расхождение значения ${sec}.${k} после генерации`);
    }
    if (Object.keys(re[sec]).length !== Object.keys(next[sec]).length) throw new GeneratorError(`Расхождение числа ключей в секции ${sec}`);
  }
  checks.push('config round-trip: ok');

  const jsBuf = Buffer.from(out, 'utf8');
  const iso = now.toISOString();
  const normalized = { ...cfg, metadata: { ...cfg.metadata, createdAt: cfg.metadata.createdAt || iso, updatedAt: iso, templateVersion: sha256(Buffer.from(template, 'utf8')).slice(0, 16) } };
  const manifest = {
    schemaVersion: 1,
    hudId: cfg.hudId,
    version: cfg.version,
    templateVersion: normalized.metadata.templateVersion,
    createdAt: iso,
    files: [{ name: 'hud.js', sha256: sha256(jsBuf), size: jsBuf.length }],
    applied,
    warnings,
    signature: null, // подпись выполняет backend (приватный ключ только на сервере)
  };
  return { js: out, jsBuffer: jsBuf, manifest, config: normalized, warnings, applied, checks };
}

module.exports = { generate, extractConfig, GeneratorError, resolveInside, sha256 };
