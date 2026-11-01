'use strict';
const C = require('./constants');

const HEX6 = /^#[0-9a-fA-F]{6}$/;
const SCHEMA_VERSION = 1;

function defaultConfig() {
  return {
    schemaVersion: SCHEMA_VERSION,
    hudId: 'HUD-001',
    distribution: 'free',        // free | paid — выбирается при создании HUD
    hudType: 'free',             // free | paid — выбирается при создании HUD; на сервере решение принимает backend
    developerId: null,           // информационное поле; доверенным источником будет backend
    version: '1.0.0',
    status: 'draft',
    assets: { auth: null, icons: {}, logos: {}, weapons: {}, dialogBackground: null },
    colors: { chat: null, radicalWindows: null, hp: null, armor: null, food: null },
    captureBoard: null,
    radar: { shape: null, outlineSize: null, outlineColor: null },
    dialogStyle: { type: null },
    metadata: { createdAt: null, updatedAt: null, templateVersion: null },
  };
}

// Миграция: принимает «плоскую» форму из ТЗ (без schemaVersion) и текущую.
function migrate(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Конфигурация должна быть объектом');
  const v = raw.schemaVersion;
  if (v === undefined) {
    const d = defaultConfig();
    const o = raw;
    d.assets.auth = o.auth ?? null;
    d.assets.icons = { ...(o.icons || {}) };
    d.assets.logos = { ...(o.logos || {}) };
    d.assets.weapons = { ...(o.weapons || {}) };
    d.colors = { ...d.colors, ...Object.fromEntries(Object.entries(o.colors || {}).filter(([k]) => k !== 'radarOutline')) };
    d.captureBoard = o.captureBoard ?? null;
    d.radar = { ...d.radar, ...(o.radar || {}) };
    if (d.radar.outlineColor == null && o.colors && o.colors.radarOutline != null) d.radar.outlineColor = o.colors.radarOutline;
    d.dialogStyle.type = (o.dialogStyle && o.dialogStyle.type) ?? null;
    if (o.dialogStyle && o.dialogStyle.image) d.assets.dialogBackground = o.dialogStyle.image;
    return d;
  }
  if (!Number.isInteger(v) || v < 1) throw new Error(`Некорректный schemaVersion: ${v}`);
  if (v > SCHEMA_VERSION) throw new Error(`Конфигурация версии ${v} новее поддерживаемой (${SCHEMA_VERSION})`);
  const d = defaultConfig();
  const c = structuredClone(raw);
  return {
    ...d, ...c,
    assets: { ...d.assets, ...(c.assets || {}) },
    colors: { ...d.colors, ...(c.colors || {}) },
    radar: { ...d.radar, ...(c.radar || {}) },
    dialogStyle: { ...d.dialogStyle, ...(c.dialogStyle || {}) },
    metadata: { ...d.metadata, ...(c.metadata || {}) },
  };
}

function isAssetRef(a) {
  if (!a || typeof a !== 'object' || Array.isArray(a)) return false;
  const keys = Object.keys(a);
  return keys.length === 1 && (keys[0] === 'file' || keys[0] === 'dataUri') &&
    typeof a[keys[0]] === 'string' && a[keys[0]].length > 0;
}

function isValidOutlineSize(n) {
  return typeof n === 'number' && Number.isFinite(n) && n >= 0 && n <= 5 &&
    Math.abs(n * 100 - Math.round(n * 100)) < 1e-6;
}

function validate(cfg) {
  const errors = [];
  const err = (p, m) => errors.push({ path: p, message: m });
  if (!cfg || typeof cfg !== 'object') return { ok: false, errors: [{ path: '', message: 'Нет конфигурации' }] };
  if (cfg.schemaVersion !== SCHEMA_VERSION) err('schemaVersion', `Ожидалась версия ${SCHEMA_VERSION}`);
  if (typeof cfg.hudId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(cfg.hudId)) err('hudId', 'Допустимы буквы, цифры, _ и - (до 64)');
  if (typeof cfg.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(cfg.version)) err('version', 'Формат версии X.Y.Z');
  if (!C.HUD_STATUSES.includes(cfg.status)) err('status', 'Недопустимый статус');
  if (cfg.hudType !== 'free' && cfg.hudType !== 'paid') err('hudType', 'free | paid');
  if (cfg.distribution !== 'free' && cfg.distribution !== 'paid') err('distribution', 'free | paid');

  const a = cfg.assets || {};
  const chk = (path, ref) => { if (ref != null && !isAssetRef(ref)) err(path, 'Ожидался {file} или {dataUri}'); };
  chk('assets.auth', a.auth);
  chk('assets.dialogBackground', a.dialogBackground);
  for (const [k, v] of Object.entries(a.icons || {})) {
    if (!C.ICON_KEYS.includes(k)) err(`assets.icons.${k}`, 'Неизвестная иконка'); else chk(`assets.icons.${k}`, v);
  }
  for (const [k, v] of Object.entries(a.logos || {})) {
    const n = Number(k);
    if (!/^\d+$/.test(k) || n < 1 || n > C.LOGO_COUNT) err(`assets.logos.${k}`, `Логотип 1..${C.LOGO_COUNT}`); else chk(`assets.logos.${k}`, v);
  }
  for (const [k, v] of Object.entries(a.weapons || {})) {
    const n = Number(k);
    if (!/^\d+$/.test(k) || n < 0 || n > C.WEAPON_MAX_ID) err(`assets.weapons.${k}`, `ID оружия 0..${C.WEAPON_MAX_ID}`); else chk(`assets.weapons.${k}`, v);
  }
  const known = Object.keys(defaultConfig().colors);
  for (const [k, v] of Object.entries(cfg.colors || {})) {
    if (!known.includes(k)) err(`colors.${k}`, 'Неизвестный цвет');
    else if (v != null && !HEX6.test(v)) err(`colors.${k}`, 'Нужен формат #RRGGBB');
  }
  const r = cfg.radar || {};
  if (r.shape != null && !C.RADAR_SHAPES.includes(r.shape)) err('radar.shape', `Одно из: ${C.RADAR_SHAPES.join(', ')}`);
  if (r.outlineSize != null && !isValidOutlineSize(r.outlineSize)) err('radar.outlineSize', 'Число 0.00–5.00 с шагом 0.01');
  if (r.outlineColor != null && !HEX6.test(r.outlineColor)) err('radar.outlineColor', 'Нужен формат #RRGGBB');
  if (cfg.captureBoard != null && !C.CAPTURE_VARIANTS.includes(cfg.captureBoard)) err('captureBoard', `Одно из: ${C.CAPTURE_VARIANTS.join(', ')}`);
  const d = cfg.dialogStyle || {};
  if (d.type != null && !C.DIALOG_TYPES.includes(d.type)) err('dialogStyle.type', `Одно из: ${C.DIALOG_TYPES.join(', ')}`);
  if (d.type === 'custom' && !a.dialogBackground) err('dialogStyle.type', 'Для custom нужна assets.dialogBackground');
  return { ok: errors.length === 0, errors };
}

module.exports = { SCHEMA_VERSION, defaultConfig, migrate, validate, isAssetRef, isValidOutlineSize, HEX6 };
