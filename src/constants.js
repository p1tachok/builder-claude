'use strict';
// Ключи иконок извлечены из templates/hud.template.js (oldRadmirConfig.icons).
const ICON_KEYS = ['active_wanted', 'armour', 'breath', 'cash', 'circle', 'health', 'hunger',
  'inactive_wanted', 'radar', 'wanted_back', 'weapon_back', 'zone'];
const LOGO_COUNT = 21;
const WEAPON_MAX_ID = 48;                              // ТЗ упоминает 0..48
const TEMPLATE_WEAPON_IDS = [...Array(45).keys(), 46]; // в шаблоне: 0..44 и 46
const RADAR_SHAPES = ['oval', 'round', 'square', 'rect']; // ключи getRadarCSS в шаблоне
const CAPTURE_VARIANTS = ['normal', 'black', 'old', 'custom'];
const DIALOG_TYPES = ['normal', 'custom'];
const HUD_STATUSES = ['draft', 'published', 'revoked'];
const LIMITS = { maxImageBytes: 2 * 1024 * 1024, maxImageDim: 4096 };
module.exports = {
  ICON_KEYS, LOGO_COUNT, WEAPON_MAX_ID, TEMPLATE_WEAPON_IDS, RADAR_SHAPES,
  CAPTURE_VARIANTS, DIALOG_TYPES, HUD_STATUSES, LIMITS,
};
