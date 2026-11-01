'use strict';
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE,                         -- DEV-001 / OWNER-001
  login TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('owner','developer')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','archived')),
  can_create_hud INTEGER NOT NULL DEFAULT 1,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  token_hash TEXT NOT NULL UNIQUE,
  family TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS huds(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hud_id TEXT NOT NULL UNIQUE,
  developer_id INTEGER NOT NULL REFERENCES accounts(id),
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','blocked')),
  min_version TEXT,
  current_version TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hud_versions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hud_id TEXT NOT NULL REFERENCES huds(hud_id),
  version TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published')),
  js_sha256 TEXT NOT NULL,
  js_size INTEGER NOT NULL,
  manifest_json TEXT NOT NULL,
  mirror TEXT NOT NULL DEFAULT 'none',
  created_at TEXT NOT NULL,
  published_at TEXT,
  UNIQUE(hud_id, version)
);
CREATE TABLE IF NOT EXISTS licenses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lic_id TEXT NOT NULL UNIQUE,                -- LK-XXXXXXXX (публичный идентификатор)
  hud_id TEXT NOT NULL REFERENCES huds(hud_id),
  key_hash TEXT NOT NULL UNIQUE,              -- sha256 ключа; сам ключ не хранится
  key_prefix TEXT NOT NULL,
  label TEXT NOT NULL,                        -- заметка разработчика: кому выдан
  max_devices INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  revoke_reason TEXT,
  flagged INTEGER NOT NULL DEFAULT 0,         -- попытка использования на лишнем устройстве
  device_attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS activations(
  lic_row INTEGER NOT NULL REFERENCES licenses(id),
  hwid_hash TEXT NOT NULL,                    -- HMAC от HWID, сырой HWID не хранится
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  loader_version TEXT,
  PRIMARY KEY(lic_row, hwid_hash)
);
CREATE TABLE IF NOT EXISTS license_attempts(
  lic_row INTEGER NOT NULL REFERENCES licenses(id),
  hwid_hash TEXT NOT NULL,                    -- другое устройство, пытавшееся использовать ключ
  count INTEGER NOT NULL DEFAULT 1,
  first_at TEXT NOT NULL,
  last_at TEXT NOT NULL,
  PRIMARY KEY(lic_row, hwid_hash)
);
CREATE TABLE IF NOT EXISTS activation_attempts(
  lic_row INTEGER NOT NULL REFERENCES licenses(id),
  hwid_hash TEXT NOT NULL,
  device_label TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  first_attempt_at TEXT NOT NULL,
  last_attempt_at TEXT NOT NULL,
  PRIMARY KEY(lic_row, hwid_hash)
);
CREATE TABLE IF NOT EXISTS installations(
  install_id TEXT NOT NULL,
  hud_id TEXT NOT NULL,
  loader_version TEXT,
  hud_version TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_status TEXT,
  PRIMARY KEY(install_id, hud_id)
);
CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  details TEXT
);
`;

function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec(SCHEMA);
  // миграции существующих БД
  const cols = db.prepare('PRAGMA table_info(huds)').all().map((c) => c.name);
  if (!cols.includes('require_license')) db.exec('ALTER TABLE huds ADD COLUMN require_license INTEGER NOT NULL DEFAULT 0');
  const acols = db.prepare('PRAGMA table_info(activations)').all().map((c) => c.name);
  if (!acols.includes('device_label')) db.exec('ALTER TABLE activations ADD COLUMN device_label TEXT');
  return db;
}
module.exports = { openDb };
