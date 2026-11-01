#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const { generate, extractConfig, sha256 } = require('./generator');
const { ApiClient, publishHud, issueBuyerKey, exportFreeBuild } = require('./client');
const { defaultConfig, migrate, validate } = require('./config');
const C = require('./constants');

const EXT = ['.png', '.jpg', '.jpeg', '.webp'];
const stem = (f) => path.basename(f, path.extname(f));

// Структура рядом с Builder.exe: auth/auth.png, ikons/*.png, logo/N.png, weapon/N.png
function configFromFolders(dir, cfg) {
  const out = cfg || defaultConfig();
  const list = (sub) => {
    const p = path.join(dir, sub);
    if (!fs.existsSync(p)) return [];
    return fs.readdirSync(p, { withFileTypes: true })
      .filter((e) => e.isFile() && EXT.includes(path.extname(e.name).toLowerCase()))
      .map((e) => e.name);
  };
  for (const f of list('auth')) if (stem(f) === 'auth') out.assets.auth = { file: `auth/${f}` };
  for (const f of list('ikons')) if (C.ICON_KEYS.includes(stem(f))) out.assets.icons[stem(f)] = { file: `ikons/${f}` };
  for (const f of list('logo')) if (/^\d+$/.test(stem(f))) out.assets.logos[String(Number(stem(f)))] = { file: `logo/${f}` };
  for (const f of list('weapon')) if (/^\d+$/.test(stem(f))) out.assets.weapons[String(Number(stem(f)))] = { file: `weapon/${f}` };
  return out;
}

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 ? process.argv[i + 1] : def;
}

async function online(cmd) {
  const server = arg('server', process.env.PITACHOK_SERVER);
  if (!server || !process.env.PITACHOK_LOGIN || !process.env.PITACHOK_PASSWORD) throw new Error('Нужны --server (или PITACHOK_SERVER) и переменные PITACHOK_LOGIN / PITACHOK_PASSWORD');
  const client = new ApiClient(server); await client.login(process.env.PITACHOK_LOGIN, process.env.PITACHOK_PASSWORD);
  const loaderPath = arg('loader');
  if (cmd === 'publish') {
    const dir = path.resolve(arg('folder', '.')); const cfgFile = arg('config');
    const cfg = configFromFolders(dir, cfgFile ? migrate(JSON.parse(fs.readFileSync(cfgFile, 'utf8'))) : defaultConfig());
    const type = arg('type') || (cfgFile && cfg.distribution !== 'free' ? cfg.distribution : undefined);
    const r = await publishHud({ client, hudId: arg('hud'), name: arg('name'), type, config: cfg, baseDir: dir, version: arg('version', '1.0.0') });
    console.log(`Опубликовано: ${r.hudId} (${r.type}) v${r.version}, SHA-256 ${r.sha256}`); for (const w of r.warnings) console.log('ВНИМАНИЕ:', w);
    console.log(r.type === 'paid' ? `Дальше: выдайте ключ покупателю: node src/cli.js issue --hud ${r.hudId} --label "ник" --out buyers` : `Дальше: общий файл для всех: node src/cli.js free-build --hud ${r.hudId} --out dist`);
  } else if (cmd === 'issue') {
    const r = await issueBuyerKey({ client, hudId: arg('hud'), label: arg('label'), maxDevices: Number(arg('devices', '1')), outDir: path.resolve(arg('out', 'buyers')), loaderPath });
    console.log(`Ключ ${r.licenseId}: ${r.licenseKey}\nПапка для покупателя: ${r.dir}\n(ключ показывается один раз; ПК привяжется при первом запуске)`);
  } else {
    const r = await exportFreeBuild({ client, hudId: arg('hud'), outDir: path.resolve(arg('out', 'dist')), loaderPath });
    console.log('Готово:', r.dir);
  }
}

function main() {
  const cmd = process.argv[2];
  const tplPath = arg('template', path.join(__dirname, '..', 'templates', 'hud.template.js'));
  if (cmd === 'inspect') {
    const cfg = extractConfig(fs.readFileSync(tplPath, 'utf8'));
    console.log('auth:', Object.keys(cfg.auth).join(', '));
    console.log('icons:', Object.keys(cfg.icons).join(', '));
    console.log('weapon ids:', Object.keys(cfg.weapon).join(','));
    console.log('logo ids:', Object.keys(cfg.logo).join(','));
    return;
  }
  if (cmd === 'build') {
    const dir = path.resolve(arg('folder', '.'));
    const outDir = path.resolve(arg('out', path.join(dir, 'output')));
    const cfgFile = arg('config');
    let cfg = cfgFile ? migrate(JSON.parse(fs.readFileSync(cfgFile, 'utf8'))) : defaultConfig();
    cfg = configFromFolders(dir, cfg);
    const v = validate(cfg);
    if (!v.ok) { console.error('Ошибки конфигурации:\n' + v.errors.map((e) => ` - ${e.path}: ${e.message}`).join('\n')); process.exit(2); }
    const res = generate({ template: fs.readFileSync(tplPath, 'utf8'), config: cfg, baseDir: dir });
    fs.mkdirSync(outDir, { recursive: true });
    // атомарная запись: во временный файл, затем rename
    const write = (name, data) => { const t = path.join(outDir, name + '.tmp'); fs.writeFileSync(t, data); fs.renameSync(t, path.join(outDir, name)); };
    write('hud.js', res.jsBuffer);
    write('config.json', JSON.stringify(res.config, null, 2));
    write('manifest.json', JSON.stringify(res.manifest, null, 2));
    write('checksums.txt', `${res.manifest.files[0].sha256}  hud.js\n`);
    console.log(`OK: ${outDir}`);
    console.log('Применено:', res.applied.length ? res.applied.join(', ') : '(ничего, шаблон без изменений)');
    for (const w of res.warnings) console.log('ВНИМАНИЕ:', w);
    console.log('SHA-256 hud.js:', res.manifest.files[0].sha256);
    return;
  }
  if (cmd === 'publish' || cmd === 'issue' || cmd === 'free-build') return online(cmd);
  console.log('Использование:\n  node src/cli.js inspect [--template t.js]\n  node src/cli.js build --folder <dir> [--config cfg.json] [--out <dir>] [--template t.js]');
  process.exit(1);
}

if (require.main === module) {
  Promise.resolve().then(main).catch((e) => { console.error('ОШИБКА:', e.message); process.exit(1); });
}
module.exports = { configFromFolders };
