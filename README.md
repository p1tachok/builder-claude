# Pitachok HUD Builder — ядро (этап 1) + backend (этап 2)

Этап 2 — backend в `server/` (Node, без зависимостей, SQLite): авторизация, HUD/версии, подпись, GitHub-публикация, лицензии, админ-API. См. `docs/API.md`.

Это ядро конструктора на Node.js (>=20, без внешних зависимостей): модель конфигурации,
логика «preview → Установить / Отмена», проверка изображений, генератор `hud.js`.
Оно НЕ является Windows-приложением `Pitachok Loader.exe`, backend-ом или ASI-модулем.

## Использование
```
npm test                                   # 49 тестов (ядро + backend)
node src/cli.js inspect                    # какие ключи есть в шаблоне
node src/cli.js build --folder <dir> [--config cfg.json] [--out <dir>]
```
`<dir>` — папка с ресурсами рядом с будущим Builder.exe:
`auth/auth.png`, `ikons/<ключ>.png`, `logo/1..21.png`, `weapon/<ID>.png`.
Результат: `hud.js`, `config.json`, `manifest.json` (SHA-256), `checksums.txt`.

## Модули
- `src/config.js` — конфиг (schemaVersion 1), валидация, миграция с формы из ТЗ
- `src/state.js` — ConfigStore: draft/preview/commit/cancel (в генератор идёт только installed)
- `src/imageutil.js` — PNG/JPEG/WEBP по сигнатуре, лимиты 2 МБ и 4096 px, безопасные data URI
- `src/generator.js` — структурная подстановка в `oldRadmirConfig`, якоря с проверкой уникальности, проверка синтаксиса и round-trip
- `schemas/hud-config.schema.json`, `docs/example.config.json`
- `templates/hud.template.js` — ваш hud_13896.js + исправленный блок AUTH-фона

## Loader
`loader/` — клиентская часть (`HudLoader.asi` + `HudLoader.build`), см. `loader/README.md`.

## Платные и бесплатные HUD: рабочий процесс
1. **Билдер** (`src/cli.js`; WPF-окно ещё не сделано): тип выбирается при публикации.
   ```
   export PITACHOK_LOGIN=... PITACHOK_PASSWORD=...
   node src/cli.js publish --server https://api.example.com --folder ./hud --name "Мой HUD" --type paid   # или --type free
   ```
   Конфиг HUD хранит поле `distribution: free | paid`.
2. **Платный:** `node src/cli.js issue --server ... --hud HUD-XXXXXXXX --label "ник покупателя" --devices 1 --out ./buyers` → папка покупателя
   с персональным `HudLoader.build` (ключ внутри). Отправьте покупателю эту папку/файл и `HudLoader.asi`. ПК привязывается автоматически при первом запуске
   игры с этим HUD. Любой другой ПК получает отказ, попытка записывается.
3. **Бесплатный:** `node src/cli.js free-build --server ... --hud HUD-XXXXXXXX --out ./dist` — один общий `.build` для всех, без привязок.
4. **Панель администратора:** `http(s)://<сервер>/panel/` — все HUD, тип, статус, привязанные ПК, число попыток с других ПК (с метками ПК и временем),
   кнопки «Отключить ключ», «Сбросить ПК», «Новый ключ», «Отключить HUD» и «Включить». Владелец видит всё, разработчик — только свои HUD.
   Проверка в браузере: `python3 server/panel/e2e/panel_e2e.py` (нужен Playwright + Chromium).
