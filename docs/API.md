# API v1 (реализовано и покрыто тестами)
Ошибки: `{ "code", "message", "traceId" }`. Access-токен 15 мин, refresh 30 дней (ротация, повторное использование = отзыв цепочки).

| Метод | Путь | Доступ |
|---|---|---|
| POST | /auth/login, /auth/refresh | публично (rate limit) |
| POST | /auth/logout, /auth/change-password | сессия |
| GET | /auth/me, /developers/me/huds | сессия |
| POST | /huds {name} | developer, `canCreateHud` |
| GET | /huds/{hudId} | владелец HUD / owner (чужой = 404) |
| POST | /huds/{hudId}/versions {version, config} | developer-владелец; сервер сам генерирует hud.js и подписывает manifest (Ed25519) |
| POST | /huds/{hudId}/publish {version} | зеркалирование в GitHub, затем статус `published` |
| GET | /artifacts/{hudId}/{version}/manifest, /download | публично, только `published` и не отозванные |
| POST | /license/validate {installationId, hudId, loaderVersion, hudVersion?} | публично; подписанный ответ |
| GET/POST | /admin/developers | owner |
| PATCH | /admin/developers/{DEV-001}/status {status?, canCreateHud?} | owner |
| DELETE | /admin/developers/{DEV-001} (архив) | owner |
| POST | /admin/developers/{DEV-001}/reset-password | owner |
| GET | /admin/huds, /admin/installations, /admin/audit-logs | owner |
| PATCH | /admin/huds/{hudId}/status {status?, minVersion?} | owner (active/blocked/revoked, принудительное обновление) |
| POST | /admin/huds/{hudId}/revoke | owner |

### Тип HUD: free / paid
`POST /huds {name, type}` и `PATCH /huds/{id}/settings {type}`; `type`: `free` (по умолчанию) или `paid`.
- **free** — ключи не нужны, привязки к ПК нет, любое число пользователей, `hud.js` скачивается без заголовков, у всех один общий `.build`
  (`GET /huds/{id}/build`). Отзыв HUD целиком (`revoked`/`blocked`) работает и для бесплатных.
- **paid** — ключ на покупателя, по умолчанию 1 ПК на ключ, закрытая загрузка, персональный `.build`. Ключи для free-HUD выдавать нельзя.
- Переключение free → paid: у тех, кто уже пользовался бесплатной версией, статус станет `license_required`.

### Лицензии покупателей (защита платных HUD)
| Метод | Путь | Что делает |
|---|---|---|
| PATCH | /huds/{hudId}/settings {requireLicense} | включает обязательный ключ для HUD |
| POST | /huds/{hudId}/licenses {label, maxDevices?} | выдаёт ключ `PTK-XXXXX-…` (показывается один раз; хранится только SHA-256) |
| GET | /huds/{hudId}/licenses | список: устройства, `flagged`, `deviceAttempts` |
| POST | …/licenses/{LK-…}/revoke {reason} · /restore · /reset-devices | отзыв одного покупателя, возврат, сброс привязок |

### Файл `.build` для loader
| Метод | Путь | Что делает |
|---|---|---|
| POST | /huds/{hudId}/licenses | в ответе `buildFile` + `buildFileName` (`HudLoader.build`): подписанный файл с hudId, адресом API, ключом покупателя (показывается один раз) |
| POST | /huds/{hudId}/licenses/{LK-…}/rotate-key | новый ключ и новый `.build`, старый ключ и привязки устройств аннулируются |
| GET | /huds/{hudId}/build | общий `.build` без ключа (только для HUD с `requireLicense=false`) |

Формат: `base64url(payload JSON).base64url(Ed25519-подпись по байтам payload)`; ответ `/license/validate` содержит такое же поле `blob`.
На сервере нужен `PUBLIC_URL` (адрес API, вшивается в `.build`). Публичный ключ вшивается в loader (`loader/tools/gen_pubkey_h.js`).

Loader шлёт в `/license/validate` поля `licenseKey` и `hwid` (произвольная строка 16–128 символов, например хеш железа; сервер хранит только HMAC).
Новые статусы: `license_required`, `license_invalid`, `license_revoked`, `device_limit` (ответ подписан). Скачивание `hud.js` для HUD с
`requireLicense` требует заголовки `X-License-Key` и `X-HWID` активированного устройства. Попытка активации сверх `maxDevices` помечает ключ
(`flagged`) и пишет событие `license_device_limit` — так видно ключи, которыми делятся.

Статусы лицензии: `active`, `revoked`, `blocked`, `no_release`, `update_required`. Лицензия содержит `expiresAt`
(= выдача + OFFLINE_GRACE_HOURS, по умолчанию 72 ч); loader обязан проверять подпись публичным ключом и не запускать HUD после `expiresAt`
без новой проверки.

## Запуск
```
export PITACHOK_DATA_DIR=./server/data
node server/src/index.js init --owner <login>   # ключи подписи + владелец (пароль показывается один раз)
node server/src/index.js start                  # слушает 127.0.0.1:8080; HTTPS — через reverse proxy (Caddy/nginx)
```
Нужен Node >= 22.13 (встроенный node:sqlite). Резервное копирование: копировать `server/data` (sqlite + artifacts + keys) при остановленном
сервере или через `sqlite3 .backup`.

## Панель и данные для неё
`GET /panel/` — статическая страница (CSP `script-src 'self'`, без inline-скриптов и стилей). Данные берёт из:
`GET /admin/huds` (owner) или `GET /developers/me/huds`, `GET /huds/{id}`, `GET /huds/{id}/licenses` (в каждой лицензии: `devices` — привязанные ПК,
`attempts` — попытки с других ПК, `flagged`), `GET /admin/audit-logs`; действия: `…/licenses/{LK}/revoke|restore|reset-devices|rotate-key`,
`POST /huds/{id}/status` и `PATCH /admin/huds/{id}/status` (отключить/включить HUD целиком; включить обратно может только владелец).
