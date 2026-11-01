# HudLoader (клиентская часть)

Файлы в корне игры (как у вас сейчас: пара `.asi` + `.build`):
```
HudLoader.asi     — loader (собирается из loader/win/hudloader_win.c)
HudLoader.build   — персональный подписанный файл: HUD + ключ покупателя + адрес API (выдаёт сервер)
```
`HudLoader.build` создаётся сервером: при выдаче лицензии (`POST /huds/{id}/licenses` → поля `buildFile`, `buildFileName`) или для HUD без ключей
(`GET /huds/{id}/build`). Подпись Ed25519; править файл нельзя — подпись не сойдётся.

## Что проверено, а что нет
- `core/` (проверка подписи, разбор JSON, срок): собран `gcc -Wall -Wextra -Werror` с ASan/UBSan, проверен на blob-ах реального сервера через libsodium,
  плюс 200 000 фаззинг-входов парсера. Запуск: `node loader/test/run.js` (входит в `npm test`).
- `win/hudloader_win.c` (WinHTTP, BCrypt, реестр, поток, экспорты): **не компилировался и не запускался**. Ожидайте мелкие правки при первой сборке.

## Сборка на Windows (MinGW-w64, 32-бит — игра x86)
```
node loader/tools/gen_pubkey_h.js server/data/keys/signing.pub.pem > loader/win/pubkey.h
i686-w64-mingw32-gcc -O2 -shared -o HudLoader.asi loader/win/hudloader_win.c loader/core/hudblob.c \
  -I<путь к libsodium>/include <путь к libsodium>/lib/libsodium.a -lwinhttp -lbcrypt -ladvapi32 -static-libgcc
```
libsodium (статическая, x86) нужна для `crypto_sign_verify_detached`; можно заменить на Monocypher, поменяв функцию `verify` в одном месте.

## Что делает loader / чего не делает
Проверяет `.build` и лицензию, скачивает `hud.js` и сверяет его SHA-256 с подписанным значением, держит скрипт ТОЛЬКО в памяти (на диск не пишет) и отдаёт через экспорт
`HudLoader_GetScript()`. Загрузка скрипта в клиент игры (CEF) — задача отдельного модуля (в вашем случае `hud.asi`), он должен вызывать этот экспорт;
как именно `hud.asi` принимает скрипт, мне неизвестно. При отзыве лицензии loader перестаёт отдавать скрипт и стирает кэш; если игра уже загрузила
скрипт, выгрузить его должен потребитель по `HudLoader_Status() == -1`.
