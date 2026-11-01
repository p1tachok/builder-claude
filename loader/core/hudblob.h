/* Проверка и разбор подписанных blob-ов (.build и ответ лицензии).
 * Формат: base64url(payload).base64url(Ed25519 подпись по байтам payload).
 * Ядро не зависит от ОС и от криптобиблиотеки: Ed25519-проверку передаёт вызывающий (libsodium, Monocypher...). */
#ifndef HUDBLOB_H
#define HUDBLOB_H
#include <stddef.h>
#include <stdint.h>

#define HB_MAX_BLOB 4096
#define HB_MAX_PAYLOAD 2048
#define HB_MAX_FIELDS 24
#define HB_MAX_KEY 32
#define HB_MAX_VAL 256

typedef enum { HB_OK = 0, HB_ERR_FORMAT = 1, HB_ERR_SIGNATURE = 2, HB_ERR_JSON = 3 } hb_result;
typedef enum { HB_STR = 1, HB_NUM = 2, HB_BOOL = 3, HB_NULL = 4 } hb_type;

/* Возвращает 1 если подпись верна */
typedef int (*hb_verify_fn)(const uint8_t sig[64], const uint8_t *msg, size_t len, const uint8_t pk[32]);

typedef struct {
  int count;
  char key[HB_MAX_FIELDS][HB_MAX_KEY];
  char val[HB_MAX_FIELDS][HB_MAX_VAL];
  hb_type type[HB_MAX_FIELDS];
} hb_doc;

hb_result hb_open(const char *text, size_t len, hb_verify_fn verify, const uint8_t pk[32], hb_doc *out);
const char *hb_str(const hb_doc *d, const char *key);                 /* NULL если нет/не строка */
int hb_i64(const hb_doc *d, const char *key, long long *out);          /* 1 если число найдено и влезает */
/* Лицензия действует, если now < expiresAt и (необязательно) now >= issuedAt - skew */
int hb_not_expired(const hb_doc *d, long long now_unix);
int hb_b64url_decode(const char *s, size_t n, uint8_t *out, size_t cap); /* длина или -1 */
#endif
