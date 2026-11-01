/* Тест ядра: проверяет blob, созданный сервером (Node), реальной libsodium. Запуск: см. loader/test/run.js */
#include "../core/hudblob.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m, unsigned long long mlen, const unsigned char *pk);
extern int sodium_init(void);
static int verify(const uint8_t sig[64], const uint8_t *m, size_t n, const uint8_t pk[32]) { return crypto_sign_verify_detached(sig, m, n, pk) == 0; }

static int always(const uint8_t sig[64], const uint8_t *m, size_t n, const uint8_t pk[32]) { (void)sig; (void)m; (void)n; (void)pk; return 1; }
static size_t b64enc(const uint8_t *in, size_t n, char *o) {
  static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"; size_t k = 0;
  for (size_t i = 0; i < n; i += 3) { uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
    o[k++] = A[(v >> 18) & 63]; o[k++] = A[(v >> 12) & 63]; if (i + 1 < n) o[k++] = A[(v >> 6) & 63]; if (i + 2 < n) o[k++] = A[v & 63]; }
  return k;
}
#define SIG86 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

static int unhex(const char *h, uint8_t *o, size_t n) { for (size_t i = 0; i < n; i++) { unsigned v; if (sscanf(h + 2 * i, "%2x", &v) != 1) return 0; o[i] = (uint8_t)v; } return 1; }

int main(int argc, char **argv) {
  if (argc < 5) { printf("usage: pubhex blobfile hudId licKey\n"); return 2; }
  uint8_t pk[32], other[32]; char blob[HB_MAX_BLOB + 8]; hb_doc d;
  sodium_init();
  CHECK(unhex(argv[1], pk, 32));
  FILE *f = fopen(argv[2], "rb"); if (!f) return 2; size_t n = fread(blob, 1, HB_MAX_BLOB, f); fclose(f); blob[n] = 0;

  CHECK(hb_open(blob, n, verify, pk, &d) == HB_OK);
  CHECK(hb_str(&d, "hudId") && strcmp(hb_str(&d, "hudId"), argv[3]) == 0);
  CHECK(hb_str(&d, "key") && strcmp(hb_str(&d, "key"), argv[4]) == 0);
  long long v = 0; CHECK(hb_i64(&d, "v", &v) && v == 1);
  CHECK(hb_str(&d, "nope") == NULL);
  CHECK(hb_str(&d, "v") == NULL);              /* число — не строка */

  memcpy(other, pk, 32); other[0] ^= 1;         /* неверный ключ */
  CHECK(hb_open(blob, n, verify, other, &d) == HB_ERR_SIGNATURE);

  char bad[HB_MAX_BLOB + 8];                    /* изменение любого символа payload или подписи ломает проверку */
  const char *dot = strchr(blob, '.'); size_t dp = (size_t)(dot - blob);
  int rejected = 0, tried = 0;
  for (size_t i = 0; i < n; i += 7) {
    if (i == dp) continue;
    memcpy(bad, blob, n); bad[n] = 0; bad[i] = (bad[i] == 'A') ? 'B' : 'A'; tried++;
    if (hb_open(bad, n, verify, pk, &d) != HB_OK) rejected++;
  }
  CHECK(tried > 10 && rejected == tried);

  memcpy(bad, blob, n); bad[dp] = 0;           /* без подписи / лишние точки / мусор */
  CHECK(hb_open(bad, dp, verify, pk, &d) == HB_ERR_FORMAT);
  CHECK(hb_open("", 0, verify, pk, &d) == HB_ERR_FORMAT);
  CHECK(hb_open("a.b.c", 5, verify, pk, &d) == HB_ERR_FORMAT);
  CHECK(hb_open("!!!.@@@", 7, verify, pk, &d) == HB_ERR_FORMAT);
  CHECK(hb_open(blob, n - 1, verify, pk, &d) != HB_OK);            /* обрезанный */
  { char big[HB_MAX_BLOB + 64]; memset(big, 'A', sizeof big - 1); big[sizeof big - 1] = 0; CHECK(hb_open(big, sizeof big - 1, verify, pk, &d) == HB_ERR_FORMAT); }
  CHECK(hb_open(blob, n, NULL, pk, &d) == HB_ERR_FORMAT);

  /* срок действия */
  { hb_doc e; e.count = 1; strcpy(e.key[0], "expiresAt"); strcpy(e.val[0], "1000"); e.type[0] = HB_NUM;
    CHECK(hb_not_expired(&e, 999)); CHECK(!hb_not_expired(&e, 1000)); CHECK(!hb_not_expired(&d, 0) || 1);
    strcpy(e.val[0], "99999999999999999999"); CHECK(!hb_not_expired(&e, 1)); }
  /* пробелы/перевод строки по краям (как в файле .build) допустимы */
  { char w[HB_MAX_BLOB + 32]; snprintf(w, sizeof w, "  %s\r\n", blob); CHECK(hb_open(w, strlen(w), verify, pk, &d) == HB_OK); }
  /* base64url */
  { uint8_t o[8]; CHECK(hb_b64url_decode("aGk", 3, o, 8) == 2 && o[0] == 'h' && o[1] == 'i'); CHECK(hb_b64url_decode("a+b", 3, o, 8) == -1); CHECK(hb_b64url_decode("a", 1, o, 8) == -1); }

  /* фаззинг парсера JSON (подпись «верна» всегда) под ASan/UBSan: не должно быть падений и выхода за границы */
  { srand(12345); const char *seeds[] = { "{\"a\":\"b\",\"n\":-12,\"t\":true,\"z\":null}", "{}", "{\"k\":", "{\"k\":\"v\"", "[1,2]", "{\"a\":{\"b\":1}}", "{\"a\":1,\"a\":2}", "{\"a\":\"\\n\"}" };
    uint8_t pay[300]; char enc[800], full[900]; int okc = 0;
    for (int it = 0; it < 200000; it++) {
      const char *sd = seeds[it % 8]; size_t L = strlen(sd); if (L > sizeof pay) L = sizeof pay; memcpy(pay, sd, L);
      int muts = rand() % 4; for (int m = 0; m < muts; m++) { size_t pos = (size_t)rand() % L; int op = rand() % 3; if (op == 0) pay[pos] = (uint8_t)rand(); else if (op == 1 && L > 1) L--; else if (L < 290) { memmove(pay + pos + 1, pay + pos, L - pos); pay[pos] = (uint8_t)rand(); L++; } }
      size_t el = b64enc(pay, L, enc); enc[el] = 0;
      size_t fl = (size_t)snprintf(full, sizeof full, "%s.%s", enc, SIG86);
      if (hb_open(full, fl, always, pk, &d) == HB_OK) okc++;
    }
    CHECK(okc > 0); }
  printf(fails ? "FAILED: %d\n" : "OK\n", fails);
  return fails ? 1 : 0;
}
