#include "hudblob.h"
#include <string.h>

int hb_b64url_decode(const char *s, size_t n, uint8_t *out, size_t cap) {
  uint32_t acc = 0; int bits = 0; size_t o = 0;
  if (n == 0 || n % 4 == 1) return -1;
  for (size_t i = 0; i < n; i++) {
    char c = s[i]; int v;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
    else if (c >= '0' && c <= '9') v = c - '0' + 52;
    else if (c == '-') v = 62; else if (c == '_') v = 63;
    else return -1;
    acc = (acc << 6) | (uint32_t)v; bits += 6;
    if (bits >= 8) { bits -= 8; if (o >= cap) return -1; out[o++] = (uint8_t)((acc >> bits) & 0xFF); }
  }
  return (int)o;
}

static void skip_ws(const char *p, size_t n, size_t *i) { while (*i < n && (p[*i] == ' ' || p[*i] == '\t' || p[*i] == '\n' || p[*i] == '\r')) (*i)++; }

/* строка без escape-последовательностей и управляющих символов (сервер гарантирует это для своих полей) */
static int read_str(const char *p, size_t n, size_t *i, char *dst, size_t cap) {
  size_t o = 0;
  if (*i >= n || p[*i] != '"') return 0;
  (*i)++;
  while (*i < n && p[*i] != '"') {
    unsigned char c = (unsigned char)p[*i];
    if (c == '\\' || c < 0x20) return 0;
    if (o + 1 >= cap) return 0;
    dst[o++] = (char)c; (*i)++;
  }
  if (*i >= n) return 0;
  (*i)++; dst[o] = 0; return 1;
}

/* плоский JSON-объект: значения только string/number/true/false/null; вложенность и массивы отвергаются */
static int parse_flat_json(const char *p, size_t n, hb_doc *d) {
  size_t i = 0; d->count = 0;
  skip_ws(p, n, &i);
  if (i >= n || p[i] != '{') return 0;
  i++; skip_ws(p, n, &i);
  if (i < n && p[i] == '}') { i++; skip_ws(p, n, &i); return i == n; }
  for (;;) {
    char k[HB_MAX_KEY];
    if (d->count >= HB_MAX_FIELDS) return 0;
    skip_ws(p, n, &i);
    if (!read_str(p, n, &i, k, sizeof k)) return 0;
    for (int j = 0; j < d->count; j++) if (strcmp(d->key[j], k) == 0) return 0; /* дубликаты запрещены */
    skip_ws(p, n, &i);
    if (i >= n || p[i] != ':') return 0;
    i++; skip_ws(p, n, &i);
    if (i >= n) return 0;
    int c = d->count;
    strcpy(d->key[c], k);
    if (p[i] == '"') { d->type[c] = HB_STR; if (!read_str(p, n, &i, d->val[c], HB_MAX_VAL)) return 0; }
    else if (p[i] == '-' || (p[i] >= '0' && p[i] <= '9')) {
      size_t o = 0; d->type[c] = HB_NUM;
      while (i < n && ((p[i] >= '0' && p[i] <= '9') || p[i] == '-' || p[i] == '.' || p[i] == 'e' || p[i] == 'E' || p[i] == '+')) { if (o + 1 >= HB_MAX_VAL) return 0; d->val[c][o++] = p[i++]; }
      d->val[c][o] = 0;
    } else if (n - i >= 4 && strncmp(p + i, "true", 4) == 0) { d->type[c] = HB_BOOL; strcpy(d->val[c], "true"); i += 4; }
    else if (n - i >= 5 && strncmp(p + i, "false", 5) == 0) { d->type[c] = HB_BOOL; strcpy(d->val[c], "false"); i += 5; }
    else if (n - i >= 4 && strncmp(p + i, "null", 4) == 0) { d->type[c] = HB_NULL; d->val[c][0] = 0; i += 4; }
    else return 0;
    d->count++;
    skip_ws(p, n, &i);
    if (i >= n) return 0;
    if (p[i] == ',') { i++; continue; }
    if (p[i] == '}') { i++; skip_ws(p, n, &i); return i == n; }
    return 0;
  }
}

hb_result hb_open(const char *text, size_t len, hb_verify_fn verify, const uint8_t pk[32], hb_doc *out) {
  const char *dot = NULL; uint8_t payload[HB_MAX_PAYLOAD + 4]; uint8_t sig[80];
  /* обрезать пробелы и переводы строк по краям */
  while (len && (text[len - 1] == '\n' || text[len - 1] == '\r' || text[len - 1] == ' ' || text[len - 1] == '\t')) len--;
  while (len && (*text == ' ' || *text == '\t' || *text == '\n' || *text == '\r')) { text++; len--; }
  if (!verify || !pk || !out || len == 0 || len > HB_MAX_BLOB) return HB_ERR_FORMAT;
  for (size_t i = 0; i < len; i++) { if (text[i] == '.') { if (dot) return HB_ERR_FORMAT; dot = text + i; } }
  if (!dot) return HB_ERR_FORMAT;
  int pn = hb_b64url_decode(text, (size_t)(dot - text), payload, HB_MAX_PAYLOAD);
  int sn = hb_b64url_decode(dot + 1, len - (size_t)(dot + 1 - text), sig, sizeof sig);
  if (pn <= 0 || sn != 64) return HB_ERR_FORMAT;
  if (!verify(sig, payload, (size_t)pn, pk)) return HB_ERR_SIGNATURE;   /* сначала подпись, потом разбор */
  if (!parse_flat_json((const char *)payload, (size_t)pn, out)) return HB_ERR_JSON;
  return HB_OK;
}

static int find(const hb_doc *d, const char *key) { for (int i = 0; i < d->count; i++) if (strcmp(d->key[i], key) == 0) return i; return -1; }
const char *hb_str(const hb_doc *d, const char *key) { int i = find(d, key); return (i >= 0 && d->type[i] == HB_STR) ? d->val[i] : NULL; }
int hb_i64(const hb_doc *d, const char *key, long long *out) {
  int i = find(d, key); if (i < 0 || d->type[i] != HB_NUM) return 0;
  const char *s = d->val[i]; long long v = 0; int neg = 0;
  if (*s == '-') { neg = 1; s++; }
  if (!*s) return 0;
  for (; *s; s++) { if (*s < '0' || *s > '9') return 0; if (v > (9223372036854775807LL - (*s - '0')) / 10) return 0; v = v * 10 + (*s - '0'); }
  *out = neg ? -v : v; return 1;
}
int hb_not_expired(const hb_doc *d, long long now) { long long e; return hb_i64(d, "expiresAt", &e) && now < e; }
