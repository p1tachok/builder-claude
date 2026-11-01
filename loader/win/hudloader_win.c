/* HudLoader.asi — Windows-часть loader. ВНИМАНИЕ: этот файл НЕ компилировался и НЕ запускался (в среде разработки нет Windows-тулчейна).
 * Логика проверки подписей протестирована отдельно (../core, ../test). Сборка: см. ../README.md.
 *
 * Что делает:
 *  1) читает HudLoader.build рядом с .asi, проверяет подпись сервера (ключ вшит в pubkey.h);
 *  2) спрашивает сервер о лицензии (POST /api/v1/license/validate), проверяет подпись ответа, срок и привязку к установке;
 *  3) при статусе "active" скачивает hud.js, сверяет SHA-256 из подписанной лицензии и отдаёт скрипт через HudLoader_GetScript();
 *  4) hud.js хранится ТОЛЬКО В ПАМЯТИ: на диск ничего не пишется (ни скрипт, ни картинки). При отзыве скрипт стирается из памяти;
 *     перепроверка раз в 30 минут; без сети уже загруженный скрипт доступен до expiresAt лицензии, после перезапуска игры нужна сеть.
 * Передача скрипта в клиент игры (CEF) — задача отдельного модуля: он вызывает HudLoader_GetScript(). Здесь её нет намеренно. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../core/hudblob.h"
#include "pubkey.h"

extern int crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m, unsigned long long mlen, const unsigned char *pk); /* libsodium */

#define LOADER_VERSION "1.0.0"
#define BUILD_FILE "HudLoader.build"
#define MAX_JS (16u * 1024u * 1024u)
#define RECHECK_MS (30u * 60u * 1000u)

static char g_dir[MAX_PATH];
static CRITICAL_SECTION g_cs;
static long long g_expires = 0;   /* срок последней подписанной лицензии (unix); после него скрипт не отдаётся */
static char *g_script = NULL; static size_t g_script_len = 0; static int g_state = 0; /* 0 нет, 1 активен, -1 запрещён */

static int verify(const uint8_t sig[64], const uint8_t *m, size_t n, const uint8_t pk[32]) { return crypto_sign_verify_detached(sig, m, n, pk) == 0; }

static void logf_(const char *msg) {
  char p[MAX_PATH + 32]; FILE *f; snprintf(p, sizeof p, "%s\\HudLoader.log", g_dir);
  f = fopen(p, "a"); if (f) { fprintf(f, "[%lld] %s\n", (long long)time(NULL), msg); fclose(f); }
}
static void path_of(const char *name, char *out, size_t cap) { snprintf(out, cap, "%s\\%s", g_dir, name); }

static int read_file(const char *path, char **buf, size_t *len, size_t cap) {
  FILE *f = fopen(path, "rb"); long sz; if (!f) return 0;
  fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
  if (sz < 0 || (size_t)sz > cap) { fclose(f); return 0; }
  *buf = (char *)malloc((size_t)sz + 1); if (!*buf) { fclose(f); return 0; }
  *len = fread(*buf, 1, (size_t)sz, f); (*buf)[*len] = 0; fclose(f); return 1;
}

static int sha256(const void *data, size_t len, uint8_t out[32]) {
  BCRYPT_ALG_HANDLE alg = NULL; int ok = 0;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return 0;
  ok = BCryptHash(alg, NULL, 0, (PUCHAR)data, (ULONG)len, out, 32) == 0;
  BCryptCloseAlgorithmProvider(alg, 0); return ok;
}
static void to_hex(const uint8_t *b, size_t n, char *o) { static const char H[] = "0123456789abcdef"; for (size_t i = 0; i < n; i++) { o[2 * i] = H[b[i] >> 4]; o[2 * i + 1] = H[b[i] & 15]; } o[2 * n] = 0; }

/* Идентификаторы устройства: только хеши от MachineGuid; сам GUID не покидает ПК */
static int device_ids(char *hwid, size_t hcap, char *inst, size_t icap) {
  char guid[128] = {0}; DWORD sz = sizeof guid; uint8_t h[32]; char hx[65], tmp[160];
  if (hcap < 72 || icap < 40) return 0;
  if (RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", RRF_RT_REG_SZ | RRF_SUBKEY_WOW64_64KEY, NULL, guid, &sz) != ERROR_SUCCESS) return 0;
  if (!sha256(guid, strlen(guid), h)) return 0; to_hex(h, 32, hx); snprintf(hwid, hcap, "hw-%s", hx);
  snprintf(tmp, sizeof tmp, "%s|install", guid); if (!sha256(tmp, strlen(tmp), h)) return 0; to_hex(h, 16, inst); return 1;
}

/* ---- HTTP ---- */
typedef struct { char host[200]; char base[200]; INTERNET_PORT port; int secure; } url_t;
static int parse_url(const char *u, url_t *o) {
  const char *p = u; memset(o, 0, sizeof *o);
  if (strncmp(p, "https://", 8) == 0) { o->secure = 1; o->port = 443; p += 8; } else if (strncmp(p, "http://", 7) == 0) { o->port = 80; p += 7; } else return 0;
  size_t hl = strcspn(p, ":/"); if (hl == 0 || hl >= sizeof o->host) return 0; memcpy(o->host, p, hl); p += hl;
  if (*p == ':') { o->port = (INTERNET_PORT)atoi(p + 1); p += strcspn(p, "/"); }
  if (strlen(p) >= sizeof o->base) return 0; strcpy(o->base, p);
  size_t bl = strlen(o->base); while (bl && o->base[bl - 1] == '/') o->base[--bl] = 0;
  return 1;
}
/* method GET/POST; extra_headers — wide-строка заголовков или NULL; ответ malloc-ится вызывающему; возвращает HTTP-статус или 0 при сбое сети */
static int http(const url_t *u, const wchar_t *method, const char *path, const wchar_t *extra_headers, const char *body, char **out, size_t *outlen, size_t cap) {
  wchar_t whost[256], wpath[512]; HINTERNET s = NULL, c = NULL, r = NULL; int status = 0; char *buf = NULL; size_t len = 0;
  char full[512]; snprintf(full, sizeof full, "%s%s", u->base, path);
  MultiByteToWideChar(CP_UTF8, 0, u->host, -1, whost, 256); MultiByteToWideChar(CP_UTF8, 0, full, -1, wpath, 512);
  s = WinHttpOpen(L"HudLoader/" L"1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0); if (!s) goto done;
  WinHttpSetTimeouts(s, 8000, 8000, 15000, 30000);
  c = WinHttpConnect(s, whost, u->port, 0); if (!c) goto done;
  r = WinHttpOpenRequest(c, method, wpath, NULL, NULL, NULL, u->secure ? WINHTTP_FLAG_SECURE : 0); if (!r) goto done;
  if (!WinHttpSendRequest(r, extra_headers ? extra_headers : WINHTTP_NO_ADDITIONAL_HEADERS, extra_headers ? (DWORD)-1L : 0, (LPVOID)body, body ? (DWORD)strlen(body) : 0, body ? (DWORD)strlen(body) : 0, 0)) goto done;
  if (!WinHttpReceiveResponse(r, NULL)) goto done;
  { DWORD code = 0, sz = sizeof code; if (!WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &code, &sz, NULL)) goto done; status = (int)code; }
  buf = (char *)malloc(1);
  for (;;) {
    DWORD avail = 0, rd = 0; char *nb;
    if (!WinHttpQueryDataAvailable(r, &avail) || avail == 0) break;
    if (len + avail > cap) { free(buf); buf = NULL; status = 0; goto done; }
    nb = (char *)realloc(buf, len + avail + 1); if (!nb) { free(buf); buf = NULL; status = 0; goto done; } buf = nb;
    if (!WinHttpReadData(r, buf + len, avail, &rd)) { free(buf); buf = NULL; status = 0; goto done; } len += rd;
  }
  if (buf) buf[len] = 0;
done:
  if (r) WinHttpCloseHandle(r); if (c) WinHttpCloseHandle(c); if (s) WinHttpCloseHandle(s);
  if (status && buf) { *out = buf; *outlen = len; } else { free(buf); *out = NULL; *outlen = 0; }
  return status;
}

/* ---- логика ---- */
typedef struct { char hudId[32], server[208], key[48], hwid[80], inst[40]; } ctx_t;

static void set_script(char *js, size_t len, int state) {
  EnterCriticalSection(&g_cs); free(g_script); g_script = js; g_script_len = len; g_state = state; LeaveCriticalSection(&g_cs);
}

/* проверка blob лицензии: подпись, hudId, installationId, срок */
static int check_license(const char *blob, size_t n, const ctx_t *c, hb_doc *d) {
  const char *v;
  if (hb_open(blob, n, verify, HB_SERVER_PUBKEY, d) != HB_OK) return 0;
  v = hb_str(d, "hudId"); if (!v || strcmp(v, c->hudId) != 0) return 0;
  v = hb_str(d, "installationId"); if (!v || strcmp(v, c->inst) != 0) return 0;
  return hb_not_expired(d, (long long)time(NULL));
}
static int load_verified_js(const hb_doc *lic, char *js, size_t len) {
  const char *want = hb_str(lic, "artifactSha256"); uint8_t h[32]; char hx[65];
  if (!want || !sha256(js, len, h)) return 0; to_hex(h, 32, hx); return strcmp(hx, want) == 0;
}

static void run_once(void) {
  char bp[MAX_PATH + 32], *bf = NULL, *resp = NULL, *js = NULL; size_t bl = 0, rl = 0, jl = 0; hb_doc bd, ld; ctx_t c; url_t u; char body[512], path[256];
  const char *s;
  path_of(BUILD_FILE, bp, sizeof bp);
  if (!read_file(bp, &bf, &bl, HB_MAX_BLOB)) { logf_("no .build"); return; }
  if (hb_open(bf, bl, verify, HB_SERVER_PUBKEY, &bd) != HB_OK) { logf_(".build: bad signature"); free(bf); return; }
  free(bf); memset(&c, 0, sizeof c);
  if (!(s = hb_str(&bd, "hudId")) || strlen(s) >= sizeof c.hudId) return; strcpy(c.hudId, s);
  if (!(s = hb_str(&bd, "server")) || strlen(s) >= sizeof c.server || !parse_url(s, &u)) return; strcpy(c.server, s);
  s = hb_str(&bd, "key"); if (s && strlen(s) < sizeof c.key) strcpy(c.key, s);
  if (!device_ids(c.hwid, sizeof c.hwid, c.inst, sizeof c.inst)) { logf_("device id failed"); return; }

  snprintf(body, sizeof body, "{\"installationId\":\"%s\",\"hudId\":\"%s\",\"loaderVersion\":\"" LOADER_VERSION "\",\"licenseKey\":\"%s\",\"hwid\":\"%s\"}", c.inst, c.hudId, c.key, c.hwid);
  { int st = http(&u, L"POST", "/api/v1/license/validate", L"Content-Type: application/json\r\n", body, &resp, &rl, 65536);
    if (st != 200 || !resp) { logf_(st == 0 ? "network down: in-memory script kept until license expiry" : "validate: http error"); free(resp); return; } }
  { const char *k = strstr(resp, "\"blob\":\""); char *e; char blob[HB_MAX_BLOB + 1];
    if (!k) { free(resp); logf_("no blob"); return; }
    k += 8; e = (char *)strchr(k, '"'); if (!e || (size_t)(e - k) > HB_MAX_BLOB) { free(resp); return; }
    memcpy(blob, k, (size_t)(e - k)); blob[e - k] = 0; free(resp); resp = NULL;
    if (!check_license(blob, strlen(blob), &c, &ld)) { logf_("license blob invalid/expired"); return; }
    s = hb_str(&ld, "status");
    if (!s || strcmp(s, "active") != 0) { logf_(s ? s : "no status"); set_script(NULL, 0, -1); return; }
    { const char *ver = hb_str(&ld, "allowedVersion"); wchar_t hdr[256]; char hk[96];
      if (!ver) return; snprintf(path, sizeof path, "/api/v1/artifacts/%s/%s/download", c.hudId, ver);
      snprintf(hk, sizeof hk, "%s", c.key); swprintf(hdr, 256, L"X-License-Key: %hs\r\nX-HWID: %hs\r\n", hk, c.hwid);
      if (http(&u, L"GET", path, hdr, NULL, &js, &jl, MAX_JS) != 200 || !js) { logf_("download failed"); free(js); return; }
      if (!load_verified_js(&ld, js, jl)) { logf_("hud.js hash mismatch"); free(js); return; }
      hb_i64(&ld, "expiresAt", &g_expires);
      set_script(js, jl, 1); logf_("hud.js verified and ready"); } }
}

static DWORD WINAPI worker(LPVOID p) { (void)p; for (;;) { run_once(); Sleep(RECHECK_MS); } }

/* ---- экспорт для модуля, который доставляет скрипт в клиент ---- */
__declspec(dllexport) int HudLoader_GetScript(const char **js, size_t *len) {
  int ok = 0; EnterCriticalSection(&g_cs);
  if (g_state == 1 && g_script && (long long)time(NULL) < g_expires) { *js = g_script; *len = g_script_len; ok = 1; }
  LeaveCriticalSection(&g_cs); return ok;     /* указатель действителен до следующей перепроверки; потребитель обязан скопировать */
}
__declspec(dllexport) int HudLoader_Status(void) { return g_state; }  /* 1 активен, 0 неизвестно, -1 запрещён */

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
  (void)r;
  if (reason == DLL_PROCESS_ATTACH) {
    HMODULE self = NULL; char *slash;
    DisableThreadLibraryCalls(h); InitializeCriticalSection(&g_cs);
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)&worker, &self);
    GetModuleFileNameA(self, g_dir, MAX_PATH); slash = strrchr(g_dir, '\\'); if (slash) *slash = 0;
    CreateThread(NULL, 0, worker, NULL, 0, NULL);
  }
  return TRUE;
}
