'use strict';
const crypto = require('crypto');

class RegistryError extends Error {}

const gitBlobSha = (buf) => crypto.createHash('sha1').update(`blob ${buf.length}\0`).update(buf).digest('hex');

// Публикация в GitHub-реестр: published/{hudId}/{version}/{file}. Токен — только на сервере.
class GithubRegistry {
  constructor({ token, repo, branch = 'main', fetchImpl = globalThis.fetch, apiBase = 'https://api.github.com', timeoutMs = 60000 }) {
    if (!token || !/^[\w.-]+\/[\w.-]+$/.test(repo || '')) throw new Error('GithubRegistry: нужны token и repo вида owner/name');
    Object.assign(this, { token, repo, branch, fetchImpl, apiBase, timeoutMs });
  }
  async _req(method, path, body) {
    const res = await this.fetchImpl(`${this.apiBase}/repos/${this.repo}/contents/${path}${method === 'GET' ? `?ref=${encodeURIComponent(this.branch)}` : ''}`, {
      method,
      headers: { Authorization: `Bearer ${this.token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'pitachok-hud-server', 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    let data = null; try { data = await res.json(); } catch { /* пустой ответ */ }
    return { status: res.status, data };
  }
  // Репозиторий должен быть приватным: проверка через GitHub API (private === true); при любой неясности — false
  async isPrivate() {
    const res = await this.fetchImpl(`${this.apiBase}/repos/${this.repo}`, {
      headers: { Authorization: `Bearer ${this.token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'pitachok-hud-server' },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (res.status !== 200) throw new RegistryError(`GitHub GET repo: HTTP ${res.status}`);
    const data = await res.json();
    return !!data && data.private === true;
  }
  // files: { 'hud.js': Buffer, ... }. Версии неизменяемы: существующий файл с тем же содержимым — ок, с другим — ошибка.
  async publish(hudId, version, files) {
    const done = [];
    for (const [name, buf] of Object.entries(files)) {
      const p = `published/${hudId}/${version}/${name}`;
      const want = gitBlobSha(buf);
      const ex = await this._req('GET', p);
      if (ex.status === 200) {
        if (ex.data && ex.data.sha === want) { done.push(p); continue; }
        throw new RegistryError(`Файл уже существует с другим содержимым: ${p}`);
      }
      if (ex.status !== 404) throw new RegistryError(`GitHub GET ${p}: HTTP ${ex.status}`);
      const put = await this._req('PUT', p, { message: `publish ${hudId}@${version}: ${name}`, content: buf.toString('base64'), branch: this.branch });
      if (put.status !== 201 && put.status !== 200) throw new RegistryError(`GitHub PUT ${p}: HTTP ${put.status}`);
      if (!put.data || !put.data.content || put.data.content.sha !== want) throw new RegistryError(`GitHub: хеш не совпал после записи ${p}`);
      done.push(p);
    }
    return { mirror: 'github', paths: done };
  }
}
module.exports = { GithubRegistry, RegistryError, gitBlobSha };
