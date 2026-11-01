'use strict';
const { validate } = require('./config');

function getPath(o, p) { return p.split('.').reduce((x, k) => (x == null ? undefined : x[k]), o); }
function setPath(o, p, v) {
  const ks = p.split('.'); const last = ks.pop();
  const t = ks.reduce((x, k) => (x[k] == null || typeof x[k] !== 'object' ? (x[k] = {}) : x[k]), o);
  if (v === undefined) delete t[last]; else t[last] = v;
}

// Разделяет «установленное» значение и «черновик/preview».
// В генератор попадает ТОЛЬКО store.installed (никогда черновик).
class ConfigStore {
  constructor(initial) {
    const v = validate(initial);
    if (!v.ok) throw new Error('Некорректная начальная конфигурация: ' + JSON.stringify(v.errors));
    this._installed = structuredClone(initial);
    this._open = null;   // { path, draft }
  }
  get installed() { return structuredClone(this._installed); }
  get openPath() { return this._open ? this._open.path : null; }
  get isDirty() {
    return !!this._open &&
      JSON.stringify(this._open.draft) !== JSON.stringify(getPath(this._installed, this._open.path) ?? null);
  }

  open(path) {
    if (this._open) this.cancel();                       // незавершённый черновик отбрасывается
    this._open = { path, draft: structuredClone(getPath(this._installed, path) ?? null) };
    return structuredClone(this._open.draft);
  }
  setDraft(value) {
    if (!this._open) throw new Error('Модуль не открыт');
    this._open.draft = structuredClone(value);
  }
  // Конфигурация для предпросмотра: установленное + черновик (ничего не мутирует).
  preview() {
    const c = structuredClone(this._installed);
    if (this._open) setPath(c, this._open.path, structuredClone(this._open.draft) ?? undefined);
    return c;
  }
  commit() {
    if (!this._open) throw new Error('Модуль не открыт');
    const candidate = this.preview();
    const v = validate(candidate);
    if (!v.ok) return { ok: false, errors: v.errors };   // состояние не меняется, окно остаётся открытым
    this._installed = candidate;
    this._open = null;
    return { ok: true };
  }
  cancel() { this._open = null; }                        // «Отмена» и закрытие окна «X»
  reset(path, defaultValue) {
    const c = structuredClone(this._installed);
    setPath(c, path, structuredClone(defaultValue));
    const v = validate(c);
    if (!v.ok) return { ok: false, errors: v.errors };
    this._installed = c; this._open = null; return { ok: true };
  }
}
module.exports = { ConfigStore, getPath, setPath };
