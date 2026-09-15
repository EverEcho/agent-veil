const supportedLocales = new Set(['zh-CN', 'en']);
let activeLocale = 'zh-CN';
let messages = {};

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

export function preferredLocale() {
  const stored = localStorage.getItem('agentveil.locale');
  return supportedLocales.has(stored) ? stored : 'zh-CN';
}

export async function setLocale(locale) {
  const next = supportedLocales.has(locale) ? locale : 'zh-CN';
  const response = await fetch(`/locales/${encodeURIComponent(next)}.json`, {credentials:'same-origin'});
  if (!response.ok) throw new Error(`Unable to load locale ${next}`);
  messages = object(await response.json());
  activeLocale = next;
  localStorage.setItem('agentveil.locale', next);
  document.documentElement.lang = next;
  return next;
}

export function locale() {
  return activeLocale;
}

export function t(key, params = {}) {
  const value = String(key).split('.').reduce((current, part) => object(current)[part], messages);
  if (typeof value !== 'string') return value ?? key;
  return value.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name) => Object.hasOwn(params, name) ? String(params[name]) : match);
}

export function translateValue(namespace, value) {
  const raw = String(value ?? '');
  return object(messages[namespace])[raw] || raw;
}

export function translatePrefix(namespace, value) {
  const raw = String(value ?? '');
  for (const [prefix, translated] of Object.entries(object(messages[namespace]))) {
    if (raw.startsWith(prefix)) return translated + raw.slice(prefix.length);
  }
  return raw;
}
