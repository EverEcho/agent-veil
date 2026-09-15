const API_VERSION = 'v1';

function runtimeInvoke() {
  const publicInvoke = window.__TAURI__?.core?.invoke;
  if (typeof publicInvoke === 'function') return publicInvoke.bind(window.__TAURI__.core);
  const internalInvoke = window.__TAURI_INTERNALS__?.invoke;
  return typeof internalInvoke === 'function' ? internalInvoke.bind(window.__TAURI_INTERNALS__) : null;
}

async function invokeDesktop(command, args) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const invoke = runtimeInvoke();
    if (invoke) return invoke(command, args);
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('AgentVeil 桌面桥接尚未就绪');
}

// __TAURI_INTERNALS__ is injected by the webview itself and is the authoritative
// runtime marker. The asset origin is a second, non-spoofable-in-this-app hint
// that also covers the short interval before the bridge globals become visible.
export const isDesktop = Boolean(window.__TAURI_INTERNALS__)
  || window.location.protocol === 'tauri:'
  || window.location.hostname === 'tauri.localhost'
  || new URLSearchParams(window.location.search).get('agentveil-runtime') === 'desktop';

export async function desktopInfo() {
  if (!isDesktop) return {desktop:false, ready:true, channel:'web'};
  return invokeDesktop('desktop_info');
}

export async function launchCodexDesktop() {
  if (!isDesktop) throw new Error('Codex Desktop can only be launched from AgentVeil Desktop');
  return invokeDesktop('launch_codex_desktop');
}

export async function exchangeBrowserTicket(ticket) {
  if (isDesktop || typeof ticket !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(ticket)) throw new Error('Invalid browser ticket');
  const response = await fetch('/v1/browser-sessions/exchange', {
    method:'POST',
    headers:{'Content-Type':'application/json', 'X-AgentVeil-API-Version':API_VERSION},
    body:JSON.stringify({ticket}),
    credentials:'same-origin'
  });
  if (response.headers.get('X-AgentVeil-API-Version') !== API_VERSION || !response.ok) throw new Error('Browser session exchange failed');
  return response.json();
}

export async function requestCore(path, options = {}) {
  if (isDesktop) {
    return invokeDesktop('core_request', {
      path,
      method: String(options.method || 'GET').toUpperCase(),
      body: options.body == null ? null : String(options.body)
    });
  }
  const headers = new Headers(options.headers || {});
  headers.set('X-AgentVeil-API-Version', API_VERSION);
  const response = await fetch(path, {...options, headers, credentials:'same-origin'});
  if (response.headers.get('X-AgentVeil-API-Version') !== API_VERSION) throw new Error('API version mismatch');
  if (!response.ok) {
    let detail = null;
    try { detail = await response.json(); } catch (_) {}
    const error = new Error(detail?.message || `${path}: HTTP ${response.status}`);
    error.code = detail?.error || 'CORE_REQUEST_FAILED';
    throw error;
  }
  if (response.status === 204) return null;
  return response.json();
}
