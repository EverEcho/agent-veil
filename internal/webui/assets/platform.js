const API_VERSION = 'v1';
const invoke = window.__TAURI__?.core?.invoke;

export const isDesktop = typeof invoke === 'function';

export async function desktopInfo() {
  if (!isDesktop) return {desktop:false, ready:true, channel:'web'};
  return invoke('desktop_info');
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
    return invoke('core_request', {
      path,
      method: String(options.method || 'GET').toUpperCase(),
      body: options.body == null ? null : String(options.body)
    });
  }
  const headers = new Headers(options.headers || {});
  headers.set('X-AgentVeil-API-Version', API_VERSION);
  const response = await fetch(path, {...options, headers, credentials:'same-origin'});
  if (response.headers.get('X-AgentVeil-API-Version') !== API_VERSION) throw new Error('API version mismatch');
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  if (response.status === 204) return null;
  return response.json();
}
