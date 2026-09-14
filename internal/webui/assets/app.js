import {desktopInfo, exchangeBrowserTicket, isDesktop, requestCore} from './platform.js';

const state = {
  health: null, tools: [], agents: [], approvals: [], audit: [], calls: {},
  policy: null, rules: null, models: null, browserSession: false, refreshTimer: null, locale: localStorage.getItem('agentveil.locale') || 'zh-CN'
};

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const array = value => Array.isArray(value) ? value : [];
const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));

const copy = {
  'zh-CN': {
    overview: ['概览', '首页'], tools: ['自动发现', '我的工具'], activity: ['本机记录', '保护记录'],
    settings: ['偏好与诊断', '设置'], advanced: ['谨慎操作', '高级功能'],
    connected: '保护服务正常', degraded: '保护服务需要检查', offline: '无法连接保护服务',
    noTools: '没有发现支持的 AI 工具', noToolsHelp: '确认工具已安装，并从系统菜单重新启动 AgentVeil。',
    verified: '已识别，可检查', unverified: '已发现，兼容性待确认', versionUnknown: '已发现，版本未知',
    protected: '已加入保护', notProtected: '尚未加入保护', inspect: '查看保护能力',
    noActivity: '暂无保护记录', noActivityHelp: '启动受保护的 AI 工具后，安全处理摘要会显示在这里。',
    loadPartial: '部分信息暂时无法读取，其他模块仍可正常使用。', authFailed: '本机会话无效，或 Privacy Core 尚未启动。',
    saveOK: '策略已保存', saveFailed: '保存失败，请检查 JSON 内容', diagnosisOK: '诊断文件已导出', diagnosisFailed: '诊断导出失败',
    surfaces: '可检查的连接', risks: '需要了解', noSurface: '没有可显示的连接信息',
    protectionTruth: '“已发现”不代表“已保护”。只有通过 AgentVeil 启动并建立保护会话后，才会显示为正在保护。'
  },
  en: {
    overview: ['Overview', 'Home'], tools: ['Auto discovery', 'My tools'], activity: ['On-device history', 'Protection activity'],
    settings: ['Preferences & diagnostics', 'Settings'], advanced: ['Use with care', 'Advanced'],
    connected: 'Protection service is healthy', degraded: 'Protection service needs attention', offline: 'Unable to reach protection service',
    noTools: 'No supported AI tools found', noToolsHelp: 'Make sure a tool is installed, then restart AgentVeil from the system menu.',
    verified: 'Recognized and inspectable', unverified: 'Found, compatibility pending', versionUnknown: 'Found, version unknown',
    protected: 'Protection configured', notProtected: 'Not protected yet', inspect: 'View protection capability',
    noActivity: 'No protection activity yet', noActivityHelp: 'Safe summaries appear here after a protected AI tool runs.',
    loadPartial: 'Some information is temporarily unavailable. Other sections remain usable.', authFailed: 'The local session is invalid or Privacy Core is not running.',
    saveOK: 'Policy saved', saveFailed: 'Save failed. Check the JSON document.', diagnosisOK: 'Diagnostics exported', diagnosisFailed: 'Diagnostics export failed',
    surfaces: 'Inspectable connections', risks: 'Things to know', noSurface: 'No connection details are available',
    protectionTruth: '“Found” does not mean “protected”. A tool is protected only while it is launched through AgentVeil with an active protection session.'
  }
};

function t(key) { return (copy[state.locale] || copy['zh-CN'])[key] || key; }

async function api(path, options = {}) {
  return requestCore(path, options);
}

async function enter() {
  if (!isDesktop && !state.browserSession) return;
  try {
    state.health = await api('/v1/health');
    $('#auth').hidden = true;
    $('#auth-error').textContent = '';
    await loadAll();
    configureRefresh();
  } catch (_) {
    $('#auth-error').textContent = t('authFailed');
  }
}

async function safeLoad(path, apply) {
  try { apply(await api(path)); return true; }
  catch (_) { return false; }
}

async function loadAll() {
  $('#refresh').disabled = true;
  const results = await Promise.all([
    safeLoad('/v1/health', value => state.health = value),
    safeLoad('/v1/discovery', value => state.tools = array(value)),
    safeLoad('/v1/agents', value => state.agents = array(value)),
    safeLoad('/v1/approvals', value => state.approvals = array(value)),
    safeLoad('/v1/audit', value => state.audit = array(value)),
    safeLoad('/v1/call-tree', value => state.calls = object(value))
  ]);
  renderAll();
  const failed = results.filter(result => !result).length;
  $('#notice').hidden = failed === 0;
  $('#notice').textContent = failed ? t('loadPartial') : '';
  $('#refresh').disabled = false;
  if ($('#advanced-toggle').checked) loadAdvanced();
}

function renderAll() {
  renderHealth(); renderMetrics(); renderTools(); renderActivity(); renderAdvancedSummary();
}

function renderHealth() {
  const health = object(state.health), good = health.status === 'ok';
  $('#sidebar-dot').className = `status-dot ${good ? 'good' : 'bad'}`;
  $('#sidebar-status').textContent = good ? t('connected') : t('degraded');
  $('#hero-pill').className = `pill ${good ? 'good' : 'bad'}`;
  $('#hero-pill').textContent = good ? 'CORE OK' : '需要检查';
  $('#hero-title').textContent = good ? 'AgentVeil 正在保护这台电脑' : 'AgentVeil 需要你的注意';
  $('#hero-copy').textContent = good
    ? 'Privacy Core 正常运行，所有检测和处理都在本机完成。'
    : '部分保护能力暂不可用，请导出诊断信息后重新启动 AgentVeil。';
}

function sessionCount() {
  return Object.values(object(state.calls)).reduce((total, entries) => total + array(entries).length, 0);
}

function renderMetrics() {
  $('#metric-installed').textContent = state.tools.length;
  $('#metric-protected').textContent = state.agents.length;
  $('#metric-sessions').textContent = sessionCount();
  $('#metric-actions').textContent = state.approvals.length;
  $('#nav-tool-count').textContent = state.tools.length;
  const next = $('#next-step');
  if (!state.tools.length) next.innerHTML = `<span class="step-number">!</span><div><strong>${t('noTools')}</strong><p>${t('noToolsHelp')}</p></div>`;
  else if (!state.agents.length) next.innerHTML = `<span class="step-number">1</span><div><strong>已发现 ${state.tools.length} 个工具</strong><p>打开“我的工具”查看保护能力。${t('protectionTruth')}</p></div>`;
  else next.innerHTML = `<span class="step-number">✓</span><div><strong>${state.agents.length} 个工具已建立保护配置</strong><p>当前有 ${sessionCount()} 个任务正在通过 AgentVeil 运行。</p></div>`;
}

function registeredFor(tool) {
  return state.agents.find(entry => {
    const agent = object(object(entry.manifest).agent);
    return agent.kind === tool.agent || agent.id === `${tool.agent}-local`;
  });
}

function renderTools() {
  const grid = $('#tool-grid');
  if (!state.tools.length) {
    grid.innerHTML = `<div class="empty-state"><div class="empty-icon">?</div><div><strong>${t('noTools')}</strong><p>${t('noToolsHelp')}</p></div></div>`;
    return;
  }
  grid.innerHTML = state.tools.map(tool => {
    const registered = registeredFor(tool), verified = tool.status === 'verified';
    const label = registered ? t('protected') : tool.status === 'version_unknown' ? t('versionUnknown') : verified ? t('verified') : t('unverified');
    return `<article class="tool-card"><div class="tool-head"><div class="tool-icon">${escapeHTML(tool.agent.slice(0,1))}</div><div><h3>${escapeHTML(tool.agent)}</h3><p class="version">版本 ${escapeHTML(tool.version || '未知')}</p></div></div><p class="tool-state"><span class="pill ${registered ? 'good' : verified ? 'neutral' : 'warning'}">${escapeHTML(label)}</span><br><br>${registered ? 'AgentVeil 已保存该工具的保护配置。' : t('protectionTruth')}</p><button class="button ${verified ? 'primary' : ''}" data-inspect="${escapeHTML(tool.agent)}">${t('inspect')}</button></article>`;
  }).join('');
}

function actionLabel(action) {
  return ({allow:'已放行', redact:'已脱敏', block:'已阻止', ask:'等待确认'}[action] || action || '已处理');
}

function renderActivity() {
  $('#approval-list').innerHTML = state.approvals.map(item => `<article class="approval-card"><strong>需要你的确认</strong><p>${escapeHTML(object(item.finding).category || '检测到敏感内容')}</p><div class="row-actions"><button class="button primary" data-decision="redact" data-approval="${escapeHTML(item.id)}">脱敏后继续</button><button class="button" data-decision="allow" data-approval="${escapeHTML(item.id)}">本次放行</button><button class="button" data-decision="block" data-approval="${escapeHTML(item.id)}">阻止</button></div></article>`).join('');
  const list = $('#activity-list');
  if (!state.audit.length) list.innerHTML = `<div class="empty-state"><div class="empty-icon">✓</div><div><strong>${t('noActivity')}</strong><p>${t('noActivityHelp')}</p></div></div>`;
  else list.innerHTML = [...state.audit].reverse().slice(0,100).map(event => `<article class="timeline-item"><span class="timeline-dot"></span><div><strong>${escapeHTML(actionLabel(event.action))} · ${escapeHTML(event.agent_id || 'Agent')}</strong><p>发现 ${Number(event.finding_count || 0)} 项 · ${escapeHTML(event.protocol || '本地处理')}</p></div><time>${formatTime(event.timestamp)}</time></article>`).join('');
  const latest = state.audit[state.audit.length - 1];
  $('#overview-activity').innerHTML = latest
    ? `<div class="empty-icon">✓</div><div><strong>${escapeHTML(actionLabel(latest.action))} · ${escapeHTML(latest.agent_id || 'Agent')}</strong><p>${formatTime(latest.timestamp)}，发现 ${Number(latest.finding_count || 0)} 项敏感信息。</p></div>`
    : `<div class="empty-icon">✓</div><div><strong>${t('noActivity')}</strong><p>${t('noActivityHelp')}</p></div>`;
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '刚刚' : new Intl.DateTimeFormat(state.locale, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}).format(date);
}

async function inspectTool(name) {
  const dialog = $('#tool-dialog'), detail = $('#tool-detail');
  detail.innerHTML = '<p class="muted">正在检查保护能力…</p>'; dialog.showModal();
  try {
    const result = await api(`/v1/discovery/${encodeURIComponent(name)}`), manifest = object(result.manifest), plan = object(result.protection_plan), agent = object(manifest.agent), coverage = array(plan.coverage), risks = array(plan.risks);
    detail.innerHTML = `<p class="eyebrow">保护能力</p><h2>${escapeHTML(agent.kind || name)} <span class="muted">${escapeHTML(agent.version || '')}</span></h2><p class="muted">检查只读取配置，不会启动、关闭或接管这个工具。</p><h3>${t('surfaces')}</h3><div class="coverage-list">${coverage.map(item => `<div class="coverage-row"><span class="pill ${item.status === 'protected' ? 'good' : item.status === 'unprotected' ? 'bad' : 'warning'}">${escapeHTML(item.status)}</span><strong> ${escapeHTML(item.surface_id)}</strong><p>${escapeHTML(item.reason || '暂无说明')}</p></div>`).join('') || `<p class="muted">${t('noSurface')}</p>`}</div>${risks.length ? `<h3>${t('risks')}</h3><div class="coverage-list">${risks.map(risk => `<div class="coverage-row"><strong>${escapeHTML(risk.title || risk.code || '兼容性提示')}</strong><p>${escapeHTML(risk.action || risk.impact || '')}</p></div>`).join('')}</div>` : ''}<div class="error-box protection-note">${t('protectionTruth')}</div>`;
  } catch (_) { detail.innerHTML = '<div class="error-box"><strong>无法检查这个工具</strong><p>没有修改任何配置，请稍后重新扫描。</p></div>'; }
}

async function decide(id, action) {
  await api(`/v1/approvals/${encodeURIComponent(id)}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action})});
  await loadAll();
}

async function loadAdvanced() {
  await Promise.all([
    safeLoad('/v1/policy', value => { state.policy = value; if (document.activeElement !== $('#policy')) $('#policy').value = JSON.stringify(value, null, 2); }),
    safeLoad('/v1/rules', value => state.rules = value), safeLoad('/v1/models', value => state.models = value)
  ]);
  $('#advanced-rules').textContent = JSON.stringify(state.rules, null, 2);
  $('#advanced-models').textContent = JSON.stringify(state.models, null, 2);
}

function renderAdvancedSummary() {
  $('#advanced-routes').textContent = JSON.stringify(state.agents.map(entry => ({agent:object(object(entry.manifest).agent), state:entry.state, generation:entry.generation, routes:array(object(entry.plan).routes)})), null, 2);
  $('#advanced-calls').textContent = JSON.stringify(state.calls, null, 2);
}

async function savePolicy() {
  const result = $('#policy-result');
  try {
    const source = $('#policy').value; JSON.parse(source);
    await api('/v1/policy', {method:'PUT', headers:{'Content-Type':'application/json'}, body:source});
    result.textContent = t('saveOK'); result.className = 'inline-result success';
  } catch (_) { result.textContent = t('saveFailed'); result.className = 'inline-result failure'; }
}

async function downloadDiagnostics() {
  const result = $('#diagnostic-result');
  try {
    const diagnostics = await api('/v1/diagnostics');
    const blob = new Blob([JSON.stringify(diagnostics, null, 2) + '\n'], {type:'application/json'});
    const url = URL.createObjectURL(blob), link = document.createElement('a');
    link.href = url; link.download = 'agentveil-diagnostics.json'; link.click(); URL.revokeObjectURL(url);
    result.textContent = t('diagnosisOK');
  } catch (_) { result.textContent = t('diagnosisFailed'); }
}

function navigate(page) {
  $$('.page').forEach(node => { node.hidden = node.id !== `page-${page}`; node.classList.toggle('active-page', !node.hidden); });
  $$('.nav-item').forEach(node => node.classList.toggle('active', node.dataset.page === page));
  const labels = t(page); $('#page-eyebrow').textContent = labels[0]; $('#page-title').textContent = labels[1];
  $('.sidebar').classList.remove('open');
  if (page === 'advanced') loadAdvanced();
}

function configureRefresh() {
  clearInterval(state.refreshTimer);
  if ($('#auto-refresh').checked) state.refreshTimer = setInterval(() => { if (!document.hidden) loadAll(); }, 5000);
}

function applyLocale(locale) {
  state.locale = locale; localStorage.setItem('agentveil.locale', locale); document.documentElement.lang = locale;
  renderAll(); const active = $('.nav-item.active')?.dataset.page || 'overview'; navigate(active);
}

$('#refresh').onclick = loadAll; $('#scan-tools').onclick = loadAll;
$('#save-policy').onclick = savePolicy; $('#download-diagnostics').onclick = downloadDiagnostics;
$('#dialog-close').onclick = () => $('#tool-dialog').close();
$('#menu-button').onclick = () => $('.sidebar').classList.toggle('open');
$('#locale').value = state.locale; $('#locale').onchange = event => applyLocale(event.currentTarget.value);
$('#auto-refresh').onchange = configureRefresh;
$('#advanced-toggle').onchange = event => { $('#advanced-nav').hidden = !event.currentTarget.checked; if (!event.currentTarget.checked && $('.nav-item.active')?.dataset.page === 'advanced') navigate('settings'); };
document.body.onclick = event => {
  const nav = event.target.closest('[data-page]'), go = event.target.closest('[data-go]'), inspect = event.target.closest('[data-inspect]'), decision = event.target.closest('[data-decision]');
  if (nav) navigate(nav.dataset.page); if (go) navigate(go.dataset.go); if (inspect) inspectTool(inspect.dataset.inspect);
  if (decision) decide(decision.dataset.approval, decision.dataset.decision).catch(() => loadAll());
};

document.documentElement.dataset.agentveilUiReady = 'true';
applyLocale(state.locale);

async function startDesktop() {
  document.documentElement.dataset.agentveilDesktop = 'true';
  $('#auth').hidden = true;
  for (let attempt = 0; attempt < 150; attempt += 1) {
    try {
      const info = await desktopInfo();
      $('#channel-badge').textContent = String(info.channel || 'dev').toUpperCase();
      if (info.desktop && info.ready) {
        await enter();
        return;
      }
    } catch (_) {}
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  state.health = {status:'offline'};
  renderAll();
  $('#notice').hidden = false;
  $('#notice').textContent = t('authFailed');
}

async function startBrowserSession() {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const ticket = fragment.get('ticket');
  if (!ticket) {
    state.browserSession = true;
    await enter();
    return;
  }
  history.replaceState(null, '', window.location.pathname + window.location.search);
  try {
    await exchangeBrowserTicket(ticket);
    state.browserSession = true;
    await enter();
  } catch (_) {
    $('#auth-error').textContent = '浏览器会话已失效，请重新运行 veil web。';
  }
}

if (isDesktop) startDesktop(); else startBrowserSession();
