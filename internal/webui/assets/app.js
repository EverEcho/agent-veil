import {desktopInfo, exchangeBrowserTicket, isDesktop, launchCodexDesktop, requestCore} from './platform.js';

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
    verified: '支持保护', unverified: '暂不支持此版本', versionUnknown: '暂不支持此版本',
    protected: '已加入保护', notProtected: '尚未加入保护', inspect: '查看详情',
    noActivity: '暂无保护记录', noActivityHelp: '启动受保护的 AI 工具后，安全处理摘要会显示在这里。',
    loadPartial: '部分信息暂时无法读取，其他模块仍可正常使用。', authFailed: '本机会话无效，或 Privacy Core 尚未启动。',
    saveOK: '策略已保存', saveFailed: '保存失败，请检查 JSON 内容', diagnosisOK: '诊断文件已导出', diagnosisFailed: '诊断导出失败',
    surfaces: '保护范围', risks: '需要注意', noSurface: '没有可显示的保护范围',
    protectionTruth: '“已发现”不代表“已保护”。只有通过 AgentVeil 启动并建立保护会话后，才会显示为正在保护。',
    launchDesktop: '受保护地启动 Codex', launchStarting: '正在创建受保护会话…', launchStarted: 'Codex 已从受保护会话启动'
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
    surfaces: 'Protection scope', risks: 'Things to know', noSurface: 'No protection scope is available',
    protectionTruth: '“Found” does not mean “protected”. A tool is protected only while it is launched through AgentVeil with an active protection session.',
    launchDesktop: 'Launch protected Codex', launchStarting: 'Creating a protected session…', launchStarted: 'Codex launched in a protected session'
  }
};

function t(key) { return (copy[state.locale] || copy['zh-CN'])[key] || key; }
function agentLabel(value) {
  if (value === 'codex-desktop') return state.locale === 'zh-CN' ? 'Codex 桌面版' : 'Codex Desktop';
  return value;
}

const zhCoverage = {
  protected: '已保护', local: '本机运行', partial: '部分保护', observed: '仅观察', unprotected: '未保护'
};

const zhReasons = {
  'request, response and stream inspection are available': '请求、响应和流式内容均可检查',
  'surface uses local stdio; descendant network egress is separate': '该连接使用本机 stdio；子进程的网络出口需要单独评估',
  'unknown surfaces and protocols fail closed': '未知连接或协议按安全策略阻断',
  'no protocol capability is registered': '当前没有注册该协议的保护能力',
  'traffic can be observed but the surface cannot be safely rewritten': '可观察流量，但无法安全改写该连接',
  'surface cannot be safely rewritten': '当前无法安全改写该连接',
  'request content is not inspectable': '请求内容暂不可检查',
  'request inspection is available but response or stream protection is incomplete': '请求可检查，但响应或流式保护不完整',
  'routing graph contains a content modifier after AgentVeil': '路由中 AgentVeil 之后仍有内容修改器',
  'agent version has no verified complete Surface inventory': '当前 Agent 版本尚无完整连接清单的验证记录',
  'custom model provider requires a versioned launch adapter': '自定义模型 Provider 需要匹配版本的启动适配器',
  'provider query, header, dynamic discovery, or signer settings cannot yet be preserved': 'Provider 的查询参数、请求头、动态发现或签名配置尚不能完整保留',
  'selected provider has no base URL': '当前选择的 Provider 没有可解析的服务地址',
  'Codex authentication mode is unknown': '无法确认 Codex 当前使用的登录方式',
  'Codex model route could not be resolved': '无法解析 Codex 当前使用的模型连接',
  'effective Codex MCP inventory could not be verified': '无法确认 Codex 最终生效的 MCP 清单',
  'effective Codex MCP inventory is invalid or exceeds its limit': 'Codex 最终生效的 MCP 清单无效或超过限制',
  'effective Codex MCP inventory contains an invalid entry': 'Codex 最终生效的 MCP 清单包含无效项目',
  'effective Codex MCP inventory contains duplicate entries': 'Codex 最终生效的 MCP 清单包含重复项目',
  'enabled Codex stdio MCP server has no executable command': '已启用的 Codex stdio MCP 没有可执行命令',
  'enabled Codex HTTP MCP endpoint could not be represented safely': '已启用的 Codex HTTP MCP 地址无法安全表示',
  'enabled Codex MCP server uses an unrecognized transport': '已启用的 Codex MCP 使用了无法识别的传输方式',
  'Codex remote MCP launch rewriting is not implemented': 'Codex 远程 MCP 尚未实现受保护启动改写',
  'stdio is local IPC; descendant process network egress is outside the model route': 'stdio 是本机进程通信；其子进程独立联网不经过主模型保护路线'
};

const zhRiskCodes = {
  OBSERVED_ONLY: '仅可观察', UNKNOWN_PROTOCOL: '未知协议', NOT_REWRITABLE: '无法安全改写',
  UNSUPPORTED_CAPABILITY: '尚不支持该能力', REQUEST_ONLY: '仅保护请求',
  UNEXPECTED_EGRESS: '发现未预期的网络出口', DOWNSTREAM_MODIFIER: '下游仍会修改内容'
};

const zhSurfaceNames = {
  'Primary model': '主模型', 'Small model': '轻量模型', Vision: '视觉模型', Fallback: '备用模型',
  'Unverified version egress': '未验证版本的网络出口', 'Unresolved agent egress': '未解析的 Agent 网络出口',
  'Unresolved Codex egress': '未解析的 Codex 网络出口', 'Browser automation': '浏览器自动化',
  'Web tools': 'Web 工具', 'Local MCP': '本机 MCP', 'Remote MCP': '远程 MCP'
};

function localizedValue(value, dictionary) {
  const raw = String(value ?? '');
  return state.locale === 'zh-CN' ? dictionary[raw] || raw : raw;
}

function coverageLabel(value) { return localizedValue(value, zhCoverage); }
function reasonLabel(value) { return localizedValue(value, zhReasons); }
function riskLabel(value) { return localizedValue(value, zhRiskCodes); }
function surfaceLabel(value) {
  const raw = String(value ?? '');
  if (state.locale !== 'zh-CN') return raw;
  if (zhSurfaceNames[raw]) return zhSurfaceNames[raw];
  for (const [prefix, translated] of [['Local MCP ', '本机 MCP '], ['Remote MCP ', '远程 MCP '], ['Cline provider ', 'Cline Provider '], ['Zed model ', 'Zed 模型 '], ['ACP agent ', 'ACP Agent ']]) {
    if (raw.startsWith(prefix)) return translated + raw.slice(prefix.length);
  }
  return raw;
}

function protectionScopeRows(surfaces, coverage) {
  const surfaceByID = new Map(surfaces.map(surface => [surface.id, surface]));
  const entries = coverage.map(item => ({item, surface: object(surfaceByID.get(item.surface_id))}));
  const local = entries.filter(({surface}) => surface.type === 'mcp_stdio');
  const network = entries.filter(({surface}) => surface.type !== 'mcp_stdio');
  const rows = network.map(({item, surface}) => {
    const model = ['model_primary', 'model_auxiliary', 'model_fallback', 'vision'].includes(surface.type);
    const name = model
      ? state.locale === 'zh-CN' ? 'AI 对话' : 'AI conversations'
      : surfaceLabel(surface.name || item.surface_id);
    const description = model
      ? item.status === 'protected'
        ? state.locale === 'zh-CN' ? '发送给 AI 的内容和 AI 返回的内容，会先经过本机隐私检查。' : 'Messages sent to and returned by the AI pass through on-device privacy checks.'
        : state.locale === 'zh-CN' ? '这部分内容目前还不能安全接入 AgentVeil。' : 'This content cannot yet be safely routed through AgentVeil.'
      : reasonLabel(item.reason || object(surface.metadata).reason || '');
    return {status:item.status, name, description};
  });
  if (local.length) {
    rows.push({
      status:'local',
      name: state.locale === 'zh-CN' ? `本地工具（${local.length} 个）` : `Local tools (${local.length})`,
      description: state.locale === 'zh-CN'
        ? '这些工具在你的电脑上运行；如果它们自己联网，当前不会经过 AgentVeil。'
        : 'These tools run on your computer. Their own network requests do not currently pass through AgentVeil.'
    });
  }
  return rows;
}

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
    return `<article class="tool-card"><div class="tool-head"><div class="tool-icon">${escapeHTML(tool.agent.slice(0,1))}</div><div><h3>${escapeHTML(agentLabel(tool.agent))}</h3><p class="version">版本 ${escapeHTML(tool.version || '未知')}</p></div></div><p class="tool-state"><span class="pill ${registered ? 'good' : verified ? 'neutral' : 'warning'}">${escapeHTML(label)}</span></p><button class="button ${verified ? 'primary' : ''}" data-inspect="${escapeHTML(tool.agent)}">${t('inspect')}</button></article>`;
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
    const result = await api(`/v1/discovery/${encodeURIComponent(name)}`), manifest = object(result.manifest), plan = object(result.protection_plan), agent = object(manifest.agent), surfaces = array(manifest.surfaces), coverage = array(plan.coverage), risks = array(plan.risks), summary = object(plan.summary);
    const fullyProtected = Number(summary.protected || 0) > 0 && Number(summary.partial || 0) === 0 && Number(summary.observed || 0) === 0 && Number(summary.unprotected || 0) === 0;
    const localMCP = surfaces.filter(surface => surface.type === 'mcp_stdio').length;
    const scopeRows = protectionScopeRows(surfaces, coverage);
    const scopeNotice = name === 'codex' || name === 'codex-desktop' ? `<div class="notice protection-note"><strong>当前保护什么</strong><p>AgentVeil 会检查你发给 Codex 的内容，以及 Codex 返回的内容。${localMCP ? 'Codex 使用的本地工具，以及这些工具自己发起的网络请求，暂不在保护范围内。' : ''}${name === 'codex-desktop' ? ' 启动前请先退出当前运行的 Codex。' : ' 请通过 AgentVeil 启动 Codex 才能生效。'}</p></div>` : '';
    const launchAction = name === 'codex-desktop' && isDesktop ? `<button class="button primary" data-launch-codex-desktop>${escapeHTML(t('launchDesktop'))}</button><span id="launch-codex-result" class="inline-result"></span>` : `<p>在终端运行 <code>veil run ${escapeHTML(name)}</code>，原配置不会被改写。</p>`;
    const operation = fullyProtected
      ? `<div class="next-step"><span class="step-number">✓</span><div><strong>可以开始保护</strong>${launchAction}</div></div>`
      : `<div class="error-box protection-note"><strong>当前只能检查，不能安全接管</strong><p>存在 Observed、Partial 或 Unprotected 的必需连接，AgentVeil 不会静默绕过它们。</p></div>`;
    detail.innerHTML = `<p class="eyebrow">保护能力</p><h2>${escapeHTML(agentLabel(agent.kind || name))} <span class="muted">${escapeHTML(agent.version || '')}</span></h2><p class="muted">查看不会启动或修改这个工具。</p>${scopeNotice}<h3>${t('surfaces')}</h3><div class="coverage-list">${scopeRows.map(item => `<div class="coverage-row"><span class="pill ${item.status === 'protected' ? 'good' : item.status === 'unprotected' ? 'bad' : 'warning'}">${escapeHTML(coverageLabel(item.status))}</span><strong> ${escapeHTML(item.name)}</strong><p>${escapeHTML(item.description)}</p></div>`).join('') || `<p class="muted">${t('noSurface')}</p>`}</div>${risks.length ? `<h3>${t('risks')}</h3><div class="coverage-list">${risks.map(risk => `<div class="coverage-row"><strong>${escapeHTML(riskLabel(risk.title || risk.code || '保护提示'))}</strong><p>${escapeHTML(reasonLabel(risk.message || risk.action || risk.impact || ''))}</p></div>`).join('')}</div>` : ''}${operation}`;
  } catch (error) { const message = typeof error === 'string' ? error : error?.message; detail.innerHTML = `<div class="error-box"><strong>无法检查这个工具</strong><p>${escapeHTML(message || '未修改任何原配置。')}</p></div>`; }
}

async function startProtectedCodexDesktop(button) {
  const result = $('#launch-codex-result');
  button.disabled = true;
  if (result) result.textContent = t('launchStarting');
  try {
    await launchCodexDesktop();
    if (result) { result.textContent = t('launchStarted'); result.className = 'inline-result success'; }
    await loadAll();
  } catch (error) {
    if (result) { result.textContent = error?.message || String(error); result.className = 'inline-result failure'; }
    button.disabled = false;
  }
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
  const nav = event.target.closest('[data-page]'), go = event.target.closest('[data-go]'), inspect = event.target.closest('[data-inspect]'), decision = event.target.closest('[data-decision]'), launchCodex = event.target.closest('[data-launch-codex-desktop]');
  if (nav) navigate(nav.dataset.page); if (go) navigate(go.dataset.go); if (inspect) inspectTool(inspect.dataset.inspect);
  if (decision) decide(decision.dataset.approval, decision.dataset.decision).catch(() => loadAll());
  if (launchCodex) startProtectedCodexDesktop(launchCodex);
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
