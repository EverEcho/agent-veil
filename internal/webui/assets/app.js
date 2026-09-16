import {checkForUpdate, desktopInfo, downloadUpdate, exchangeBrowserTicket, installUpdate, isDesktop, launchCodexDesktop, requestCore, setUpdateChannel, updateInfo} from './platform.js';
import {locale, preferredLocale, setLocale, t, translatePrefix, translateValue} from './i18n.js';

const state = {
  health: null, tools: [], agents: [], approvals: [], audit: [], calls: {},
  policy: null, policySaving: false, rules: null, models: null, desktopInfo: null, browserSession: false, refreshTimer: null, locale: preferredLocale(),
  developerSettings: null, developerTraces: [], developerSaving: false, update: null
};

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const array = value => Array.isArray(value) ? value : [];
const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));

const protectionSettingGroups = {
  contact: ['pii.email', 'pii.cn.phone', 'pii.cn.landline'],
  identity: ['pii.cn.id_card', 'pii.cn.license_plate', 'pii.cn.passport', 'pii.cn.uscc', 'pii.us.ssn', 'pii.iban', 'pii.bank_card'],
  environment: ['secret.assignment'],
  database: ['secret.database_url'],
  'known-secrets': ['secret.github_pat', 'secret.openai_key', 'secret.anthropic_key', 'secret.google_key', 'secret.huggingface_token', 'secret.groq_key', 'secret.aws_access_key', 'secret.aws_secret_key', 'secret.alibaba_access_key', 'secret.tencent_secret_id', 'secret.volcengine_access_key', 'secret.slack_token', 'secret.gitlab_pat', 'secret.stripe_key', 'secret.jwt', 'secret.bearer'],
  'unknown-secrets': ['secret.high_entropy'],
  network: ['pii.ipv4', 'pii.ipv6', 'pii.mac']
};

function agentLabel(value) {
  return translateValue('agentLabels', value);
}
function localizedValue(value, namespace) {
  return translateValue(namespace, value);
}

function coverageLabel(value) { return localizedValue(value, 'coverage'); }
function reasonLabel(value) { return localizedValue(value, 'reasons'); }
function riskLabel(value) { return localizedValue(value, 'riskCodes'); }
function surfaceLabel(value) {
  const raw = String(value ?? '');
  const translatedName = translateValue('surfaceNames', raw);
  return translatedName === raw ? translatePrefix('surfacePrefixes', raw) : translatedName;
}

function applyStaticTranslations() {
  $$('[data-i18n]').forEach(node => { node.textContent = t(node.dataset.i18n); });
  $$('[data-i18n-placeholder]').forEach(node => { node.placeholder = t(node.dataset.i18nPlaceholder); });
  $$('[data-i18n-aria]').forEach(node => { node.setAttribute('aria-label', t(node.dataset.i18nAria)); });
}

function protectionScopeRows(surfaces, coverage) {
  const surfaceByID = new Map(surfaces.map(surface => [surface.id, surface]));
  const entries = coverage.map(item => ({item, surface: object(surfaceByID.get(item.surface_id))}));
  const local = entries.filter(({surface}) => surface.type === 'mcp_stdio');
  const network = entries.filter(({surface}) => surface.type !== 'mcp_stdio');
  const rows = network.map(({item, surface}) => {
    const model = ['model_primary', 'model_auxiliary', 'model_fallback', 'vision'].includes(surface.type);
    const name = model
      ? t('scope.aiConversations')
      : surfaceLabel(surface.name || item.surface_id);
    const description = model
      ? item.status === 'protected'
        ? t('scope.protectedConversation')
        : t('scope.unprotectedConversation')
      : reasonLabel(item.reason || object(surface.metadata).reason || '');
    return {status:item.status, name, description};
  });
  if (local.length) {
    rows.push({
      status:'local',
      name: t('scope.localTools', {count:local.length}),
      description: t('scope.localToolsDescription')
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

async function loadDesktopInfo() {
  if (!isDesktop) return true;
  try { state.desktopInfo = await desktopInfo(); return true; }
  catch (_) { state.desktopInfo = null; return true; }
}

async function loadAll() {
  $('#refresh').disabled = true;
  const results = await Promise.all([
    safeLoad('/v1/health', value => state.health = value),
    safeLoad('/v1/discovery', value => state.tools = array(value)),
    safeLoad('/v1/agents', value => state.agents = array(value)),
    safeLoad('/v1/approvals', value => state.approvals = array(value)),
    safeLoad('/v1/audit', value => state.audit = array(value)),
    safeLoad('/v1/call-tree', value => state.calls = object(value)),
    safeLoad('/v1/policy', value => state.policy = object(value)),
    safeLoad('/v1/developer-settings', value => state.developerSettings = object(value)),
    safeLoad('/v1/developer-traces', value => state.developerTraces = array(value)),
    loadDesktopInfo()
  ]);
  renderAll();
  const failed = results.filter(result => !result).length;
  $('#notice').hidden = failed === 0;
  $('#notice').textContent = failed ? t('loadPartial') : '';
  $('#refresh').disabled = false;
  if ($('#advanced-toggle').checked) loadAdvanced();
}

function renderAll() {
  renderHealth(); renderMetrics(); renderTools(); renderActivity(); renderProtectionSettings(); renderDeveloperSettings(); renderUpdate(); renderAdvancedSummary();
}

function renderUpdate() {
  const card = $('#update-card');
  if (!card) return;
  card.hidden = !isDesktop;
  if (!isDesktop) return;
  const value = object(state.update);
  const select = $('#update-channel');
  select.value = value.selected_channel || 'dev';
  select.disabled = ['checking', 'downloading', 'installing'].includes(value.status);
  $('#update-version').textContent = t('settings.currentVersion', {version:value.current_version || '—', channel:value.build_channel || '—'});
  const status = $('#update-status');
  const key = `settings.updateStatus.${value.status || 'idle'}`;
  status.textContent = value.error || t(key, {version:value.available_version || ''});
  status.className = `inline-result${value.status === 'error' ? ' failure' : value.status === 'downloaded' || value.status === 'up_to_date' ? ' success' : ''}`;
  $('#check-update').disabled = select.disabled || value.supported === false;
  $('#download-update').hidden = value.status !== 'available';
  $('#install-update').hidden = value.status !== 'downloaded';
}

async function refreshUpdate(silent = false) {
  try {
    state.update = await (silent ? checkForUpdate() : updateInfo());
  } catch (error) {
    if (!silent) state.update = {...object(state.update), status:'error', error:String(error)};
  }
  renderUpdate();
}

async function runUpdateAction(action) {
  try {
    if (action === 'download' && !window.confirm(t('settings.confirmDownload', {version:object(state.update).available_version || ''}))) return;
    if (action === 'install' && !window.confirm(t('settings.confirmInstall'))) return;
    state.update = {...object(state.update), status:{check:'checking', download:'downloading', install:'installing'}[action], error:null};
    renderUpdate();
    state.update = await ({check:checkForUpdate, download:downloadUpdate, install:installUpdate}[action])();
  } catch (error) {
    state.update = {...object(state.update), status:'error', error:String(error)};
  }
  renderUpdate();
}

function globalFindingRule(rule, category) {
  const scope = object(object(rule).scope);
  const populated = Object.entries(scope).filter(([, value]) => String(value || '') !== '');
  return populated.length === 1 && scope.finding_type === category;
}

function protectionAction(category) {
  const document = object(state.policy);
  const rule = array(document.rules).find(candidate => globalFindingRule(candidate, category));
  return rule ? String(rule.action || '') : String(document.default || '');
}

function renderProtectionSettings() {
  $$('[data-protection-setting]').forEach(input => {
    const categories = protectionSettingGroups[input.dataset.protectionSetting] || [];
    input.checked = Boolean(state.policy) && categories.length > 0 && categories.every(category => protectionAction(category) !== 'allow');
    input.disabled = !state.policy || state.policySaving;
  });
  const privateKeyAction = $('#private-key-action');
  privateKeyAction.innerHTML = [
    ['block', t('policy.privateKeyBlock')],
    ['redact', t('policy.privateKeyRedact')],
    ['ask', t('policy.privateKeyAsk')],
    ['allow', t('policy.privateKeyAllow')]
  ].map(([value, label]) => `<option value="${value}">${escapeHTML(label)}</option>`).join('');
  privateKeyAction.value = protectionAction('secret.private_key') || 'block';
  privateKeyAction.disabled = !state.policy || state.policySaving;
  $('#private-key-policy-title').textContent = t('policy.privateKeyTitle');
  $('#private-key-policy-description').textContent = t('policy.privateKeyDescription');
  $('#settings-safety-note').textContent = t('policy.safetyNote');
}

async function updateProtectionSetting(input) {
  const result = $('#protection-settings-result'), enabled = input.checked;
  state.policySaving = true; renderProtectionSettings();
  result.textContent = t('saving');
  result.className = 'inline-result';
  try {
    const latest = object(await api('/v1/policy'));
    const categories = protectionSettingGroups[input.dataset.protectionSetting] || [];
    const retained = array(latest.rules).filter(rule => !categories.some(category => globalFindingRule(rule, category)));
    latest.rules = retained.concat(categories.map(category => ({scope:{finding_type:category}, action:enabled ? 'redact' : 'allow'})));
    await api('/v1/policy', {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(latest)});
    state.policy = latest;
    if (document.activeElement !== $('#policy')) $('#policy').value = JSON.stringify(latest, null, 2);
    result.textContent = t('saved');
    result.className = 'inline-result success';
  } catch (_) {
    result.textContent = t('saveRetry');
    result.className = 'inline-result failure';
  }
  state.policySaving = false; renderProtectionSettings();
}

async function updatePrivateKeyAction(select) {
  const result = $('#protection-settings-result'), action = select.value;
  if (!['block', 'redact', 'ask', 'allow'].includes(action)) return;
  state.policySaving = true; renderProtectionSettings();
  result.textContent = t('saving');
  result.className = 'inline-result';
  try {
    const latest = object(await api('/v1/policy'));
    latest.rules = array(latest.rules).filter(rule => !globalFindingRule(rule, 'secret.private_key'));
    if (action !== latest.default) latest.rules.push({scope:{finding_type:'secret.private_key'}, action});
    await api('/v1/policy', {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(latest)});
    state.policy = latest;
    if (document.activeElement !== $('#policy')) $('#policy').value = JSON.stringify(latest, null, 2);
    result.textContent = t('saved');
    result.className = 'inline-result success';
  } catch (_) {
    result.textContent = t('saveRetry');
    result.className = 'inline-result failure';
  }
  state.policySaving = false; renderProtectionSettings();
}

function renderDeveloperSettings() {
  const settings = object(state.developerSettings), enabled = settings.enabled === true;
  const enabledInput = $('#developer-enabled'), captureInput = $('#developer-capture-bodies');
  enabledInput.checked = enabled;
  enabledInput.disabled = !state.developerSettings || state.developerSaving;
  captureInput.checked = enabled && settings.capture_request_bodies === true;
  captureInput.disabled = !enabled || state.developerSaving;
  $('#developer-title').textContent = t('developer.title');
  $('#developer-description').textContent = t('developer.description');
  $('#developer-enabled-title').textContent = t('developer.enabledTitle');
  $('#developer-enabled-description').textContent = t('developer.enabledDescription');
  $('#developer-capture-title').textContent = t('developer.captureTitle');
  $('#developer-capture-description').textContent = t('developer.captureDescription');
  $('#developer-warning').textContent = t('developer.warning');
  $('#developer-log-title').textContent = t('developer.logTitle');
  $('#developer-log-count').textContent = String(state.developerTraces.length);
  const list = $('#developer-trace-list');
  if (!state.developerTraces.length) {
    list.innerHTML = `<p class="muted">${escapeHTML(t('developer.empty'))}</p>`;
    return;
  }
  list.innerHTML = [...state.developerTraces].reverse().map(trace => {
    const findings = array(trace.findings);
    const findingRows = findings.map(finding => {
      const location = object(finding.location);
      const range = `${String(location.path || '')}:${Number(location.start || 0)}-${Number(location.end || 0)}`;
      return `<li><strong>${escapeHTML(finding.category || finding.rule_id || '')}</strong> · ${escapeHTML(actionLabel(finding.action))}<br><code>${escapeHTML(range)}</code> · ${escapeHTML(finding.detector || '')} · ${Number(finding.match_bytes || 0)} bytes · ${Math.round(Number(finding.confidence || 0) * 100)}%</li>`;
    }).join('');
    const before = trace.request_before ? `<div><strong>${escapeHTML(t('developer.before'))}${trace.request_before_truncated ? ` · ${escapeHTML(t('developer.truncated'))}` : ''}</strong><pre>${escapeHTML(trace.request_before)}</pre></div>` : '';
    const after = trace.request_after ? `<div><strong>${escapeHTML(t('developer.after'))}${trace.request_after_truncated ? ` · ${escapeHTML(t('developer.truncated'))}` : ''}</strong><pre>${escapeHTML(trace.request_after)}</pre></div>` : '';
    return `<details class="developer-trace"><summary>${formatTime(trace.timestamp)} · ${escapeHTML(trace.method || '')} ${escapeHTML(trace.endpoint || '')} · ${findings.length} ${escapeHTML(t('developer.findings'))}</summary><div class="developer-trace-meta"><span>${escapeHTML(trace.agent_id || 'Agent')}</span><span>${escapeHTML(trace.protocol || '')}</span><span>${Number(trace.original_body_bytes || 0)} → ${Number(trace.processed_body_bytes || 0)} bytes</span>${trace.error_code ? `<span class="pill bad">${escapeHTML(trace.error_code)}</span>` : ''}</div>${trace.preview ? `<p class="audit-preview"><b>${escapeHTML(t('protectedContent'))}：</b>${escapeHTML(trace.preview)}</p>` : ''}${findingRows ? `<ul>${findingRows}</ul>` : `<p class="muted">${escapeHTML(t('developer.noFindings'))}</p>`}${before}${after}</details>`;
  }).join('');
}

async function updateDeveloperSettings(next) {
  const result = $('#developer-settings-result');
  state.developerSaving = true; renderDeveloperSettings();
  result.textContent = t('saving'); result.className = 'inline-result';
  const settings = {schema_version:'v1', enabled:Boolean(next.enabled), capture_request_bodies:Boolean(next.enabled && next.capture_request_bodies)};
  try {
    await api('/v1/developer-settings', {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(settings)});
    state.developerSettings = settings;
    result.textContent = t('saved'); result.className = 'inline-result success';
  } catch (_) {
    result.textContent = t('saveRetry'); result.className = 'inline-result failure';
  }
  state.developerSaving = false; renderDeveloperSettings();
}

function renderHealth() {
  const health = object(state.health), good = health.status === 'ok';
  $('#protection-badge').className = `protection-badge ${good ? 'good' : 'bad'}`;
  $('#protection-badge-label').textContent = good ? t('shell.coreHealthy') : t('shell.coreDegraded');
  $('#hero-pill').className = `pill ${good ? 'good' : 'bad'}`;
  $('#hero-pill').textContent = good ? t('dashboard.coreOK') : t('dashboard.needsAttention');
  $('#hero-title').textContent = good ? t('dashboard.protectingDevice') : t('dashboard.attentionTitle');
  $('#hero-copy').textContent = good
    ? t('dashboard.healthyCopy')
    : t('dashboard.degradedCopy');
}

function sessionCount() {
  return Object.values(object(state.calls)).reduce((total, entries) => total + array(entries).length, 0);
}

function renderMetrics() {
  const compatible = state.tools.filter(tool => tool.status === 'verified').length;
  const activeSessions = sessionCount();
  $('#metric-installed').textContent = state.tools.length;
  $('#metric-protected').textContent = compatible;
  $('#metric-sessions').textContent = state.agents.length;
  $('#metric-actions').textContent = activeSessions;
  const coreHealthy = object(state.health).status === 'ok';
  $('#live-indicator').className = `live-indicator ${coreHealthy ? activeSessions > 0 ? 'good' : 'idle' : 'bad'}`;
  $('#live-indicator-label').textContent = coreHealthy
    ? activeSessions > 0 ? t('shell.activeProtection', {count:activeSessions}) : t('shell.readyForTasks')
    : t('shell.waitingForCore');
  $('#nav-tool-count').textContent = state.tools.length;
  const next = $('#next-step');
  if (state.approvals.length) next.innerHTML = `<span class="step-number">!</span><div><strong>${escapeHTML(t('dashboard.approvalsPending', {count:state.approvals.length}))}</strong><p>${escapeHTML(t('dashboard.reviewApprovals'))}</p></div>`;
  else if (!state.tools.length) next.innerHTML = `<span class="step-number">!</span><div><strong>${t('noTools')}</strong><p>${t('noToolsHelp')}</p></div>`;
  else if (!state.agents.length) next.innerHTML = `<span class="step-number">1</span><div><strong>${escapeHTML(t('dashboard.toolsFound', {count:state.tools.length}))}</strong><p>${escapeHTML(t('dashboard.openTools'))} ${escapeHTML(t('protectionTruth'))}</p></div>`;
  else next.innerHTML = `<span class="step-number">✓</span><div><strong>${escapeHTML(t('dashboard.toolsConfigured', {count:state.agents.length}))}</strong><p>${escapeHTML(t('dashboard.activeSessions', {count:sessionCount()}))}</p></div>`;
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
    renderOverviewTools();
    return;
  }
  grid.innerHTML = state.tools.map(tool => {
    const registered = registeredFor(tool), verified = tool.status === 'verified';
    const label = registered ? t('protected') : tool.status === 'version_unknown' ? t('versionUnknown') : verified ? t('verified') : t('unverified');
    const name = escapeHTML(tool.agent);
    const desktopProcess = tool.agent === 'codex-desktop' && isDesktop;
    const running = desktopProcess ? object(state.desktopInfo).codex_desktop_running : null;
    const protectedRunning = desktopProcess && object(state.desktopInfo).codex_desktop_protected === true;
    const processLabel = protectedRunning ? t('process.protected') : running === true ? t('process.unprotected') : running === false ? t('process.stopped') : t('process.unknown');
    const processState = desktopProcess ? `<span class="pill ${protectedRunning ? 'good' : running === true ? 'warning' : 'neutral'}">${escapeHTML(processLabel)}</span>` : '';
    const protectionState = `<span class="pill ${registered ? 'good' : verified ? 'neutral' : 'warning'}">${escapeHTML(label)}</span>`;
    const statePills = desktopProcess && (protectedRunning || running === true) ? processState : protectionState + processState;
    const infoIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M12 11v6"></path><path d="M12 7.25h.01"></path></svg>';
    const playIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 7 8 5-8 5z"></path></svg>';
    const restartIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M19 8a8 8 0 1 0 1 6"></path><path d="M19 3v5h-5"></path></svg>';
    const launchAction = desktopProcess
      ? `<button class="tool-action tool-launch${protectedRunning ? ' is-running' : ''}" data-launch-codex-desktop="${name}" aria-label="${escapeHTML(protectedRunning ? processLabel : running === true ? t('process.restart') : t('launchDesktop'))}" title="${escapeHTML(protectedRunning ? processLabel : running === true ? t('process.restartHint') : t('launchDesktop'))}"${protectedRunning ? ' disabled' : ''}>${running === true && !protectedRunning ? restartIcon : playIcon}</button>`
      : '';
    return `<article class="tool-card"><div class="tool-head"><div class="tool-icon">${escapeHTML(tool.agent.slice(0,1))}</div><div><h3>${escapeHTML(agentLabel(tool.agent))}</h3><p class="version">${escapeHTML(t('tool.version', {version:tool.version || t('tool.unknownVersion')}))}</p></div></div><p class="tool-state">${statePills}</p><div class="tool-card-actions">${launchAction}<button class="tool-action tool-info" data-inspect="${name}" aria-label="${escapeHTML(t('tool.viewProtection'))}" title="${escapeHTML(t('tool.viewProtection'))}">${infoIcon}</button></div><span class="tool-launch-result" data-launch-result="${name}" role="status"></span></article>`;
  }).join('');
  applyDashboardSearch();
  renderOverviewTools();
}

function renderOverviewTools() {
  const preview = $('#overview-tools');
  if (!preview) return;
  const tools = state.tools.slice(0, 6);
  if (!tools.length) {
    preview.innerHTML = `<div class="empty-state compact"><div class="empty-icon">?</div><div><strong>${escapeHTML(t('noTools'))}</strong><p>${escapeHTML(t('noToolsHelp'))}</p></div></div>`;
    return;
  }
  preview.innerHTML = tools.map(tool => {
    const registered = registeredFor(tool);
    const status = registered ? t('protected') : tool.status === 'verified' ? t('verified') : t('unverified');
    return `<button class="overview-tool-row" data-go="tools"><span class="tool-icon">${escapeHTML(tool.agent.slice(0, 1))}</span><span><strong>${escapeHTML(agentLabel(tool.agent))}</strong><small>${escapeHTML(t('tool.version', {version:tool.version || t('tool.unknownVersion')}))}</small></span><span class="pill ${registered ? 'good' : 'neutral'}">${escapeHTML(status)}</span></button>`;
  }).join('');
}

function actionLabel(action) {
  return translateValue('actions', action || 'processed');
}

function findingLabel(value) {
  return localizedValue(value, 'findingTypes');
}

function eventReason(event) {
  const errorCode = String(event.error_code || '');
  if (errorCode) {
    const reason = localizedValue(errorCode, 'errorCodes');
    return reason === errorCode ? errorCode : t('activity.errorReason', {code:errorCode, reason});
  }
  const findings = array(event.finding_types);
  if (event.action === 'block') {
    return findings.length
      ? t('activity.blockedBecause', {reason:findingLabel(findings[0]), count:Number(event.finding_count || findings.length)})
      : t('activity.blockedByPolicy');
  }
  if (findings.length) return t('activity.detectedBecause', {reason:findingLabel(findings[0]), count:Number(event.finding_count || findings.length)});
  return event.protocol || t('activity.localProcessing');
}

function eventMeta(event) {
  return `${t('activity.findings', {count:Number(event.finding_count || 0)})} · ${event.protocol || t('activity.localProcessing')}`;
}

function renderActivity() {
  $('#approval-list').innerHTML = state.approvals.map(item => `<article class="approval-card"><strong>${escapeHTML(t('activity.confirmRequired'))}</strong><p>${escapeHTML(object(item.finding).category || t('activity.sensitiveContent'))}</p><div class="row-actions"><button class="button primary" data-decision="redact" data-approval="${escapeHTML(item.id)}">${escapeHTML(t('activity.redact'))}</button><button class="button" data-decision="allow" data-approval="${escapeHTML(item.id)}">${escapeHTML(t('activity.allow'))}</button><button class="button" data-decision="block" data-approval="${escapeHTML(item.id)}">${escapeHTML(t('activity.block'))}</button></div></article>`).join('');
  const list = $('#activity-list');
  if (!state.audit.length) list.innerHTML = `<div class="empty-state"><div class="empty-icon">✓</div><div><strong>${t('noActivity')}</strong><p>${t('noActivityHelp')}</p></div></div>`;
  else list.innerHTML = [...state.audit].reverse().slice(0,100).map(event => `<article class="timeline-item action-${escapeHTML(event.action || 'processed')}"><span class="timeline-dot"></span><div><strong>${escapeHTML(actionLabel(event.action))} · ${escapeHTML(event.agent_id || 'Agent')}</strong><p class="event-reason">${escapeHTML(eventReason(event))}</p><p class="event-meta">${escapeHTML(eventMeta(event))}</p>${event.preview ? `<p class="audit-preview"><b>${escapeHTML(t('protectedContent'))}：</b>${escapeHTML(event.preview)}</p>` : ''}</div><time>${formatTime(event.timestamp)}</time></article>`).join('');
  const latest = state.audit[state.audit.length - 1];
  $('#overview-activity').innerHTML = latest
    ? `<div class="empty-icon">✓</div><div><strong>${escapeHTML(actionLabel(latest.action))} · ${escapeHTML(latest.agent_id || 'Agent')}</strong><p>${escapeHTML(eventReason(latest))}</p><small class="event-meta">${escapeHTML(formatTime(latest.timestamp))} · ${escapeHTML(eventMeta(latest))}</small></div>`
    : `<div class="empty-icon">✓</div><div><strong>${t('noActivity')}</strong><p>${t('noActivityHelp')}</p></div>`;
  applyDashboardSearch();
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? t('justNow') : new Intl.DateTimeFormat(locale(), {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}).format(date);
}

async function inspectTool(name) {
  const dialog = $('#tool-dialog'), detail = $('#tool-detail');
  detail.innerHTML = `<p class="muted">${escapeHTML(t('tool.loading'))}</p>`; dialog.showModal();
  try {
    const result = await api(`/v1/discovery/${encodeURIComponent(name)}`), manifest = object(result.manifest), plan = object(result.protection_plan), agent = object(manifest.agent), surfaces = array(manifest.surfaces), coverage = array(plan.coverage), risks = array(plan.risks);
    const localMCP = surfaces.filter(surface => surface.type === 'mcp_stdio').length;
    const scopeRows = protectionScopeRows(surfaces, coverage);
    const scopeNotice = name === 'codex' || name === 'codex-desktop' ? `<div class="notice protection-note"><strong>${escapeHTML(t('tool.currentProtection'))}</strong><p>${escapeHTML(t('tool.codexDescription'))}${localMCP ? escapeHTML(t('tool.codexLocalTools')) : ''}</p></div>` : '';
    detail.innerHTML = `<p class="eyebrow">${escapeHTML(t('tool.description'))}</p><h2>${escapeHTML(agentLabel(agent.kind || name))} <span class="muted">${escapeHTML(agent.version || '')}</span></h2>${scopeNotice}<h3>${t('surfaces')}</h3><div class="coverage-list">${scopeRows.map(item => `<div class="coverage-row"><span class="pill ${item.status === 'protected' ? 'good' : item.status === 'unprotected' ? 'bad' : 'warning'}">${escapeHTML(coverageLabel(item.status))}</span><strong> ${escapeHTML(item.name)}</strong><p>${escapeHTML(item.description)}</p></div>`).join('') || `<p class="muted">${t('noSurface')}</p>`}</div>${risks.length ? `<h3>${t('risks')}</h3><div class="coverage-list">${risks.map(risk => `<div class="coverage-row"><strong>${escapeHTML(riskLabel(risk.title || risk.code || t('tool.protectionNotice')))}</strong><p>${escapeHTML(reasonLabel(risk.message || risk.action || risk.impact || ''))}</p></div>`).join('')}</div>` : ''}`;
  } catch (error) { const message = typeof error === 'string' ? error : error?.message; detail.innerHTML = `<div class="error-box"><strong>${escapeHTML(t('tool.inspectFailed'))}</strong><p>${escapeHTML(message || t('tool.noChanges'))}</p></div>`; }
}

async function startProtectedCodexDesktop(button) {
  const name = button.dataset.launchCodexDesktop;
  const card = button.closest('.tool-card');
  const result = card?.querySelector('[data-launch-result]');
  const label = button.querySelector('span');
  button.disabled = true;
  button.classList.add('is-loading');
  if (label) label.textContent = t('launchStarting');
  if (result) { result.textContent = ''; result.className = 'tool-launch-result'; }
  try {
    const discovery = await api(`/v1/discovery/${encodeURIComponent(name)}`);
    const summary = object(object(discovery.protection_plan).summary);
    const fullyProtected = Number(summary.protected || 0) > 0 && Number(summary.partial || 0) === 0 && Number(summary.observed || 0) === 0 && Number(summary.unprotected || 0) === 0;
    if (!fullyProtected) throw new Error(t('launchUnavailable'));
    await launchCodexDesktop();
    await loadAll();
  } catch (error) {
    if (result) { result.textContent = error?.message || String(error); result.className = 'tool-launch-result failure'; }
    if (label) label.textContent = t('launch');
    button.classList.remove('is-loading');
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
    const source = $('#policy').value, document = JSON.parse(source);
    await api('/v1/policy', {method:'PUT', headers:{'Content-Type':'application/json'}, body:source});
    state.policy = document; renderProtectionSettings();
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
  $('.sidebar').classList.remove('open');
  if (page === 'advanced') loadAdvanced();
}

function configureRefresh() {
  clearInterval(state.refreshTimer);
  if ($('#auto-refresh').checked) state.refreshTimer = setInterval(() => { if (!document.hidden) loadAll(); }, 5000);
}

async function applyLocale(locale) {
  state.locale = await setLocale(locale);
  applyStaticTranslations();
  renderAll(); const active = $('.nav-item.active')?.dataset.page || 'overview'; navigate(active);
}

function applyDashboardSearch() {
  const query = ($('#dashboard-search')?.value || '').trim().toLocaleLowerCase(state.locale);
  const panel = $('#dashboard-search-results'), input = $('#dashboard-search');
  if (!query) {
    panel.hidden = true;
    panel.innerHTML = '';
    input.setAttribute('aria-expanded', 'false');
    return;
  }
  const includes = value => String(value || '').toLocaleLowerCase(state.locale).includes(query);
  const tools = state.tools.filter(tool => includes([tool.agent, agentLabel(tool.agent), tool.version, tool.status].join(' '))).slice(0, 6);
  const events = [...state.audit].reverse().filter(event => includes([
    event.agent_id, event.action, actionLabel(event.action), event.error_code,
    eventReason(event), event.protocol, ...array(event.finding_types)
  ].join(' '))).slice(0, 6);
  const toolRows = tools.map(tool => `<button class="search-result" data-search-tool="${escapeHTML(tool.agent)}"><span class="search-result-icon">${escapeHTML(tool.agent.slice(0, 1))}</span><span><strong>${escapeHTML(agentLabel(tool.agent))}</strong><small>${escapeHTML(t('tool.version', {version:tool.version || t('tool.unknownVersion')}))}</small></span><span class="search-result-action">${escapeHTML(t('tool.viewProtection'))} →</span></button>`).join('');
  const eventRows = events.map(event => `<button class="search-result" data-search-event><span class="search-result-icon event">◎</span><span><strong>${escapeHTML(actionLabel(event.action))} · ${escapeHTML(event.agent_id || 'Agent')}</strong><small>${escapeHTML(eventReason(event))}</small></span><time>${escapeHTML(formatTime(event.timestamp))}</time></button>`).join('');
  panel.innerHTML = `${toolRows ? `<section><h2>${escapeHTML(t('search.apps'))}</h2>${toolRows}</section>` : ''}${eventRows ? `<section><h2>${escapeHTML(t('search.events'))}</h2>${eventRows}</section>` : ''}${!toolRows && !eventRows ? `<div class="search-empty"><strong>${escapeHTML(t('search.noResults'))}</strong><p>${escapeHTML(t('search.noResultsHint'))}</p></div>` : ''}`;
  panel.hidden = false;
  input.setAttribute('aria-expanded', 'true');
}

$('#refresh').onclick = loadAll; $('#scan-tools').onclick = loadAll;
$('#save-policy').onclick = savePolicy; $('#download-diagnostics').onclick = downloadDiagnostics;
$('#dialog-close').onclick = () => $('#tool-dialog').close();
$('#menu-button').onclick = () => $('.sidebar').classList.toggle('open');
$('#locale').value = state.locale; $('#locale').onchange = event => applyLocale(event.currentTarget.value).catch(() => { event.currentTarget.value = state.locale; });
$('#auto-refresh').onchange = configureRefresh;
$('#dashboard-search').oninput = applyDashboardSearch;
document.addEventListener('keydown', event => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault();
    $('#dashboard-search').focus();
  }
  if (event.key === 'Escape') {
    $('#dashboard-search').value = '';
    applyDashboardSearch();
  }
});
$('#advanced-toggle').onchange = event => { $('#advanced-nav').hidden = !event.currentTarget.checked; if (!event.currentTarget.checked && $('.nav-item.active')?.dataset.page === 'advanced') navigate('settings'); };
$$('[data-protection-setting]').forEach(input => { input.onchange = () => updateProtectionSetting(input); });
$('#private-key-action').onchange = event => updatePrivateKeyAction(event.currentTarget);
$('#developer-enabled').onchange = event => updateDeveloperSettings({enabled:event.currentTarget.checked, capture_request_bodies:object(state.developerSettings).capture_request_bodies});
$('#developer-capture-bodies').onchange = event => updateDeveloperSettings({enabled:true, capture_request_bodies:event.currentTarget.checked});
$('#update-channel').onchange = async event => {
  try { state.update = await setUpdateChannel(event.currentTarget.value); }
  catch (error) { state.update = {...object(state.update), status:'error', error:String(error)}; }
  renderUpdate();
};
$('#check-update').onclick = () => runUpdateAction('check');
$('#download-update').onclick = () => runUpdateAction('download');
$('#install-update').onclick = () => runUpdateAction('install');
document.body.onclick = event => {
  const nav = event.target.closest('[data-page]'), go = event.target.closest('[data-go]'), inspect = event.target.closest('[data-inspect]'), decision = event.target.closest('[data-decision]'), launchCodex = event.target.closest('[data-launch-codex-desktop]'), searchTool = event.target.closest('[data-search-tool]'), searchEvent = event.target.closest('[data-search-event]');
  if (nav) navigate(nav.dataset.page); if (go) navigate(go.dataset.go); if (inspect) inspectTool(inspect.dataset.inspect);
  if (decision) decide(decision.dataset.approval, decision.dataset.decision).catch(() => loadAll());
  if (launchCodex) startProtectedCodexDesktop(launchCodex);
  if (searchTool) { inspectTool(searchTool.dataset.searchTool); $('#dashboard-search').value = ''; applyDashboardSearch(); }
  if (searchEvent) { navigate('activity'); $('#dashboard-search').value = ''; applyDashboardSearch(); }
};

async function startDesktop() {
  document.documentElement.dataset.agentveilDesktop = 'true';
  $('#auth').hidden = true;
  for (let attempt = 0; attempt < 150; attempt += 1) {
    try {
      const info = await desktopInfo();
      state.desktopInfo = info;
      $('#channel-badge').textContent = String(info.channel || 'dev').toUpperCase();
      if (info.desktop && info.ready) {
        try { state.update = await updateInfo(); } catch (_) {}
        await enter();
        if (object(state.update).supported !== false) refreshUpdate(true);
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

async function boot() {
  await applyLocale(state.locale);
  document.documentElement.dataset.agentveilUiReady = 'true';
  if (isDesktop) await startDesktop(); else await startBrowserSession();
}

boot().catch(() => {
  $('#auth-error').textContent = 'AgentVeil language resources could not be loaded.';
});
