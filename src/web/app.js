'use strict';
const $ = (id) => document.getElementById(id);
const API = '/panel/api/';
let csrf = '', state = null, createMode = 'xray', renewTarget = null, confirmResolve = null, refreshing = false;
let noticeTimer;

function notify(message, error = false) {
  const box = $('notice'); box.textContent = message; box.classList.toggle('error', error); box.hidden = false;
  clearTimeout(noticeTimer); noticeTimer = setTimeout(() => { box.hidden = true; }, error ? 12000 : 5500);
}
function element(tag, cls, text) {
  const node = document.createElement(tag); if (cls) node.className = cls; if (text !== undefined) node.textContent = text; return node;
}
function setText(id, text) { $(id).textContent = text; }
function pill(text, kind = '') { return element('span', `pill ${kind}`, text); }
function button(text, action, cls = '') {
  const btn = element('button', cls, text); btn.type = 'button';
  btn.addEventListener('click', () => busy(btn, action)); return btn;
}
async function busy(btn, action) {
  if (btn.disabled) return;
  btn.disabled = true; btn.setAttribute('aria-busy', 'true');
  try { await action(); } catch (err) { notify(err.message || 'Request failed', true); }
  finally { btn.disabled = false; btn.removeAttribute('aria-busy'); }
}
async function api(path, data) {
  const options = {credentials: 'same-origin', headers: {}};
  if (data !== undefined) {
    options.method = 'POST'; options.headers['Content-Type'] = 'application/json';
    options.headers['X-CSRF-Token'] = csrf; options.body = JSON.stringify(data);
  }
  let response;
  try { response = await fetch(API + path, options); } catch (_) { throw new Error('Connection failed. Check the node and your network.'); }
  let result;
  try { result = await response.json(); } catch (_) { throw new Error(`Server returned HTTP ${response.status}. Check Nginx and the web service.`); }
  if (!response.ok) {
    if (response.status === 401 && path !== 'login') showLogin();
    throw new Error(result.error || `Request failed (${response.status})`);
  }
  return result;
}
async function command(name, params = {}, message = 'Saved successfully') {
  const result = await api('command', {command: name, params});
  if (message) notify(message);
  await refresh(); return result;
}
function showLogin() {
  csrf = ''; state = null; $('app').hidden = true; $('login-screen').hidden = false;
  document.querySelectorAll('dialog[open]').forEach(d => d.close());
  $('export-links').replaceChildren(); setText('login-error', '');
}
function showApp(session) {
  csrf = session.csrf; setText('admin-name', session.username);
  $('login-screen').hidden = true; $('app').hidden = false;
}
function view(name) {
  document.querySelectorAll('.view').forEach(n => { n.hidden = n.id !== `view-${name}`; });
  document.querySelectorAll('.nav').forEach(n => n.classList.toggle('active', n.dataset.view === name));
  setText('breadcrumb', {overview: 'Overview', ssh: 'SSH accounts', xray: 'Xray profiles', network: 'DNS & SSL', diagnostics: 'Diagnostics'}[name]);
}
const size = (value) => !Number.isFinite(value) ? '—' : value >= 1024 ** 3 ? `${(value / 1024 ** 3).toFixed(1)} GB` : `${(value / 1024 ** 2).toFixed(0)} MB`;
const percent = (used, total) => total > 0 ? Math.max(0, Math.min(100, used / total * 100)) : 0;
function tags(protocols) { const box = element('div'); protocols.forEach(p => box.append(element('span', `tag ${p}`, p.toUpperCase()))); return box; }
function emptyRow(body, columns, text) {
  const row = element('tr'), cell = element('td', 'empty', text); cell.colSpan = columns; row.append(cell); body.append(row);
}
function profileRows(id, rows, controls) {
  const body = $(id); body.replaceChildren();
  if (!rows.length) { emptyRow(body, 5, 'No profiles yet. Enable Xray, then create your first profile.'); return; }
  rows.forEach(row => {
    const tr = element('tr'); tr.append(element('td', 'mono', row.name));
    const protocols = element('td'); protocols.append(tags(row.protocols)); tr.append(protocols, element('td', 'mono muted', row.expiry));
    const status = element('td'); status.append(pill(row.active ? 'Active' : row.enabled === false ? 'Disabled' : 'Expired', row.active ? 'good' : 'warn')); tr.append(status);
    const actions = element('td'), group = element('div', 'row-actions');
    if (row.active) group.append(button('Export ↗', () => exportProfile(row.name)));
    if (controls) {
      group.append(button('Renew', () => openRenew('xray', row.name)), button(row.enabled === false ? 'Enable' : 'Disable', () => command('xray_update', {name: row.name, action: 'toggle', enabled: row.enabled === false}, 'Profile updated')),
        button('Delete', async () => { if (await confirmAction(`Delete Xray profile “${row.name}”? Its import links will stop working.`)) await command('xray_update', {name: row.name, action: 'delete'}, 'Profile deleted'); }, 'delete'));
    }
    actions.append(group); tr.append(actions); body.append(tr);
  });
}
function render() {
  const s = state, system = s.system;
  setText('node-host', system.hostname); setText('node-domain', s.domain === 'Not set' ? 'Domain not configured' : s.domain);
  setText('node-uptime', `UP ${Math.floor(system.uptime_seconds / 86400)}d ${Math.floor(system.uptime_seconds / 3600) % 24}h`);
  const services = Object.entries(s.services), running = services.filter(([, status]) => status === 'active').length;
  const healthy = s.services['abdulbasit-paneld'] === 'active' && s.services['nginx'] === 'active';
  $('node-status').replaceWith(Object.assign(pill(healthy ? 'Node online' : 'Needs attention', healthy ? 'good' : 'warn'), {id: 'node-status'}));
  setText('stat-load', system.load[0].toFixed(2)); setText('stat-cpus', `${system.cpu_count || '?'} CPU threads · 1-min load`);
  const memUsed = system.memory_total - system.memory_available, memPercent = percent(memUsed, system.memory_total), diskPercent = percent(system.disk_used, system.disk_total);
  setText('stat-memory', `${memPercent.toFixed(0)}%`); $('memory-meter').value = memPercent; setText('memory-detail', `${size(memUsed)} / ${size(system.memory_total)}`);
  setText('stat-disk', `${diskPercent.toFixed(0)}%`); $('disk-meter').value = diskPercent; setText('disk-detail', `${size(system.disk_used)} / ${size(system.disk_total)}`);
  const count = s.accounts.filter(a => a.active).length;
  setText('stat-profiles', String(count)); setText('nav-profiles', String(s.accounts.length));
  setText('stat-access', `${s.users.length} SSH accounts · ${s.sessions.reduce((sum, x) => sum + x.count, 0)} sessions`);
  setText('service-total', `${running}/${services.length} running`);
  const serviceList = $('service-list'); serviceList.replaceChildren();
  const labels = {nginx: 'Nginx gateway', dropbear: 'Dropbear SSH', 'abdulbasit-ws': 'SSH upgrade proxy', 'abdulbasit-session-enforcer': 'Session enforcer', 'abdulbasit-bot': 'Telegram bot', 'abdulbasit-paneld': 'Panel daemon', 'abdulbasit-web': 'Web dashboard', 'abdulbasit-xray': 'Xray core'};
  services.forEach(([service, status]) => {
    const row = element('div', 'service-row'); row.append(element('span', `service-dot ${status === 'active' ? 'good' : ''}`), element('strong', '', labels[service] || service), element('span', 'service-label', status));
    if (!['abdulbasit-paneld', 'abdulbasit-web', 'abdulbasit-bot'].includes(service)) {
      const restart = button('↻', async () => { if (await confirmAction(`Restart ${labels[service] || service}? Active connections may briefly reconnect.`)) await command('restart_service', {service}, 'Service restarted'); }, 'service-restart');
      restart.setAttribute('aria-label', `Restart ${service}`); row.append(restart);
    }
    serviceList.append(row);
  });
  const protocols = $('protocol-cards'); protocols.replaceChildren();
  for (const [i, endpoint] of s.endpoints.entries()) {
    const row = element('div', 'protocol-row'), detail = element('div');
    detail.append(element('strong', '', endpoint.protocol.toUpperCase()), element('p', '', `WS + TLS  /  ${endpoint.path}`));
    row.append(element('span', 'protocol-symbol', ['V', 'M', 'T'][i]), detail, pill(s.network.enabled && s.services['abdulbasit-xray'] === 'active' ? 'Ready' : 'Offline', s.network.enabled && s.services['abdulbasit-xray'] === 'active' ? 'good' : '')); protocols.append(row);
  }
  profileRows('overview-profiles', s.accounts.slice(0, 4), false); profileRows('xray-accounts', s.accounts, true);
  const users = $('ssh-users'); users.replaceChildren();
  if (!s.users.length) emptyRow(users, 5, 'No SSH accounts yet. Create an account to grant access.');
  s.users.forEach(user => {
    const tr = element('tr'); tr.append(element('td', 'mono', user.username), element('td', 'mono muted', user.expiry), element('td', '', `${(s.sessions.find(x => x.username === user.username) || {}).count || 0} / ${user.max_sessions}`), element('td', 'muted', user.quota_gb == null ? 'Unlimited · metadata' : `${user.quota_gb} GB · metadata`));
    const td = element('td'), actions = element('div', 'row-actions'); actions.append(button('Renew', () => openRenew('ssh', user.username)), button('Delete', async () => { if (await confirmAction(`Delete SSH account “${user.username}”? Its active sessions will be disconnected.`)) await command('delete_user', {username: user.username}, 'Account deleted'); }, 'delete')); td.append(actions); tr.append(td); users.append(tr);
  });
  setText('xray-summary', `${s.xray_installed ? 'Installed' : 'Core not installed · run install.sh --with-xray'} · ${s.network.enabled ? 'Enabled' : 'Disabled'} · TLS on port 443`);
  $('toggle-xray').textContent = s.network.enabled ? 'Disable Xray' : 'Enable Xray';
  $('toggle-xray').classList.toggle('primary', !s.network.enabled); $('toggle-xray').disabled = !s.xray_installed;
  if (!$('domain-form').contains(document.activeElement)) $('domain-input').value = s.domain === 'Not set' ? '' : s.domain;
  if (!$('dns-form').contains(document.activeElement)) { $('dns-servers').value = s.network.dns.servers.join('\n'); $('dns-strategy').value = s.network.dns.query_strategy; }
  setText('connection-state', 'Connected'); $('connection-state').classList.add('online'); setText('last-updated', `Updated ${new Date().toLocaleTimeString()}`);
}
async function refresh() {
  if (!csrf || refreshing) return;
  refreshing = true; $('refresh').classList.add('refreshing');
  try { state = await api('state'); render(); }
  catch (err) { setText('connection-state', 'Disconnected'); $('connection-state').classList.remove('online'); throw err; }
  finally { refreshing = false; $('refresh').classList.remove('refreshing'); }
}
function openCreate(mode) {
  createMode = mode; $('create-form').reset(); $('ssh-fields').hidden = mode !== 'ssh'; $('protocol-fields').hidden = mode === 'ssh';
  $('create-form').elements.password.required = mode === 'ssh';
  setText('create-title', mode === 'ssh' ? 'New SSH account' : 'New Xray profile'); $('create-dialog').showModal();
}
function openRenew(type, name) { renewTarget = {type, name}; setText('renew-name', name); $('renew-form').reset(); $('renew-dialog').showModal(); }
function confirmAction(message) {
  setText('confirm-message', message); $('confirm-dialog').showModal();
  return new Promise(resolve => { confirmResolve = resolve; });
}
async function exportProfile(name) {
  const result = await api(`export?name=${encodeURIComponent(name)}`);
  setText('export-title', name); const container = $('export-links'); container.replaceChildren();
  Object.entries(result.links).forEach(([protocol, link]) => {
    const item = element('div', 'export-item'), input = element('textarea'); input.value = link; input.readOnly = true; input.setAttribute('aria-label', `${protocol} import link`);
    item.append(element('strong', '', protocol.toUpperCase()), input, button('Copy link', async () => {
      try { await navigator.clipboard.writeText(link); notify('Import link copied'); }
      catch (_) { input.select(); notify('Select and copy the highlighted link manually'); }
    }, 'btn small'), button('↓ Xray JSON', () => {
      const blob = new Blob([result.files[`${name}-${protocol}.json`]], {type: 'application/json'}), url = URL.createObjectURL(blob);
      const a = element('a'); a.href = url; a.download = `${name}-${protocol}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
    }, 'btn small')); container.append(item);
  });
  $('download-zip').href = API + `export?name=${encodeURIComponent(name)}&format=zip`; $('export-dialog').showModal();
}
function bindForm(id, handler) {
  $(id).addEventListener('submit', event => { event.preventDefault(); busy($(id).querySelector('[type="submit"]'), () => handler(new FormData($(id)))); });
}
document.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', () => view(btn.dataset.view)));
document.querySelectorAll('[data-new]').forEach(btn => btn.addEventListener('click', () => openCreate(btn.dataset.new)));
document.querySelectorAll('[data-close]').forEach(btn => btn.addEventListener('click', () => $(btn.dataset.close).close()));
$('confirm-dialog').addEventListener('close', () => { if (confirmResolve) { confirmResolve(false); confirmResolve = null; } });
$('confirm-form').addEventListener('submit', event => { event.preventDefault(); const resolve = confirmResolve; confirmResolve = null; $('confirm-dialog').close(); if (resolve) resolve(true); });
$('export-dialog').addEventListener('close', () => { $('export-links').replaceChildren(); $('download-zip').removeAttribute('href'); });
$('create-dialog').addEventListener('close', () => { $('create-form').elements.password.value = ''; });
bindForm('login-form', async data => {
  setText('login-error', '');
  try { const session = await api('login', Object.fromEntries(data)); $('login-form').reset(); showApp(session); await refresh(); }
  catch (err) { setText('login-error', err.message); }
});
bindForm('create-form', async data => {
  const name = data.get('name'), days = Number(data.get('days'));
  const params = createMode === 'ssh' ? {username: name, days, password: data.get('password'), max_sessions: Number(data.get('sessions')), quota_gb: data.get('quota')} : {name, days, protocols: ['vless', 'vmess', 'trojan'].filter(p => data.has(p))};
  await command(createMode === 'ssh' ? 'create_user' : 'xray_create', params, 'Account created'); $('create-dialog').close();
  if (createMode === 'xray') { view('xray'); await exportProfile(name); }
});
bindForm('renew-form', async data => {
  await command(renewTarget.type === 'ssh' ? 'renew_user' : 'xray_update', renewTarget.type === 'ssh' ? {username: renewTarget.name, days: Number(data.get('days'))} : {name: renewTarget.name, action: 'renew', days: Number(data.get('days'))}, 'Validity extended'); $('renew-dialog').close();
});
bindForm('domain-form', async data => {
  const domain = data.get('domain').trim();
  if (await confirmAction(`Set the public domain to ${domain}? If it changes, reopen the dashboard at https://${domain}/panel/ after issuing SSL.`)) await command('set_domain', {domain}, 'Domain saved');
});
bindForm('dns-form', async data => { await command('dns_set', {servers: data.get('servers').split(/\r?\n/).map(s => s.trim()).filter(Boolean), query_strategy: data.get('strategy')}, 'Resolver settings applied'); });
$('refresh').addEventListener('click', () => busy($('refresh'), refresh));
$('logout').addEventListener('click', () => busy($('logout'), async () => { await api('logout', {}); showLogin(); }));
$('toggle-xray').addEventListener('click', () => busy($('toggle-xray'), async () => {
  const enabled = !state.network.enabled;
  if (await confirmAction(enabled ? 'Enable Xray with VLESS, VMess and Trojan over TLS?' : 'Disable Xray? Existing Xray connections will disconnect.')) await command('xray_configure', {enabled}, enabled ? 'Xray enabled' : 'Xray disabled');
}));
$('lookup-dns').addEventListener('click', () => busy($('lookup-dns'), async () => {
  const result = await api('command', {command: 'dns_lookup', params: {domain: $('domain-input').value.trim()}});
  setText('dns-result', JSON.stringify(result.records, null, 2)); $('dns-result').hidden = false;
}));
$('issue-cert').addEventListener('click', () => busy($('issue-cert'), async () => {
  if (await confirmAction('Issue or renew SSL for the saved domain? This can take a few minutes. Ensure its A/AAAA records point to this VPS and port 80 is reachable.')) {
    notify('Certificate request is running…'); await command('issue_cert', {}, 'TLS certificate installed');
  }
}));
$('run-diagnostics').addEventListener('click', () => busy($('run-diagnostics'), async () => {
  const report = await api('diagnostics'), list = $('diagnostic-list'); list.replaceChildren();
  setText('diagnostic-summary', `${report.passed}/${report.total} passed`);
  report.checks.forEach(check => {
    const row = element('div', 'diagnostic-row'), detail = element('div'); detail.append(element('strong', '', check.name), element('p', 'mono', check.detail || (check.ok ? 'Check passed' : 'No details')));
    if (check.hint) detail.append(element('p', 'hint', check.hint)); row.append(pill(check.ok ? 'PASS' : 'CHECK', check.ok ? 'good' : 'warn'), detail); list.append(row);
  });
}));
setInterval(() => { if (csrf && document.visibilityState === 'visible' && !document.querySelector('dialog[open]')) refresh().catch(() => {}); }, 30000);
(async () => {
  try { const session = await api('session'); showApp(session); await refresh(); }
  catch (_) { showLogin(); }
})();
