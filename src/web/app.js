'use strict';
const $ = (id) => document.getElementById(id);
const API = '/panel/api/';
let csrf = '', state = null, createMode = 'xray', renewTarget = null, confirmResolve = null, refreshing = false;
let noticeTimer;
let currentExport = null;
let currentSubscription = null;
let trialMode = false, usageTarget = null;

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
  try { await refresh(); }
  catch (_) { notify('Change saved, but the dashboard could not refresh. Refresh before making another change.', true); }
  return result;
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
  setText('breadcrumb', {overview: 'Overview', ssh: 'SSH accounts', xray: 'Xray profiles', network: 'DNS & SSL', cloudfront: 'CloudFront', diagnostics: 'Diagnostics', recovery: 'Backup & recovery', traffic: 'Traffic & connections', transports: 'UDP & SlowDNS', system: 'System toolbox', maintenance: 'Telegram & maintenance'}[name]);
}
const size = (value, unit = 'GB') => {
  if (!Number.isFinite(value)) return '—';
  const base = unit === 'GiB' ? 1024 : 1000;
  if (value >= base ** 3) return `${(value / base ** 3).toFixed(3)} ${unit}`;
  if (value >= base ** 2) return `${(value / base ** 2).toFixed(3)} ${base === 1024 ? 'MiB' : 'MB'}`;
  return `${Math.trunc(value).toLocaleString()} bytes`;
};
const quotaLabel = (row) => row.quota_gb == null ? 'Unlimited' : `${row.quota_gb} ${row.quota_unit || 'GiB'}`;
const profileStatus = (row) => row.enabled === false ? 'Locked' : row.meter_unavailable || row.ip_monitoring_failed ? 'Monitor unavailable' : row.quota_exhausted ? 'Quota reached' : row.ip_blocked_until && Date.parse(row.ip_blocked_until) > Date.now() ? 'IP limit · cooldown' : row.active ? 'Active' : 'Expired';
function byteCell(row, field) {
  const node = element('td', 'mono', size(row[field] || 0, row.quota_unit || 'GiB') + (field === 'used_bytes' ? ` / ${quotaLabel(row)}` : ''));
  node.title = `${row.exact_bytes?.[field] ?? row[field] ?? 0} bytes`;
  node.append(element('div', 'small muted', node.title));
  return node;
}
const percent = (used, total) => total > 0 ? Math.max(0, Math.min(100, used / total * 100)) : 0;
function tags(protocols) { const box = element('div'); protocols.forEach(p => box.append(element('span', `tag ${p}`, p.toUpperCase()))); return box; }
function emptyRow(body, columns, text) {
  const row = element('tr'), cell = element('td', 'empty', text); cell.colSpan = columns; row.append(cell); body.append(row);
}
function profileRows(id, rows, controls) {
  const body = $(id); body.replaceChildren();
  if (!rows.length) { emptyRow(body, controls ? 6 : 5, 'No matching profiles. Create an account or change your filter.'); return; }
  rows.forEach(row => {
    const tr = element('tr'); tr.append(element('td', 'mono', row.name));
    const protocols = element('td'); protocols.append(tags(row.protocols)); if (row.trial) protocols.append(pill('24H TRIAL', 'warn')); tr.append(protocols, element('td', 'mono muted', row.expires_at ? new Date(row.expires_at).toLocaleString() : row.expiry));
    const status = element('td'); status.append(pill(profileStatus(row), row.active ? 'good' : 'warn')); tr.append(status);
    if (controls) { const usage = element('td', 'usage-cell'); usage.append(element('strong', 'mono', `${size(row.used_bytes || 0, row.quota_unit || 'GiB')} / ${quotaLabel(row)}`)); if (row.quota_gb) { const meter = element('meter'); meter.min = 0; meter.max = 100; meter.value = percent(row.used_bytes || 0, row.quota_bytes ?? row.quota_gb * 1024 ** 3); meter.setAttribute('aria-label', `${row.name} quota utilization`); usage.append(meter); } usage.append(element('div', 'small muted', `${row.exact_bytes?.used_bytes ?? row.used_bytes ?? 0} bytes · IP cap: ${row.max_ips || 'Unlimited'}`)); tr.append(usage); }
    const actions = element('td'), group = element('div', 'row-actions');
    if (row.active) group.append(button('Export ↗', () => exportProfile(row.name)));
    if (controls) {
      group.append(button('Subscription', () => openSubscription(row)));
      group.append(button('Limits', () => openUsage('xray', row)), button('Renew', () => openRenew('xray', row.name)), button(row.enabled === false ? 'Unlock' : 'Lock', () => command('xray_update', {name: row.name, action: 'toggle', enabled: row.enabled === false}, 'Profile updated')),
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
  const labels = {nginx: 'Nginx gateway', dropbear: 'Dropbear SSH', 'abdulbasit-ws': 'SSH upgrade proxy', 'abdulbasit-session-enforcer': 'Session enforcer', 'abdulbasit-bot': 'Telegram bot', 'abdulbasit-paneld': 'Panel daemon', 'abdulbasit-web': 'Web dashboard', 'abdulbasit-xray': 'Xray core', 'abdulbasit-dnstt': 'SlowDNS tunnel'};
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
    detail.append(element('strong', '', endpoint.protocol.toUpperCase()), element('p', '', `${endpoint.transport.toUpperCase()}  /  ${endpoint.path}`));
    row.append(element('span', 'protocol-symbol', ['V', 'M', 'T', 'X'][i] || 'X'), detail, pill(s.network.enabled && s.services['abdulbasit-xray'] === 'active' ? 'Ready' : 'Offline', s.network.enabled && s.services['abdulbasit-xray'] === 'active' ? 'good' : '')); protocols.append(row);
  }
  profileRows('overview-profiles', s.accounts.slice(0, 4), false); renderProfiles(); renderTraffic();
  setText('ssh-note', 'SSH byte metering is unavailable. Finite GB quotas are rejected. IP/session checks target 5 seconds plus processing time. Unknown sources cannot use an IP-limited account.' + (s.ssh_attribution?.journal_available === false ? ' Authentication journal unavailable: older root Dropbear sessions may be unattributable.' : '') + (s.ssh_attribution?.unattributed_root_processes ? ` ${s.ssh_attribution.unattributed_root_processes} root process(es) unattributed; some may still be authenticating.` : ''));
  const users = $('ssh-users'); users.replaceChildren();
  if (!s.users.length) emptyRow(users, 5, 'No SSH accounts yet. Create an account to grant access.');
  s.users.forEach(user => {
    const tr = element('tr'); tr.append(element('td', 'mono', user.username), element('td', 'mono muted', user.expiry), element('td', '', `${(s.sessions.find(x => x.username === user.username) || {}).count || 0} / ${user.max_sessions}`), element('td', 'muted', `GB unavailable · IP cap: ${user.max_ips || 'Unlimited'}`));
    const td = element('td'), actions = element('div', 'row-actions'); actions.append(button('Limits', () => openUsage('ssh', user)), button(user.enabled === false ? 'Unlock' : 'Lock', () => command('set_user_lock', {username: user.username, enabled: user.enabled === false}, 'SSH account updated')), button('Renew', () => openRenew('ssh', user.username)), button('Delete', async () => { if (await confirmAction(`Delete SSH account “${user.username}”? Its active sessions will be disconnected.`)) await command('delete_user', {username: user.username}, 'Account deleted'); }, 'delete')); td.append(actions); tr.append(td); users.append(tr);
  });
  setText('xray-summary', `${s.xray_installed ? 'Installed' : 'Core not installed · run install.sh --with-xray'} · ${s.network.enabled ? 'Enabled' : 'Disabled'} · TLS on port 443`);
  $('toggle-xray').textContent = s.network.enabled ? 'Disable Xray' : 'Enable Xray';
  $('toggle-xray').classList.toggle('primary', !s.network.enabled); $('toggle-xray').disabled = !s.xray_installed || $('toggle-xray').hasAttribute('aria-busy');
  $('toggle-xhttp').textContent = s.network.xhttp_enabled ? 'Disable XHTTP' : 'Enable XHTTP';
  $('toggle-xhttp').disabled = !s.network.enabled || $('toggle-xhttp').hasAttribute('aria-busy');
  setText('udp-state', s.network.udp_enabled === false ? 'UDP blocked' : 'UDP forwarding allowed');
  $('toggle-udp').disabled = !s.network.enabled;
  const cf = s.cloudfront || {};
  setText('cf-state', cf.stage === 'attached' ? 'Endpoint attached' : cf.stage === 'prepared' ? 'Origin prepared' : 'Disabled');
  setText('cf-check-note', cf.last_check ? `${cf.last_check.ok ? 'Handshake checks passed' : 'Check needs attention'} · ${new Date(cf.last_check.checked_at).toLocaleString()}. Login and speed not tested.` : 'No endpoint check has run.');
  if (!$('cloudfront-form').contains(document.activeElement)) { $('cf-endpoint').value = cf.endpoint || ''; $('cf-price').value = cf.price_class || 'PriceClass_All'; }
  $('cf-check').disabled = !cf.enabled || !cf.endpoint || $('cf-check').hasAttribute('aria-busy');
  $('cf-disable').disabled = !cf.enabled || $('cf-disable').hasAttribute('aria-busy');
  $('cf-setup').hidden = !cf.enabled; $('cf-ssh').value = cf.ssh_url || '';
  $('cf-paths').replaceChildren();
  for (const [name, path] of Object.entries(cf.paths || {})) { const row = element('div', 'service-row'); row.append(element('strong', '', name.toUpperCase()), element('code', 'mono muted', path)); $('cf-paths').append(row); }
  const slow = s.slowdns || {};
  setText('slowdns-state', !slow.installed ? 'Core not installed' : slow.enabled ? 'Enabled' : 'Disabled');
  if (!$('slowdns-form').contains(document.activeElement)) { $('slowdns-zone').value = slow.zone || ''; $('slowdns-ns').value = slow.ns_host || ''; $('slowdns-port').value = slow.port || 53; }
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
function openCreate(mode, trial = false) {
  trialMode = trial;
  createMode = mode; $('create-form').reset(); $('ssh-fields').hidden = mode !== 'ssh'; $('protocol-fields').hidden = mode === 'ssh';
  $('create-form').elements.password.required = mode === 'ssh';
  $('xray-fields').hidden = mode === 'ssh'; $('trial-note').hidden = !trial;
  $('create-form').elements.days.disabled = trial;
  if (trial) { $('create-form').elements.days.value = 1; $('create-form').elements.xray_quota.value = '1'; }
  setText('create-title', mode === 'ssh' ? 'New SSH account' : trial ? '24-hour Xray trial' : 'New VIP profile'); $('create-dialog').showModal();
}
function openRenew(type, name) { renewTarget = {type, name}; setText('renew-name', name); $('renew-form').reset(); $('renew-dialog').showModal(); }
function confirmAction(message) {
  setText('confirm-message', message); $('confirm-dialog').showModal();
  return new Promise(resolve => { confirmResolve = resolve; });
}
async function exportProfile(name, route = 'direct') {
  const result = await api(`export?name=${encodeURIComponent(name)}&route=${encodeURIComponent(route)}`);
  $('export-route').value = route;
  currentExport = result;
  const warnings = result.readiness?.warnings || [];
  setText('export-warning', warnings.join(' ')); $('export-warning').hidden = !warnings.length;
  setText('export-title', name); const container = $('export-links'); container.replaceChildren();
  Object.entries(result.links).forEach(([protocol, link]) => {
    const item = element('div', 'export-item'), input = element('textarea'); input.value = link; input.readOnly = true; input.setAttribute('aria-label', `${protocol} import link`);
    item.append(element('strong', '', protocol.toUpperCase()), input, button(`Copy ${protocol.toUpperCase()} link`, async () => {
      try { await navigator.clipboard.writeText(link); notify('Import link copied'); }
      catch (_) { input.select(); notify('Select and copy the highlighted link manually'); }
    }, 'btn small'), button('↓ Xray JSON', () => {
      const blob = new Blob([result.files[`${name}-${protocol}.json`]], {type: 'application/json'}), url = URL.createObjectURL(blob);
      const a = element('a'); a.href = url; a.download = `${name}-${protocol}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
    }, 'btn small'));
    const textFile = element('a', 'btn small', '↓ Link TXT');
    textFile.href = API + `export?name=${encodeURIComponent(name)}&route=${encodeURIComponent(route)}&format=link&protocol=${encodeURIComponent(protocol)}`;
    item.append(textFile, button('QR code', () => showQR(link), 'btn small')); container.append(item);
  });
  for (const [suffix, label] of [['singbox.json', 'sing-box JSON'], ['clash.yaml', 'Clash.Meta YAML']]) {
    const content = result.files[`${name}-${suffix}`];
    if (content) container.append(button(`↓ ${label}`, () => downloadText(content, `${name}-${suffix}`), 'btn small'));
  }
  $('download-zip').href = API + `export?name=${encodeURIComponent(name)}&route=${encodeURIComponent(route)}&format=zip`; if (!$('export-dialog').open) $('export-dialog').showModal();
}
function downloadText(content, filename) {
  const url = URL.createObjectURL(new Blob([content], {type: 'text/plain;charset=utf-8'}));
  const anchor = element('a'); anchor.href = url; anchor.download = filename; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
}
function showQR(text) {
  const code = qrcode(0, 'M'); code.addData(text); code.make();
  $('qr-image').src = code.createDataURL(4, 16); $('qr-dialog').showModal();
}
function openSubscription(row) {
  currentSubscription = {name: row.name, enabled: row.subscription_enabled};
  setText('subscription-title', `${row.name} · subscription`);
  setText('subscription-note', row.subscription_enabled ? 'A URL already exists. Its secret cannot be retrieved; rotate only if you need a replacement.' : 'No subscription URL is enabled for this profile.');
  $('subscription-route').value = 'direct';
  $('subscription-url').value = ''; $('subscription-formats').replaceChildren();
  $('subscription-revoke').disabled = !row.subscription_enabled;
  $('subscription-copy').disabled = true; $('subscription-qr').disabled = true;
  $('subscription-dialog').showModal();
}
function renderSubscription() {
  const result = currentSubscription?.result;
  if (!result) return;
  const extra = $('subscription-route').value === 'cloudfront' ? '&route=cloudfront' : '';
  $('subscription-url').value = extra ? result.cloudfront_url : result.url;
  const formats = $('subscription-formats'); formats.replaceChildren();
  Object.entries(result.formats).forEach(([format, url]) => { const link = element('a', 'btn small', format); link.href = url + extra; link.target = '_blank'; link.rel = 'noreferrer'; formats.append(link); });
}
function bindForm(id, handler) {
  $(id).addEventListener('submit', event => { event.preventDefault(); busy($(id).querySelector('[type="submit"]'), () => handler(new FormData($(id)))); });
}
document.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', () => view(btn.dataset.view)));
document.querySelectorAll('[data-new]').forEach(btn => btn.addEventListener('click', () => openCreate(btn.dataset.new)));
document.querySelectorAll('[data-trial]').forEach(btn => btn.addEventListener('click', () => openCreate('xray', true)));
document.querySelectorAll('[data-close]').forEach(btn => btn.addEventListener('click', () => $(btn.dataset.close).close()));
$('confirm-dialog').addEventListener('close', () => { if (confirmResolve) { confirmResolve(false); confirmResolve = null; } });
$('confirm-form').addEventListener('submit', event => { event.preventDefault(); const resolve = confirmResolve; confirmResolve = null; $('confirm-dialog').close(); if (resolve) resolve(true); });
$('export-dialog').addEventListener('close', () => { currentExport = null; $('export-links').replaceChildren(); $('download-zip').removeAttribute('href'); });
$('qr-dialog').addEventListener('close', () => $('qr-image').removeAttribute('src'));
$('subscription-dialog').addEventListener('close', () => { currentSubscription = null; $('subscription-url').value = ''; $('subscription-formats').replaceChildren(); });
$('subscription-rotate').addEventListener('click', () => busy($('subscription-rotate'), async () => {
  if (!currentSubscription) return;
  const name = currentSubscription.name;
  if (!await confirmAction('Create a replacement subscription URL? The old URL will stop updating. Proxy credentials already downloaded stay unchanged.')) return;
  const result = await command('subscription_rotate', {name}, 'Private subscription URL created');
  if (!currentSubscription) return;
  currentSubscription = {name, enabled: true, result}; renderSubscription();
  $('subscription-revoke').disabled = false; $('subscription-copy').disabled = false; $('subscription-qr').disabled = false;
  setText('subscription-note', 'Save this URL now. Only its hash is stored; the full URL is shown once.');

}));
$('subscription-revoke').addEventListener('click', () => busy($('subscription-revoke'), async () => {
  if (!currentSubscription || !await confirmAction('Revoke this subscription URL? Previously imported proxy credentials are unchanged.')) return;
  await command('subscription_revoke', {name: currentSubscription.name}, 'Subscription URL revoked'); $('subscription-dialog').close();
}));
$('subscription-copy').addEventListener('click', () => busy($('subscription-copy'), async () => {
  try { await navigator.clipboard.writeText($('subscription-url').value); notify('Private URL copied'); }
  catch (_) { $('subscription-url').select(); notify('Copy the selected URL manually'); }
}));
$('subscription-qr').addEventListener('click', () => { if ($('subscription-url').value) showQR($('subscription-url').value); });
$('copy-all-links').addEventListener('click', () => busy($('copy-all-links'), async () => {
  if (!currentExport) return;
  try { await navigator.clipboard.writeText(Object.values(currentExport.links).join('\n')); notify('All import links copied'); }
  catch (_) { notify('Clipboard is unavailable. Select and copy each visible link manually.', true); }
}));
$('create-dialog').addEventListener('close', () => { $('create-form').elements.password.value = ''; });
bindForm('login-form', async data => {
  setText('login-error', '');
  try { const session = await api('login', Object.fromEntries(data)); $('login-form').reset(); showApp(session); await refresh(); }
  catch (err) { setText('login-error', err.message); }
});
bindForm('create-form', async data => {
  const name = data.get('name'), days = trialMode ? 1 : Number(data.get('days'));
  const params = createMode === 'ssh' ? {username: name, days, password: data.get('password'), max_sessions: Number(data.get('sessions')), quota_gb: 'Unlimited', max_ips: Number(data.get('ips'))} : {name, days, trial: trialMode, quota_gb: data.get('xray_quota'), max_ips: Number(data.get('ips')), protocols: ['vless', 'vmess', 'trojan'].filter(p => data.has(p))};
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
$('toggle-xhttp').addEventListener('click', () => busy($('toggle-xhttp'), async () => {
  const enabled = !state.network.xhttp_enabled;
  if (await confirmAction(`${enabled ? 'Enable' : 'Disable'} the additional VLESS XHTTP endpoint? The core will restart.`)) await command('xray_configure', {enabled: true, xhttp_enabled: enabled}, 'XHTTP transport updated');
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
function renderProfiles() {
  if (!state) return;
  const search = $('profile-search').value.trim().toLowerCase(), filter = $('profile-filter').value;
  profileRows('xray-accounts', state.accounts.filter(row => row.name.includes(search) && (filter === 'all' || filter === 'active' && row.active || filter === 'locked' && row.enabled === false || filter === 'trial' && row.trial || filter === 'quota' && row.quota_exhausted)), true);
}
function renderTraffic() {
  const rows = state.accounts, up = rows.reduce((n, r) => n + (r.upload_bytes || 0), 0), down = rows.reduce((n, r) => n + (r.download_bytes || 0), 0);
  setText('traffic-total', size(up + down)); setText('traffic-up', size(up)); setText('traffic-down', size(down));
  setText('traffic-sampled', state.traffic?.sampled_at ? `Sampled ${new Date(state.traffic.sampled_at).toLocaleString()}` : 'No successful core sample yet');
  const body = $('traffic-profiles'); body.replaceChildren();
  if (!rows.length) emptyRow(body, 5, 'Create an Xray profile to measure its usage.');
  rows.forEach(row => { const tr = element('tr'); tr.append(element('td', 'mono', row.name), byteCell(row, 'upload_bytes'), byteCell(row, 'download_bytes'), Object.assign(byteCell(row, 'used_bytes'), {title: `${row.exact_bytes?.used_bytes ?? row.used_bytes ?? 0} bytes / ${quotaLabel(row)}`}), element('td', '', profileStatus(row))); body.append(tr); });
}
function showResult(title, result) {
  setText('result-title', title); setText('operation-result', typeof result === 'string' ? result : JSON.stringify(result, null, 2)); $('result-dialog').showModal();
}
async function operation(name, params = {}) { return api('command', {command: name, params}); }
function openUsage(type, row) {
  usageTarget = {type, name: type === 'ssh' ? row.username : row.name};
  setText('usage-title', usageTarget.name + ' · limits');
  setText('usage-scope', type === 'ssh' ? 'SSH GB metering is unavailable. IP/session checks run every 5 seconds. Unknown sources (including SlowDNS) are disconnected when an IP cap is set.' : '5-second target checks plus API/restart time; quotas can overshoot. Too many unique IPs suspend this profile for 30 seconds. Core changes reconnect active clients. 0 IPs = Unlimited.');
  $('usage-quota').value = row.quota_gb == null ? 'Unlimited' : row.quota_gb;
  $('usage-quota').disabled = type === 'ssh'; $('usage-unit').disabled = type === 'ssh';
  $('usage-unit').value = row.quota_unit || 'GiB'; $('usage-ips').value = row.max_ips || 0;
  $('usage-sessions-label').hidden = type !== 'ssh'; $('usage-sessions').value = row.max_sessions || 2;
  $('reset-usage').hidden = type === 'ssh'; $('usage-dialog').showModal();
}
$('profile-search').addEventListener('input', renderProfiles); $('profile-filter').addEventListener('change', renderProfiles);
bindForm('usage-form', async data => {
  const target = usageTarget;
  if (target.type === 'ssh') { await command('set_sessions', {username: target.name, max_sessions: Number(data.get('sessions')), max_ips: Number(data.get('ips'))}, 'SSH limits updated'); }
  else await command('xray_update', {name: target.name, action: 'limits', quota_gb: data.get('quota'), quota_unit: data.get('unit'), max_ips: Number(data.get('ips'))}, 'Limits updated');
  $('usage-dialog').close();
});
$('reset-usage').addEventListener('click', () => busy($('reset-usage'), async () => {
  if (usageTarget?.type === 'xray' && await confirmAction(`Reset measured traffic for ${usageTarget.name}? Its quota allowance starts again.`)) { await command('xray_update', {name: usageTarget.name, action: 'reset_usage'}, 'Measured usage reset'); $('usage-dialog').close(); }
}));
$('sample-traffic').addEventListener('click', () => busy($('sample-traffic'), async () => {
  const sample = await operation('traffic_sample'); await refresh();
  const live = await operation('live_connections');
  setText('traffic-note', sample.available ? (sample.note || 'Core sample updated. SSH usage is excluded.') : sample.reason);
  const auth = [...new Map((live.xray?.connections || []).map(row => [`${row.name || row.email}:${row.ip}`, row])).values()], peers = live.gateway_peers || [];
  setText('online-total', live.xray?.available ? String(new Set(auth.map(row => row.ip)).size) : 'Unavailable');
  for (const [id, rows, authenticated] of [['authenticated-ips', auth, true], ['gateway-ips', peers, false]]) {
    const box = $(id); box.replaceChildren();
    if (!rows.length) box.append(element('p', 'muted', authenticated ? live.xray?.available ? 'No active authenticated streams.' : live.xray?.note || 'Core API unavailable.' : 'No external TCP peers observed.'));
    rows.forEach(row => { const item = element('div', 'connection-item'); item.append(element('strong', 'mono', row.ip), element('span', 'small muted', authenticated ? `${row.name || row.email} · active stream` : `${row.transport} · :${row.port} · account unverified`)); box.append(item); });
  }
}));
for (const [id, name, title] of [['view-config', 'config_view', 'Managed configuration · credentials redacted'], ['doctor-inspect', 'doctor', 'Auto-doctor report'], ['memory-report', 'memory_report', 'Memory report']]) {
  $(id).addEventListener('click', () => busy($(id), async () => showResult(title, await operation(name))));
}
$('doctor-repair').addEventListener('click', () => busy($('doctor-repair'), async () => {
  if (await confirmAction('Restart failed managed services after validating Nginx? This can reconnect clients. DNS provider/firewall settings are not changed.')) showResult('Repair results', await operation('doctor', {repair: true}));
}));
$('restart-managed').addEventListener('click', () => busy($('restart-managed'), async () => {
  if (await confirmAction('Restart the managed gateway, Dropbear and enabled transports? Connected clients may disconnect.')) { showResult('Gateway restart', await operation('restart_managed')); await refresh(); }
}));
$('read-logs').addEventListener('click', () => busy($('read-logs'), async () => { const result = await operation('live_logs', {service: $('log-service').value, level: $('log-level').value}); showResult((result.service || $('log-service').value) + ' · journal', result.text || 'No matching journal entries.'); }));
$('packet-test').addEventListener('click', () => busy($('packet-test'), async () => { notify('Sending 15 ICMP probes…'); const result = await operation('packet_test', {target: $('packet-target').value}); showResult('Packet test · ' + result.target, result.text + '\n\n' + result.note); }));
$('load-banner').addEventListener('click', () => busy($('load-banner'), async () => { const result = await operation('banner_get'); $('banner-text').value = result.text; $('save-banner').disabled = false; }));
bindForm('banner-form', async data => { if (await confirmAction('Save this Dropbear banner and restart managed SSH?')) await command('banner_set', {text: data.get('text')}, 'SSH banner saved'); });
$('toggle-udp').addEventListener('click', () => busy($('toggle-udp'), async () => { if (await confirmAction('Change authenticated UDP forwarding policy and restart Xray?')) await command('xray_configure', {enabled: true, udp_enabled: state.network.udp_enabled === false}, 'UDP policy saved'); }));
bindForm('slowdns-form', async data => {
  if (await confirmAction('Enable the DNS tunnel on the selected UDP port? An official core, NS delegation and external firewall access are required.')) await command('slowdns_configure', {enabled: true, zone: data.get('zone'), ns_host: data.get('ns_host'), port: Number(data.get('port'))}, 'DNS tunnel enabled');
});
$('disable-slowdns').addEventListener('click', () => busy($('disable-slowdns'), async () => { if (await confirmAction('Disable the DNS tunnel and disconnect its clients?')) await command('slowdns_configure', {enabled: false}, 'DNS tunnel disabled'); }));
$('check-slowdns').addEventListener('click', () => busy($('check-slowdns'), async () => { const result = await operation('slowdns_check'); setText('slowdns-result', JSON.stringify(result, null, 2)); $('slowdns-result').hidden = false; }));
$('copy-result').addEventListener('click', () => busy($('copy-result'), async () => { try { await navigator.clipboard.writeText($('operation-result').textContent); notify('Result copied'); } catch (_) { notify('Select the visible result and copy manually.'); } }));
document.querySelectorAll('.command-snippet').forEach(box => { const code = box.querySelector('code'); box.append(button('Copy', async () => { try { await navigator.clipboard.writeText(code.textContent); notify('Command copied'); } catch (_) { notify('Select and copy the visible command.'); } }, 'btn small copy-command')); });
setInterval(() => { if (csrf && document.visibilityState === 'visible' && !document.querySelector('dialog[open]')) refresh().catch(() => {}); }, 30000);
(async () => {
  try { const session = await api('session'); showApp(session); await refresh(); }
  catch (_) { showLogin(); }
})();

$('export-route').addEventListener('change', async () => {
  const previous = currentExport;
  if (!previous) return;
  $('export-route').disabled = true;
  try { await exportProfile(previous.name, $('export-route').value); }
  catch (err) { $('export-route').value = previous.route || 'direct'; notify(err.message, true); }
  finally { $('export-route').disabled = false; }
});
$('subscription-route').addEventListener('change', renderSubscription);
bindForm('cloudfront-form', async data => { await command('cloudfront_configure', {enabled: true, endpoint: data.get('endpoint').trim(), price_class: data.get('price_class')}, 'CloudFront settings saved. Deploy the private AWS setup before checking the endpoint.'); });
$('cf-disable').addEventListener('click', () => busy($('cf-disable'), async () => { if (await confirmAction('Disable CloudFront origin routes? Existing CDN tunnels may disconnect. AWS resources and billing must be managed in your AWS account.')) await command('cloudfront_configure', {enabled: false}, 'CloudFront routes disabled'); }));
$('cf-check').addEventListener('click', () => busy($('cf-check'), async () => { notify('Checking TLS and four WebSocket routes…'); const result = await operation('cloudfront_check'); setText('cf-result', JSON.stringify(result, null, 2)); $('cf-result').hidden = false; await refresh(); }));
