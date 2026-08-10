'use strict';

let csrf = '';
let users = [];
let activeCdn = 'direct';

const q = selector => document.querySelector(selector);
const loginView = q('#login-view');
const appView = q('#app-view');
const toast = q('#toast');

function escapeHtml(value) {
  const node = document.createElement('div');
  node.textContent = String(value);
  return node.innerHTML;
}

function notify(message, bad = false) {
  toast.textContent = message;
  toast.className = `toast ${bad ? 'error' : ''}`;
  setTimeout(() => toast.classList.add('hidden'), 4200);
}

async function api(path, options = {}) {
  const headers = {'Content-Type': 'application/json', ...(options.headers || {})};
  if (csrf && options.method && options.method !== 'GET') headers['X-CSRF-Token'] = csrf;
  const response = await fetch(path, {credentials: 'same-origin', ...options, headers});
  const type = response.headers.get('content-type') || '';
  const data = type.includes('json') ? await response.json() : null;
  if (!response.ok) throw new Error(data?.error || `Request failed (${response.status})`);
  return data;
}

async function session() {
  try {
    const data = await api('api/session');
    csrf = data.csrf;
    loginView.classList.add('hidden');
    appView.classList.remove('hidden');
    q('#logout').classList.remove('hidden');
    await refreshAll();
  } catch {
    loginView.classList.remove('hidden');
    appView.classList.add('hidden');
  }
}

q('#login-form').addEventListener('submit', async event => {
  event.preventDefault();
  q('#login-error').textContent = '';
  const form = new FormData(event.currentTarget);
  try {
    const data = await api('api/login', {method: 'POST', body: JSON.stringify(Object.fromEntries(form))});
    csrf = data.csrf;
    await session();
  } catch (error) {
    q('#login-error').textContent = error.message;
  }
});

q('#logout').addEventListener('click', async () => {
  try { await api('api/logout', {method: 'POST', body: '{}'}); } catch {}
  location.reload();
});

async function refreshAll() {
  await loadUsers();
  await Promise.all([loadStatus(), loadCdn(), loadDnstt()]);
}

async function loadStatus() {
  try {
    const data = await api('api/status');
    const required = data.required_services || Object.keys(data.services || {});
    const active = required.filter(name => data.services?.[name] === 'active').length;
    const total = required.length;
    q('#health-pill').textContent = `${active}/${total} required services`;
    q('#health-pill').className = `pill ${active === total ? 'ok' : 'bad'}`;
    q('#stats').innerHTML = `
      <div class="stat"><strong>${users.length}</strong><span>Managed users</span></div>
      <div class="stat"><strong>${active}/${total}</strong><span>Required services active</span></div>
      <div class="stat"><strong>${escapeHtml(data.domain || 'Not set')}</strong><span>Origin domain</span></div>
      <div class="stat"><strong>${escapeHtml(data.cdn?.active || 'direct')}</strong><span>Active route</span></div>`;
  } catch {
    q('#health-pill').textContent = 'Service error';
    q('#health-pill').className = 'pill bad';
  }
}

function formatBytes(value) {
  const amount = Number(value || 0);
  if (amount < 1e6) return `${(amount / 1e3).toFixed(1)} KB`;
  if (amount < 1e9) return `${(amount / 1e6).toFixed(1)} MB`;
  return `${(amount / 1e9).toFixed(2)} GB`;
}

async function loadUsers() {
  const data = await api('api/users');
  users = data.users || [];
  const body = q('#users-body');
  body.innerHTML = '';
  for (const user of users) {
    const row = document.createElement('tr');
    const protocols = Object.entries(user.protocols || {})
      .map(([name, value]) => `<span class="proto ${value.enabled ? 'on' : ''}">${escapeHtml(name)}</span>`)
      .join('');
    const usage = user.usage || {};
    const state = usage.expired ? 'Expired' : usage.quota_exceeded ? 'Limit reached' : user.exists ? 'Active' : 'System user missing';
    row.innerHTML = `
      <td><strong>${escapeHtml(user.username)}</strong><br><small>${escapeHtml(user.max_sessions)} sessions</small></td>
      <td>${protocols || '—'}</td>
      <td>${escapeHtml(user.expiry)}</td>
      <td>${formatBytes(usage.used_bytes)} / ${usage.limit_bytes == null ? 'Unlimited' : formatBytes(usage.limit_bytes)}</td>
      <td>${escapeHtml(state)}</td>
      <td><div class="actions">
        <button class="button tiny" data-action="renew">Renew</button>
        <button class="button tiny" data-action="limits">Limits</button>
        <button class="button tiny" data-action="protocols">Protocols</button>
        <button class="button tiny" data-action="reset">Reset data</button>
        <button class="button tiny" data-action="files">Files</button>
        <button class="button tiny" data-action="dnstt">DNSTT file</button>
        <button class="button tiny danger" data-action="delete">Delete</button>
      </div></td>`;
    row.querySelectorAll('button').forEach(button => {
      button.addEventListener('click', () => userAction(user, button.dataset.action));
    });
    body.appendChild(row);
  }
  q('#export-user').innerHTML = users.map(user => `<option>${escapeHtml(user.username)}</option>`).join('');
}

async function userAction(user, action) {
  const username = user.username;
  try {
    if (action === 'delete') {
      if (!confirm(`Delete ${username} and all generated files?`)) return;
      await api(`api/users/${encodeURIComponent(username)}`, {method: 'DELETE'});
    } else if (action === 'renew') {
      const days = prompt('Days to add', '30');
      if (!days) return;
      await api(`api/users/${encodeURIComponent(username)}/renew`, {method: 'POST', body: JSON.stringify({days})});
    } else if (action === 'limits') {
      const quota = prompt('Xray data limit in GB, or Unlimited', user.quota_gb == null ? 'Unlimited' : user.quota_gb);
      if (quota === null) return;
      const maxSessions = prompt('Concurrent SSH session limit (1-20)', user.max_sessions);
      if (maxSessions === null) return;
      await api(`api/users/${encodeURIComponent(username)}/quota`, {method: 'POST', body: JSON.stringify({quota_gb: quota})});
      await api(`api/users/${encodeURIComponent(username)}/sessions`, {method: 'POST', body: JSON.stringify({max_sessions: maxSessions})});
    } else if (action === 'protocols') {
      const operation = (prompt('Operation: enable, disable, or rotate', 'enable') || '').trim().toLowerCase();
      if (!['enable', 'disable', 'rotate'].includes(operation)) return;
      const protocol = prompt(operation === 'enable' ? 'Protocol(s), comma-separated' : 'Protocol', 'vless');
      if (!protocol) return;
      const payload = operation === 'enable' ? {protocols: protocol} : {protocol};
      await api(`api/users/${encodeURIComponent(username)}/protocols/${operation}`, {method: 'POST', body: JSON.stringify(payload)});
    } else if (action === 'reset') {
      if (!confirm(`Reset Xray data usage for ${username}?`)) return;
      await api(`api/users/${encodeURIComponent(username)}/usage/reset`, {method: 'POST', body: '{}'});
    } else if (action === 'dnstt') {
      await api(`api/users/${encodeURIComponent(username)}/dnstt-export`, {method: 'POST', body: '{}'});
      q('#export-user').value = username;
      await loadFiles();
    } else {
      q('#export-user').value = username;
      await loadFiles();
    }
    notify(`${username}: ${action} completed`);
    await refreshAll();
  } catch (error) {
    notify(error.message, true);
  }
}

q('#create-user-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const data = Object.fromEntries(form);
  data.protocols = form.getAll('protocols');
  try {
    await api('api/users', {method: 'POST', body: JSON.stringify(data)});
    notify('Account created and Xray config synchronized');
    event.currentTarget.reset();
    await refreshAll();
  } catch (error) {
    notify(error.message, true);
  }
});

q('#generate-origin-secret').addEventListener('click', () => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  q('#origin-secret').value = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
});

q('#cdn-form').addEventListener('submit', async event => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget));
  try {
    const result = await api('api/cdn', {method: 'POST', body: JSON.stringify(data)});
    notify(`${data.provider} configured`);
    await refreshAll();
    q('#cdn-result').textContent = JSON.stringify(result.profile, null, 2);
  } catch (error) {
    notify(error.message, true);
  }
});

async function loadCdn() {
  try {
    const data = await api('api/cdn');
    activeCdn = data.cdn?.active || 'direct';
    const profile = data.cdn?.profiles?.[activeCdn];
    if (profile) q('#cdn-result').textContent = JSON.stringify(profile, null, 2);
  } catch {}
}

q('#disable-cdn').addEventListener('click', async () => {
  if (activeCdn === 'direct') return notify('No CDN profile is active', true);
  if (!confirm(`Disable ${activeCdn}?`)) return;
  try {
    await api(`api/cdn/${encodeURIComponent(activeCdn)}`, {method: 'DELETE'});
    q('#cdn-result').textContent = '';
    notify(`${activeCdn} disabled`);
    await refreshAll();
  } catch (error) {
    notify(error.message, true);
  }
});

q('#dnstt-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const data = Object.fromEntries(form);
  data.rotate_keys = form.has('rotate_keys');
  try {
    const result = await api('api/dnstt', {method: 'POST', body: JSON.stringify(data)});
    q('#dnstt-result').textContent = JSON.stringify(result, null, 2);
    notify('DNSTT configured; add the displayed DNS records');
    await refreshAll();
  } catch (error) {
    notify(error.message, true);
  }
});

async function loadDnstt() {
  try {
    const data = await api('api/dnstt');
    if (data.dnstt?.zone) q('#dnstt-result').textContent = JSON.stringify(data, null, 2);
  } catch {}
}

q('#disable-dnstt').addEventListener('click', async () => {
  if (!confirm('Disable DNSTT service?')) return;
  try {
    await api('api/dnstt', {method: 'DELETE'});
    q('#dnstt-result').textContent = '';
    notify('DNSTT disabled');
    await refreshAll();
  } catch (error) {
    notify(error.message, true);
  }
});

q('#refresh').addEventListener('click', refreshAll);
q('#generate-files').addEventListener('click', async () => {
  const username = q('#export-user').value;
  if (!username) return;
  try {
    await api(`api/users/${encodeURIComponent(username)}/exports`, {
      method: 'POST',
      body: JSON.stringify({protocol: q('#export-protocol').value, provider: q('#export-provider').value}),
    });
    notify('Import files and payload generated');
    await loadFiles();
  } catch (error) {
    notify(error.message, true);
  }
});
q('#list-files').addEventListener('click', loadFiles);
q('#export-user').addEventListener('change', loadFiles);

async function loadFiles() {
  const username = q('#export-user').value;
  const area = q('#files');
  if (!username) {
    area.innerHTML = '';
    return;
  }
  try {
    const data = await api(`api/exports?username=${encodeURIComponent(username)}`);
    area.innerHTML = '';
    for (const name of data.files || []) {
      const item = document.createElement('div');
      item.className = 'file';
      item.innerHTML = `<span class="file-name">${escapeHtml(name)}</span><span class="actions"><a class="button tiny" href="api/exports/${encodeURIComponent(username)}/${encodeURIComponent(name)}">Download</a><button class="button tiny danger">Delete</button></span>`;
      item.querySelector('button').addEventListener('click', async () => {
        if (!confirm(`Delete ${name}?`)) return;
        try {
          await api(`api/exports/${encodeURIComponent(username)}/${encodeURIComponent(name)}`, {method: 'DELETE'});
          await loadFiles();
        } catch (error) {
          notify(error.message, true);
        }
      });
      area.appendChild(item);
    }
  } catch (error) {
    notify(error.message, true);
  }
}

session();
