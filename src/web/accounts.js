'use strict';
// Account-scoped, lazy IP detail pages. Existing administration views stay usable.
const expandedAccounts = new Map(), accountDetails = new Map(), accountLoads = new Map(), ipDrafts = new Map();
const accountKey = (kind, name) => kind + ':' + name;

function accountByteCell(row, field, available = true) {
  if (!available) return element('td', 'mono muted', 'Awaiting meter');
  const cell = byteCell(row, field);
  return cell;
}

async function fetchAccountDetails(kind, name, limit = 8) {
  const key = accountKey(kind, name);
  if (accountLoads.has(key)) return accountLoads.get(key);
  const task = operation('account_connections', {kind, name, limit}).then(result => {
    accountDetails.set(key, result);
  }).finally(() => { accountLoads.delete(key); renderAccountManagement(); });
  accountLoads.set(key, task);
  return task;
}

function accountDetail(kind, name) {
  const key = accountKey(kind, name), result = accountDetails.get(key);
  const box = element('div', 'account-detail');
  const heading = element('div', 'account-detail-heading');
  heading.append(element('div', '', 'Connected IPs and their usage'), button('Refresh IPs', () => fetchAccountDetails(kind, name, expandedAccounts.get(key)), 'btn small'));
  box.append(heading);
  if (!result) { box.append(element('p', 'muted', accountLoads.has(key) ? 'Loading authenticated IPs…' : 'IP details could not load. Use Refresh IPs.')); return box; }
  box.append(element('p', 'small muted', `${result.online_count} online · ${result.total} recorded · ${result.sampled_at ? 'Sampled ' + new Date(result.sampled_at).toLocaleTimeString() : 'Awaiting a meter sample'}`));
  if (!result.usage_available) box.append(element('p', 'meter-note', 'Per-IP byte metering is not active on this backend yet. Activate the metered runtime to collect measured usage.'));
  const scroll = element('div', 'table-scroll'), table = element('table', 'ip-table'), head = element('thead'), header = element('tr');
  ['SOURCE IP', 'UPLOAD', 'DOWNLOAD', 'TOTAL', 'ACCESS', 'PROTOCOL', 'ACTION'].forEach(t => header.append(element('th', '', t)));
  head.append(header); table.append(head); const body = element('tbody');
  if (!result.connections.length) emptyRow(body, 7, 'No authenticated IPs recorded for this account.');
  result.connections.forEach(ip => {
    const row = element('tr'), identity = element('td', 'mono');
    identity.append(element('strong', '', ip.ip === 'unknown' ? 'Unknown / unavailable source' : ip.ip), element('div', 'small muted', ip.online ? 'Connected now' : ip.last_seen ? 'Last seen ' + new Date(ip.last_seen).toLocaleString() : 'Offline / policy entry'));
    row.append(identity, accountByteCell(ip, 'upload_bytes', ip.usage_available), accountByteCell(ip, 'download_bytes', ip.usage_available), accountByteCell({...ip, quota_gb: null}, 'used_bytes', ip.usage_available));
    const access = element('td'); access.append(pill(ip.blocked ? 'Blocked' : 'Allowed', ip.blocked ? 'warn' : 'good'));
    const protocols = element('td'); protocols.append(tags(ip.protocols)); const action = element('td');
    if (ip.ip !== 'unknown') action.append(button(ip.blocked ? 'Allow' : 'Block', async () => {
      await command('account_ip_set', {kind, name, ip: ip.ip, blocked: !ip.blocked}, ip.blocked ? 'IP allowed for this account' : 'IP blocked for this account');
      await fetchAccountDetails(kind, name, expandedAccounts.get(key));
    }, ip.blocked ? 'btn small' : 'btn small danger'));
    row.append(access, protocols, action); body.append(row);
  });
  table.append(body); scroll.append(table); box.append(scroll);
  if (result.has_more && result.connections.length < 50) box.append(button(`Show more · ${result.total - result.offset - result.connections.length} remaining`, async () => {
    const count = Math.min(50, (expandedAccounts.get(key) || 8) + 8);
    expandedAccounts.set(key, count); await fetchAccountDetails(kind, name, count);
  }, 'btn full show-more'));
  // Page beyond 50 without silently truncating a large history.
  if (result.has_more && result.connections.length >= 50) box.append(button('Next 50 IPs', async () => {
    const next = await operation('account_connections', {kind, name, offset: result.offset + result.connections.length, limit: 50});
    accountDetails.set(key, next); renderAccountManagement();
  }, 'btn full'));
  if (result.offset) box.append(button('Back to first IPs', () => fetchAccountDetails(kind, name, 8), 'btn small'));
  const form = element('form', 'account-ip-form'), input = element('input'); input.placeholder = 'IPv4 or IPv6 address'; input.setAttribute('aria-label', `IP to block for ${name}`); input.value = ipDrafts.get(key) || '';
  input.addEventListener('input', () => ipDrafts.set(key, input.value));
  const submit = element('button', 'btn small', 'Block IP'); submit.type = 'submit';
  form.append(input, submit); form.addEventListener('submit', event => {
    event.preventDefault(); busy(submit, async () => {
      await command('account_ip_set', {kind, name, ip: input.value.trim(), blocked: true}, 'Account IP policy saved');
      ipDrafts.delete(key); input.blur(); await fetchAccountDetails(kind, name, expandedAccounts.get(key));
    });
  }); box.append(form, element('p', 'small muted', 'Block/Allow applies to this account only. IPs are network sources; shared Wi-Fi can use one IP.'));
  return box;
}

function renderAccountManagement() {
  if (!state || !$('account-management')) return;
  if ($('account-management').contains(document.activeElement) && document.activeElement.tagName === 'INPUT') return;
  const search = $('account-search').value.trim().toLowerCase(), filter = $('account-kind').value;
  const rows = [...state.users.map(row => ({...row, kind: 'ssh', name: row.username, protocols: ['ssh'], online_ips: (state.sessions.find(s => s.username === row.username) || {}).ips || []})),
    ...state.accounts.map(row => ({...row, kind: 'xray', usage_available: true}))];
  const selected = rows.filter(row => row.name.toLowerCase().includes(search) && (filter === 'all' || filter === row.kind));
  setText('account-count', String(rows.length));
  setText('account-active', String(rows.filter(row => row.active).length));
  const sum = field => rows.filter(row => row.usage_available !== false).reduce((n, row) => n + BigInt(row.exact_bytes?.[field] || row[field] || 0), 0n);
  setText('account-upload', size(Number(sum('upload_bytes')))); setText('account-download', size(Number(sum('download_bytes'))));
  setText('accounts-meter-note', `${state.traffic?.ssh_available ? 'SSH payload meter active' : 'SSH meter awaiting activation'} · ${state.traffic?.ip_meter_available ? 'Xray per-IP meter active' : 'Xray account totals available; per-IP meter awaiting activation'} · sampled limits can overshoot.`);
  const body = $('account-management'); body.replaceChildren();
  if (!selected.length) emptyRow(body, 7, 'No matching accounts. Create an SSH account or Xray profile.');
  selected.forEach(row => {
    const key = accountKey(row.kind, row.name), tr = element('tr', 'account-summary'), name = element('td');
    const toggle = button(`${expandedAccounts.has(key) ? '▾' : '▸'} ${row.name}`, async () => {
      if (expandedAccounts.has(key)) expandedAccounts.delete(key);
      else { expandedAccounts.clear(); expandedAccounts.set(key, 8); renderAccountManagement(); await fetchAccountDetails(row.kind, row.name); }
      renderAccountManagement();
    }, 'account-toggle');
    toggle.setAttribute('aria-expanded', String(expandedAccounts.has(key))); toggle.setAttribute('aria-label', `${expandedAccounts.has(key) ? 'Collapse' : 'Expand'} IPs for ${row.kind} ${row.name}`);
    name.append(toggle, tags(row.protocols), element('div', 'small muted', 'Expires ' + row.expiry));
    tr.append(name, accountByteCell(row, 'upload_bytes', row.usage_available !== false), accountByteCell(row, 'download_bytes', row.usage_available !== false), accountByteCell(row, 'used_bytes', row.usage_available !== false), element('td', 'mono', `${(row.online_ips || []).length} / ${row.max_ips || '∞'}`));
    const status = element('td'); status.append(pill(profileStatus(row), row.active ? 'good' : 'warn')); tr.append(status);
    const actions = element('td'), group = element('div', 'row-actions');
    group.append(button('Limits', () => openUsage(row.kind, row)), button('Links & settings', () => row.kind === 'ssh' ? exportSSH(row.name) : exportProfile(row.name)), button(row.enabled === false ? 'Unlock' : 'Lock', () => command(row.kind === 'ssh' ? 'set_user_lock' : 'xray_update', row.kind === 'ssh' ? {username: row.name, enabled: row.enabled === false} : {name: row.name, action: 'toggle', enabled: row.enabled === false}, 'Account access updated')), button('Renew', () => openRenew(row.kind, row.name)));
    actions.append(group); tr.append(actions);
    tr.addEventListener('click', event => { if (!event.target.closest('button, a, input, select')) toggle.click(); }); body.append(tr);
    if (expandedAccounts.has(key)) { const detail = element('tr', 'account-detail-row'), cell = element('td'); cell.colSpan = 7; cell.append(accountDetail(row.kind, row.name)); detail.append(cell); body.append(detail); }
  });
}

$('account-search').addEventListener('input', renderAccountManagement);
$('account-kind').addEventListener('change', renderAccountManagement);
$('accounts-refresh').addEventListener('click', () => busy($('accounts-refresh'), async () => { await refresh(); for (const [key, count] of expandedAccounts) { const [kind, name] = key.split(':'); await fetchAccountDetails(kind, name, count); } }));
setInterval(async () => {
  if (!csrf || document.visibilityState !== 'visible' || $('view-accounts').hidden || document.querySelector('dialog[open]') || $('account-management').contains(document.activeElement) && document.activeElement.tagName === 'INPUT') return;
  try { await refresh(); for (const [key, count] of expandedAccounts) { if (accountDetails.get(key)?.offset) continue; const [kind, name] = key.split(':'); await fetchAccountDetails(kind, name, count); } } catch (_) { /* retain the last sample; normal refresh reports connectivity */ }
}, 5000);

$('ssh-share-generate').addEventListener('click', () => busy($('ssh-share-generate'), async () => {
  if (currentExport?.kind === 'ssh') await exportSSH(currentExport.name, currentExport.route, $('ssh-share-password').value);
}));
$('download-zip').addEventListener('click', event => {
  const exported = currentExport;
  if (exported?.kind !== 'ssh' || !exported.profile.password) return;
  event.preventDefault(); busy($('download-zip'), async () => {
    const response = await fetch(API + 'ssh-export', {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify({name: exported.name, route: exported.route, password: exported.profile.password, format: 'zip'})});
    if (!response.ok) throw new Error((await response.json()).error || 'Private export failed');
    const url = URL.createObjectURL(await response.blob()), link = element('a'); link.href = url; link.download = `NOWAY-${exported.name}.zip`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 5000);
  });
});
$('export-dialog').addEventListener('close', () => { $('ssh-share-password').value = ''; currentExport = null; $('export-links').replaceChildren(); });
