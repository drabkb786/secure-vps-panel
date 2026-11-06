'use strict';
// Account-scoped, lazy IP detail pages. Existing administration views stay usable.
const expandedAccounts = new Map(), accountDetails = new Map(), accountLoads = new Map(), ipDrafts = new Map();
const accountKey = (kind, name) => kind + ':' + name;

function accountByteCell(row, field, available = true, withQuota = field === 'used_bytes') {
  const raw = row.exact_bytes?.[field] ?? row[field] ?? 0;
  if (!available && BigInt(raw) === 0n) return element('td', 'mono muted', 'No recorded usage');
  const cell = byteCell(row, field);
  if (field === 'used_bytes' && !withQuota) cell.firstChild.textContent = exactSize(raw);
  if (!available) cell.append(element('div', 'small meter-note', 'Last recorded'));
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
  if (!result.usage_available) box.append(element('p', 'meter-note', 'Per-IP coverage is unavailable or incomplete. Last recorded counters are retained; activate/check the metered backend for current usage.'));
  const scroll = element('div', 'table-scroll'), table = element('table', 'ip-table'), head = element('thead'), header = element('tr');
  ['SOURCE IP', 'UPLOAD', 'DOWNLOAD', 'TOTAL', 'ACCESS', 'PROTOCOL', 'ACTION'].forEach(t => header.append(element('th', '', t)));
  head.append(header); table.append(head); const body = element('tbody');
  if (!result.connections.length) emptyRow(body, 7, 'No authenticated IPs recorded for this account.');
  result.connections.forEach(ip => {
    const row = element('tr'), identity = element('td', 'mono');
    identity.append(element('strong', '', ip.ip === 'unknown' ? 'Unknown / unavailable source' : ip.ip), element('div', 'small muted', ip.online ? 'Connected now' : ip.last_seen ? 'Last seen ' + new Date(ip.last_seen).toLocaleString() : 'Offline / policy entry'));
    row.append(identity, accountByteCell(ip, 'upload_bytes', ip.usage_available), accountByteCell(ip, 'download_bytes', ip.usage_available), accountByteCell(ip, 'used_bytes', ip.usage_available, false));
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
  const sum = field => rows.reduce((n, row) => n + BigInt(row.exact_bytes?.[field] || row[field] || 0), 0n);
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
    group.append(button('Limits', () => openUsage(row.kind, row)), button('Links & settings', () => row.kind === 'ssh' ? exportSSH(row.name) : exportProfile(row.name)), button(row.enabled === false ? 'Unlock' : 'Lock', () => command(row.kind === 'ssh' ? 'set_user_lock' : 'xray_update', row.kind === 'ssh' ? {username: row.name, enabled: row.enabled === false} : {name: row.name, action: 'toggle', enabled: row.enabled === false}, 'Account access updated')), button('Renew', () => openRenew(row.kind, row.name)), button('Download check', () => openDownloadCheck(row.kind, row.name)));
    actions.append(group); tr.append(actions);
    tr.addEventListener('click', event => { if (!event.target.closest('button, a, input, select')) toggle.click(); }); body.append(tr);
    if (expandedAccounts.has(key)) { const detail = element('tr', 'account-detail-row'), cell = element('td'); cell.colSpan = 7; cell.append(accountDetail(row.kind, row.name)); detail.append(cell); body.append(detail); }
  });
}

$('account-search').addEventListener('input', renderAccountManagement);
$('account-kind').addEventListener('change', renderAccountManagement);
$('accounts-refresh').addEventListener('click', () => busy($('accounts-refresh'), async () => { await refresh(); for (const [key, count] of expandedAccounts) { const [kind, name] = key.split(':'); await fetchAccountDetails(kind, name, count); } }));
async function refreshExpandedAccounts() {
  for (const [key, count] of expandedAccounts) {
    if (accountDetails.get(key)?.offset) continue;
    const [kind, name] = key.split(':'); await fetchAccountDetails(kind, name, count);
  }
}

$('ssh-share-generate').addEventListener('click', () => busy($('ssh-share-generate'), async () => {
  if (currentExport?.kind === 'ssh') await exportSSH(currentExport.name, currentExport.route, $('ssh-share-password').value, true, currentExport.port, currentExport.path);
}));
$('export-dialog').addEventListener('close', () => { $('ssh-share-password').value = ''; currentExport = null; $('export-links').replaceChildren(); });

let downloadTarget = null, downloadBaseline = null, downloadCapture = null;
function openDownloadCheck(kind, name) {
  downloadTarget = {kind, name}; downloadBaseline = null; downloadCapture = null;
  setText('download-check-title', `Download check · ${name}`);
  $('download-check-file').value = '';
  $('download-check-bytes').value = '157286400';
  $('download-check-result').replaceChildren();
  setText('download-check-progress', '');
  $('download-check-end').disabled = true;
  $('download-check-start').disabled = false;
  $('download-check-dialog').showModal();
}
function showDownloadSnapshot(label, sample) {
  const bytes = sample.download_bytes;
  $('download-check-result').append(element('p', 'mono', `${label}: ${bytes} bytes · ${exactSize(bytes)} · ${exactSize(bytes, true)}`),
    element('p', 'small muted', `Sampled ${sample.sampled_at ? new Date(sample.sampled_at).toLocaleString() : 'before first traffic'}`));
}
function sameDownloadScope(a, b) {
  return a.identity === b.identity && a.reset_at === b.reset_at && BigInt(b.download_bytes) >= BigInt(a.download_bytes);
}
async function settledDownloadSnapshot(target) {
  const started = Date.now();
  let sample = await operation('download_snapshot', target), quietSince = Date.now();
  while (downloadTarget === target) {
    setText('download-check-progress', 'Checking the download counter. Keep this account’s downloads paused…');
    await new Promise(resolve => setTimeout(resolve, 1000));
    if (downloadTarget !== target) return null;
    const next = await operation('download_snapshot', target);
    if (downloadTarget !== target) return null;
    if (!sameDownloadScope(sample, next)) { downloadBaseline = null; throw new Error('Account was recreated or usage reset. Start a new measurement.'); }
    if (next.download_bytes !== sample.download_bytes) quietSince = Date.now();
    sample = next;
    if (Date.now() - quietSince >= 5000) return sample;
    if (Date.now() - started >= 15000) throw new Error('Download bytes are still changing. Pause this account’s downloads, then retry.');
  }
  return null;
}
async function captureDownload(ending) {
  if (!downloadTarget || downloadCapture) return;
  const target = downloadTarget, before = downloadBaseline, capture = {};
  if (ending && !before) return;
  const text = $('download-check-bytes').value.trim();
  if (ending && (!/^[0-9]{1,19}$/.test(text) || BigInt(text) === 0n)) { notify('Enter the exact positive file size in bytes', true); return; }
  if (!ending) downloadBaseline = null;
  downloadCapture = capture;
  $('download-check-start').disabled = true; $('download-check-end').disabled = true;
  try {
    const sample = await settledDownloadSnapshot(target);
    if (!sample || downloadTarget !== target) return;
    if (!ending) {
      downloadBaseline = sample;
      $('download-check-result').replaceChildren(); showDownloadSnapshot('Before', sample);
      setText('download-check-progress', 'Starting counter saved. Start your test download now.');
    } else {
      if (!sameDownloadScope(before, sample)) { downloadBaseline = null; throw new Error('Account was recreated or usage reset. Start a new measurement.'); }
      const delta = BigInt(sample.download_bytes) - BigInt(before.download_bytes), difference = delta - BigInt(text);
      $('download-check-result').replaceChildren();
      showDownloadSnapshot('Before', before); showDownloadSnapshot('After', sample);
      $('download-check-result').append(element('p', 'mono', `Download increase: ${delta} bytes · ${exactSize(delta)} · ${exactSize(delta, true)}`),
        element('p', 'mono', `File: ${text} bytes`), element('p', 'mono', `Difference: ${difference > 0n ? '+' : ''}${difference} bytes`));
      setText('download-check-progress', 'Comparison saved after the download counter stopped changing.');
    }
  } catch (err) {
    if (downloadTarget === target) { setText('download-check-progress', 'Counter was not saved. Retry after pausing downloads.'); notify(err.message || 'Download measurement failed', true); }
  } finally {
    if (downloadCapture === capture) { downloadCapture = null; $('download-check-start').disabled = false; $('download-check-end').disabled = !downloadBaseline; }
  }
}
$('download-check-start').addEventListener('click', () => captureDownload(false));
$('download-check-file').addEventListener('change', () => {
  const file = $('download-check-file').files[0];
  if (file) $('download-check-bytes').value = String(file.size);
});
$('download-check-end').addEventListener('click', () => captureDownload(true));
$('download-check-dialog').addEventListener('close', () => { downloadTarget = null; downloadBaseline = null; downloadCapture = null; });
