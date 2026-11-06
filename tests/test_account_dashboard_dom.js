'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const {JSDOM} = require('jsdom');
const root = path.resolve(__dirname, '..'), B = 1000000000;
const tick = () => new Promise(resolve => setImmediate(resolve));
const bytes = (up, down) => ({upload_bytes: up, download_bytes: down, used_bytes: up + down, exact_bytes: {upload_bytes: String(up), download_bytes: String(down), used_bytes: String(up + down)}});

async function dashboard() {
  const dom = new JSDOM(fs.readFileSync(path.join(root, 'src/web/index.html'), 'utf8'), {url:'http://localhost/panel/', runScripts:'outside-only'});
  const win = dom.window, calls = [];
  win.setInterval = () => 0;
  win.HTMLDialogElement.prototype.showModal = function() { this.open = true; };
  win.HTMLDialogElement.prototype.close = function() { this.open = false; this.dispatchEvent(new win.Event('close')); };
  const common = {expiry:'2030-01-01', enabled:true, active:true, quota_gb:50, quota_unit:'GB', quota_bytes:50*B, max_ips:2, blocked_ips:[]};
  const ssh = {...common, ...bytes(B, 2*B), username:'basit', usage_available:true, max_sessions:3};
  const profile = {...common, ...bytes(5*B, 25*B), name:'noway', protocols:['vless'], online_ips:['192.0.2.1']};
  const state = {users:[ssh], accounts:[profile], sessions:[{username:'basit',count:1,ips:['198.51.100.1']}], services:{nginx:'active','abdulbasit-paneld':'active'}, endpoints:[], domain:'vpn.example.com', xray_installed:true, network:{enabled:true,dns:{servers:['1.1.1.1'],query_strategy:'UseIPv4'}}, traffic:{ssh_available:true,ip_meter_available:true}, slowdns:{}, cloudfront:{}, system:{hostname:'example',uptime_seconds:1000,cpu_count:2,load:[.1],memory_total:B,memory_available:B,disk_total:B,disk_used:0}};
  const ips = Array.from({length:16}, (_,i)=>({ip:`192.0.2.${i+1}`,...bytes(i===0?5*B:0,i===0?25*B:0),online:i===0,blocked:false,usage_available:true,protocols:['vless']}));
  function exported(password='demo-secret', route='direct', port=80, path='/cdn-cgi') {
    const host = route==='direct'?'vpn.example.com':'cdn.example.com', prefix = route==='direct'?'':'/'+route;
    return {name:'basit',share:{credentials:`${host}:${route==='direct'?port:443}@basit:${password}`,payload:`GET ${prefix}${path} HTTP/1.1[crlf]Host: ${host}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]`},password_available:!!password,share_warnings:[],links:{},files:{},profile:{password},readiness:{warnings:[]}};
  }
  win.fetch = async (url, options={}) => {
    const data = options.body ? JSON.parse(options.body) : undefined;
    calls.push({url,data});
    let value = {};
    if (url.endsWith('session')) value = {csrf:'test-csrf',username:'demo'};
    else if (url.endsWith('state')) value = state;
    else if (url.includes('export?kind=ssh')) value = exported();
    else if (url.endsWith('ssh-export')) {
      if (data.remember_password) state.legacyShare=false;
      value = exported(data.password || (state.legacyShare?'':'demo-secret'), data.route, data.port, data.path);
    }
    else if (url.endsWith('command')) {
      const p = data.params;
      if (data.command === 'account_connections') value = {connections:ips.slice(p.offset||0,(p.offset||0)+p.limit),total:ips.length,online_count:1,usage_available:true,offset:p.offset||0,has_more:(p.offset||0)+p.limit<ips.length};
      if (data.command === 'account_ip_set') ips.find(ip=>ip.ip===p.ip).blocked = p.blocked;
      if (data.command === 'set_quota') { ssh.quota_gb = Number(p.quota_gb); ssh.max_ips = p.max_ips; }
      if (data.command === 'download_snapshot') {
        const row = p.kind === 'ssh' ? ssh : profile;
        value = {kind:p.kind,name:p.name,identity:p.kind+':'+p.name,reset_at:state.downloadReset || null,
          download_bytes:row.exact_bytes.download_bytes,sampled_at:'2026-11-05T17:00:00Z'};
      }
    }
    return {ok:true,status:200,json:async()=>JSON.parse(JSON.stringify(value))};
  };
  const context = dom.getInternalVMContext();
  for (const name of ['app.js','accounts.js']) new vm.Script(fs.readFileSync(path.join(root,'src/web',name),'utf8'),{filename:name}).runInContext(context);
  for (let i=0;i<6;i++) await tick();
  return {dom,win,document:win.document,calls,state,flush:async()=>{for(let i=0;i<8;i++)await tick();}};
}

test('real account template expands and paginates IPs without flattening account totals', async t => {
  const app = await dashboard(); t.after(()=>app.dom.window.close());
  const d = app.document;
  assert.equal(d.getElementById('view-accounts').hidden,false);
  assert.equal(d.querySelectorAll('#account-management .account-summary').length,2);
  assert.match(d.querySelectorAll('#account-management .account-summary')[1].textContent,/30\.000 GB/);
  d.querySelector('[aria-label="Expand IPs for xray noway"]').click(); await app.flush();
  assert.equal(d.querySelectorAll('.ip-table tbody tr').length,8);
  assert.ok(!d.querySelector('.ip-table tbody tr').textContent.includes('Unlimited'));
  [...d.querySelectorAll('.show-more')][0].click(); await app.flush();
  assert.equal(d.querySelectorAll('.ip-table tbody tr').length,16);
  assert.equal(d.querySelectorAll('.show-more').length,0);
});

test('IP Block/Allow submits the selected account identity and updates its row', async t => {
  const app = await dashboard(); t.after(()=>app.dom.window.close()); const d=app.document;
  d.querySelector('[aria-label="Expand IPs for xray noway"]').click(); await app.flush();
  d.querySelector('.ip-table tbody tr button').click(); await app.flush();
  const call=app.calls.find(c=>c.data?.command==='account_ip_set');
  assert.deepEqual(call.data.params,{kind:'xray',name:'noway',ip:'192.0.2.1',blocked:true});
  assert.match(d.querySelector('.ip-table tbody tr').textContent,/Blocked/);
  assert.equal(d.querySelector('.ip-table tbody tr button').textContent,'Allow');
});

test('SSH limits save a real quota with session/IP caps, and disable quota without a meter', async t => {
  const app = await dashboard(); t.after(()=>app.dom.window.close()); const d=app.document;
  d.querySelector('#account-management .account-summary .row-actions button').click(); await app.flush();
  assert.equal(d.getElementById('usage-quota').disabled,false);
  d.getElementById('usage-quota').value='20'; d.getElementById('usage-ips').value='1';
  d.getElementById('usage-form').dispatchEvent(new app.win.Event('submit',{cancelable:true})); await app.flush();
  assert.deepEqual(app.calls.find(c=>c.data?.command==='set_quota').data.params,{username:'basit',quota_gb:'20',quota_unit:'GB',max_sessions:3,max_ips:1});
  app.state.traffic.ssh_available=false;
  d.getElementById('accounts-refresh').click(); await app.flush();
  d.querySelector('#account-management .account-summary .row-actions button').click(); await app.flush();
  assert.equal(d.getElementById('usage-quota').disabled,true);
  d.getElementById('usage-form').dispatchEvent(new app.win.Event('submit',{cancelable:true})); await app.flush();
  const last=app.calls.filter(c=>c.data?.command).at(-1);
  assert.equal(last.data.command,'set_sessions');
  assert.ok(!('quota_gb' in last.data.params));
});

test('SSH auto-share uses POST and shows exactly credentials and complete payload', async t => {
  const app = await dashboard(); t.after(()=>app.dom.window.close()); const d=app.document;
  d.querySelectorAll('#account-management .account-summary .row-actions button')[1].click(); await app.flush();
  assert.equal(d.querySelectorAll('#export-links textarea').length,2);
  assert.equal(d.querySelector('[aria-label="server:port@username:password"]').value,'vpn.example.com:80@basit:demo-secret');
  assert.match(d.querySelector('[aria-label="Payload"]').value,/GET \/cdn-cgi HTTP\/1\.1\[crlf\]Host: vpn\.example\.com/);
  assert.equal(d.getElementById('ssh-share-options').hidden,true);
  assert.equal(d.getElementById('download-zip').hidden,true);
  assert.equal(d.getElementById('copy-all-links').hidden,true);
  const port = d.getElementById('ssh-direct-port'), path = d.getElementById('ssh-direct-path');
  port.value = '443';
  port.dispatchEvent(new app.win.Event('change')); await app.flush();
  path.value = '/';
  path.dispatchEvent(new app.win.Event('change')); await app.flush();
  assert.equal(d.querySelector('[aria-label="server:port@username:password"]').value,'vpn.example.com:443@basit:demo-secret');
  assert.match(d.querySelector('[aria-label="Payload"]').value,/^GET \/ HTTP/);
  assert.equal(d.querySelectorAll('#export-links textarea').length,2);
  assert.ok(app.calls.every(c=>!c.url.includes('demo-secret')));
  d.getElementById('export-dialog').close();
  assert.equal(d.getElementById('export-links').childElementCount,0);
});

test('older account can register its current password once using CSRF POST', async t => {
  const app = await dashboard(); t.after(()=>app.dom.window.close()); const d=app.document;
  app.state.legacyShare=true;
  d.querySelectorAll('#account-management .account-summary .row-actions button')[1].click(); await app.flush();
  assert.equal(d.getElementById('ssh-share-options').hidden,false);
  d.getElementById('ssh-share-password').value='demo-secret'; d.getElementById('ssh-share-generate').click(); await app.flush();
  const call=app.calls.find(c=>c.data?.remember_password);
  assert.equal(call.data.password,'demo-secret');
  assert.equal(call.data.remember_password,true);
  assert.ok(app.calls.every(c=>!c.url.includes('demo-secret')));
  assert.match(d.querySelector('#export-links textarea').value,/@basit:demo-secret$/);
  assert.equal(d.getElementById('ssh-share-options').hidden,true);
  d.getElementById('export-dialog').close();
  assert.equal(d.getElementById('ssh-share-password').value,'');
  assert.equal(d.getElementById('export-links').childElementCount,0);
});

test('download check subtracts exact directional baselines and compares the local file size', async t => {
  const app = await dashboard(); t.after(()=>app.dom.window.close()); const d=app.document;
  [...d.querySelectorAll('#account-management .account-summary button')].find(b=>b.textContent==='Download check').click();
  d.getElementById('download-check-start').click(); await app.flush();
  Object.assign(app.state.users[0], bytes(B+9999999, 2*B+157286400));
  const file = new app.win.File(['fixture'], '150MiB.zip');
  Object.defineProperty(file, 'size', {value:157286400});
  Object.defineProperty(d.getElementById('download-check-file'), 'files', {value:[file]});
  d.getElementById('download-check-file').dispatchEvent(new app.win.Event('change'));
  assert.equal(d.getElementById('download-check-bytes').value,'157286400');
  d.getElementById('download-check-end').click(); await app.flush();
  const result = d.getElementById('download-check-result').textContent;
  assert.match(result,/Download increase: 157286400 bytes · 157\.286 MB · 150\.000 MiB/);
  assert.match(result,/Difference: 0 bytes/);
  assert.ok(app.calls.filter(c=>c.data?.command==='download_snapshot').every(c=>Object.keys(c.data.params).sort().join(',')==='kind,name'));
});

test('download check refuses a comparison after a reset even when usage grows past the baseline', async t => {
  const app = await dashboard(); t.after(()=>app.dom.window.close()); const d=app.document;
  [...d.querySelectorAll('#account-management .account-summary button')].find(b=>b.textContent==='Download check').click();
  d.getElementById('download-check-start').click(); await app.flush();
  app.state.downloadReset='2026-11-05T17:01:00Z';
  Object.assign(app.state.users[0],bytes(B,3*B));
  d.getElementById('download-check-end').click(); await app.flush();
  assert.match(d.getElementById('notice').textContent,/usage reset/);
  assert.ok(!d.getElementById('download-check-result').textContent.includes('Download increase:'));
});

test('both DNS mode requires a second zone and submits both routes together', async t => {
  const app=await dashboard(); t.after(()=>app.dom.window.close()); const d=app.document;
  d.getElementById('slowdns-mode').value='both';
  d.getElementById('slowdns-mode').dispatchEvent(new app.win.Event('change'));
  assert.equal(d.getElementById('slowdns-xray-zone-label').hidden,false);
  assert.equal(d.getElementById('slowdns-xray-zone').required,true);
  d.getElementById('slowdns-zone').value='ssh.example.com';
  d.getElementById('slowdns-xray-zone').value='xdns.example.com';
  d.getElementById('slowdns-ns').value='ns1.example.com';
  d.getElementById('slowdns-form').dispatchEvent(new app.win.Event('submit',{cancelable:true})); await app.flush();
  d.getElementById('confirm-form').dispatchEvent(new app.win.Event('submit',{cancelable:true})); await app.flush();
  const call=app.calls.find(c=>c.data?.command==='slowdns_configure');
  assert.equal(call.data.params.mode,'both');
  assert.equal(call.data.params.xray_zone,'xdns.example.com');
  assert.equal(call.data.params.port,53);
});
