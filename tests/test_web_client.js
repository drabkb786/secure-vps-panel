// Exercise the actual mutation helper's result handling without a browser or server.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../src/web/app.js'), 'utf8');
const helper = source.slice(source.indexOf('async function command('), source.indexOf('\nfunction showLogin'));
const usageHelpers = source.slice(source.indexOf('const size ='), source.indexOf('\nfunction profileRows'));

test('decimal and binary quotas use distinct units and preserve exact byte text', () => {
  const context = vm.createContext({element: (tag, cls, text) => ({text, append() {}})});
  vm.runInContext(usageHelpers, context);
  assert.equal(vm.runInContext('size(1000000000)', context), '1.000 GB');
  assert.equal(vm.runInContext('size(1073741824, "GiB")', context), '1.000 GiB');
  assert.equal(vm.runInContext('quotaLabel({quota_gb:20,quota_unit:"GiB"})', context), '20 GiB');
  const node = context.byteCell({used_bytes: Number('9007199254741115'), exact_bytes:{used_bytes:'9007199254741115'}}, 'used_bytes');
  assert.equal(node.title, '9007199254741115 bytes');
});

test('monitor failure and IP cooldown are never labelled as expiry', () => {
  const context = vm.createContext({}); vm.runInContext(usageHelpers, context);
  assert.equal(vm.runInContext('profileStatus({meter_unavailable:true})', context), 'Monitor unavailable');
  assert.equal(vm.runInContext('profileStatus({ip_blocked_until:"2099-01-01T00:00:00Z"})', context), 'IP limit · cooldown');
});

test('a successful account mutation stays successful if the dashboard refresh fails', async () => {
  const notes = [], saved = {account: {name: 'created_once'}, links: {vless: 'vless://fixture'}};
  let mutations = 0;
  const context = vm.createContext({
    api: async () => { mutations++; return saved; },
    notify: (...args) => notes.push(args),
    refresh: async () => { throw new Error('Daemon temporarily unavailable'); },
  });
  vm.runInContext(helper, context);
  const result = await context.command('xray_create', {name: 'created_once'});
  assert.equal(result, saved);
  assert.equal(mutations, 1);
  assert.ok(notes.some(([message]) => /Change saved/.test(message)));
});

test('a rejected account mutation still fails and does not report success', async () => {
  const notes = [];
  const context = vm.createContext({
    api: async () => { throw new Error('Account exists'); },
    notify: (...args) => notes.push(args), refresh: async () => {},
  });
  vm.runInContext(helper, context);
  await assert.rejects(context.command('xray_create', {}), /Account exists/);
  assert.equal(notes.length, 0);
});
