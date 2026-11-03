const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const {execFileSync} = require('node:child_process');
const source = execFileSync(process.env.PYTHON || 'python3', ['-c', 'import sys; sys.path.insert(0,"src"); import cdn_manager; print(cdn_manager.template()["Resources"]["RouteGuard"]["Properties"]["FunctionCode"])'], {encoding:'utf8'});
const context = vm.createContext({}); vm.runInContext(source, context);
function request(uri, method = 'GET') {
  return context.handler({request:{uri, method, headers:{'x-noway-viewer-ip':{value:'forged'}}}, viewer:{ip:'198.51.100.42'}});
}
test('CloudFront route guard permits XHTTP upload and replaces viewer identity', () => {
  const result = request('/cloudfront/xhttp/session/123', 'POST');
  assert.equal(result.headers['x-noway-viewer-ip'].value, '198.51.100.42');
  assert.equal(request('/cloudfront/ssh/ws').uri, '/cloudfront/ssh/ws');
});
test('CloudFront route guard rejects admin paths and unrelated methods', () => {
  for (const [uri, method] of [['/panel/api/state','GET'], ['/cloudfront/vless','POST'], ['/cloudfront/xhttp/session','PUT'], ['/vless','GET']]) {
    assert.equal(request(uri, method).statusCode, 403);
  }
});
