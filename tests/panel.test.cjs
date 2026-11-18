// SPDX-License-Identifier: MIT
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../ui/panel.js'), 'utf8');

async function open({local = false, cached = '', route = 'off'} = {}) {
  const nodes = new Map(), storage = new Map([['relay-token', cached]]), requests = [];
  function element(id) {
    if (!nodes.has(id)) nodes.set(id, {
      hidden: true, disabled: false, value: '', textContent: '', dataset: {}, options: [],
      addEventListener() {}, focus() {}, select() {}, replaceChildren() {this.options = [];},
      add(option) {this.options.push(option);}, scrollTop: 0, scrollHeight: 0, clientHeight: 0,
    });
    return nodes.get(id);
  }
  const sessionToken = 'new-local-session';
  const snapshot = {state: route === 'unavailable' ? 'active' : 'idle', proxy: 'ready',
    check: 'ready', egress: 'ready', download: 'ready', webview: 'idle',
    webview_route: route === 'unavailable' ? 'armed' : 'off', orbit_route: route,
    diagnosing: false, pid: 0, name: '', error: route === 'unavailable' ? 'orbit_image' : ''};
  vm.runInNewContext(source, {
    document: {getElementById: element}, AbortController,
    sessionStorage: {getItem: k => storage.get(k), setItem: (k, v) => storage.set(k, v),
      removeItem: k => storage.delete(k)},
    setTimeout() {return 1;}, clearTimeout() {},
    fetch: async (path, options) => {
      requests.push({path, options});
      let status = 200, data;
      if (path === '/api/local-session') {
        status = local ? 200 : 401;
        data = local ? {token: sessionToken} : {error: 'auth'};
      } else if (path === '/api/status') data = snapshot;
      else if (path === '/api/processes') data = [];
      else if (path === '/api/log') data = '';
      else throw new Error(`Unexpected request ${path}`);
      return {ok: status === 200, status, json: async () => data, text: async () => data};
    },
  });
  for (let n = 0; n < 8; n++) await new Promise(setImmediate);
  return {element, storage, requests, sessionToken};
}

test('console opens controls without a saved session or PIN', async () => {
  const page = await open({local: true});
  assert.equal(page.element('login-view').hidden, true);
  assert.equal(page.element('controls').hidden, false);
  assert.equal(page.storage.get('relay-token'), page.sessionToken);
  assert.equal(page.requests.find(r => r.path === '/api/status').options.headers['X-Relay-Token'], page.sessionToken);
  assert.equal(page.requests.some(r => r.path === '/api/login'), false);
});

test('console replaces a token left over from a previous payload run', async () => {
  const page = await open({local: true, cached: 'stale-session'});
  assert.equal(page.storage.get('relay-token'), page.sessionToken);
  assert.equal(page.element('controls').hidden, false);
});

test('LAN clients without a session keep the PIN form', async () => {
  const page = await open();
  assert.equal(page.element('login-view').hidden, false);
  assert.equal(page.element('controls').hidden, true);
  assert.equal(page.requests.some(r => r.path === '/api/status'), false);
});

test('LAN clients can reuse their existing authenticated session', async () => {
  const page = await open({cached: 'authenticated-lan-session'});
  assert.equal(page.element('login-view').hidden, true);
  assert.equal(page.element('controls').hidden, false);
  assert.equal(page.requests.find(r => r.path === '/api/status').options.headers['X-Relay-Token'], 'authenticated-lan-session');
});

test('WebView-only mode is clearly identified when Orbit could not attach', async () => {
  const page = await open({local: true, route: 'unavailable'});
  assert.equal(page.element('status-text').textContent, 'Работает только WebView');
  assert.equal(page.element('panel-message').dataset.kind, 'error');
  assert.match(page.element('panel-message').textContent, /Orbit/);
});
