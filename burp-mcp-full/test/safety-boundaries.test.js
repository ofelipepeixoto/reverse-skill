'use strict';
// In-memory transport mocks only. This does not start Burp or an HTTP server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const source = fs.readFileSync(path.join(__dirname, '..', 'mcp-bridge.js'), 'utf8');
let checks = 0;
function check(value, message) { checks++; assert.ok(value, message); }
function fixture() {
  const requests = [];
  const timers = new Set();
  const stdin = new EventEmitter();
  stdin.destroy = () => { stdin.destroyed = true; };
  const output = [];
  const fakeProcess = {
    env: { BURP_MCP_TOKEN: 'synthetic-test-token' }, stdin,
    stdout: { write: text => output.push(JSON.parse(text)) },
    stderr: { write() {} }, exit: code => { fakeProcess.exitCode = code; }
  };
  let reply = () => {};
  const http = { request(options, callback) {
    const req = new EventEmitter();
    req.destroy = () => { req.destroyed = true; };
    req.end = body => { req.body = body; reply(req, callback); };
    requests.push(req); return req;
  }};
  const module = { exports: {} };
  const requireFake = name => {
    if (name === 'http') return http;
    if (name === 'fs') return { existsSync() { throw new Error('No credential files in tests'); } };
    if (name === 'os') return { homedir() { throw new Error('No home access'); } };
    if (name === 'path') return path;
    throw new Error('Unexpected dependency ' + name);
  };
  const context = {
    module, require: requireFake, process: fakeProcess, Buffer,
    setTimeout: callback => { timers.add(callback); return callback; },
    clearTimeout: callback => timers.delete(callback)
  };
  vm.runInNewContext(source, context, { filename: 'mcp-bridge.js' });
  return { bridge: module.exports, requests, timers, stdin, output, process: fakeProcess,
    reply(fn) { reply = fn; },
    respond(body, status = 200) {
      reply = (req, callback) => {
        const res = new EventEmitter(); res.statusCode = status;
        res.destroy = () => { res.destroyed = true; };
        callback(res); res.emit('data', Buffer.from(body)); res.emit('end');
      };
    }
  };
}
async function reject(promise, pattern) { await assert.rejects(promise, pattern); checks++; }
async function isolationChecks() {
  if (process.env.TEST_REQUIRE_ISOLATION !== '1') return;
  assert.throws(() => fs.readFileSync('/etc/hostname'), { code: 'ERR_ACCESS_DENIED' }); checks++;
  assert.throws(() => fs.writeFileSync('/tmp/reverse-skill-denied', 'synthetic'), { code: 'ERR_ACCESS_DENIED' }); checks++;
  assert.throws(() => require('node:child_process').spawnSync('true'), { code: 'ERR_ACCESS_DENIED' }); checks++;
  await new Promise((resolve, rejectProbe) => {
    const socket = require('node:net').createConnection({ host: '127.0.0.1', port: 9 });
    socket.on('connect', () => { socket.destroy(); rejectProbe(new Error('Network was allowed')); });
    socket.on('error', error => {
      if (!['EPERM', 'EACCES'].includes(error.code)) rejectProbe(error);
      else { checks++; resolve(); }
    });
  });
}
async function run() {
  await isolationChecks();
  let f = fixture(); f.respond('["encode"]');
  check((await f.bridge.fetchTools())[0] === 'encode', 'valid tool discovery');
  check(f.timers.size === 0, 'deadline cleaned up on success');
  f = fixture(); f.respond('["invalid tool"]');
  await reject(f.bridge.fetchTools(), /Invalid/);
  f = fixture(); f.respond('synthetic-secret', 500);
  await reject(f.bridge.requestJson('GET', '/'), /^Error: Burp MCP HTTP 500; response body omitted$/);
  f = fixture(); f.respond('synthetic-secret');
  await reject(f.bridge.requestJson('GET', '/'), /invalid JSON; response body omitted/);
  f = fixture(); f.respond('x'.repeat(f.bridge.MAX_BYTES + 1));
  await reject(f.bridge.requestJson('GET', '/'), /response exceeds byte limit/);
  check(f.requests[0].destroyed && f.timers.size === 0, 'oversize transport disposed');
  f = fixture();
  await reject(f.bridge.requestJson('POST', '/', { data: 'x'.repeat(f.bridge.MAX_BYTES) }), /Request exceeds byte limit/);
  check(f.requests.length === 0, 'oversize request never reached transport');
  f = fixture();
  const timed = f.bridge.requestJson('POST', '/', {});
  [...f.timers][0]();
  await reject(timed, /outcome may be unknown/);
  check(f.requests[0].destroyed, 'deadline destroys transport without retry');
  check(f.requests.length === 1, 'no automatic POST retry');
  f = fixture(); f.reply((req, cb) => {
    const res = new EventEmitter(); res.destroy = () => {}; cb(res); res.emit('aborted');
  });
  await reject(f.bridge.requestJson('GET', '/'), /aborted/);
  f = fixture(); f.respond('["encode"]');
  await f.bridge.handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  let result = await f.bridge.handleRequest({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'burp_unknown' } });
  check(result.error.code === -32602 && f.requests.length === 1, 'unknown tool not sent');
  result = await f.bridge.handleRequest({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'burp_encode', arguments: null } });
  check(result.error.code === -32602 && f.requests.length === 1, 'non-object arguments not sent');
  f.respond('{"error":"synthetic policy denial"}');
  result = await f.bridge.handleRequest({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'burp_encode', arguments: {} } });
  check(result.result.isError === true, 'domain errors marked isError');
  check((await f.bridge.handleRequest(null)).error.code === -32600, 'invalid envelope handled');
  f = fixture(); f.bridge.main();
  f.stdin.emit('data', Buffer.alloc(f.bridge.MAX_BYTES + 1, 120));
  check(f.stdin.destroyed && f.process.exitCode === 1, 'newline-free oversized input rejected');
  f = fixture(); f.bridge.main();
  for (let i = 0; i <= f.bridge.MAX_PENDING; i++) {
    f.stdin.emit('data', Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: i, method: 'tools/list' }) + '\n'));
  }
  check(f.output.some(row => row.error && row.error.message === 'Too many pending requests'), 'pending concurrency capped');
  console.log('BRIDGE_SAFETY_OK checks=' + checks + ' mocked transport; no server started');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
