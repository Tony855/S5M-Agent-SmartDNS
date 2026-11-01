#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('server/web/app.js', 'utf8');
const start = source.indexOf('const v2rayNOutboundLinks = (root) => {');
const end = source.indexOf('const handleFileUpload = (e) => {', start);
assert(start >= 0 && end > start, 'V2RayN import converter must exist');
const converterSource = source.slice(start, end);
const convert = vm.runInNewContext(converterSource + String.fromCharCode(10) + 'v2rayNOutboundLinks;', {
  URLSearchParams,
  btoa: globalThis.btoa,
  unescape,
  encodeURIComponent
});

const config = {
  outbounds: [
    {
      tag: 'VLESS Reality',
      protocol: 'vless',
      settings: { vnext: [{ address: 'edge.example.test', port: 443, users: [{ id: 'vless-uuid', flow: 'xtls-rprx-vision' }] }] },
      streamSettings: {
        network: 'tcp',
        security: 'reality',
        realitySettings: { serverName: 'www.example.test', publicKey: 'public-key', shortId: 'abcd', fingerprint: 'chrome' }
      }
    },
    {
      tag: 'VMess WS TLS',
      protocol: 'vmess',
      settings: { vnext: [{ address: 'vmess.example.test', port: 8443, users: [{ id: 'vmess-uuid', alterId: 0, security: 'auto' }] }] },
      streamSettings: { network: 'ws', security: 'tls', tlsSettings: { serverName: 'cdn.example.test' }, wsSettings: { path: '/ws', headers: { Host: 'cdn.example.test' } } }
    },
    {
      tag: 'SS node',
      protocol: 'shadowsocks',
      settings: { servers: [{ address: 'ss.example.test', port: 8388, method: '2022-blake3-aes-128-gcm', password: 'ss-secret' }] }
    }
  ]
};

const links = convert(config);
assert.equal(links.length, 3, 'all supported outbound protocols should be converted');
assert.ok(links[0].startsWith('vless://vless-uuid@edge.example.test:443?'));
assert.match(links[0], /security=reality/);
assert.match(links[0], /pbk=public-key/);
assert.match(links[0], /sid=abcd/);
assert.ok(links[1].startsWith('vmess://'));
const vmess = JSON.parse(Buffer.from(links[1].slice('vmess://'.length), 'base64').toString('utf8'));
assert.equal(vmess.id, 'vmess-uuid');
assert.equal(vmess.net, 'ws');
assert.equal(vmess.host, 'cdn.example.test');
assert.equal(vmess.path, '/ws');
assert.equal(vmess.tls, 'tls');
assert.ok(links[2].startsWith('ss://'));
console.log('V2RayN outbound JSON import conversion tests passed.');
