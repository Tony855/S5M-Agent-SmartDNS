'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('server/web/app.js', 'utf8');
const helper = source.match(/const isTelemetryFresh = \(node, now = Date\.now\(\)\) => \{[\s\S]*?\n    \};/);
assert.ok(helper, 'dashboard telemetry freshness helper must exist');
const context = { TELEMETRY_FRESHNESS_MS: 15000 };
vm.runInNewContext(helper[0] + '\nthis.isTelemetryFresh = isTelemetryFresh;', context);
const isFresh = context.isTelemetryFresh;
const now = 1_800_000_000_000;

assert.equal(isFresh({ telemetryUpdatedAt: now - 15_000 }, now), true, '15-second boundary is fresh');
assert.equal(isFresh({ telemetryUpdatedAt: now - 15_001 }, now), false, 'older telemetry is stale');
assert.equal(isFresh({ telemetryUpdatedAt: now + 1 }, now), false, 'future receive timestamps are rejected');
assert.equal(isFresh({ telemetryUpdatedAt: now - 1, telemetryStale: true }, now), false, 'Agent stale flag wins');
assert.equal(isFresh({ last_seen: Math.floor(now / 1000) }, now), false, 'heartbeat alone never makes telemetry fresh');
assert.equal(isFresh({ telemetrySampledAt: now - 1 }, now), false, 'Agent wall-clock sample time is not trusted');
assert.equal(isFresh({}, now), false, 'missing receive timestamp is stale');

assert.match(source, /telemetryUpdatedAt: Number\(status\.telemetry_received_at_ms\)/,
  'status updates may advance freshness only with the server receive timestamp');
assert.doesNotMatch(source, /telemetryUpdatedAt: Number\(lastSeen\)/,
  'heartbeat last_seen must never be copied into telemetry freshness');
assert.match(source, /!isTelemetryFresh\(node\)/,
  'stale timer must expire live telemetry while heartbeat remains online');

const telemetryHelper = source.match(/const normalizeTelemetryFields = \(status, receivedAt\) => \{[\s\S]*?\n    \};/);
assert.ok(telemetryHelper, 'shared telemetry normalizer must exist');
vm.runInNewContext(telemetryHelper[0] + '\nthis.normalizeTelemetryFields = normalizeTelemetryFields;', context);
const normalizeTelemetry = context.normalizeTelemetryFields;
const freshFields = normalizeTelemetry({
  connections: 9, upload_speed: 120, download_speed: 240,
  upload_total: 5000, download_total: 7000,
  telemetry_stale: false, telemetry_sampled_at_ms: 1234,
  traffic_error: '', connections_error: ''
}, now);
assert.equal(freshFields.connections, 9);
assert.equal(freshFields.uploadSpeed, 120);
assert.equal(freshFields.downloadSpeed, 240);
assert.equal(freshFields.uploadTotal, 5000);
assert.equal(freshFields.downloadTotal, 7000);
assert.equal(freshFields.telemetryUpdatedAt, now);
const staleFields = normalizeTelemetry({
  connections: 9, upload_speed: 120, download_speed: 240,
  upload_total: 5000, download_total: 7000,
  telemetry_stale: true, telemetry_sampled_at_ms: 1234,
  traffic_error: 'timeout', connections_error: ''
}, now);
assert.equal(staleFields.connections, 0);
assert.equal(staleFields.uploadSpeed, 0);
assert.equal(staleFields.downloadSpeed, 0);
assert.equal(staleFields.uploadTotal, 5000, 'stale telemetry retains cumulative totals');
assert.equal(staleFields.telemetryStale, true);
assert.equal(staleFields.telemetryError, 'timeout');

const countsHelper = source.match(/const withRemoteNodeCounts = \(current, nodes\) => \{[\s\S]*?\n    \};/);
assert.ok(countsHelper, 'shared remote node counters helper must exist');
vm.runInNewContext(countsHelper[0] + '\nthis.withRemoteNodeCounts = withRemoteNodeCounts;', context);
const withCounts = context.withRemoteNodeCounts;
const counted = withCounts({ proxy_total: 4 }, [
  { online: true, healthy: true }, { online: true, healthy: false }, { online: false, healthy: true }
]);
assert.equal(counted.proxy_total, 4, 'unrelated overview fields are preserved');
assert.equal(counted.agent_online, 2);
assert.equal(counted.remote_online, 2);
assert.equal(counted.mihomo_healthy, 1);
assert.equal(counted.remote_mihomo_healthy, 1);

assert.doesNotMatch(source, /const getMachineCount =/);
assert.doesNotMatch(source, /const proxyCountForMachine =/);
assert.match(source, /getMachineProxyCount/);

console.log('PASS dashboard telemetry freshness regression tests');
