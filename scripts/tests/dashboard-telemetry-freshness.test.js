'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('server/web/app.js', 'utf8');
const helper = source.match(/const isTelemetryFresh = \(node, now = Date\.now\(\)\) => \{[\s\S]*?\n    \};/);
assert.ok(helper, 'dashboard telemetry freshness helper must exist');
const context = {};
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

console.log('PASS dashboard telemetry freshness regression tests');
