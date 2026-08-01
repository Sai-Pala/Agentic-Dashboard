'use strict';

/**
 * Phase 0 characterization tests for the REST surface of server.js.
 *
 * These tests describe what the app CURRENTLY does, not what it should do. They
 * exist so a later refactor (splitting server.js into modules) can prove it
 * changed nothing observable over HTTP. If one of them fails after a refactor,
 * the refactor changed behaviour — that is the signal, whether or not the old
 * behaviour was desirable.
 *
 * Consequences of that framing:
 *   - Assertions are on SHAPE (array vs object, key presence, types, status
 *     codes, error strings) and on invariants, never on values that legitimately
 *     vary run to run (ids, timestamps).
 *   - Nothing here is a bug report. Where current behaviour looks surprising it
 *     is recorded with a comment, not corrected.
 *
 * HOW TO RE-RECORD: boot the app on a scratch port and inspect the real
 * responses before touching an assertion — never guess a shape:
 *   PORT=4573 node server.js &
 *   curl -s localhost:4573/api/findings | python3 -m json.tool
 * then update the assertion to match what the server actually returns.
 *
 * The server is booted ONCE for the whole file (startup is slow) and torn down
 * in `after`. Because the store is process-wide and session-lifetime, test
 * ORDER matters: the read-only shape assertions run first, the mutating tests
 * (POST /api/findings, POST /api/session/clear) run last.
 *
 * Run: node --test test/rest-api.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer } = require('./helpers/server');

const PORT = 4571;

let server;
let baseUrl;

async function get(pathname, init) {
  const res = await fetch(baseUrl + pathname, init);
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { res, text, json, status: res.status };
}

function postJson(pathname, body) {
  return get(pathname, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

test.before(async () => {
  server = await startServer({ port: PORT, readyTimeoutMs: 90_000 });
  baseUrl = server.baseUrl;
}, { timeout: 120_000 });

test.after(async () => {
  if (server) await server.stop();
});

// ---------------------------------------------------------------------------
// 1. Read-only shape assertions. These run first and must not mutate state.
// ---------------------------------------------------------------------------

test('GET /api/agents returns the per-finding agent names only', async () => {
  const { status, json } = await get('/api/agents');
  assert.equal(status, 200);
  assert.ok(Array.isArray(json), 'expected an array of agent names');
  for (const name of json) assert.equal(typeof name, 'string');

  // Included: the per-finding pipeline agents.
  for (const name of ['remediation', 'threat_model', 'verify']) {
    assert.ok(json.includes(name), `expected /api/agents to include "${name}"`);
  }
  // Excluded: NON_FINDING_AGENTS — whole-directory agents that are never run as
  // a per-finding stage. Asserted in both directions on purpose: a refactor that
  // drops the filter would otherwise pass.
  for (const name of ['scan', 'adjudicate', 'app_threat_model', 'controls_assist']) {
    assert.ok(!json.includes(name), `expected /api/agents to exclude "${name}"`);
  }
});

test('GET /api/agents?all=1 is unfiltered and a superset of the filtered list', async () => {
  const { status, json: all } = await get('/api/agents?all=1');
  assert.equal(status, 200);
  assert.ok(Array.isArray(all));
  for (const name of ['scan', 'adjudicate', 'app_threat_model', 'controls_assist', 'remediation', 'threat_model', 'verify']) {
    assert.ok(all.includes(name), `expected /api/agents?all=1 to include "${name}"`);
  }

  const { json: filtered } = await get('/api/agents');
  for (const name of filtered) assert.ok(all.includes(name));
  assert.ok(all.length > filtered.length);
});

test('GET /api/agents/:name returns {name, content, isBuiltIn}', async () => {
  const { status, json } = await get('/api/agents/remediation');
  assert.equal(status, 200);
  assert.equal(json.name, 'remediation');
  assert.equal(typeof json.content, 'string');
  assert.ok(json.content.length > 0);
  assert.equal(json.isBuiltIn, true);
});

test('GET /api/agents/:name rejects an unknown name (404) and an invalid name (400)', async () => {
  const missing = await get('/api/agents/definitely_not_an_agent');
  assert.equal(missing.status, 404);
  assert.equal(missing.json.error, 'Agent not found.');

  // AGENT_NAME_RE is ^[a-zA-Z0-9_-]+$ — the name is joined into a filesystem
  // path, so this validation is load-bearing, not cosmetic.
  const invalid = await get('/api/agents/bad%20name');
  assert.equal(invalid.status, 400);
  assert.equal(invalid.json.error, 'Invalid agent name.');
});

test('GET /api/scans returns an array (empty on a fresh boot)', async () => {
  const { status, json } = await get('/api/scans');
  assert.equal(status, 200);
  assert.ok(Array.isArray(json));
  assert.equal(json.length, 0, 'scans store should start empty');
});

test('GET /api/scans/:id 404s for an unknown id', async () => {
  const { status, json } = await get('/api/scans/no-such-scan');
  assert.equal(status, 404);
  assert.deepEqual(json, { error: 'not found' });
});

test('GET /api/scans/:id/surface 404s for an unknown scan', async () => {
  const { status, json } = await get('/api/scans/no-such-scan/surface');
  assert.equal(status, 404);
  assert.deepEqual(json, { error: 'not found' });

  // NOTE: the handler has a second 404 branch — a scan that exists but carries
  // no `surface` returns an explanatory message rather than 'not found'. That
  // branch is not exercised here because the only way to create a scan record
  // is the WebSocket `scan` flow, which spawns `claude -p` (real cost, real
  // auth). Covering it needs either a seam for injecting a scan record or a
  // WebSocket-level test; both are out of scope for this REST characterization.
});

test('DELETE /api/scans/:id 404s for an unknown id', async () => {
  const { status, json } = await get('/api/scans/no-such-scan', { method: 'DELETE' });
  assert.equal(status, 404);
  assert.deepEqual(json, { error: 'not found' });
});

test('GET /api/app-threat-models returns an array; /:id 404s for an unknown id', async () => {
  const list = await get('/api/app-threat-models');
  assert.equal(list.status, 200);
  assert.ok(Array.isArray(list.json));
  assert.equal(list.json.length, 0);

  const one = await get('/api/app-threat-models/no-such-record');
  assert.equal(one.status, 404);
  assert.deepEqual(one.json, { error: 'not found' });
});

test('GET /api/control-assessments returns an array; /:id 404s for an unknown id', async () => {
  const list = await get('/api/control-assessments');
  assert.equal(list.status, 200);
  assert.ok(Array.isArray(list.json));
  assert.equal(list.json.length, 0);

  const one = await get('/api/control-assessments/no-such-record');
  assert.equal(one.status, 404);
  assert.deepEqual(one.json, { error: 'not found' });
});

test('the findings store starts EMPTY on boot (seedFindings() is gone)', async () => {
  // This is the whole point of the test: seedFindings() used to push six sample
  // findings at boot and was removed. If it (or any other re-seeding) comes
  // back, this fails immediately instead of silently changing what every other
  // consumer sees.
  const { status, json } = await get('/api/findings');
  assert.equal(status, 200);
  assert.ok(Array.isArray(json));
  assert.equal(json.length, 0, 'findings store should be empty on a fresh boot');
});

test('GET /api/findings/:id 404s for an unknown id', async () => {
  const { status, json } = await get('/api/findings/no-such-finding');
  assert.equal(status, 404);
  assert.deepEqual(json, { error: 'not found' });
});

test('GET /api/timeline returns an array (empty on a fresh boot)', async () => {
  const { status, json } = await get('/api/timeline');
  assert.equal(status, 200);
  assert.ok(Array.isArray(json));
  assert.equal(json.length, 0);
});

test('GET /api/findings/export.csv returns CSV with a header row', async () => {
  const { res, status, text } = await get('/api/findings/export.csv');
  assert.equal(status, 200);
  assert.equal(res.headers.get('content-type'), 'text/csv; charset=utf-8');
  assert.match(res.headers.get('content-disposition') || '', /^attachment; filename="findings-export-\d+\.csv"$/);

  const [header] = text.split('\r\n');
  const columns = header.split(',');
  assert.equal(columns[0], 'id');
  assert.equal(columns[1], 'title');
  assert.equal(columns[2], 'scan_type');
  assert.equal(columns[columns.length - 1], 'created_at');
  // 26 columns today; asserted by presence rather than count where the exact
  // set is the interesting part.
  for (const col of ['status', 'severity', 'verdict', 'nist_800_53', 'run_count', 'latest_agent', 'source_scan_path']) {
    assert.ok(columns.includes(col), `expected CSV column "${col}"`);
  }
});

// ---------------------------------------------------------------------------
// 2. Mutating tests. Ordered after the read-only ones; session/clear last.
// ---------------------------------------------------------------------------

test('POST /api/findings requires title and description', async () => {
  const noTitle = await postJson('/api/findings', { description: 'D' });
  assert.equal(noTitle.status, 400);
  assert.deepEqual(noTitle.json, { error: 'title and description are required' });

  const noDescription = await postJson('/api/findings', { title: 'T' });
  assert.equal(noDescription.status, 400);
  assert.deepEqual(noDescription.json, { error: 'title and description are required' });
});

test('POST /api/findings creates a reasoning finding with exactly one synthetic triage run', async () => {
  const { status, json: finding } = await postJson('/api/findings', {
    title: 'Characterization finding',
    description: 'Created by test/rest-api.test.js',
    severity: 'high',
    rule: 'TEST_RULE',
    file: 'src/example.js',
    code: 'const x = req.query.x;',
  });

  assert.equal(status, 201);
  assert.equal(typeof finding.id, 'string');
  assert.equal(finding.title, 'Characterization finding');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.scanType, 'reasoning', 'scanType defaults to reasoning');
  assert.equal(typeof finding.createdAt, 'number');

  // THE INVARIANT: a reasoning finding is created already triaged. Triage is no
  // longer a live agent stage, so without this run the Remediation Loop's first
  // stage points at something that can never run.
  assert.ok(Array.isArray(finding.runs));
  assert.equal(finding.runs.length, 1, 'expected exactly one auto-attached run');
  const [run] = finding.runs;
  assert.equal(run.agent, 'triage');
  assert.equal(run.status, 'done');
  assert.equal(typeof run.runId, 'string');
  assert.equal(run.verdict.verdict, 'needs_review');
  assert.equal(run.verdict.severity_confirmed, 'high');
  assert.equal(run.verdict.source, 'manual-placeholder');

  // Status is derived from that run, not from the request body.
  assert.equal(finding.status, 'in_review');

  // Round-trips through GET /api/findings/:id unchanged.
  const fetched = await get(`/api/findings/${finding.id}`);
  assert.equal(fetched.status, 200);
  assert.equal(fetched.json.id, finding.id);
  assert.equal(fetched.json.runs.length, 1);
  assert.equal(fetched.json.runs[0].agent, 'triage');
});

test('POST /api/findings with scanType "sca" attaches NO triage run', async () => {
  // Recorded as-is: the auto-triage branch is reasoning-only. An SCA finding has
  // no remediation loop, so it gets no synthetic run and stays status "new".
  const { status, json: finding } = await postJson('/api/findings', {
    title: 'Characterization SCA finding',
    description: 'Created by test/rest-api.test.js',
    scanType: 'sca',
    packageName: 'left-pad',
    packageVersion: '1.0.0',
    fixedVersion: '1.3.0',
  });

  assert.equal(status, 201);
  assert.equal(finding.scanType, 'sca');
  assert.deepEqual(finding.runs, []);
  assert.equal(finding.status, 'new');
  assert.equal(finding.severity, 'medium', 'severity defaults to medium');
  assert.equal(finding.packageName, 'left-pad');
  assert.equal(finding.fixedVersion, '1.3.0');
});

test('GET /api/findings list items expose runCount/latestRun/stageRuns', async () => {
  const { status, json: list } = await get('/api/findings');
  assert.equal(status, 200);
  assert.equal(list.length, 2, 'the two findings created above');

  // Newest first.
  assert.ok(list[0].createdAt >= list[1].createdAt);

  for (const item of list) {
    for (const key of [
      'id', 'title', 'severity', 'scanType', 'rule', 'file', 'description', 'code',
      'packageName', 'packageVersion', 'fixedVersion', 'endpoint', 'method',
      'status', 'createdAt', 'runCount', 'latestRun', 'stageRuns', 'sourceScanId', 'flow',
    ]) {
      assert.ok(key in item, `expected list item key "${key}"`);
    }
    assert.deepEqual(Object.keys(item.stageRuns).sort(), ['fix', 'remediation', 'triage', 'verify']);
    // A list item is a projection, not the stored record — no raw `runs` array.
    assert.ok(!('runs' in item));
    assert.equal(item.sourceScanId, null, 'manually added findings have no source scan');
  }

  const reasoning = list.find((f) => f.scanType === 'reasoning');
  assert.equal(reasoning.runCount, 1);
  assert.equal(reasoning.latestRun.agent, 'triage');
  assert.ok(reasoning.stageRuns.triage, 'triage stage run is populated');
  assert.equal(reasoning.stageRuns.remediation, null);
  assert.equal(reasoning.stageRuns.fix, null);
  assert.equal(reasoning.stageRuns.verify, null);

  const sca = list.find((f) => f.scanType === 'sca');
  assert.equal(sca.runCount, 0);
  assert.equal(sca.latestRun, null);
  assert.equal(sca.stageRuns.triage, null);
});

test('GET /api/timeline flattens finding runs (one entry per run, kind = agent)', async () => {
  const { status, json } = await get('/api/timeline');
  assert.equal(status, 200);
  // Only the reasoning finding has a run; the SCA finding has none.
  assert.equal(json.length, 1);
  const [entry] = json;
  assert.equal(entry.kind, 'triage');
  assert.equal(entry.agent, 'triage');
  assert.equal(entry.status, 'done');
  assert.equal(typeof entry.runId, 'string');
  assert.equal(typeof entry.findingId, 'string');
  assert.equal(entry.findingTitle, 'Characterization finding');
  assert.equal(typeof entry.startedAt, 'number');
  assert.ok(entry.verdict && typeof entry.verdict === 'object');
});

test('GET /api/findings/export.csv emits one data row per finding, oldest first', async () => {
  const { status, text } = await get('/api/findings/export.csv');
  assert.equal(status, 200);
  const lines = text.split('\r\n');
  assert.equal(lines.length, 3, 'header + two findings');

  const columns = lines[0].split(',');
  const idx = (name) => columns.indexOf(name);

  // Export sorts oldest-first (the opposite of GET /api/findings).
  const first = lines[1].split(',');
  assert.equal(first[idx('title')], 'Characterization finding');
  assert.equal(first[idx('scan_type')], 'reasoning');
  assert.equal(first[idx('status')], 'in_review');
  assert.equal(first[idx('severity')], 'high');
  assert.equal(first[idx('verdict')], 'needs_review');
  assert.equal(first[idx('run_count')], '1');
  assert.equal(first[idx('latest_agent')], 'triage');
  assert.equal(first[idx('source_scan_path')], '');
  assert.match(first[idx('created_at')], /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/);

  const second = lines[2].split(',');
  assert.equal(second[idx('scan_type')], 'sca');
  assert.equal(second[idx('package_name')], 'left-pad');
  assert.equal(second[idx('run_count')], '0');
  assert.equal(second[idx('latest_agent')], '');
});

// Must be the last test in the file: it wipes every in-memory store.
test('POST /api/session/clear returns {ok:true} and empties every store', async () => {
  const before = await get('/api/findings');
  assert.ok(before.json.length > 0, 'precondition: findings exist before clearing');

  const { status, json } = await postJson('/api/session/clear', {});
  assert.equal(status, 200);
  assert.deepEqual(json, { ok: true });

  const findings = await get('/api/findings');
  assert.equal(findings.status, 200);
  assert.deepEqual(findings.json, []);

  const timeline = await get('/api/timeline');
  assert.deepEqual(timeline.json, []);

  const scans = await get('/api/scans');
  assert.deepEqual(scans.json, []);

  const atms = await get('/api/app-threat-models');
  assert.deepEqual(atms.json, []);

  const controls = await get('/api/control-assessments');
  assert.deepEqual(controls.json, []);

  // Export drops back to a bare header row — no reseed.
  const csv = await get('/api/findings/export.csv');
  assert.equal(csv.text.split('\r\n').length, 1);
});
