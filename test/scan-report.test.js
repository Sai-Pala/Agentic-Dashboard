'use strict';

/**
 * The agent roster and the recon summary.
 *
 * Both exist to answer "why does this scan look the way it does". The load-bearing assertion is
 * that an agent which never ran still appears: a roster built from results alone silently drops
 * every gated-out agent, which turns "17 of 32 agents ran" into "17 agents ran" — a materially
 * different, and false, claim about coverage.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { summarizeRecon, buildAgentRoster } = require('../src/services/scan-report');

const AGENTS = [
  { name: 'SqlInjectionAgent', category: 'injection', description: 'SQL injection' },
  { name: 'MobileScanner', category: 'mobile', description: 'Mobile app issues' },
  { name: 'SecretsAgent', category: 'secrets', description: 'Hardcoded secrets' },
  { name: 'XssAgent', category: 'injection', description: 'Cross-site scripting' },
];

describe('agent roster', () => {
  const results = [
    { agent: 'SqlInjectionAgent', category: 'injection', findingCount: 3, suppressedCount: 1, success: true },
    { agent: 'SecretsAgent', category: 'secrets', findingCount: 0, success: false, error: 'timed out' },
    { agent: 'XssAgent', category: 'injection', findingCount: 7, success: true },
  ];

  test('an agent that was gated out still appears', () => {
    // THE point of the roster. MobileScanner produced no result of any kind — it was filtered by
    // shouldRun() before the run loop started. Omitting it makes relevance gating invisible.
    const roster = buildAgentRoster(AGENTS, results, ['MobileScanner']);
    assert.equal(roster.length, 4);
    const mobile = roster.find((a) => a.name === 'MobileScanner');
    assert.equal(mobile.status, 'skipped');
    assert.equal(mobile.category, 'mobile');
  });

  test('a failed agent is distinguished from one that ran clean', () => {
    const roster = buildAgentRoster(AGENTS, results, ['MobileScanner']);
    const secrets = roster.find((a) => a.name === 'SecretsAgent');
    // Both found zero. Only one of them looked.
    assert.equal(secrets.status, 'failed');
    assert.equal(secrets.error, 'timed out');
    assert.equal(roster.find((a) => a.name === 'MobileScanner').status, 'skipped');
  });

  test('an agent that is neither gated out nor reported back is flagged, not assumed clean', () => {
    // No result and not in the skipped list means the orchestrator lost it. Recording that as
    // "not applicable" would invent a decision nobody made.
    const roster = buildAgentRoster(AGENTS, results, []);
    assert.equal(roster.find((a) => a.name === 'MobileScanner').status, 'unknown');
  });

  test('ordering puts coverage holes first and gated-out agents last', () => {
    const roster = buildAgentRoster(AGENTS, results, ['MobileScanner']);
    assert.equal(roster[0].name, 'SecretsAgent', 'the failure leads');
    assert.equal(roster.at(-1).name, 'MobileScanner', 'the scoping decision trails');
    // Among agents that ran, the noisiest is the one worth looking at first.
    assert.equal(roster[1].name, 'XssAgent');
  });

  test('suppression is carried through, since a silenced finding is not an absent one', () => {
    const roster = buildAgentRoster(AGENTS, results, ['MobileScanner']);
    assert.equal(roster.find((a) => a.name === 'SqlInjectionAgent').suppressedCount, 1);
  });

  test('missing inputs produce an empty roster rather than throwing', () => {
    assert.deepEqual(buildAgentRoster(null, null, null), []);
  });
});

describe('recon summary', () => {
  const recon = {
    frameworks: ['express', 'express', 'nextjs'],
    languages: new Set(['javascript', 'typescript']),
    databases: ['postgres'],
    cloudProviders: [],
    hasDockerfile: true,
    hasTerraform: false,
    hasKubernetes: false,
    apiRoutes: [{ file: 'a.js' }, { file: 'b.js' }],
    configFiles: ['package.json'],
  };

  test('record-shaped entries reduce to a name, not "[object Object]"', () => {
    // recon is not uniform: `frameworks` holds strings, `cicd` holds {platform, file}.
    const s = summarizeRecon({ ...recon, cicd: [{ platform: 'github-actions', file: '.github/workflows/ci.yml' }] });
    assert.deepEqual(s.signals.find((x) => x.label === 'CI/CD').values, ['github-actions']);
  });

  test('a Set and an array both flatten to a list of strings', () => {
    const s = summarizeRecon(recon);
    const langs = s.signals.find((x) => x.label === 'Languages');
    assert.deepEqual(langs.values.sort(), ['javascript', 'typescript']);
  });

  test('duplicates collapse', () => {
    const s = summarizeRecon(recon);
    assert.deepEqual(s.signals.find((x) => x.label === 'Frameworks').values, ['express', 'nextjs']);
  });

  test('empty signal lists are dropped, but absent infrastructure is still reported', () => {
    const s = summarizeRecon(recon);
    assert.ok(!s.signals.some((x) => x.label === 'Cloud providers'), 'nothing detected, nothing shown');
    // Flags are the opposite: "no Terraform" is exactly why an IaC agent stayed silent.
    assert.deepEqual(s.flags.find((f) => f.label === 'Terraform'), { label: 'Terraform', present: false });
    assert.equal(s.flags.find((f) => f.label === 'Dockerfile').present, true);
  });

  test('large lists survive only as counts', () => {
    const s = summarizeRecon(recon);
    assert.equal(s.routeCount, 2);
    assert.equal(s.configFileCount, 1);
  });

  test('no recon yields null rather than an empty shell', () => {
    assert.equal(summarizeRecon(null), null);
    assert.equal(summarizeRecon(undefined), null);
  });
});
