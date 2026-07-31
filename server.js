const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const fg = require('fast-glob'); // CommonJS-compatible — used by partitionReasoningModules() below

const PORT = process.env.PORT || 4500;
const AGENTS_DIR = path.join(__dirname, 'agents');
const AGENT_NAME_RE = /^[a-zA-Z0-9_-]+$/;
const RUN_ID_RE = /^[a-zA-Z0-9_-]+$/;
const BRANCH_NAME_RE = /^[\w./-]+$/;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const PRIORITIES = ['p0', 'p1', 'p2', 'p3'];
// SCA Scan is purely deterministic (sast-engine/'s dependency audit — no LLM equivalent is
// worth building for known-CVE lookups). Reasoning Scan is a hybrid: sast-engine's 29
// deterministic pattern agents run in parallel with a real claude -p reasoning pass
// (agents/scan.md) over the same directory, and the two result sets get merged — the
// deterministic engine gives fast, consistent coverage of known categories, the reasoning
// pass covers business-logic/authorization/attack-surface reasoning no fixed rule set can do.
// See runHybridReasoningScan() below and CLAUDE.md's Reasoning Scan bullet. The old 'custom'
// scan type (a free-form claude -p instruction with no canned framing) stays removed — it was
// already unreachable from the UI before this change and still has no equivalent here.
const SCAN_TYPES = ['reasoning', 'sca'];
const FINDING_SCAN_TYPES = ['reasoning', 'sca'];
const SCAN_SCOPES = ['full', 'diff'];
// Reasoning Scan's LLM half no longer takes one unscoped pass over an entire target directory
// on a "full" scope scan — that scales token spend and hallucination surface directly with
// repo size, with nothing bounding how far the model roams. Instead the directory is
// partitioned into modules (see partitionReasoningModules()) sized by actual file count, not
// just directory boundaries, and each module gets its own scoped `claude -p` call — smaller
// context, a hard dollar cap via --max-budget-usd, and results from all modules are merged
// before the usual dedup-against-deterministic-findings step. A "diff" scope scan skips
// partitioning entirely — the changed-file list from git is already a tight, pre-bounded scope,
// so it stays exactly one call, same as before.
const REASONING_MODULE_BUDGET_USD = 0.5; // per-module hard cap — tune here; no UI exposed for this yet
const REASONING_MODULE_CONCURRENCY = 3; // how many module-scoped claude -p processes run at once
// Target file count per module. A group over this gets recursively split by subdirectory
// (partitionReasoningModules()); groups under this get merged back together (by actual size, not
// arbitrary order) so a repo that's naturally small — or a giant single top-level directory that
// can't be split further — doesn't pay for more or fewer module calls than its real size justifies.
const REASONING_MODULE_MAX_FILES = 30;
const REASONING_MODULE_SPLIT_MAX_DEPTH = 3; // how many directory levels we'll recurse into an oversized group before accepting its size as-is
const REASONING_MODULE_MAX = 24; // hard cap on total modules after merging — see the bin-packing merge step
// A cross-cutting pass runs once per "full" scope scan, unscoped (unlike the module calls),
// specifically hunting for wiring gaps a per-module call structurally can't see — a protection
// defined in one module (auth middleware, a validator) never actually applied where it should be
// in another. Slightly higher budget than a single module since it has to sample across the
// whole tree rather than deep-dive one area. See runLLMReasoningScan()'s crosscut branch.
const REASONING_CROSSCUT_BUDGET_USD = 0.75;
// Shipped with the app and load-bearing for other hardcoded UI (the scan flow,
// the Dashboard's pipeline health panel) — editable, but not deletable via the
// Agents screen.
// 'triage' was removed from this list (and its .md file deleted) once Triage moved to a
// synthetic verdict assigned at finding-creation time instead of a live agent stage — see
// CLAUDE.md. 'scan' is back (agents/scan.md exists again, invoked by handleScanMessage's
// reasoning-pass half, not the generic per-finding run path — see NON_FINDING_AGENTS below).
const BUILTIN_AGENTS = ['scan', 'threat_model', 'remediation', 'verify', 'app_threat_model', 'controls_assist'];
// Agent .md files that operate on a whole directory via their own dedicated flow
// (Scans, App Threat Model, Controls Assist) rather than the per-finding stage/branch
// UI — excluded from the per-finding agent dropdown and the SCA "run after scan" pill
// row, but still editable in Agent Configuration (see the `all` query flag below).
const NON_FINDING_AGENTS = ['scan', 'app_threat_model', 'controls_assist'];

// Lazily loads the vendored deterministic scanning engine (sast-engine/, ported from the
// MIT-licensed ship-safe project — see CLAUDE.md's Reasoning Scan / SCA Scan bullets). It's a
// real ES module (its own package.json sets "type": "module"), so it's loaded via dynamic
// import() from this CommonJS file rather than converting the whole engine to require().
// Cached after the first call since none of these modules hold per-call state.
let _sastEnginePromise = null;
function loadSastEngine() {
  if (!_sastEnginePromise) {
    _sastEnginePromise = Promise.all([
      import('./sast-engine/agents/index.js'),
      import('./sast-engine/commands/deps.js'),
      import('./sast-engine/remediation-apply.js'),
      import('./sast-engine/utils/patterns.js'),
    ]).then(([agentsIndex, deps, remediationApply, patterns]) => ({
      buildOrchestratorAsync: agentsIndex.buildOrchestratorAsync,
      BUILT_IN_AGENT_COUNT: agentsIndex.BUILT_IN_AGENT_COUNT,
      runDepsAudit: deps.runDepsAudit,
      validatePlan: remediationApply.validatePlan,
      applyPlan: remediationApply.applyPlan,
      SKIP_DIRS: patterns.SKIP_DIRS,
      SKIP_EXTENSIONS: patterns.SKIP_EXTENSIONS,
      SKIP_FILENAMES: patterns.SKIP_FILENAMES,
      MAX_FILE_SIZE: patterns.MAX_FILE_SIZE,
      loadGitignorePatterns: patterns.loadGitignorePatterns,
    }));
  }
  return _sastEnginePromise;
}

// Deterministic severity+confidence -> priority table, replacing what agents/triage.md (an
// LLM call) used to decide case by case. Mirrors triage.md's p0-p3 definitions: p0 same-day,
// p1 this sprint, p2 normal backlog, p3 track only.
function priorityFromSeverityConfidence(severity, confidence) {
  if (severity === 'critical') return confidence === 'low' ? 'p1' : 'p0';
  if (severity === 'high') return confidence === 'high' ? 'p0' : 'p1';
  if (severity === 'medium') return confidence === 'low' ? 'p3' : 'p2';
  return 'p3'; // low, informational, or unrecognized
}

// npm/pip audit tools use "moderate" where this app's SEVERITIES uses "medium" — normalize so
// SCA findings sort/filter/display the same as reasoning findings.
function normalizeSeverity(raw) {
  const s = String(raw || '').toLowerCase();
  if (s === 'moderate') return 'medium';
  return SEVERITIES.includes(s) ? s : 'medium';
}

// Synthetic 'triage' run for a reasoning finding with no source directory to actually check
// anything against (manually added via "+ Add", or seed data) — see the /api/findings POST
// handler and seedFindings() below. Triage is no longer a live agent stage at all (its .md
// file is gone), so every reasoning finding needs *some* triage run at creation time or the
// Remediation Loop's first stage is permanently stuck pointing at a stage that can't run.
function placeholderTriageRun(severity) {
  return {
    runId: crypto.randomUUID(),
    agent: 'triage',
    status: 'done',
    startedAt: Date.now(),
    finishedAt: Date.now(),
    verdict: {
      verdict: 'needs_review',
      severity_confirmed: severity,
      confidence: 'low',
      priority: priorityFromSeverityConfidence(severity, 'low'),
      reasoning: 'No scan or source directory to verify against.',
      owasp: null,
      asvs: null,
      cwe: null,
      nist_800_53: [],
      next_agent: null,
      source: 'manual-placeholder',
    },
    fullText: '',
  };
}

function agentFilePath(name) {
  return path.join(AGENTS_DIR, `${name}.md`);
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/agents', (req, res) => {
  const files = fs.readdirSync(AGENTS_DIR).filter((f) => f.endsWith('.md'));
  const names = files.map((f) => f.replace(/\.md$/, ''));
  // `?all=1` is used by the Agent Configuration screen, which manages every agent .md
  // file including the whole-directory ones. Everywhere else (the per-finding stage/
  // branch dropdown, the SCA "run after scan" pill row) wants the filtered list.
  if (req.query.all) {
    res.json(names);
    return;
  }
  res.json(names.filter((n) => !NON_FINDING_AGENTS.includes(n)));
});

app.get('/api/agents/:name', (req, res) => {
  const { name } = req.params;
  if (!AGENT_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid agent name.' });
  const filePath = agentFilePath(name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent not found.' });
  const content = fs.readFileSync(filePath, 'utf8');
  res.json({ name, content, isBuiltIn: BUILTIN_AGENTS.includes(name) });
});

app.post('/api/agents', (req, res) => {
  const { name, content } = req.body || {};
  if (typeof name !== 'string' || !AGENT_NAME_RE.test(name)) {
    return res.status(400).json({ error: 'Agent name must match ^[a-zA-Z0-9_-]+$.' });
  }
  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Agent content must not be empty.' });
  }
  const filePath = agentFilePath(name);
  if (fs.existsSync(filePath)) return res.status(409).json({ error: 'An agent with this name already exists.' });
  fs.writeFileSync(filePath, content, 'utf8');
  res.status(201).json({ name });
});

app.put('/api/agents/:name', (req, res) => {
  const { name } = req.params;
  const { content } = req.body || {};
  if (!AGENT_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid agent name.' });
  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Agent content must not be empty.' });
  }
  const filePath = agentFilePath(name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent not found.' });
  fs.writeFileSync(filePath, content, 'utf8');
  res.json({ name });
});

app.delete('/api/agents/:name', (req, res) => {
  const { name } = req.params;
  if (!AGENT_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid agent name.' });
  if (BUILTIN_AGENTS.includes(name)) {
    return res.status(403).json({ error: 'Built-in pipeline agents cannot be deleted.' });
  }
  const filePath = agentFilePath(name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent not found.' });
  fs.unlinkSync(filePath);
  res.json({ ok: true });
});

// ---------- in-memory findings store ----------
// Session-lifetime only — lost on restart. No CSV ingestion/persistence yet
// (see CLAUDE.md "Not yet built"). Each finding owns a list of agent runs,
// which is how the pipeline chains (triage -> threat_model -> remediation).

const findings = new Map(); // id -> finding record
const runIndex = new Map(); // runId -> { findingId, run } for O(1) lookup on done/error/cancel

// Last run of a given agent type, or null if that agent hasn't run against this finding yet.
// Needed because the light list-item shape only otherwise carries the single overall latest
// run — the client's multi-stage Remediation Loop track (Triage -> Fixed -> Verified) needs to
// know each stage's own status independently, since a later Remediation/Verify run would
// otherwise hide whether Triage ever ran at all.
function latestRunByAgent(runs, agentName) {
  for (let i = runs.length - 1; i >= 0; i--) {
    if (runs[i].agent === agentName) return { status: runs[i].status, verdict: runs[i].verdict };
  }
  return null;
}

function toListItem(finding) {
  const runs = finding.runs;
  const latest = runs.length ? runs[runs.length - 1] : null;
  return {
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    scanType: finding.scanType,
    rule: finding.rule,
    file: finding.file,
    description: finding.description,
    code: finding.code || null,
    packageName: finding.packageName || null,
    packageVersion: finding.packageVersion || null,
    fixedVersion: finding.fixedVersion || null,
    endpoint: finding.endpoint || null,
    method: finding.method || null,
    status: finding.status,
    createdAt: finding.createdAt,
    runCount: runs.length,
    latestRun: latest ? { agent: latest.agent, status: latest.status, verdict: latest.verdict } : null,
    stageRuns: {
      triage: latestRunByAgent(runs, 'triage'),
      remediation: latestRunByAgent(runs, 'remediation'),
      verify: latestRunByAgent(runs, 'verify'),
    },
    sourceScanId: finding.sourceScanId || null,
  };
}

function deriveStatus(finding) {
  const latest = finding.runs[finding.runs.length - 1];
  if (!latest) return 'new';
  if (latest.status === 'running') return 'in_review';
  if (latest.status === 'error' || latest.status === 'cancelled') return 'in_review';
  const v = latest.verdict && latest.verdict.verdict;
  if (v === 'false_positive' || v === 'duplicate') return 'closed';
  // Verify's own verdict vocabulary (verified_fixed/still_vulnerable/partially_fixed/
  // inconclusive) doesn't overlap with any check below, so only verified_fixed needs its own
  // branch — the other three fall through to the generic in_review default at the bottom,
  // which is the right outcome: still needs more work, or couldn't be confirmed either way.
  if (latest.agent === 'verify' && v === 'verified_fixed') return 'verified_fixed';
  if (latest.agent === 'remediation' && latest.verdict && latest.verdict.corrected_code && (v === 'confirmed' || v === 'needs_review')) return 'remediation_generated';
  if (v === 'confirmed' && !latest.verdict.next_agent) return 'remediation_ready';
  if (v === 'confirmed' || v === 'needs_review') return 'in_review';
  return 'in_review';
}

// Builds a Finding record from one sast-engine finding, plus a synthetic 'triage'
// run derived straight from its VerifierAgent output — see CLAUDE.md's Reasoning Scan bullet.
// This is the one place Triage happens for a scan-sourced finding now; there is no more live
// claude -p Triage call for these. Every other part of the pipeline (findingLoopState,
// deriveStatus, the Finding Detail page) already renders/derives from *any* triage run
// generically, so this is the only integration point needed to make a scan-sourced finding
// show up already "Triaged".
function findingFromSastEngine(f, scan, targetPath) {
  const relFile = f.file ? path.relative(targetPath, f.file).split(path.sep).join('/') : null;
  const fileLabel = relFile ? `${relFile}${f.line ? ':' + f.line : ''}` : null;
  const severity = normalizeSeverity(f.severity);
  const confidence = ['high', 'medium', 'low'].includes(f.confidence) ? f.confidence : 'medium';
  const codeSnippet = Array.isArray(f.codeContext) && f.codeContext.length
    ? f.codeContext.map((c) => c.text).join('\n')
    : null;

  const finding = {
    id: crypto.randomUUID(),
    title: f.title || f.rule || 'Untitled finding',
    severity,
    scanType: 'reasoning',
    rule: f.rule || null,
    file: fileLabel,
    description: f.description || '',
    code: codeSnippet,
    packageName: null,
    packageVersion: null,
    fixedVersion: null,
    endpoint: null,
    method: null,
    status: 'new',
    createdAt: Date.now(),
    runs: [],
    sourceScanId: scan.id,
  };

  // Only critical/high findings actually go through VerifierAgent's code-context checks
  // (f.verified is null for everything else — "not checked", not "unverified"). Either way we
  // still synthesize a triage run so the finding enters the pipeline already triaged; an
  // unverified finding just lands as 'needs_review' instead of 'confirmed'.
  const verdictLabel = f.verified === true ? 'confirmed' : 'needs_review';
  finding.runs.push({
    runId: crypto.randomUUID(),
    agent: 'triage',
    status: 'done',
    startedAt: Date.now(),
    finishedAt: Date.now(),
    verdict: {
      verdict: verdictLabel,
      severity_confirmed: severity,
      confidence,
      priority: priorityFromSeverityConfidence(severity, confidence),
      reasoning: f.verifierNote || 'Deterministic pattern match; below the verification severity floor, so not independently re-checked against surrounding code.',
      owasp: f.owasp || null,
      asvs: null, // sast-engine has no ASVS mapping — see CLAUDE.md's taxonomy convention note
      cwe: f.cwe || null,
      nist_800_53: [], // same gap as asvs above
      next_agent: verdictLabel === 'confirmed' ? 'remediation' : null,
      source: 'sast-engine-verifier', // marks this as an auto-triage, not an LLM run — Finding Detail badges it accordingly
    },
    fullText: '',
  });
  finding.status = deriveStatus(finding);
  return finding;
}

// Builds an SCA Finding record from one sast-engine dependency-audit vulnerability. No
// synthetic triage run here — SCA findings never enter the Remediation Loop (see CLAUDE.md),
// they just show a plain status badge pending manual review, same as before this change.
function findingFromDepVuln(v, scan) {
  const severity = normalizeSeverity(v.severity);
  return {
    id: crypto.randomUUID(),
    title: `${v.name}@${v.range} — ${v.title}`,
    severity,
    scanType: 'sca',
    rule: v.cve || null,
    file: null,
    description: [v.title, v.cve ? `CVE: ${v.cve}` : null, v.url || null].filter(Boolean).join('\n'),
    code: null,
    packageName: v.name,
    packageVersion: v.range,
    fixedVersion: v.fix || null,
    endpoint: null,
    method: null,
    status: 'new',
    createdAt: Date.now(),
    runs: [],
    sourceScanId: scan.id,
  };
}

// Builds a Finding record from one agents/scan.md (LLM reasoning pass) finding, plus a real
// triage run from the taxonomy fields it assigned itself — unlike findingFromSastEngine()'s
// synthetic triage (derived from VerifierAgent's code-context checks), this one comes straight
// from the same reasoning pass that found the issue, since scan.md now does both jobs in one
// call (there's no separate live Triage stage to hand off to — see CLAUDE.md).
function findingFromLLMScan(rf, scan) {
  const severity = normalizeSeverity(rf.severity);
  const loc = parseFileLine(rf.file);
  const fileLabel = loc.file ? `${loc.file}${loc.line ? ':' + loc.line : ''}` : null;

  const finding = {
    id: crypto.randomUUID(),
    title: String(rf.title).trim(),
    severity,
    scanType: 'reasoning',
    rule: rf.rule ? String(rf.rule).trim() : null,
    file: fileLabel,
    description: String(rf.description).trim(),
    code: rf.code ? String(rf.code) : null,
    packageName: rf.package_name ? String(rf.package_name).trim() : null,
    packageVersion: rf.package_version ? String(rf.package_version).trim() : null,
    fixedVersion: rf.fixed_version ? String(rf.fixed_version).trim() : null,
    endpoint: rf.endpoint ? String(rf.endpoint).trim() : null,
    method: rf.method ? String(rf.method).trim() : null,
    status: 'new',
    createdAt: Date.now(),
    runs: [],
    sourceScanId: scan.id,
  };

  const VERDICTS = ['confirmed', 'needs_review', 'false_positive', 'duplicate'];
  const verdict = VERDICTS.includes(rf.verdict) ? rf.verdict : 'needs_review';
  const confidence = ['high', 'medium', 'low'].includes(rf.confidence) ? rf.confidence : 'medium';
  const severityConfirmed = SEVERITIES.includes(rf.severity_confirmed) ? rf.severity_confirmed : severity;
  finding.runs.push({
    runId: crypto.randomUUID(),
    agent: 'triage',
    status: 'done',
    startedAt: Date.now(),
    finishedAt: Date.now(),
    verdict: {
      verdict,
      severity_confirmed: severityConfirmed,
      confidence,
      priority: PRIORITIES.includes(rf.priority) ? rf.priority : priorityFromSeverityConfidence(severityConfirmed, confidence),
      reasoning: rf.reasoning ? String(rf.reasoning).trim() : '',
      owasp: rf.owasp || null,
      asvs: rf.asvs || null,
      cwe: rf.cwe || null,
      nist_800_53: Array.isArray(rf.nist_800_53) ? rf.nist_800_53 : [],
      next_agent: verdict === 'confirmed' ? 'remediation' : null,
      source: 'reasoning-scan', // marks this as the LLM pass's own assessment, not sast-engine's or a placeholder
    },
    fullText: '',
  });
  finding.status = deriveStatus(finding);
  return finding;
}

function seedFindings() {
  const samples = [
    {
      title: 'SQL Injection via title search parameter',
      severity: 'high',
      scanType: 'reasoning',
      rule: 'CWE-89 SQL Injection',
      file: 'findings-dashboard.jsx:112 (example legacy endpoint, hypothetical Node/Express backend)',
      description:
        "Scanner: Veracode SAST\nRule: CWE-89 SQL Injection\n\nUser-controlled query parameter `title` is concatenated directly into a SQL string and executed without parameterization.",
      code:
        "app.get('/api/findings/search', (req, res) => {\n  const q = req.query.title;\n  const sql = `SELECT * FROM findings WHERE title LIKE '%${q}%'`;\n  db.query(sql, (err, rows) => {\n    if (err) return res.status(500).send('error');\n    res.json(rows);\n  });\n});",
    },
    {
      title: 'Reflected XSS in finding title render',
      severity: 'medium',
      scanType: 'reasoning',
      rule: 'CWE-79 Cross-Site Scripting',
      file: 'findings-dashboard.jsx:58 (hypothetical detail pane)',
      description:
        "Scanner: manual review\nRule: CWE-79 Reflected XSS\n\nfinding.title comes from an uploaded CSV and is interpolated directly into innerHTML with no escaping. A crafted title in the CSV would execute in the analyst's browser session.",
      code: "detailPane.innerHTML = `<h2>${finding.title}</h2>`;",
    },
    {
      title: 'Hardcoded Azure DevOps PAT in ticket-creation helper',
      severity: 'critical',
      scanType: 'reasoning',
      rule: 'CWE-798 Use of Hard-coded Credentials',
      file: 'findings-dashboard.jsx:201 (ticket creation helper, hypothetical)',
      description:
        "Scanner: gitleaks\nRule: CWE-798 Hardcoded credentials\n\nA personal access token is committed directly in client-side JS, shipped to every browser that loads the dashboard.",
      code:
        "const ADO_PAT = 'ado_pat_9f2a...redacted...';\nfetch(`https://dev.azure.com/org/_apis/wit/workitems?api-version=6.0`, {\n  headers: { Authorization: `Basic ${btoa(':' + ADO_PAT)}` }\n});",
    },
    {
      title: 'Missing authorization check on /api/findings/:id/status',
      severity: 'low',
      scanType: 'reasoning',
      rule: 'CWE-862 Missing Authorization',
      file: 'server.js (hypothetical future endpoint, not yet built here)',
      description:
        "Scanner: manual review (design note)\nRule: CWE-862 Missing Authorization\n\nThe planned PATCH /api/findings/:id/status endpoint (for marking findings triaged/closed from the dashboard) has no auth model defined yet in this local single-user tool. Flagging now so it's not forgotten if this app is ever exposed beyond localhost.",
    },
    {
      title: 'Prototype pollution in lodash <4.17.21 (merge/defaultsDeep)',
      severity: 'high',
      scanType: 'sca',
      rule: 'CVE-2020-8203',
      file: 'package.json',
      description:
        "Scanner: npm audit\nRule: CVE-2020-8203 Prototype Pollution\n\nlodash@4.17.15 is resolved via a transitive dependency. Versions before 4.17.21 allow prototype pollution via `_.merge`/`_.defaultsDeep` on attacker-controlled objects, which can lead to denial of service or, in some call sites, property-injection based logic bypass.",
      packageName: 'lodash',
      packageVersion: '4.17.15',
      fixedVersion: '4.17.21',
    },
    {
      title: 'Unauthenticated internal metrics endpoint reachable externally',
      severity: 'medium',
      scanType: 'reasoning',
      rule: 'CWE-306 Missing Authentication for Critical Function',
      file: 'server.js (route registration, hypothetical)',
      description:
        "Scanner: manual review (static approximation of runtime testing)\nRule: CWE-306 Missing Authentication\n\n/internal/metrics is registered with no auth middleware ahead of it and no IP allowlist, so it's reachable by anyone who can route to this host, not just the ops network it was intended for. Response includes queue depths and internal hostnames.",
      endpoint: '/internal/metrics',
      method: 'GET',
    },
  ];

  for (const s of samples) {
    const id = crypto.randomUUID();
    const finding = {
      id,
      title: s.title,
      severity: s.severity,
      scanType: s.scanType,
      rule: s.rule,
      file: s.file,
      description: s.description,
      code: s.code || null,
      packageName: s.packageName || null,
      packageVersion: s.packageVersion || null,
      fixedVersion: s.fixedVersion || null,
      endpoint: s.endpoint || null,
      method: s.method || null,
      status: 'new',
      createdAt: Date.now(),
      runs: [],
    };
    // Same reasoning as the manual "+ Add" handler above: Triage no longer exists as a
    // runnable stage, so this seed data needs a synthetic run too or its Remediation Loop
    // starts permanently stuck.
    if (finding.scanType === 'reasoning') {
      finding.runs.push(placeholderTriageRun(finding.severity));
    }
    finding.status = deriveStatus(finding);
    findings.set(id, finding);
  }
}
seedFindings();

// ---------- in-memory scans store ----------
// A scan is one "scan this directory" invocation of sast-engine's deterministic pattern
// agents (reasoning) or dependency audit (sca) — see runDeterministicReasoningScan/
// runDeterministicScaScan below. It doesn't chain like a per-finding run does — on completion
// it creates zero or more new Finding records (tagged with sourceScanId) and remembers their
// ids, so the Scans view can show "this scan produced N findings" and link through to them.

const scans = new Map(); // id -> scan record
const scanRunIndex = new Map(); // runId -> scan record, for O(1) lookup on done/error/cancel

function toScanListItem(scan) {
  return {
    id: scan.id,
    runId: scan.runId,
    path: scan.path,
    instruction: scan.instruction,
    branch: scan.branch,
    app: scan.app,
    scanType: scan.scanType,
    scope: scan.scope,
    baseBranch: scan.baseBranch,
    diffFileCount: scan.diffFileCount,
    status: scan.status,
    error: scan.error,
    findingIds: scan.findingIds,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    // Whether the reasoning half's calls got a --max-budget-usd cap at all (the Reasoning
    // Scan form's "Budget cap" toggle) — always true for an SCA scan (no reasoning half, so
    // the field is inert, but a real boolean rather than undefined keeps the API shape simple).
    budgetEnabled: scan.budgetEnabled !== false,
    // Real dollar spend across the reasoning half's claude -p calls (modules + the
    // cross-cutting pass) — set once runHybridReasoningScan() finishes; undefined until then,
    // and always undefined for an SCA scan (no reasoning half to spend anything).
    reasoningCostUsd: scan.reasoningCostUsd,
  };
}

app.get('/api/scans', (req, res) => {
  const list = [...scans.values()].sort((a, b) => b.startedAt - a.startedAt).map(toScanListItem);
  res.json(list);
});

app.get('/api/scans/:id', (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json({
    ...toScanListItem(scan),
    findings: scan.findingIds.map((id) => findings.get(id)).filter(Boolean).map(toListItem),
  });
});

app.delete('/api/scans/:id', (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  if (scan.status === 'running') {
    res.status(409).json({ error: 'Cancel the scan before deleting it.' });
    return;
  }
  scans.delete(req.params.id);
  res.json({ ok: true });
});

// ---------- in-memory app-level threat models store ----------
// A whole-app threat model is a single holistic run (agents/app_threat_model.md)
// against an entire directory — a security-architect-style narrative (trust
// boundaries, data flows, top structural risks), not a per-finding artifact and
// not tied to any particular findings scan. It's an independent, parallel action
// a user can fire alongside a normal scan from the Dashboard.

const appThreatModels = new Map(); // id -> record
const appThreatModelRunIndex = new Map(); // runId -> record, for O(1) lookup on done/error/cancel

function toAppThreatModelListItem(record) {
  return {
    id: record.id,
    runId: record.runId,
    path: record.path,
    app: record.app,
    branch: record.branch,
    instruction: record.instruction,
    status: record.status,
    verdict: record.verdict,
    error: record.error,
    startedAt: record.startedAt,
    finishedAt: record.finishedAt,
  };
}

app.get('/api/app-threat-models', (req, res) => {
  const list = [...appThreatModels.values()].sort((a, b) => b.startedAt - a.startedAt).map(toAppThreatModelListItem);
  res.json(list);
});

app.get('/api/app-threat-models/:id', (req, res) => {
  const record = appThreatModels.get(req.params.id);
  if (!record) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json(toAppThreatModelListItem(record));
});

// ---------- in-memory control assessments store ----------
// A control assessment is a single holistic run (agents/controls_assist.md) against an
// entire directory — identifies which NIST 800-53 controls the application layer provides
// evidence for and drafts SSP-ready narratives, for RMF/ISSO staff. Same shape and same
// independent-from-findings relationship as the app-level threat model store above.

const controlAssessments = new Map(); // id -> record
const controlAssessmentRunIndex = new Map(); // runId -> record, for O(1) lookup on done/error/cancel

function toControlAssessmentListItem(record) {
  return {
    id: record.id,
    runId: record.runId,
    path: record.path,
    app: record.app,
    branch: record.branch,
    instruction: record.instruction,
    status: record.status,
    verdict: record.verdict,
    error: record.error,
    startedAt: record.startedAt,
    finishedAt: record.finishedAt,
  };
}

app.get('/api/control-assessments', (req, res) => {
  const list = [...controlAssessments.values()].sort((a, b) => b.startedAt - a.startedAt).map(toControlAssessmentListItem);
  res.json(list);
});

app.get('/api/control-assessments/:id', (req, res) => {
  const record = controlAssessments.get(req.params.id);
  if (!record) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json(toControlAssessmentListItem(record));
});

app.get('/api/findings', (req, res) => {
  const list = [...findings.values()]
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(toListItem);
  res.json(list);
});

app.post('/api/findings', (req, res) => {
  const body = req.body || {};
  const title = String(body.title || '').trim();
  const description = String(body.description || '').trim();
  if (!title || !description) {
    res.status(400).json({ error: 'title and description are required' });
    return;
  }

  const id = crypto.randomUUID();
  const finding = {
    id,
    title,
    severity: SEVERITIES.includes(body.severity) ? body.severity : 'medium',
    scanType: FINDING_SCAN_TYPES.includes(body.scanType) ? body.scanType : 'reasoning',
    rule: body.rule ? String(body.rule).trim() : null,
    file: body.file ? String(body.file).trim() : null,
    description,
    code: body.code ? String(body.code) : null,
    packageName: body.packageName ? String(body.packageName).trim() : null,
    packageVersion: body.packageVersion ? String(body.packageVersion).trim() : null,
    fixedVersion: body.fixedVersion ? String(body.fixedVersion).trim() : null,
    endpoint: body.endpoint ? String(body.endpoint).trim() : null,
    method: body.method ? String(body.method).trim() : null,
    status: 'new',
    createdAt: Date.now(),
    runs: [],
  };
  // Triage is no longer a live agent stage (see CLAUDE.md) — every reasoning finding enters
  // the pipeline already triaged. Scan-sourced findings get a real verdict from sast-engine's
  // VerifierAgent (findingFromSastEngine); a manually-added finding has no source directory to
  // check anything against, so it gets placeholderTriageRun()'s neutral verdict instead.
  if (finding.scanType === 'reasoning') {
    finding.runs.push(placeholderTriageRun(finding.severity));
  }
  finding.status = deriveStatus(finding);
  findings.set(id, finding);
  res.status(201).json(finding);
});

function csvEscape(value) {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// Must be registered before `/api/findings/:id` — otherwise Express matches
// this request as that route with id="export.csv" and 404s.
app.get('/api/findings/export.csv', (req, res) => {
  const columns = [
    'id', 'title', 'scan_type', 'status', 'severity', 'rule', 'file',
    'package_name', 'package_version', 'fixed_version', 'endpoint', 'method',
    'verdict', 'severity_confirmed', 'confidence', 'priority',
    'owasp', 'cwe', 'nist_800_53',
    'root_cause', 'fix_guidance', 'effort',
    'run_count', 'latest_agent', 'source_scan_path', 'created_at',
  ];
  const rows = [columns.join(',')];

  for (const finding of [...findings.values()].sort((a, b) => a.createdAt - b.createdAt)) {
    const latest = finding.runs[finding.runs.length - 1];
    const v = (latest && latest.verdict) || {};
    const scan = finding.sourceScanId ? scans.get(finding.sourceScanId) : null;
    rows.push([
      finding.id, finding.title, finding.scanType, finding.status, finding.severity, finding.rule || '', finding.file || '',
      finding.packageName || '', finding.packageVersion || '', finding.fixedVersion || '', finding.endpoint || '', finding.method || '',
      v.verdict || '', v.severity_confirmed || '', v.confidence || '', v.priority || '',
      v.owasp || '', v.cwe || '', Array.isArray(v.nist_800_53) ? v.nist_800_53.join('; ') : '',
      v.root_cause || '', v.fix_guidance || '', v.effort || '',
      finding.runs.length, latest ? latest.agent : '', scan ? scan.path : '',
      new Date(finding.createdAt).toISOString(),
    ].map(csvEscape).join(','));
  }

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="findings-export-${Date.now()}.csv"`);
  res.send(rows.join('\r\n'));
});

app.get('/api/findings/:id', (req, res) => {
  const finding = findings.get(req.params.id);
  if (!finding) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json(finding);
});

app.get('/api/timeline', (req, res) => {
  const entries = [];
  for (const finding of findings.values()) {
    for (const run of finding.runs) {
      entries.push({
        kind: run.agent, // 'triage' | 'threat_model' | 'remediation'
        runId: run.runId,
        findingId: finding.id,
        findingTitle: finding.title,
        agent: run.agent,
        status: run.status,
        instruction: run.instruction,
        verdict: run.verdict,
        startedAt: run.startedAt,
        finishedAt: run.finishedAt,
      });
    }
  }
  for (const scan of scans.values()) {
    entries.push({
      kind: 'scan',
      runId: scan.runId,
      scanId: scan.id,
      path: scan.path,
      scanType: scan.scanType,
      status: scan.status,
      instruction: scan.instruction,
      findingCount: scan.findingIds.length,
      error: scan.error,
      startedAt: scan.startedAt,
      finishedAt: scan.finishedAt,
    });
  }
  entries.sort((a, b) => b.startedAt - a.startedAt);
  res.json(entries);
});

// ---------- websocket: agent invocation ----------

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

function extractVerdict(text) {
  const match = text.match(/```json\s*([\s\S]*?)```/);
  if (!match) return null;
  try {
    return JSON.parse(match[1]);
  } catch (err) {
    return null;
  }
}

wss.on('connection', (ws) => {
  const children = new Map(); // runId -> ChildProcess

  const send = (payload) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(payload));
  };

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (err) {
      send({ type: 'error', message: 'Malformed message.' });
      return;
    }

    if (msg.type === 'cancel') {
      const runId = String(msg.runId || '');
      const child = children.get(runId);
      const indexed = runIndex.get(runId);
      if (indexed && indexed.run.status === 'running') {
        indexed.run.status = 'cancelled';
        indexed.run.finishedAt = Date.now();
      }
      const scanIndexed = scanRunIndex.get(runId);
      if (scanIndexed && scanIndexed.status === 'running') {
        scanIndexed.status = 'cancelled';
        scanIndexed.finishedAt = Date.now();
      }
      // A module-scoped reasoning scan's actual claude processes are never registered under
      // the scan's own runId (see runLLMReasoningScan()) — each module has its own synthetic
      // `${runId}::modN` key instead, tracked on scanIndexed.moduleRunIds. Without this, the
      // top-level `children.get(runId)` lookup above finds nothing and cancelling a full-scope
      // reasoning scan wouldn't actually kill any of its in-flight module processes.
      if (scanIndexed && Array.isArray(scanIndexed.moduleRunIds)) {
        for (const modRunId of scanIndexed.moduleRunIds) {
          const modChild = children.get(modRunId);
          if (modChild) modChild.kill();
        }
      }
      const atmIndexed = appThreatModelRunIndex.get(runId);
      if (atmIndexed && atmIndexed.status === 'running') {
        atmIndexed.status = 'cancelled';
        atmIndexed.finishedAt = Date.now();
      }
      const caIndexed = controlAssessmentRunIndex.get(runId);
      if (caIndexed && caIndexed.status === 'running') {
        caIndexed.status = 'cancelled';
        caIndexed.finishedAt = Date.now();
      }
      if (child) child.kill();
      return;
    }

    if (msg.type === 'scan') {
      handleScanMessage(msg, { children, send });
      return;
    }

    if (msg.type === 'app_threat_model') {
      handleAppThreatModelMessage(msg, { children, send });
      return;
    }

    if (msg.type === 'controls_assist') {
      handleControlsAssistMessage(msg, { children, send });
      return;
    }

    if (msg.type === 'remediate_apply') {
      handleRemediateApplyMessage(msg, { children, send });
      return;
    }

    if (msg.type === 'remediate_all') {
      handleRemediateAllMessage(msg, { children, send });
      return;
    }

    if (msg.type !== 'run') return;

    const runId = String(msg.runId || '').trim();
    if (!RUN_ID_RE.test(runId)) {
      send({ type: 'error', message: 'Invalid or missing runId.' });
      return;
    }

    if (children.has(runId)) {
      send({ type: 'error', runId, message: 'This runId is already active.' });
      return;
    }

    const agentName = String(msg.agent || '').trim();
    const context = String(msg.context || '');
    const instruction = String(msg.instruction || '');
    const findingId = msg.findingId ? String(msg.findingId) : null;

    if (!AGENT_NAME_RE.test(agentName)) {
      send({ type: 'error', runId, message: `Invalid agent name: ${agentName}` });
      return;
    }

    const agentPath = agentFilePath(agentName);
    if (!fs.existsSync(agentPath)) {
      send({ type: 'error', runId, message: `Unknown agent: ${agentName}` });
      return;
    }

    let systemPrompt;
    try {
      systemPrompt = fs.readFileSync(agentPath, 'utf8');
    } catch (err) {
      send({ type: 'error', runId, message: `Failed to read agent prompt: ${err.message}` });
      return;
    }

    const finding = findingId ? findings.get(findingId) : null;
    let runRecord = null;
    if (finding) {
      runRecord = {
        runId,
        agent: agentName,
        instruction,
        context,
        status: 'running',
        verdict: null,
        fullText: '',
        startedAt: Date.now(),
        finishedAt: null,
      };
      finding.runs.push(runRecord);
      runIndex.set(runId, { findingId: finding.id, run: runRecord });
    }

    const userPrompt = `${instruction}\n\nFinding context:\n${context}`;

    // Per-finding agents normally run with cwd = this app's own directory and no Glob, since
    // they reason primarily over the `code` snippet already embedded in context. Verify is the
    // exception: confirming a fix actually landed benefits from reading the finding's real
    // target codebase, not this dashboard's. If the client resolved a source path (from the
    // finding's originating scan) and it's still a valid directory, spawn there with Glob added;
    // otherwise fall back to the default — verify.md is written to recognize that case and
    // return `inconclusive` rather than silently reasoning over the wrong repo. (Triage used to
    // get the same live-path treatment when triggered from the loop's step arrow, but it's no
    // longer a live agent stage at all — see CLAUDE.md.)
    let runCwd = process.cwd();
    let allowedTools = 'Read,Grep';
    const requestedPath = String(msg.path || '').trim();
    if (requestedPath) {
      try {
        if (fs.statSync(requestedPath).isDirectory()) {
          runCwd = requestedPath;
          allowedTools = 'Read,Grep,Glob';
        }
      } catch (err) {
        // Path no longer exists (e.g. a temp checkout was cleaned up) — fall back silently.
      }
    }

    const args = [
      '-p', userPrompt,
      '--append-system-prompt', systemPrompt,
      '--output-format', 'stream-json',
      '--verbose',
      '--allowedTools', allowedTools,
      '--permission-mode', 'acceptEdits',
    ];

    send({ type: 'started', runId, findingId, agent: agentName });

    const child = spawn('claude', args, { cwd: runCwd, shell: false });
    children.set(runId, child);

    let stdoutBuffer = '';
    let fullText = '';

    child.stdout.on('data', (chunk) => {
      stdoutBuffer += chunk.toString();
      const lines = stdoutBuffer.split('\n');
      stdoutBuffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;

        let event;
        try {
          event = JSON.parse(line);
        } catch (err) {
          continue;
        }

        if (event.type === 'assistant' && event.message && Array.isArray(event.message.content)) {
          for (const block of event.message.content) {
            if (block.type === 'text' && typeof block.text === 'string') {
              fullText += block.text;
            }
          }
        }

        send({ type: 'event', runId, findingId, event });
      }
    });

    child.stderr.on('data', (chunk) => {
      send({ type: 'stderr', runId, findingId, data: chunk.toString() });
    });

    child.on('close', (code) => {
      const verdict = extractVerdict(fullText);
      if (runRecord && runRecord.status === 'running') {
        runRecord.status = code === 0 ? 'done' : 'error';
      }
      if (runRecord) {
        runRecord.verdict = verdict;
        runRecord.fullText = fullText;
        runRecord.finishedAt = Date.now();
      }
      if (finding) finding.status = deriveStatus(finding);
      send({ type: 'done', runId, findingId, code, verdict, fullText });
      children.delete(runId);
      runIndex.delete(runId);
    });

    child.on('error', (err) => {
      if (runRecord) {
        runRecord.status = 'error';
        runRecord.finishedAt = Date.now();
      }
      if (finding) finding.status = deriveStatus(finding);
      send({ type: 'error', runId, findingId, message: `Failed to spawn claude: ${err.message}` });
      children.delete(runId);
      runIndex.delete(runId);
    });
  });

  ws.on('close', () => {
    // A module-scoped reasoning scan's children are keyed by synthetic `${runId}::modN` ids
    // (see runLLMReasoningScan()), not the scan's own runId, so the per-child lookups below
    // (runIndex/scanRunIndex/etc, all keyed by the *real* runId) miss them — every child still
    // gets killed regardless via child.kill() at the end of this loop, but mark every
    // still-running scan cancelled directly here too, so a modular scan's bookkeeping doesn't
    // depend on its module keys happening to match a real runId.
    for (const scanIndexed of scanRunIndex.values()) {
      if (scanIndexed.status === 'running') {
        scanIndexed.status = 'cancelled';
        scanIndexed.finishedAt = Date.now();
      }
    }
    for (const [runId, child] of children.entries()) {
      const indexed = runIndex.get(runId);
      if (indexed && indexed.run.status === 'running') {
        indexed.run.status = 'cancelled';
        indexed.run.finishedAt = Date.now();
      }
      const atmIndexed = appThreatModelRunIndex.get(runId);
      if (atmIndexed && atmIndexed.status === 'running') {
        atmIndexed.status = 'cancelled';
        atmIndexed.finishedAt = Date.now();
      }
      const caIndexed = controlAssessmentRunIndex.get(runId);
      if (caIndexed && caIndexed.status === 'running') {
        caIndexed.status = 'cancelled';
        caIndexed.finishedAt = Date.now();
      }
      child.kill();
    }
    children.clear();
  });
});

// Safety gate for the one flow that lets an agent write to a finding's real target directory:
// refuse unless it's a clean git working tree, so every change is trivially inspectable
// (git diff) and revertible (git checkout) entirely outside this app.
function checkCleanGitTarget(targetPath) {
  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (err) {
    return { ok: false, message: `Path not found: ${targetPath}` };
  }
  if (!stat.isDirectory()) return { ok: false, message: `Not a directory: ${targetPath}` };

  let gitStatus;
  try {
    gitStatus = execFileSync('git', ['status', '--porcelain'], { cwd: targetPath, encoding: 'utf8' });
  } catch (err) {
    return { ok: false, message: `Applying a fix requires a git repository — "${targetPath}" doesn't look like one: ${String(err.message).split('\n')[0]}` };
  }
  if (gitStatus.trim()) {
    return { ok: false, message: 'Target directory has uncommitted changes. Commit or stash them first so the fix stays cleanly revertible.' };
  }
  return { ok: true };
}

// Validates and applies a Remediation verdict's `edit_plan` (see sast-engine/
// remediation-apply.js) against the real target directory, then captures a git diff of
// whatever actually changed. This is the ONE place any agent's output can touch disk in this
// app — the model that produced `verdict` never gets Edit/Write tools itself (see CLAUDE.md's
// Security posture); it only proposes edits, which get validated against the live file before
// anything is written.
//
// Returns { applied, diff, error }:
//   - no edit_plan / empty files array -> { applied: false, diff: null, error: null } — the
//     model chose not to propose an edit (matches remediation.md's own "don't guess" guidance,
//     e.g. an architectural fix). Not a failure.
//   - edit_plan present but invalid (ambiguous/missing find string, protected path, no-op) ->
//     { applied: false, diff: null, error: <reason> } — a real failure, surfaced as the run
//     erroring so the Remediation Loop shows "Fix failed" / offers a retry.
//   - edit_plan valid -> written to disk, { applied: true, diff, error: null }.
async function applyRemediationPlan(targetPath, verdict) {
  const plan = verdict && verdict.edit_plan;
  if (!plan || !Array.isArray(plan.files) || plan.files.length === 0) {
    return { applied: false, diff: null, error: null };
  }

  const engine = await loadSastEngine();
  const validation = engine.validatePlan(targetPath, plan);
  if (!validation.ok) {
    return { applied: false, diff: null, error: `Proposed edit could not be applied: ${validation.reason}` };
  }

  try {
    engine.applyPlan(targetPath, plan);
  } catch (err) {
    return { applied: false, diff: null, error: `Failed to apply edit: ${err.message}` };
  }

  let diff = '';
  try {
    diff = execFileSync('git', ['diff'], { cwd: targetPath, encoding: 'utf8' });
  } catch (err) {
    diff = `(failed to capture git diff: ${String(err.message).split('\n')[0]})`;
  }
  return { applied: true, diff: diff || null, error: null };
}

// Spawns a real per-finding agent stage against a specific cwd (used by
// handleRemediateApplyMessage below, kept separate from that function just to keep it
// readable). Pushes/updates the run record and relays started/event/stderr/done exactly like
// the generic per-finding `run` path, registered in the same `runIndex`/`children` maps, so
// cancellation and the client's existing run-rendering code both work unmodified.
function spawnAgentStage({ runId, findingId, finding, agentName, systemPrompt, userPrompt, allowedTools, cwd, instruction, children, send }) {
  return new Promise((resolve) => {
    const runRecord = {
      runId, agent: agentName, instruction, context: userPrompt,
      status: 'running', verdict: null, fullText: '',
      startedAt: Date.now(), finishedAt: null,
    };
    finding.runs.push(runRecord);
    runIndex.set(runId, { findingId: finding.id, run: runRecord });

    send({ type: 'started', runId, findingId, agent: agentName });

    const args = [
      '-p', userPrompt,
      '--append-system-prompt', systemPrompt,
      '--output-format', 'stream-json',
      '--verbose',
      '--allowedTools', allowedTools,
      '--permission-mode', 'acceptEdits',
    ];
    const child = spawn('claude', args, { cwd, shell: false });
    children.set(runId, child);

    let stdoutBuffer = '';
    let fullText = '';

    child.stdout.on('data', (chunk) => {
      stdoutBuffer += chunk.toString();
      const lines = stdoutBuffer.split('\n');
      stdoutBuffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        let event;
        try {
          event = JSON.parse(line);
        } catch (err) {
          continue;
        }
        if (event.type === 'assistant' && event.message && Array.isArray(event.message.content)) {
          for (const block of event.message.content) {
            if (block.type === 'text' && typeof block.text === 'string') fullText += block.text;
          }
        }
        send({ type: 'event', runId, findingId, event });
      }
    });

    child.stderr.on('data', (chunk) => {
      send({ type: 'stderr', runId, findingId, data: chunk.toString() });
    });

    child.on('close', (code) => {
      const cancelled = runRecord.status === 'cancelled';
      const verdict = extractVerdict(fullText);
      if (runRecord.status === 'running') runRecord.status = code === 0 ? 'done' : 'error';
      runRecord.verdict = verdict;
      runRecord.fullText = fullText;
      runRecord.finishedAt = Date.now();
      children.delete(runId);
      runIndex.delete(runId);
      resolve({ code, verdict, cancelled });
    });

    child.on('error', (err) => {
      runRecord.status = 'error';
      runRecord.finishedAt = Date.now();
      children.delete(runId);
      runIndex.delete(runId);
      send({ type: 'error', runId, findingId, message: `Failed to spawn claude: ${err.message}` });
      resolve({ code: 1, verdict: null, cancelled: false });
    });
  });
}

// Writes a real fix to the finding's actual target directory (git-clean gated) and stops — no
// automatic Verify chain. This is what the Agent Triage loop cell's single "advance" button
// fires when the next step in Found -> Fixed -> Verified is "Fixed"; the human clicks the
// advance button again once ready to run Verify as its own separate step. Remediation itself
// runs read-only (Read,Grep,Glob) and proposes an `edit_plan` in its verdict rather than
// editing directly — applyRemediationPlan() is what actually touches disk, after validating
// the plan against the real file (see CLAUDE.md's Security posture).
function handleRemediateApplyMessage(msg, { children, send }) {
  const findingId = msg.findingId ? String(msg.findingId) : null;
  const runId = String(msg.runId || '').trim();
  const context = String(msg.context || '');
  const instruction = String(msg.instruction || '');
  const targetPath = String(msg.path || '').trim();

  if (!RUN_ID_RE.test(runId)) {
    send({ type: 'error', message: 'Invalid or missing run id.' });
    return;
  }
  if (children.has(runId)) {
    send({ type: 'error', runId, findingId, message: 'This run is already active.' });
    return;
  }
  const finding = findingId ? findings.get(findingId) : null;
  if (!finding) {
    send({ type: 'error', runId, findingId, message: 'Unknown finding.' });
    return;
  }
  if (!targetPath) {
    send({ type: 'error', runId, findingId, message: 'A target directory is required to apply a fix.' });
    return;
  }

  const gate = checkCleanGitTarget(targetPath);
  if (!gate.ok) {
    send({ type: 'error', runId, findingId, message: gate.message });
    return;
  }

  const remediationAgentPath = agentFilePath('remediation');
  if (!fs.existsSync(remediationAgentPath)) {
    send({ type: 'error', runId, findingId, message: 'Remediation agent file is missing.' });
    return;
  }
  let remediationPrompt;
  try {
    remediationPrompt = fs.readFileSync(remediationAgentPath, 'utf8');
  } catch (err) {
    send({ type: 'error', runId, findingId, message: `Failed to read agent prompt: ${err.message}` });
    return;
  }

  (async () => {
    const userPrompt = `${instruction}\n\nFinding context:\n${context}\n\nApply mode: propose the fix as an \`edit_plan\` in your verdict (see your instructions) — you do not have Edit/Write access; a separate deterministic step will validate and apply your plan against the real file.`;
    const rem = await spawnAgentStage({
      runId, findingId, finding, agentName: 'remediation',
      systemPrompt: remediationPrompt, userPrompt, allowedTools: 'Read,Grep,Glob',
      cwd: targetPath, instruction, children, send,
    });

    if (!rem.cancelled && rem.code === 0 && rem.verdict) {
      const result = await applyRemediationPlan(targetPath, rem.verdict);
      rem.verdict.applied_diff = result.diff;
      const remRunRecord = finding.runs.find((r) => r.runId === runId);
      if (remRunRecord) {
        remRunRecord.verdict = rem.verdict;
        if (result.error) {
          remRunRecord.status = 'error';
          rem.code = 1;
          send({ type: 'stderr', runId, findingId, data: result.error });
        }
      }
    }
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId, findingId, code: rem.code, verdict: rem.verdict, fullText: '' });
  })();
}

// Chains Remediation (write) -> Verify for the loop cell's "run all stages" button. This used
// to run Triage first too, but Triage is no longer a live agent stage (see CLAUDE.md) — every
// finding reaching this handler already carries a triage verdict from when it was created
// (sast-engine's VerifierAgent for scan-sourced findings, or a neutral placeholder for manual
// ones), and buildBaseContext() on the client already folds that prior verdict into `context`
// below, so Remediation sees it without a fresh live call.
function handleRemediateAllMessage(msg, { children, send }) {
  const findingId = msg.findingId ? String(msg.findingId) : null;
  const remediationRunId = String(msg.remediationRunId || '').trim();
  const verifyRunId = String(msg.verifyRunId || '').trim();
  const context = String(msg.context || '');
  const instruction = String(msg.instruction || '');
  const targetPath = String(msg.path || '').trim();

  if (!RUN_ID_RE.test(remediationRunId) || !RUN_ID_RE.test(verifyRunId)) {
    send({ type: 'error', message: 'Invalid or missing run id(s).' });
    return;
  }
  if (children.has(remediationRunId) || children.has(verifyRunId)) {
    send({ type: 'error', runId: remediationRunId, findingId, message: 'This run is already active.' });
    return;
  }
  const finding = findingId ? findings.get(findingId) : null;
  if (!finding) {
    send({ type: 'error', runId: remediationRunId, findingId, message: 'Unknown finding.' });
    return;
  }
  if (!targetPath) {
    send({ type: 'error', runId: remediationRunId, findingId, message: 'A target directory is required to run the full pipeline.' });
    return;
  }

  const gate = checkCleanGitTarget(targetPath);
  if (!gate.ok) {
    send({ type: 'error', runId: remediationRunId, findingId, message: gate.message });
    return;
  }

  const remediationAgentPath = agentFilePath('remediation');
  const verifyAgentPath = agentFilePath('verify');
  if (!fs.existsSync(remediationAgentPath) || !fs.existsSync(verifyAgentPath)) {
    send({ type: 'error', runId: remediationRunId, findingId, message: 'Remediation or Verify agent file is missing.' });
    return;
  }

  let remediationPrompt, verifyPrompt;
  try {
    remediationPrompt = fs.readFileSync(remediationAgentPath, 'utf8');
    verifyPrompt = fs.readFileSync(verifyAgentPath, 'utf8');
  } catch (err) {
    send({ type: 'error', runId: remediationRunId, findingId, message: `Failed to read agent prompt: ${err.message}` });
    return;
  }

  (async () => {
    const remediationUserPrompt = `${instruction}\n\nFinding context:\n${context}\n\nApply mode: propose the fix as an \`edit_plan\` in your verdict (see your instructions) — you do not have Edit/Write access; a separate deterministic step will validate and apply your plan against the real file.`;
    const rem = await spawnAgentStage({
      runId: remediationRunId, findingId, finding, agentName: 'remediation',
      systemPrompt: remediationPrompt, userPrompt: remediationUserPrompt,
      allowedTools: 'Read,Grep,Glob', cwd: targetPath, instruction, children, send,
    });

    if (rem.cancelled || rem.code !== 0 || !rem.verdict) {
      finding.status = deriveStatus(finding);
      send({ type: 'done', runId: remediationRunId, findingId, code: rem.code, verdict: rem.verdict, fullText: '' });
      return;
    }

    const result = await applyRemediationPlan(targetPath, rem.verdict);
    rem.verdict.applied_diff = result.diff;
    const remRunRecord = finding.runs.find((r) => r.runId === remediationRunId);
    if (remRunRecord) {
      remRunRecord.verdict = rem.verdict;
      if (result.error) {
        remRunRecord.status = 'error';
        rem.code = 1;
        send({ type: 'stderr', runId: remediationRunId, findingId, data: result.error });
      }
    }
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId: remediationRunId, findingId, code: rem.code, verdict: rem.verdict, fullText: '' });

    if (result.error) return; // apply failed — don't chain into Verify against an unapplied fix

    const verifyUserPrompt = `${instruction}\n\nFinding context:\n${context}\n\nThe Remediation agent just ran against this exact directory and reported:\n${JSON.stringify(rem.verdict, null, 2)}\n\nConfirm whether the fix it describes actually landed and resolves the finding.`;
    const ver = await spawnAgentStage({
      runId: verifyRunId, findingId, finding, agentName: 'verify',
      systemPrompt: verifyPrompt, userPrompt: verifyUserPrompt,
      allowedTools: 'Read,Grep,Glob', cwd: targetPath, instruction, children, send,
    });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId: verifyRunId, findingId, code: ver.code, verdict: ver.verdict, fullText: '' });
  })();
}

function handleScanMessage(msg, { children, send }) {
  const runId = String(msg.runId || '').trim();
  if (!RUN_ID_RE.test(runId)) {
    send({ type: 'error', message: 'Invalid or missing runId.' });
    return;
  }
  if (scanRunIndex.has(runId) || children.has(runId)) {
    send({ type: 'error', runId, message: 'This runId is already active.' });
    return;
  }

  const targetPath = String(msg.path || '').trim();
  const branch = String(msg.branch || '').trim();
  const app = String(msg.app || '').trim();
  const scanType = SCAN_TYPES.includes(msg.scanType) ? msg.scanType : 'reasoning';
  const scope = SCAN_SCOPES.includes(msg.scope) ? msg.scope : 'full';
  const baseBranch = String(msg.baseBranch || '').trim();
  // Whether reasoning-half calls get a --max-budget-usd cap at all — defaults true (the safe
  // default) unless the client explicitly sends false (the Reasoning Scan form's Budget cap
  // toggle). Irrelevant for an SCA scan, which never touches the reasoning half.
  const budgetEnabled = msg.budgetEnabled !== false;

  if (!targetPath) {
    send({ type: 'scan-error', runId, message: 'A target directory path is required.' });
    return;
  }

  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (err) {
    send({ type: 'scan-error', runId, message: `Path not found: ${targetPath}` });
    return;
  }
  if (!stat.isDirectory()) {
    send({ type: 'scan-error', runId, message: `Not a directory: ${targetPath}` });
    return;
  }

  let diffFiles = null;
  if (scope === 'diff') {
    if (scanType === 'sca') {
      send({ type: 'scan-error', runId, message: 'Diff-only scope does not apply to a dependency audit — it always reviews the full manifest/lockfile.' });
      return;
    }
    if (!baseBranch || !BRANCH_NAME_RE.test(baseBranch)) {
      send({ type: 'scan-error', runId, message: `A valid base branch is required for diff-only scope (got "${baseBranch}").` });
      return;
    }
    try {
      const out = execFileSync('git', ['diff', '--name-only', `${baseBranch}...HEAD`], { cwd: targetPath, encoding: 'utf8' });
      diffFiles = out.split('\n').map((l) => l.trim()).filter(Boolean);
    } catch (err) {
      send({ type: 'scan-error', runId, message: `Failed to diff against "${baseBranch}": ${String(err.message).split('\n')[0]}` });
      return;
    }
    if (!diffFiles.length) {
      send({ type: 'scan-error', runId, message: `No changed files between "${baseBranch}" and HEAD — nothing to scan.` });
      return;
    }
  }

  const scan = {
    id: crypto.randomUUID(),
    runId,
    path: targetPath,
    instruction: '',
    branch: branch || null,
    app: app || null,
    scanType,
    scope,
    baseBranch: scope === 'diff' ? baseBranch : null,
    diffFileCount: diffFiles ? diffFiles.length : null,
    budgetEnabled,
    status: 'running',
    error: null,
    findingIds: [],
    startedAt: Date.now(),
    finishedAt: null,
  };
  scans.set(scan.id, scan);
  scanRunIndex.set(runId, scan);

  send({ type: 'scan-started', runId, scanId: scan.id, path: targetPath });

  const finish = (createdListItems) => {
    if (scan.status !== 'cancelled') {
      scan.status = 'done';
      scan.error = null;
    }
    scan.finishedAt = Date.now();
    send({ type: 'scan-done', runId, scanId: scan.id, code: 0, findings: createdListItems });
    scanRunIndex.delete(runId);
  };
  const fail = (message) => {
    if (scan.status !== 'cancelled') {
      scan.status = 'error';
      scan.error = message;
    }
    scan.finishedAt = Date.now();
    send({ type: 'scan-error', runId, scanId: scan.id, message });
    scanRunIndex.delete(runId);
  };

  if (scanType === 'sca') {
    runDeterministicScaScan(scan, targetPath, { send, finish, fail });
  } else {
    runHybridReasoningScan(scan, targetPath, diffFiles, { children, send, finish, fail });
  }
}

// Reasoning Scan runs two independent engines against the same directory and merges their
// results (see CLAUDE.md's Reasoning Scan bullet for the reasoning behind this):
//   - sast-engine's 29 deterministic pattern agents + VerifierAgent — fast, consistent
//     coverage of known vulnerability categories, no LLM involved.
//   - a real `claude -p` reasoning pass over agents/scan.md — covers business-logic/
//     authorization/attack-surface reasoning a fixed rule set structurally can't do, and
//     assigns its own findings a full triage verdict in the same pass (there's no separate
//     live Triage stage to hand off to).
// Both run concurrently; whichever finishes first still has to wait for the other before
// findings are created, since a finding from one pass might duplicate one from the other.
async function runHybridReasoningScan(scan, targetPath, diffFiles, { children, send, finish, fail }) {
  let engine;
  try {
    engine = await loadSastEngine();
  } catch (err) {
    fail(`Failed to load scan engine: ${err.message}`);
    return;
  }

  const [detResult, llmResult] = await Promise.all([
    runDeterministicPatternScan(engine, scan, targetPath, diffFiles, { send }),
    runLLMReasoningScan(scan, targetPath, diffFiles, { children, send }),
  ]);

  if (scan.status === 'cancelled') return;

  if (detResult.error && llmResult.error) {
    fail(`Deterministic scan: ${detResult.error} — Reasoning pass: ${llmResult.error}`);
    return;
  }
  if (detResult.error) send({ type: 'scan-warning', runId: scan.runId, scanId: scan.id, message: `Deterministic scan failed (reasoning pass still succeeded): ${detResult.error}` });
  if (llmResult.error) send({ type: 'scan-warning', runId: scan.runId, scanId: scan.id, message: `Reasoning pass failed (deterministic scan still succeeded): ${llmResult.error}` });

  const created = [];
  for (const f of detResult.findings) {
    const finding = findingFromSastEngine(f, scan, targetPath);
    findings.set(finding.id, finding);
    scan.findingIds.push(finding.id);
    created.push(toListItem(finding));
  }

  // Dedup: drop a reasoning-pass finding whose file+line sits within a couple lines of a
  // deterministic finding in the same file — same underlying issue, no need to show it twice.
  // Findings with no resolvable line (e.g. a cross-file business-logic finding) always survive,
  // since there's nothing meaningful to compare them against.
  const detLocations = detResult.findings
    .map((f) => ({ file: f.file ? path.relative(targetPath, f.file).split(path.sep).join('/') : null, line: f.line }))
    .filter((l) => l.file);
  const isDuplicateOfDeterministic = (rf) => {
    const loc = parseFileLine(rf.file);
    if (!loc.file || loc.line == null) return false;
    return detLocations.some((d) => d.file === loc.file && d.line != null && Math.abs(d.line - loc.line) <= 2);
  };

  for (const rf of llmResult.findings) {
    const title = String(rf.title || '').trim();
    const description = String(rf.description || '').trim();
    if (!title || !description) continue; // skip malformed entries rather than fail the whole scan
    if (isDuplicateOfDeterministic(rf)) continue;
    const finding = findingFromLLMScan(rf, scan);
    findings.set(finding.id, finding);
    scan.findingIds.push(finding.id);
    created.push(toListItem(finding));
  }

  // Real dollar spend across every reasoning-half call (modules + the cross-cutting pass),
  // aggregated from each call's stream-json `result.total_cost_usd` — persisted on the scan
  // record (not just relayed live via scan-progress) so it's visible via GET /api/scans/:id too.
  scan.reasoningCostUsd = llmResult.costUsd || 0;
  finish(created);
}

// Runs sast-engine's deterministic pattern agents and returns { findings, error } rather than
// calling finish()/fail() directly, since runHybridReasoningScan() needs both engines' results
// together before it can dedupe and create findings.
async function runDeterministicPatternScan(engine, scan, targetPath, diffFiles, { send }) {
  let orchestrator;
  try {
    orchestrator = await engine.buildOrchestratorAsync(targetPath);
  } catch (err) {
    return { findings: [], error: `Failed to initialize scan engine: ${err.message}` };
  }

  let done = 0;
  const total = orchestrator.agents.length;
  try {
    const result = await orchestrator.runAll(targetPath, {
      quiet: true,
      onlyFiles: diffFiles || undefined,
      onAgentDone: (agentResult, agentFindings) => {
        done++;
        if (scan.status === 'cancelled') return;
        // Drives the "Pattern match" progress bar on the scan card — see updateDetBar() in
        // index.html. Sent every time regardless of whether this agent found anything, unlike
        // the scan-event below (narration-only, so only sent when there's something to narrate).
        send({ type: 'scan-progress', runId: scan.runId, scanId: scan.id, engine: 'deterministic', done, total });
        if (!agentFindings.length) return;
        const lines = agentFindings.map((f) => {
          const rel = f.file ? path.relative(targetPath, f.file).split(path.sep).join('/') : 'unknown file';
          const loc = f.line ? `${rel}:${f.line}` : rel;
          return `[${normalizeSeverity(f.severity)}] \`${loc}\` — ${f.title}`;
        });
        send({
          type: 'scan-event',
          runId: scan.runId,
          scanId: scan.id,
          event: { type: 'assistant', message: { content: [{ type: 'text', text: lines.join('\n') }] } },
        });
      },
    });
    return { findings: result.findings, error: null };
  } catch (err) {
    return { findings: [], error: err.message };
  }
}

// Deterministically splits a target directory into scoped "modules" for the reasoning pass —
// one per top-level subdirectory (skipping sast-engine's own SKIP_DIRS + dotfiles/dotdirs), plus
// one bucket for any loose files sitting directly in the root. Each module becomes its own
// scoped claude -p call in runLLMReasoningScan() instead of one unscoped pass over the whole
// tree, so token spend and hallucination surface stop scaling with total repo size. This is a
// coarse proxy for "module" (a real one would need a symbol/call-graph index this app doesn't
// have — see the design discussion this shipped under) but costs nothing beyond a directory
// listing and works for the common case of one top-level dir per logical area (src/, lib/,
// routes/, services/, etc).
// Recursively groups a flat file list by path segment, splitting any group whose file count
// exceeds REASONING_MODULE_MAX_FILES by descending into the *next* path segment instead — e.g.
// a repo whose only top-level entry is `src/` groups everything under the same segment at depth
// 0 (no separation there), so it tries depth 1 next and splits by src's own subdirectories
// instead; any of those that's still too big splits one level deeper again, up to
// REASONING_MODULE_SPLIT_MAX_DEPTH. A group that can't be subdivided further even at max depth
// (hundreds of flat files with no nesting left to split on) is returned as-is rather than
// recursing forever; it's still bounded by --max-budget-usd regardless of size.
function splitFileGroup(fileList, depth) {
  if (fileList.length <= REASONING_MODULE_MAX_FILES) return [fileList];
  if (depth >= REASONING_MODULE_SPLIT_MAX_DEPTH) return [fileList];
  const buckets = new Map();
  for (const rel of fileList) {
    const parts = rel.split('/');
    const key = parts.length > depth + 1 ? parts[depth] : `(files here)`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(rel);
  }
  // Grouping by this depth's segment didn't separate anything — e.g. every file shares the same
  // single top-level directory (a repo with one `src/` and nothing else at the root). Try the
  // *next* depth on the same file list instead of giving up here; REASONING_MODULE_SPLIT_MAX_DEPTH
  // above still bounds how far this can recurse.
  if (buckets.size <= 1) return splitFileGroup(fileList, depth + 1);
  const result = [];
  for (const groupFiles of buckets.values()) {
    if (groupFiles.length > REASONING_MODULE_MAX_FILES) {
      result.push(...splitFileGroup(groupFiles, depth + 1));
    } else {
      result.push(groupFiles);
    }
  }
  return result;
}

// Deterministically splits a target directory into scoped "modules" for the reasoning pass,
// sized by actual file count — not just directory boundaries, which was the previous version's
// biggest weakness (a repo with one giant top-level `src/` and a few tiny folders got zero real
// scoping benefit, since "src/" alone was still the whole codebase in one call). This is still a
// coarse proxy for "module" (a real one would need a symbol/call-graph index this app doesn't
// have) but it's now grounded in the repo's real shape:
//   1. Enumerate every real file under targetPath via fast-glob, respecting sast-engine's own
//      skip-dirs/extensions/filenames/.gitignore rules — the same "real code" definition the
//      deterministic engine uses, so a module's budget isn't spent surveying node_modules or a
//      minified bundle.
//   2. Recursively split (splitFileGroup()) any group bigger than REASONING_MODULE_MAX_FILES by
//      subdirectory, starting from the top-level directory and descending only as needed.
//   3. Bin-pack the resulting groups smallest-first into buckets capped at
//      REASONING_MODULE_MAX_FILES each (by actual size, not arbitrary directory index — the
//      previous version's other weak spot), so a repo with many small directories doesn't spawn
//      one process per directory. Never exceeds REASONING_MODULE_MAX total buckets — anything
//      beyond that merges into whichever bucket is currently smallest rather than being dropped.
// A module's `paths` is the literal list of relative file paths it covers (not a directory
// reference) — the same explicit-file-list style the diff-scope flow already used, so the model
// gets an exact manifest instead of needing its own Glob call to discover what's in scope. A
// small repo (or one that just doesn't have much real code) naturally collapses into a single
// module here — there's no special-cased "skip partitioning" path, it falls out of the algorithm.
function partitionReasoningModules(targetPath, engine) {
  const ignore = Array.from(engine.SKIP_DIRS || []).flatMap((d) => [`**/${d}/**`, `${d}/**`]);
  if (typeof engine.loadGitignorePatterns === 'function') {
    ignore.push(...engine.loadGitignorePatterns(targetPath));
  }

  let allFiles;
  try {
    allFiles = fg.sync(['**/*'], { cwd: targetPath, onlyFiles: true, dot: false, ignore });
  } catch {
    return [];
  }

  const skipExt = engine.SKIP_EXTENSIONS || new Set();
  const skipNames = engine.SKIP_FILENAMES || new Set();
  const maxSize = engine.MAX_FILE_SIZE || 1_000_000;
  const files = allFiles.filter((rel) => {
    const ext = path.extname(rel).toLowerCase();
    if (skipExt.has(ext)) return false;
    const base = path.basename(rel);
    if (skipNames.has(base) || base.endsWith('.min.js') || base.endsWith('.min.css')) return false;
    try {
      if (fs.statSync(path.join(targetPath, rel)).size > maxSize) return false;
    } catch {
      return false;
    }
    return true;
  });
  if (!files.length) return [];

  const rawGroups = splitFileGroup(files, 0);

  const sorted = rawGroups.slice().sort((a, b) => a.length - b.length);
  const buckets = [];
  for (const group of sorted) {
    let target = buckets.find((b) => b.length + group.length <= REASONING_MODULE_MAX_FILES);
    if (!target && buckets.length < REASONING_MODULE_MAX) {
      target = [];
      buckets.push(target);
    }
    if (!target) {
      target = buckets.reduce((min, b) => (b.length < min.length ? b : min), buckets[0]);
    }
    target.push(...group);
  }

  return buckets.map((paths) => ({
    label: paths.length <= 2 ? paths.join(', ') : `${paths.slice(0, 2).join(', ')}, +${paths.length - 2} more`,
    paths,
  }));
}

// Runs the LLM reasoning pass (agents/scan.md), relaying its real narration live exactly like
// the pipeline's other claude -p stages, and returns { findings, error } — a raw array of
// finding objects merged across every module call (not yet turned into Finding records; see
// findingFromLLMScan(), called by runHybridReasoningScan() after both engines finish).
//
// Diff scope stays exactly one call over the pre-bounded changed-file list, same as before this
// scan was module-scoped — there's nothing to partition when the scope is already tight. Full
// scope partitions the directory (partitionReasoningModules()) and runs one scoped call per
// module, at most REASONING_MODULE_CONCURRENCY at a time, each capped at REASONING_MODULE_BUDGET_USD
// via --max-budget-usd so a single module can't blow an unbounded amount of spend chasing a
// dead end. Each module's child process is registered under its own synthetic
// `${scan.runId}::mod${i}` key in `children` (tracked on scan.moduleRunIds) so the WS 'cancel'
// handler can kill every in-flight module, not just one child, for this scan.
async function runLLMReasoningScan(scan, targetPath, diffFiles, { children, send }) {
  const scanAgentPath = agentFilePath('scan');
  if (!fs.existsSync(scanAgentPath)) {
    return { findings: [], error: 'Scan agent (agents/scan.md) is not available.' };
  }
  let systemPrompt;
  try {
    systemPrompt = fs.readFileSync(scanAgentPath, 'utf8');
  } catch (err) {
    return { findings: [], error: `Failed to read scan agent prompt: ${err.message}` };
  }

  let modules;
  if (diffFiles) {
    modules = [{ label: 'diff', paths: diffFiles }];
  } else {
    let engine;
    try {
      engine = await loadSastEngine();
    } catch (err) {
      return { findings: [], error: `Failed to load scan engine: ${err.message}` };
    }
    modules = partitionReasoningModules(targetPath, engine);
    if (!modules.length) return { findings: [], error: null }; // nothing to scan — a valid empty outcome
    // A cross-cutting pass sees the whole tree, unscoped — every module call above is told to
    // stay inside its own file list, which means none of them can notice a protection defined
    // in one module (auth middleware, a validator) never actually being applied in another. This
    // one extra call exists specifically to catch that class of gap. See CLAUDE.md.
    modules = [...modules, { label: '(cross-cutting review)', paths: null, crosscut: true }];
  }

  scan.moduleRunIds = [];
  const total = modules.length;
  let done = 0;
  const allFindings = [];
  const moduleErrors = [];
  let totalCostUsd = 0;

  const runOneModule = (mod, index) => new Promise((resolve) => {
    if (scan.status === 'cancelled') { resolve(); return; }

    const budgetUsd = mod.crosscut ? REASONING_CROSSCUT_BUDGET_USD : REASONING_MODULE_BUDGET_USD;
    const promptParts = [
      'Scan this directory for real, concrete security vulnerabilities in the code, and reason ' +
      'about externally-reachable endpoints and attack surface the way an attacker interacting ' +
      'with the running application could exploit them. No live instance is being hit — this is ' +
      'inferred from static code, so frame findings accordingly.',
    ];
    if (mod.crosscut) {
      promptParts.push(
        'This is a cross-cutting architectural pass, not a file-by-file review — separate calls ' +
        'are already deep-diving each module\'s own files individually, so do NOT re-review file ' +
        'internals in depth here. Instead, specifically check whether protections defined in one ' +
        'place are actually applied everywhere they should be: does every route that needs auth ' +
        'actually invoke the auth/authorization middleware, not just have it defined nearby? Does ' +
        'every handler touching user input actually run it through the validator/sanitizer the ' +
        'codebase defines elsewhere, or does some call site skip it? Are there routes registered ' +
        'without going through the same middleware chain as their siblings? Sample route ' +
        'registration files, middleware definitions, and shared validators/config across the whole ' +
        'tree to answer these questions — you have access to the entire directory for this pass, ' +
        'unlike the per-module calls.'
      );
    } else if (diffFiles) {
      promptParts.push(`Limit your review to only the following changed files versus the base branch — do not scan anything else in the repository:\n${mod.paths.map((p) => `- ${p}`).join('\n')}`);
    } else {
      promptParts.push(`Limit your review to only the following files, relative to the target directory below — do not read or reason about anything outside them:\n${mod.paths.map((p) => `- ${p}`).join('\n')}`);
    }
    promptParts.push(`Target directory: ${targetPath}`);
    const userPrompt = promptParts.join('\n\n');

    const args = [
      '-p', userPrompt,
      '--append-system-prompt', systemPrompt,
      '--output-format', 'stream-json',
      '--verbose',
      '--allowedTools', 'Read,Grep,Glob',
      '--permission-mode', 'acceptEdits',
    ];
    // scan.budgetEnabled defaults true (see handleScanMessage) — the Reasoning Scan form's
    // "Budget cap" toggle is the only way to turn this off, an explicit opt-in for when a scan
    // is getting cut short by the cap and the user wants it to finish regardless of cost.
    if (scan.budgetEnabled) args.push('--max-budget-usd', String(budgetUsd));

    const moduleRunId = `${scan.runId}::mod${index}`;
    const child = spawn('claude', args, { cwd: targetPath, shell: false });
    children.set(moduleRunId, child);
    scan.moduleRunIds.push(moduleRunId);

    let stdoutBuffer = '';
    let fullText = '';
    // Captures the final stream-json `result` event — carries `total_cost_usd` (real dollar
    // spend for this call, confirmed empirically — see CLAUDE.md) and, when the process hit its
    // --max-budget-usd cap rather than finishing normally, `subtype: 'error_max_budget_usd'`
    // (also `is_error: true`, `terminal_reason: 'budget_exhausted'`). Used in child.on('close')
    // below to tell a real "ran out of budget mid-exploration" from a generic crash, and to
    // aggregate real spend rather than estimating it from token/tool-call counts.
    let resultEvent = null;

    child.stdout.on('data', (chunk) => {
      stdoutBuffer += chunk.toString();
      const lines = stdoutBuffer.split('\n');
      stdoutBuffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        let event;
        try {
          event = JSON.parse(line);
        } catch (err) {
          continue;
        }
        if (event.type === 'assistant' && event.message && Array.isArray(event.message.content)) {
          for (const block of event.message.content) {
            if (block.type === 'text' && typeof block.text === 'string') fullText += block.text;
          }
        }
        if (event.type === 'result') resultEvent = event;
        send({ type: 'scan-event', runId: scan.runId, scanId: scan.id, event });
      }
    });

    child.stderr.on('data', (chunk) => {
      send({ type: 'scan-stderr', runId: scan.runId, scanId: scan.id, data: chunk.toString() });
    });

    const finishModule = (findingsForModule, err) => {
      children.delete(moduleRunId);
      done++;
      if (resultEvent && typeof resultEvent.total_cost_usd === 'number') {
        totalCostUsd += resultEvent.total_cost_usd;
      }
      if (scan.status !== 'cancelled') {
        send({ type: 'scan-progress', runId: scan.runId, scanId: scan.id, engine: 'reasoning', done, total, costUsd: totalCostUsd });
      }
      if (err) moduleErrors.push(`${mod.label}: ${err}`);
      allFindings.push(...findingsForModule);
      resolve();
    };

    child.on('close', (code) => {
      if (scan.status === 'cancelled') { finishModule([], null); return; }
      const parsed = extractVerdict(fullText);
      const rawFindings = parsed && Array.isArray(parsed.findings) ? parsed.findings : [];
      let err = null;
      if (code !== 0) {
        if (resultEvent && resultEvent.subtype === 'error_max_budget_usd') {
          err = rawFindings.length
            ? `hit its $${budgetUsd} budget cap before finishing (kept ${rawFindings.length} finding${rawFindings.length === 1 ? '' : 's'} reported before the cutoff — coverage may be incomplete)`
            : `hit its $${budgetUsd} budget cap before reporting anything — coverage of this ${mod.crosscut ? 'pass' : 'module'} is incomplete, not a clean "nothing found"`;
        } else {
          err = `claude exited with code ${code}`;
        }
      }
      finishModule(rawFindings, err);
    });

    child.on('error', (err) => {
      finishModule([], `Failed to spawn claude: ${err.message}`);
    });
  });

  // Concurrency-limited queue — at most REASONING_MODULE_CONCURRENCY calls run at once
  // regardless of how many modules (plus the one cross-cutting pass) there are, keeping process
  // count sane on a dev machine and avoiding hammering rate limits on a repo with many
  // top-level directories.
  let nextIndex = 0;
  const worker = async () => {
    while (nextIndex < modules.length && scan.status !== 'cancelled') {
      const i = nextIndex++;
      await runOneModule(modules[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(REASONING_MODULE_CONCURRENCY, modules.length) }, worker));

  if (scan.status === 'cancelled') return { findings: [], error: null, costUsd: totalCostUsd };
  if (moduleErrors.length === modules.length) {
    return { findings: [], error: moduleErrors.join(' | '), costUsd: totalCostUsd };
  }
  if (moduleErrors.length) {
    send({ type: 'scan-warning', runId: scan.runId, scanId: scan.id, message: `${moduleErrors.length}/${modules.length} reasoning calls had issues: ${moduleErrors.join(' | ')}` });
  }
  return { findings: allFindings, error: null, costUsd: totalCostUsd };
}

// Splits agents/scan.md's "path:line" file convention into parts for the dedup comparison in
// runHybridReasoningScan(). Normalizes backslashes so a Windows-style path from the model still
// compares equal to sast-engine's forward-slash-normalized relative paths.
function parseFileLine(fileStr) {
  if (!fileStr) return { file: null, line: null };
  const normalized = String(fileStr).trim().split(path.sep).join('/');
  const m = normalized.match(/^(.*?)(?::(\d+))?$/);
  return { file: m ? m[1] : normalized, line: m && m[2] ? parseInt(m[2], 10) : null };
}

// SCA Scan, replacing the old free-reasoning `claude -p` pass over manifests/lockfiles with
// sast-engine's runDepsAudit (wraps the project's own package-manager audit tool — npm/yarn/
// pnpm/pip-audit/bundler-audit). No agent-progress loop needed — this one call is already
// fast. See CLAUDE.md's SCA Scan bullet.
async function runDeterministicScaScan(scan, targetPath, { send, finish, fail }) {
  let engine;
  try {
    engine = await loadSastEngine();
  } catch (err) {
    fail(`Failed to load scan engine: ${err.message}`);
    return;
  }

  let result;
  try {
    result = await engine.runDepsAudit(targetPath);
  } catch (err) {
    fail(`Dependency audit failed: ${err.message}`);
    return;
  }

  if (scan.status === 'cancelled') return;

  if (!result.pm) {
    finish([]); // no supported manifest found — a clean, valid "nothing to report" outcome
    return;
  }
  if (result.error) {
    fail(result.error);
    return;
  }

  if (result.vulns.length) {
    const lines = result.vulns.map((v) => `[${normalizeSeverity(v.severity)}] \`${v.name}@${v.range}\` — ${v.title}`);
    send({
      type: 'scan-event',
      runId: scan.runId,
      scanId: scan.id,
      event: { type: 'assistant', message: { content: [{ type: 'text', text: lines.join('\n') }] } },
    });
  }

  const created = [];
  for (const v of result.vulns) {
    const finding = findingFromDepVuln(v, scan);
    findings.set(finding.id, finding);
    scan.findingIds.push(finding.id);
    created.push(toListItem(finding));
  }
  finish(created);
}

function handleAppThreatModelMessage(msg, { children, send }) {
  const runId = String(msg.runId || '').trim();
  if (!RUN_ID_RE.test(runId)) {
    send({ type: 'app-threat-model-error', message: 'Invalid or missing runId.' });
    return;
  }
  if (children.has(runId)) {
    send({ type: 'app-threat-model-error', runId, message: 'This runId is already active.' });
    return;
  }

  const targetPath = String(msg.path || '').trim();
  const instruction = String(msg.instruction || '').trim();
  const branch = String(msg.branch || '').trim();
  const appLabel = String(msg.app || '').trim();

  if (!targetPath) {
    send({ type: 'app-threat-model-error', runId, message: 'A target directory path is required.' });
    return;
  }

  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (err) {
    send({ type: 'app-threat-model-error', runId, message: `Path not found: ${targetPath}` });
    return;
  }
  if (!stat.isDirectory()) {
    send({ type: 'app-threat-model-error', runId, message: `Not a directory: ${targetPath}` });
    return;
  }

  const agentPath = agentFilePath('app_threat_model');
  if (!fs.existsSync(agentPath)) {
    send({ type: 'app-threat-model-error', runId, message: 'App Threat Model agent (agents/app_threat_model.md) is not available.' });
    return;
  }

  let systemPrompt;
  try {
    systemPrompt = fs.readFileSync(agentPath, 'utf8');
  } catch (err) {
    send({ type: 'app-threat-model-error', runId, message: `Failed to read agent prompt: ${err.message}` });
    return;
  }

  const record = {
    id: crypto.randomUUID(),
    runId,
    path: targetPath,
    app: appLabel || null,
    branch: branch || null,
    instruction,
    status: 'running',
    verdict: null,
    error: null,
    startedAt: Date.now(),
    finishedAt: null,
  };
  appThreatModels.set(record.id, record);
  appThreatModelRunIndex.set(runId, record);

  const promptParts = [
    'Analyze this codebase and produce a whole-app, architecture-level threat model.',
    instruction,
    `Target directory: ${targetPath}`,
  ].filter(Boolean);
  const userPrompt = promptParts.join('\n\n');

  const args = [
    '-p', userPrompt,
    '--append-system-prompt', systemPrompt,
    '--output-format', 'stream-json',
    '--verbose',
    '--allowedTools', 'Read,Grep,Glob',
    '--permission-mode', 'acceptEdits',
  ];

  send({ type: 'app-threat-model-started', runId, id: record.id, path: targetPath });

  const child = spawn('claude', args, { cwd: targetPath, shell: false });
  children.set(runId, child);

  let stdoutBuffer = '';
  let fullText = '';

  child.stdout.on('data', (chunk) => {
    stdoutBuffer += chunk.toString();
    const lines = stdoutBuffer.split('\n');
    stdoutBuffer = lines.pop();

    for (const line of lines) {
      if (!line.trim()) continue;
      let event;
      try {
        event = JSON.parse(line);
      } catch (err) {
        continue;
      }
      if (event.type === 'assistant' && event.message && Array.isArray(event.message.content)) {
        for (const block of event.message.content) {
          if (block.type === 'text' && typeof block.text === 'string') fullText += block.text;
        }
      }
      send({ type: 'app-threat-model-event', runId, id: record.id, event });
    }
  });

  child.stderr.on('data', (chunk) => {
    send({ type: 'app-threat-model-stderr', runId, id: record.id, data: chunk.toString() });
  });

  child.on('close', (code) => {
    const verdict = extractVerdict(fullText);
    if (record.status === 'running') {
      record.status = code === 0 && verdict ? 'done' : 'error';
      record.error = code === 0 && verdict ? null : `claude exited with code ${code}`;
    }
    record.verdict = verdict;
    record.finishedAt = Date.now();
    send({ type: 'app-threat-model-done', runId, id: record.id, code, verdict });
    children.delete(runId);
    appThreatModelRunIndex.delete(runId);
  });

  child.on('error', (err) => {
    record.status = 'error';
    record.error = err.message;
    record.finishedAt = Date.now();
    send({ type: 'app-threat-model-error', runId, id: record.id, message: `Failed to spawn claude: ${err.message}` });
    children.delete(runId);
    appThreatModelRunIndex.delete(runId);
  });
}

function handleControlsAssistMessage(msg, { children, send }) {
  const runId = String(msg.runId || '').trim();
  if (!RUN_ID_RE.test(runId)) {
    send({ type: 'controls-assist-error', message: 'Invalid or missing runId.' });
    return;
  }
  if (children.has(runId)) {
    send({ type: 'controls-assist-error', runId, message: 'This runId is already active.' });
    return;
  }

  const targetPath = String(msg.path || '').trim();
  const instruction = String(msg.instruction || '').trim();
  const branch = String(msg.branch || '').trim();
  const appLabel = String(msg.app || '').trim();

  if (!targetPath) {
    send({ type: 'controls-assist-error', runId, message: 'A target directory path is required.' });
    return;
  }

  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (err) {
    send({ type: 'controls-assist-error', runId, message: `Path not found: ${targetPath}` });
    return;
  }
  if (!stat.isDirectory()) {
    send({ type: 'controls-assist-error', runId, message: `Not a directory: ${targetPath}` });
    return;
  }

  const agentPath = agentFilePath('controls_assist');
  if (!fs.existsSync(agentPath)) {
    send({ type: 'controls-assist-error', runId, message: 'Controls Assist agent (agents/controls_assist.md) is not available.' });
    return;
  }

  let systemPrompt;
  try {
    systemPrompt = fs.readFileSync(agentPath, 'utf8');
  } catch (err) {
    send({ type: 'controls-assist-error', runId, message: `Failed to read agent prompt: ${err.message}` });
    return;
  }

  const record = {
    id: crypto.randomUUID(),
    runId,
    path: targetPath,
    app: appLabel || null,
    branch: branch || null,
    instruction,
    status: 'running',
    verdict: null,
    error: null,
    startedAt: Date.now(),
    finishedAt: null,
  };
  controlAssessments.set(record.id, record);
  controlAssessmentRunIndex.set(runId, record);

  const promptParts = [
    'Analyze this codebase and identify which NIST 800-53 controls the application layer provides evidence for, drafting SSP-ready narratives for each.',
    instruction,
    `Target directory: ${targetPath}`,
  ].filter(Boolean);
  const userPrompt = promptParts.join('\n\n');

  const args = [
    '-p', userPrompt,
    '--append-system-prompt', systemPrompt,
    '--output-format', 'stream-json',
    '--verbose',
    '--allowedTools', 'Read,Grep,Glob',
    '--permission-mode', 'acceptEdits',
  ];

  send({ type: 'controls-assist-started', runId, id: record.id, path: targetPath });

  const child = spawn('claude', args, { cwd: targetPath, shell: false });
  children.set(runId, child);

  let stdoutBuffer = '';
  let fullText = '';

  child.stdout.on('data', (chunk) => {
    stdoutBuffer += chunk.toString();
    const lines = stdoutBuffer.split('\n');
    stdoutBuffer = lines.pop();

    for (const line of lines) {
      if (!line.trim()) continue;
      let event;
      try {
        event = JSON.parse(line);
      } catch (err) {
        continue;
      }
      if (event.type === 'assistant' && event.message && Array.isArray(event.message.content)) {
        for (const block of event.message.content) {
          if (block.type === 'text' && typeof block.text === 'string') fullText += block.text;
        }
      }
      send({ type: 'controls-assist-event', runId, id: record.id, event });
    }
  });

  child.stderr.on('data', (chunk) => {
    send({ type: 'controls-assist-stderr', runId, id: record.id, data: chunk.toString() });
  });

  child.on('close', (code) => {
    const verdict = extractVerdict(fullText);
    if (record.status === 'running') {
      record.status = code === 0 && verdict ? 'done' : 'error';
      record.error = code === 0 && verdict ? null : `claude exited with code ${code}`;
    }
    record.verdict = verdict;
    record.finishedAt = Date.now();
    send({ type: 'controls-assist-done', runId, id: record.id, code, verdict });
    children.delete(runId);
    controlAssessmentRunIndex.delete(runId);
  });

  child.on('error', (err) => {
    record.status = 'error';
    record.error = err.message;
    record.finishedAt = Date.now();
    send({ type: 'controls-assist-error', runId, id: record.id, message: `Failed to spawn claude: ${err.message}` });
    children.delete(runId);
    controlAssessmentRunIndex.delete(runId);
  });
}

// Wipes every in-memory store (findings, scans, app-level threat models) back to empty — a
// full reset for this session, no reseed. Refuses while anything is running: the per-connection
// `children` map (inside wss.on('connection')) isn't reachable from a plain REST route, so a
// still-running child process couldn't be killed here even if we wanted to; a completed run's
// WS message landing after its record was wiped would just silently re-populate an orphaned
// object nothing references anymore, rather than crash — but refusing up front is clearer.
app.post('/api/session/clear', (req, res) => {
  const anyRunning = [...findings.values()].some((f) => f.runs.some((r) => r.status === 'running'))
    || [...scans.values()].some((s) => s.status === 'running')
    || [...appThreatModels.values()].some((r) => r.status === 'running')
    || [...controlAssessments.values()].some((r) => r.status === 'running');
  if (anyRunning) {
    res.status(409).json({ error: 'Cancel or wait for running scans/agent runs to finish before clearing the session.' });
    return;
  }
  findings.clear();
  runIndex.clear();
  scans.clear();
  scanRunIndex.clear();
  appThreatModels.clear();
  appThreatModelRunIndex.clear();
  controlAssessments.clear();
  controlAssessmentRunIndex.clear();
  res.json({ ok: true });
});

server.listen(PORT, () => {
  console.log(`Findings Agent App listening on http://localhost:${PORT}`);
});
