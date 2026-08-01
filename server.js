const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 4500;
// Bind loopback only. `server.listen(PORT)` with no host binds 0.0.0.0/:: — every interface —
// which put the entire unauthenticated REST + WebSocket surface on whatever network this
// machine is attached to. There is no auth anywhere in this app, and the WebSocket can drive
// the Fix stage, so "reachable" means "can write to this user's files". The whole documented
// security posture ("local single-user dev tool") assumed this was already loopback-bound; it
// was not, and the startup banner printing "localhost" actively hid that.
// HOST is overridable for the rare case of deliberately serving a container or VM, but the
// default must stay loopback: anything else needs auth first, not a different bind address.
const HOST = process.env.HOST || '127.0.0.1';
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
// The reasoning half is scoped by the *application's shape*, not by its file count: the
// enumerated attack surface (every route with its resolved middleware chain, every mount, every
// security control with its real call count) is what bounds the model's work, so a large
// repository costs about what a small one does. A "diff" scope scan narrows that worklist to
// the changed files on top. See runLLMReasoningScan().
// ── Reasoning-pass budgets ──────────────────────────────────────────────────
//
// The reasoning half used to partition the target into up to 24 file-count-sized
// modules and spawn a scoped `claude -p` per module plus an unscoped cross-cutting
// pass, all concurrent, each with its own scaled dollar cap and a $12 per-scan
// ceiling on top. That design made cost scale with *repo size*, and it re-read
// every file the deterministic half had just read while knowing nothing about
// what that half found — two engines racing over the same tree, reconciled
// afterwards by a dedupe step. A union, not a hybrid.
//
// It is now two calls, both taking the deterministic half's output as input:
//
//   1. ADJUDICATE — the pattern findings, with their code, asking which are real.
//      Cost scales with finding count. This is the pass that kills false
//      positives, which pattern matching cannot do for itself.
//   2. REVIEW     — the enumerated attack surface (routes, guards, mounts,
//      controls defined but never applied) plus a list of what the deterministic
//      half already reported, asking the authorization and business-logic
//      questions no fixed rule set can express. Cost scales with endpoint count.
//
// Neither scales with repo size, so a large codebase costs roughly what a small
// one does. Two calls also removes the need for a per-scan ceiling: worst case is
// the sum of the two caps below, by construction.
const REASONING_ADJUDICATE_BUDGET_USD = 1.5;
// Per review *shard*, not per scan — see planReviewShards().
const REASONING_REVIEW_BUDGET_USD = 3.5;
// Ceiling across every review shard in one scan. Sharding reintroduces the possibility of
// unbounded total spend that the two-call design had removed by construction, so the ceiling
// comes back with it. Once crossed, remaining shards are skipped and named in a scan-warning
// rather than run — coverage degrades to "partial, stated plainly" instead of an open bill.
const REASONING_REVIEW_TOTAL_USD = 8.0;

// The review pass is sharded by ATTACK SURFACE, not by files. One call cannot genuinely answer
// four questions about 800 routes: long before the dollar cap binds, the context window does,
// and `claude -p` responds to a full context by compacting — silently discarding its own
// earlier analysis. Removing the cap would therefore buy a larger bill and *the same* missing
// coverage. Bounding the routes per call is the only thing that actually fixes it.
//
// 40 is set so the measured 31-route fixture stays a single shard (identical cost and
// behaviour to before sharding existed) while still being a real per-route interrogation.
const REVIEW_ROUTES_PER_SHARD = 40;
// With the budget cap on, at most this many shards run — ~240 routes reviewed, whatever is
// left over is reported. With the cap off (the form's "Budget cap" toggle), the user has
// explicitly chosen completeness over cost, so every route is reviewed and only this much
// higher ceiling remains as a runaway backstop.
const REVIEW_MAX_SHARDS = 6;
const REVIEW_MAX_SHARDS_UNCAPPED = 24;
const REVIEW_SHARD_CONCURRENCY = 3;

// Per-agent deadline for the deterministic half. See runDeterministicPatternScan() for why
// this is a hang detector rather than a work budget.
const DETERMINISTIC_AGENT_TIMEOUT_MS = 180_000;

// Cap on how many deterministic findings go into one adjudication call. Beyond
// this the prompt stops being a review and starts being a haystack, and the
// per-finding attention that makes adjudication worth doing collapses. Findings
// past the cap keep whatever verdict VerifierAgent gave them (reported, not
// silently dropped — see runAdjudicationPass()).
const ADJUDICATE_MAX_FINDINGS = 40;
// Shipped with the app and load-bearing for other hardcoded UI (the scan flow,
// the Dashboard's pipeline health panel) — editable, but not deletable via the
// Agents screen.
// 'triage' was removed from this list (and its .md file deleted) once Triage moved to a
// synthetic verdict assigned at finding-creation time instead of a live agent stage — see
// CLAUDE.md. 'scan' is back (agents/scan.md exists again, invoked by handleScanMessage's
// reasoning-pass half, not the generic per-finding run path — see NON_FINDING_AGENTS below).
const BUILTIN_AGENTS = ['scan', 'adjudicate', 'threat_model', 'remediation', 'verify', 'app_threat_model', 'controls_assist'];
// Agent .md files that operate on a whole directory via their own dedicated flow
// (Scans, App Threat Model, Controls Assist) rather than the per-finding stage/branch
// UI — excluded from the per-finding agent dropdown and the SCA "run after scan" pill
// row, but still editable in Agent Configuration (see the `all` query flag below).
// 'adjudicate' joins these: it runs as the reasoning half's first pass over a whole scan's
// deterministic findings, not as a stage a user starts against one finding, so it must not
// appear in the per-finding agent menu or the stage modal's dropdown.
const NON_FINDING_AGENTS = ['scan', 'adjudicate', 'app_threat_model', 'controls_assist'];

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
      import('./sast-engine/enumerate.js'),
    ]).then(([agentsIndex, deps, remediationApply, patterns, enumerate]) => ({
      buildOrchestratorAsync: agentsIndex.buildOrchestratorAsync,
      listBuiltInAgents: agentsIndex.listBuiltInAgents,
      enumerateSurface: enumerate.enumerateSurface,
      renderWorklist: enumerate.renderWorklist,
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
// anything against — today that means one manually added via "+ Add"; see the /api/findings
// POST handler below. (It also covered the boot-time sample findings, until seedFindings() was
// removed and the store started empty.) Triage is no longer a live agent stage at all (its .md
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
      fix: latestRunByAgent(runs, 'fix'),
      verify: latestRunByAgent(runs, 'verify'),
    },
    sourceScanId: finding.sourceScanId || null,
    // Source→sink line span for dataflow findings, so the detail view can show
    // the path the value takes rather than just where it ended up.
    flow: finding.flow || null,
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
function findingFromSastEngine(f, scan, targetPath, adjudication = null) {
  const relFile = f.file ? path.relative(targetPath, f.file).split(path.sep).join('/') : null;
  const fileLabel = relFile ? `${relFile}${f.line ? ':' + f.line : ''}` : null;
  const severity = normalizeSeverity(f.severity);
  const confidence = ['high', 'medium', 'low'].includes(f.confidence) ? f.confidence : 'medium';
  const codeSnippet = Array.isArray(f.codeContext) && f.codeContext.length
    ? f.codeContext.map((c) => c.text).join('\n')
    : null;

  // A dataflow finding knows both ends of the path — where untrusted input
  // entered and where it reached something dangerous. Read the real lines
  // between them so the UI can show the flow rather than a single line number,
  // which is the difference between "a rule fired here" and "this is the route
  // an attacker takes". Bounded, because a 60-line span is a wall of code, not
  // an explanation.
  let flow = null;
  if (f.taintSourceLine && f.line && f.taintSourceLine < f.line && f.file) {
    const span = f.line - f.taintSourceLine;
    if (span <= 25) {
      try {
        const all = fs.readFileSync(f.file, 'utf8').split(/\r?\n/);
        flow = {
          sourceLine: f.taintSourceLine,
          sinkLine: f.line,
          lines: all
            .slice(f.taintSourceLine - 1, f.line)
            .map((text, i) => ({ n: f.taintSourceLine + i, text })),
        };
      } catch { flow = null; }
    }
  }

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
    flow,
  };

  // Only critical/high findings actually go through VerifierAgent's code-context checks
  // (f.verified is null for everything else — "not checked", not "unverified"). Either way we
  // still synthesize a triage run so the finding enters the pipeline already triaged; an
  // unverified finding just lands as 'needs_review' instead of 'confirmed'.
  //
  // When the reasoning half's adjudication pass reached a conclusion about this
  // finding, that conclusion wins — it read the surrounding code with far more
  // context than a regex plus a verification heuristic has. A finding it calls a
  // false positive still gets created; deriveStatus() maps that verdict to
  // 'closed', so it stays inspectable in Agent Triage rather than vanishing.
  // Never dropping a finding outright is deliberate: a wrong adjudication should
  // cost visibility, not evidence.
  const adjVerdict = adjudication && ['confirmed', 'needs_review', 'false_positive'].includes(adjudication.verdict)
    ? adjudication.verdict
    : null;
  const verdictLabel = adjVerdict || (f.verified === true ? 'confirmed' : 'needs_review');
  const adjSeverity = adjudication && adjudication.severity ? normalizeSeverity(adjudication.severity) : null;
  const finalSeverity = adjSeverity || severity;
  const finalConfidence = adjudication && ['high', 'medium', 'low'].includes(adjudication.confidence)
    ? adjudication.confidence
    : confidence;
  if (adjSeverity) finding.severity = finalSeverity;
  finding.runs.push({
    runId: crypto.randomUUID(),
    agent: 'triage',
    status: 'done',
    startedAt: Date.now(),
    finishedAt: Date.now(),
    verdict: {
      verdict: verdictLabel,
      severity_confirmed: finalSeverity,
      confidence: finalConfidence,
      priority: priorityFromSeverityConfidence(finalSeverity, finalConfidence),
      reasoning: (adjudication && adjudication.reasoning)
        || f.verifierNote
        || 'Deterministic pattern match; below the verification severity floor, so not independently re-checked against surrounding code.',
      owasp: f.owasp || null,
      asvs: null, // sast-engine has no ASVS mapping — see CLAUDE.md's taxonomy convention note
      cwe: f.cwe || null,
      nist_800_53: [], // same gap as asvs above
      next_agent: verdictLabel === 'confirmed' ? 'remediation' : null,
      // Distinguishes a pattern-plus-VerifierAgent auto-triage from one the
      // reasoning half actually adjudicated — Finding Detail badges them
      // differently, and it matters which one closed a finding.
      source: adjVerdict ? 'reasoning-adjudication' : 'sast-engine-verifier',
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
    // Real dollar spend across the reasoning half's claude -p calls — set once
    // runHybridReasoningScan() finishes; undefined until then.
    reasoningCostUsd: scan.reasoningCostUsd,
    // Which pattern agents this target actually warranted. Persisted rather than only relayed
    // live, because "which agents were judged inapplicable" is part of what a scan covered —
    // a card rebuilt after a page reload, or a scan read back via GET /api/scans/:id, should
    // still be able to say so instead of silently implying the engine ran whole.
    agentsRun: scan.agentsRun,
    agentsSkipped: scan.agentsSkipped || [],
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

/**
 * The structural map a scan produced: every route with its resolved middleware
 * chain, every mount and what guards it, and every security function that is
 * defined and never called.
 *
 * Deliberately its own endpoint rather than a field on GET /api/scans/:id — the
 * manifest for a large repo is far bigger than the scan summary, and the scan
 * list is fetched on nearly every view. Only the Attack Surface page pays for it.
 */
app.get('/api/scans/:id/surface', (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  if (!scan.surface) {
    res.status(404).json({ error: 'This scan has no attack-surface map. Only scans run after the feature was added carry one.' });
    return;
  }
  res.json({ scanId: scan.id, path: scan.path, app: scan.app, startedAt: scan.startedAt, ...scan.surface });
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
/**
 * Is this WebSocket handshake coming from our own page, or from some other website?
 *
 * Exported for tests. Returns true to accept.
 *
 * The same-origin policy does NOT cover WebSockets: a page on evil.example can open a socket
 * to http://127.0.0.1:4500 and the browser will happily connect. Binding to loopback does not
 * help, because the request originates from the user's own browser. Nothing here requires
 * auth, and `remediate_fix` writes to disk — so without this check, visiting a web page was
 * enough to let that page start scans and apply edit plans to the user's repository. That is
 * cross-site WebSocket hijacking, and it is the one hole where "local single-user tool" stops
 * being an adequate excuse: the attacker never needs access to the machine.
 *
 * A browser ALWAYS sends Origin on a WebSocket handshake, and script cannot forge it. So:
 *   - Origin present  -> it must be one of our own loopback origins.
 *   - Origin absent   -> not a browser (curl, a test, a CLI). Allowed: anything running
 *                        locally outside a browser already has this user's privileges, so
 *                        rejecting it buys nothing and would break the test suite.
 */
function isAllowedWsOrigin(origin, port = PORT) {
  if (!origin) return true;
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return false; // unparseable Origin is not something we should be lenient about
  }
  const hostOk = parsed.hostname === 'localhost'
    || parsed.hostname === '127.0.0.1'
    || parsed.hostname === '[::1]'
    || parsed.hostname === '::1';
  // Compare the port explicitly: another service on a different loopback port is still a
  // different origin, and one of them being localhost does not make it ours.
  const portOk = parsed.port === String(port);
  return hostOk && portOk;
}

const wss = new WebSocketServer({
  server,
  verifyClient: ({ origin, req }) => {
    if (isAllowedWsOrigin(origin)) return true;
    console.warn(`Rejected WebSocket connection from disallowed origin: ${origin} (${req.socket.remoteAddress})`);
    return false;
  },
});

function extractVerdict(text) {
  // Case-insensitive fence: every agent .md asks for ```json, but a model that emits ```JSON
  // is following the instruction in spirit and there is no reason to punish the difference.
  // It used to be case-sensitive, and the failure was silent and total — the run completed
  // "successfully" with verdict null, so the finding got no triage, no status change and no
  // error anywhere. A whole paid agent run produced nothing, and looked fine doing it.
  const match = String(text || '').match(/```json\s*([\s\S]*?)```/i);
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
      // runHybridReasoningScan()/runDeterministicScaScan() both return early once
      // scan.status === 'cancelled', before ever reaching finish()/fail() — the two places that
      // normally clean this Map entry up. Delete it here instead, since this cancel message is
      // the only signal a cancelled scan's entry will ever get. (The scans Map/REST history is
      // untouched — this only clears the transient runId->scan lookup used for WS routing.)
      if (scanIndexed) scanRunIndex.delete(runId);
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

    if (msg.type === 'remediate_preview') {
      handleRemediatePreviewMessage(msg, { children, send });
      return;
    }

    if (msg.type === 'remediate_fix') {
      handleRemediateFixMessage(msg, { children, send });
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
    for (const [runId, scanIndexed] of scanRunIndex.entries()) {
      if (scanIndexed.status === 'running') {
        scanIndexed.status = 'cancelled';
        scanIndexed.finishedAt = Date.now();
      }
      // Same leak, same fix as the 'cancel' handler above: finish()/fail() never run for a
      // cancelled scan, so nothing else ever clears this entry.
      scanRunIndex.delete(runId);
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
  let validation;
  try {
    validation = engine.validatePlan(targetPath, plan);
  } catch (err) {
    // e.g. a proposed path resolving to a directory (fs.readFileSync throws EISDIR) — an
    // unlikely but real LLM slip. Report it the same way an invalid plan is reported, rather
    // than letting it propagate as an unhandled rejection (this function's only callers are
    // fire-and-forget IIFEs with no .catch()).
    return { applied: false, diff: null, error: `Proposed edit could not be validated: ${err.message}` };
  }
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
// handleRemediatePreviewMessage/handleRemediateAllMessage below, kept separate from those
// functions just to keep them readable). Pushes/updates the run record and relays
// started/event/stderr/done exactly like
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

// Runs Remediation read-only against the finding's real target directory and stops — no apply,
// no automatic chain into Fix. This is the "Remediate" stage: a human-reviewable proposal
// (fix guidance, corrected_code, and — if the model is confident in an exact edit — an
// `edit_plan`) with nothing written to disk. The Fix stage below is a separate, later step that
// actually applies whatever this run proposed — splitting "propose" from "write" means a human
// always sees the suggested fix before anything touches their files (see CLAUDE.md's
// Remediation Loop). Remediation itself never gets Edit/Write tools (Read,Grep,Glob only).
function handleRemediatePreviewMessage(msg, { children, send }) {
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
    send({ type: 'error', runId, findingId, message: 'A target directory is required to propose a fix.' });
    return;
  }
  try {
    if (!fs.statSync(targetPath).isDirectory()) {
      send({ type: 'error', runId, findingId, message: `Not a directory: ${targetPath}` });
      return;
    }
  } catch (err) {
    send({ type: 'error', runId, findingId, message: `Path not found: ${targetPath}` });
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
    const userPrompt = `${instruction}\n\nFinding context:\n${context}\n\nApply mode: propose the fix as an \`edit_plan\` in your verdict (see your instructions) if you're confident in an exact edit — you do not have Edit/Write access. A human reviews your proposal before a separate Fix step applies it.`;
    const rem = await spawnAgentStage({
      runId, findingId, finding, agentName: 'remediation',
      systemPrompt: remediationPrompt, userPrompt, allowedTools: 'Read,Grep,Glob',
      cwd: targetPath, instruction, children, send,
    });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId, findingId, code: rem.code, verdict: rem.verdict, fullText: '' });
  })();
}

// Applies the most recent Remediate proposal's `edit_plan` to the finding's real target
// directory — this is the "Fix" stage. Deliberately makes no `claude` call at all: the plan was
// already produced by Remediate, so this step is purely deterministic (validate the plan
// against the live file, write it, capture a diff — see applyRemediationPlan()). Fails loudly
// if there's no usable proposal to apply yet, rather than silently generating a fresh one — Fix
// is meant to write exactly what a human just reviewed in the Remediate box, not something new.
function handleRemediateFixMessage(msg, { children, send }) {
  const findingId = msg.findingId ? String(msg.findingId) : null;
  const runId = String(msg.runId || '').trim();
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

  const remRun = [...finding.runs].reverse().find((r) => r.agent === 'remediation');
  const plan = remRun && remRun.verdict && remRun.verdict.edit_plan;
  if (!plan || !Array.isArray(plan.files) || !plan.files.length) {
    send({ type: 'error', runId, findingId, message: 'No proposed fix to apply yet — run Remediate first.' });
    return;
  }

  const gate = checkCleanGitTarget(targetPath);
  if (!gate.ok) {
    send({ type: 'error', runId, findingId, message: gate.message });
    return;
  }

  const runRecord = {
    runId, agent: 'fix', instruction: '', context: '',
    status: 'running', verdict: null, fullText: '',
    startedAt: Date.now(), finishedAt: null,
  };
  finding.runs.push(runRecord);
  runIndex.set(runId, { findingId: finding.id, run: runRecord });
  send({ type: 'started', runId, findingId, agent: 'fix' });

  (async () => {
    const result = await applyRemediationPlan(targetPath, { edit_plan: plan });
    const verdict = { verdict: result.applied ? 'applied' : 'not_applied', applied_diff: result.diff };
    runRecord.status = result.error ? 'error' : 'done';
    runRecord.verdict = verdict;
    runRecord.finishedAt = Date.now();
    runIndex.delete(runId);
    if (result.error) send({ type: 'stderr', runId, findingId, data: result.error });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId, findingId, code: result.error ? 1 : 0, verdict, fullText: '' });
  })();
}

// Chains Remediate (propose) -> Fix (apply, no LLM call) -> Verify for the loop's "run all
// stages" button. This used to run Triage first too, but Triage is no longer a live agent stage
// (see CLAUDE.md) — every finding reaching this handler already carries a triage verdict from
// when it was created, and buildBaseContext() on the client already folds that prior verdict
// into `context` below, so Remediate sees it without a fresh live call. The git-clean gate is
// checked once up front (Fix, further down the chain, is the step that will actually write) so
// the whole chain fails fast rather than spending an LLM call proposing a fix it then can't
// apply.
function handleRemediateAllMessage(msg, { children, send }) {
  const findingId = msg.findingId ? String(msg.findingId) : null;
  const remediationRunId = String(msg.remediationRunId || '').trim();
  const fixRunId = String(msg.fixRunId || '').trim();
  const verifyRunId = String(msg.verifyRunId || '').trim();
  const context = String(msg.context || '');
  const instruction = String(msg.instruction || '');
  const targetPath = String(msg.path || '').trim();

  if (!RUN_ID_RE.test(remediationRunId) || !RUN_ID_RE.test(fixRunId) || !RUN_ID_RE.test(verifyRunId)) {
    send({ type: 'error', message: 'Invalid or missing run id(s).' });
    return;
  }
  if (children.has(remediationRunId) || children.has(fixRunId) || children.has(verifyRunId)) {
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
    const remediationUserPrompt = `${instruction}\n\nFinding context:\n${context}\n\nApply mode: propose the fix as an \`edit_plan\` in your verdict (see your instructions) if you're confident in an exact edit — you do not have Edit/Write access; the next stage applies it automatically.`;
    const rem = await spawnAgentStage({
      runId: remediationRunId, findingId, finding, agentName: 'remediation',
      systemPrompt: remediationPrompt, userPrompt: remediationUserPrompt,
      allowedTools: 'Read,Grep,Glob', cwd: targetPath, instruction, children, send,
    });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId: remediationRunId, findingId, code: rem.code, verdict: rem.verdict, fullText: '' });

    const plan = rem.verdict && rem.verdict.edit_plan;
    if (rem.cancelled || rem.code !== 0 || !plan || !Array.isArray(plan.files) || !plan.files.length) {
      return; // nothing confident enough to apply — chain stops after the proposal
    }

    const fixRunRecord = {
      runId: fixRunId, agent: 'fix', instruction: '', context: '',
      status: 'running', verdict: null, fullText: '',
      startedAt: Date.now(), finishedAt: null,
    };
    finding.runs.push(fixRunRecord);
    runIndex.set(fixRunId, { findingId: finding.id, run: fixRunRecord });
    send({ type: 'started', runId: fixRunId, findingId, agent: 'fix' });

    const result = await applyRemediationPlan(targetPath, { edit_plan: plan });
    const fixVerdict = { verdict: result.applied ? 'applied' : 'not_applied', applied_diff: result.diff };
    fixRunRecord.status = result.error ? 'error' : 'done';
    fixRunRecord.verdict = fixVerdict;
    fixRunRecord.finishedAt = Date.now();
    runIndex.delete(fixRunId);
    if (result.error) send({ type: 'stderr', runId: fixRunId, findingId, data: result.error });
    finding.status = deriveStatus(finding);
    send({ type: 'done', runId: fixRunId, findingId, code: result.error ? 1 : 0, verdict: fixVerdict, fullText: '' });

    if (result.error || !result.applied) return; // apply failed or nothing written — don't chain into Verify

    const verifyUserPrompt = `${instruction}\n\nFinding context:\n${context}\n\nThe Remediation agent proposed this fix and it was just applied to this exact directory:\n${JSON.stringify(fixVerdict, null, 2)}\n\nConfirm whether the fix actually landed and resolves the finding.`;
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

  // scanType is always 'reasoning' now that there's no standalone SCA Scan page/flow to send
  // 'sca' — the dependency audit runs as part of this same hybrid scan instead (see
  // runHybridReasoningScan()'s SCA engine, below).
  runHybridReasoningScan(scan, targetPath, diffFiles, { children, send, finish, fail });
}

// Hybrid Scan (UI label; internal scanType/function names still say "reasoning" — see CLAUDE.md)
// runs three independent engines against the same directory and merges their results (see
// CLAUDE.md's Reasoning Scan bullet for the reasoning behind this):
//   - sast-engine's 29 deterministic pattern agents + VerifierAgent — fast, consistent
//     coverage of known vulnerability categories, no LLM involved.
//   - a real `claude -p` reasoning pass over agents/scan.md — covers business-logic/
//     authorization/attack-surface reasoning a fixed rule set structurally can't do, and
//     assigns its own findings a full triage verdict in the same pass (there's no separate
//     live Triage stage to hand off to).
//   - a dependency audit (npm/pip/etc. audit, via sast-engine's runDepsAudit) — there used to be
//     a standalone SCA Scan page/flow driving this same engine on its own; that page is gone
//     (every scan is a hybrid scan now, there's no dependency-only option left), so this is the
//     only place it runs from. Folded in here since it's fast and free of LLM cost — little
//     reason not to always check dependencies alongside the other two. Unlike them, it ignores
//     scope entirely — a dependency audit always reads the whole manifest/lockfile, "diff" scope
//     or not.
// All three run concurrently; whichever finishes first still has to wait for the others before
// findings are created, since a finding from one pass might duplicate one from another (only
// the deterministic/reasoning pair can actually overlap — SCA findings have no file+line to
// collide with either).
async function runHybridReasoningScan(scan, targetPath, diffFiles, { children, send, finish, fail }) {
  let engine;
  try {
    engine = await loadSastEngine();
  } catch (err) {
    fail(`Failed to load scan engine: ${err.message}`);
    return;
  }

  // SCA is the fastest of the three by far (one shell-out, no per-file/per-module work) — signal
  // its own completion the moment it resolves rather than waiting for Promise.all below, so the
  // client's SCA bar doesn't just sit at "Starting…" until the whole scan finishes.
  const scaPromise = runDeterministicScaScan(engine, scan, targetPath, { send }).then((result) => {
    if (scan.status !== 'cancelled') {
      send({ type: 'scan-progress', runId: scan.runId, scanId: scan.id, engine: 'sca', done: 1, total: 1 });
    }
    return result;
  });

  // The deterministic half runs FIRST, not alongside the reasoning half. It costs
  // seconds and nothing, and both reasoning calls take its output as their input:
  // the adjudication pass reviews its findings, the review pass is told what it
  // already covered so it spends its tokens elsewhere. Running them concurrently
  // (the old design) meant the expensive engine re-read the whole tree knowing
  // nothing about what the free one had just found. Serializing costs a few
  // seconds of wall clock and is what makes this a hybrid rather than a union.
  //
  // SCA keeps running in the background throughout — it shares no data with
  // either half.
  const detResult = await runDeterministicPatternScan(engine, scan, targetPath, diffFiles, { send });

  if (scan.status === 'cancelled') return;

  // Keep the structural map this scan produced. It is built every run either way
  // and was previously discarded once the prompts were assembled — but it is the
  // only description of the application's shape the app has (every endpoint, what
  // guards it, which controls are never applied), which is posture information no
  // findings list conveys. Surfaced by the Attack Surface page.
  if (detResult.surface) scan.surface = detResult.surface;

  // Collapse a deterministic rule that fired repeatedly on consecutive lines of one file. A
  // whole-file condition like "no security headers configured" is checked per line, so it
  // reported once per app.use() call — five rows for one issue. Deliberately only merges
  // *adjacent* hits of the *same rule in the same file*: three separate SQL injections in one
  // file are three real findings and must stay three, so distance is what distinguishes "one
  // condition observed repeatedly" from "several distinct sites".
  //
  // Runs before adjudication so the reasoning pass reviews 5 distinct issues
  // rather than 5 restatements of one, which is both cheaper and more accurate.
  const collapsedDet = dedupeAdjacentSameRule(detResult.findings);

  const llmResult = await runLLMReasoningScan(
    scan, targetPath, diffFiles, collapsedDet, detResult.surface, { children, send },
  );
  const scaResult = await scaPromise;

  if (scan.status === 'cancelled') return;

  if (detResult.error && llmResult.error && scaResult.error) {
    fail(`Deterministic scan: ${detResult.error} — Reasoning pass: ${llmResult.error} — Dependency audit: ${scaResult.error}`);
    return;
  }
  if (detResult.error) send({ type: 'scan-warning', runId: scan.runId, scanId: scan.id, message: `Deterministic pattern scan failed (other engines still succeeded): ${detResult.error}` });
  if (llmResult.error) send({ type: 'scan-warning', runId: scan.runId, scanId: scan.id, message: `Reasoning pass failed (other engines still succeeded): ${llmResult.error}` });
  if (scaResult.error) send({ type: 'scan-warning', runId: scan.runId, scanId: scan.id, message: `Dependency audit failed (other engines still succeeded): ${scaResult.error}` });

  const created = [];
  const adjudications = llmResult.adjudications || new Map();
  for (const [i, f] of collapsedDet.entries()) {
    const finding = findingFromSastEngine(f, scan, targetPath, adjudications.get(i) || null);
    findings.set(finding.id, finding);
    scan.findingIds.push(finding.id);
    created.push(toListItem(finding));
  }

  // Dedup: drop a reasoning-pass finding whose file+line sits within a couple lines of a
  // deterministic finding in the same file — same underlying issue, no need to show it twice.
  // Findings with no resolvable line (e.g. a cross-file business-logic finding) always survive,
  // since there's nothing meaningful to compare them against.
  const detLocations = collapsedDet
    .map((f) => ({ file: f.file ? path.relative(targetPath, f.file).split(path.sep).join('/') : null, line: f.line }))
    .filter((l) => l.file);
  const isDuplicateOfDeterministic = (rf) => {
    const loc = parseFileLine(rf.file);
    if (!loc.file || loc.line == null) return false;
    return detLocations.some((d) => d.file === loc.file && d.line != null && Math.abs(d.line - loc.line) <= 2);
  };

  // The reasoning half is several independent claude -p calls — one per module plus the
  // cross-cutting pass — and nothing stopped two of them reporting the same issue. In practice
  // the same unwired-auth gap comes back 2-3x per scan under differently-worded titles, and the
  // same IDOR twice. Titles vary too much between calls for text comparison to
  // catch it ("requireAuth ... applied to zero routes" vs. "Payment, order, and profile
  // endpoints registered without requireAuth"), but they consistently land on the same line, so
  // location is the reliable signal. Sorted most-severe-first so that when two calls disagree on
  // severity for the same issue — also measured: critical in one run, medium in another — the
  // surviving copy is the more severe reading rather than whichever call happened to finish first.
  const keptLlm = [];
  for (const rf of [...llmResult.findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))) {
    const title = String(rf.title || '').trim();
    const description = String(rf.description || '').trim();
    if (!title || !description) continue; // skip malformed entries rather than fail the whole scan
    if (isDuplicateOfDeterministic(rf)) continue;
    if (isDuplicateOfReasoning(rf, keptLlm)) continue;
    keptLlm.push(rf);
    const finding = findingFromLLMScan(rf, scan);
    findings.set(finding.id, finding);
    scan.findingIds.push(finding.id);
    created.push(toListItem(finding));
  }

  // SCA findings are package/version-keyed, not file+line-keyed — nothing for the dedup check
  // above to compare them against, so every one survives unconditionally.
  for (const v of scaResult.findings) {
    const finding = findingFromDepVuln(v, scan);
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
  // Placeholder only — orchestrator.agents.length counts every registered agent, but many are
  // gated behind shouldRun(recon) (framework-relevance checks, e.g. mobile-scanner only applies
  // to a mobile codebase) and never actually run on a given repo. onScopeReady below corrects
  // this to the real post-filter count before any onAgentDone call fires, so the "Pattern match"
  // bar doesn't permanently stall below 100% once the skipped agents' slots are unfillable.
  let total = orchestrator.agents.length;

  // Agents that errored or — far more likely on a large repo — timed out. The orchestrator
  // already records this as `success: false`, but nothing read it: a timed-out agent
  // contributed zero findings while still advancing the progress bar to 100%, so a scan that
  // could not finish checking for SQL injection looked exactly like a scan that found none.
  // That is the one confusion this engine cannot afford, and it was live until now.
  const failedAgents = [];
  // Agents filtered out by shouldRun(recon) before the run started — not failures, the
  // opposite: evidence the engine matched itself to this target. Surfaced so the UI can say
  // "17 ran, 15 not applicable" instead of an unqualified "17/17".
  let skipped = [];

  try {
    const result = await orchestrator.runAll(targetPath, {
      quiet: true,
      onlyFiles: diffFiles || undefined,
      // The orchestrator's own default is 30s per agent. Every agent walks the whole file
      // list, so its work scales with repo size while that deadline did not — on a large
      // target, agents start timing out and silently contributing nothing. Raised well past
      // any legitimate run: this is a hang detector, not a work budget. A small repo is
      // unaffected (agents finish in well under a second), and a large one gets the room it
      // actually needs. Anything still running at this point is stuck, not slow.
      timeout: DETERMINISTIC_AGENT_TIMEOUT_MS,
      onScopeReady: (realTotal, skippedNames) => {
        total = realTotal;
        skipped = Array.isArray(skippedNames) ? skippedNames : [];
        // Persisted on the scan record too, not just relayed live — which agents were judged
        // irrelevant to a target is part of what that scan actually covered, and a scan
        // reviewed later (or via GET /api/scans/:id) should still be able to say so.
        scan.agentsRun = realTotal;
        scan.agentsSkipped = skipped;
        if (scan.status === 'cancelled') return;
        send({ type: 'scan-progress', runId: scan.runId, scanId: scan.id, engine: 'deterministic', done, total, skipped });
      },
      onAgentDone: (agentResult, agentFindings) => {
        done++;
        if (agentResult && agentResult.success === false) {
          failedAgents.push(`${agentResult.agent} (${agentResult.error || 'unknown error'})`);
        }
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
    // Partial coverage is reported, never inferred from a full progress bar. Each of these
    // agents checked for a whole vulnerability class and came back with nothing because it
    // could not finish — which is not the same claim as "this class is clean."
    if (failedAgents.length && scan.status !== 'cancelled') {
      send({
        type: 'scan-warning',
        runId: scan.runId,
        scanId: scan.id,
        message: `${failedAgents.length} of ${total} pattern agents did not complete, so the vulnerability classes they cover were NOT checked — this is incomplete coverage, not a clean result: ${failedAgents.join(', ')}`,
      });
    }
    return {
      findings: result.findings,
      surface: result.surface || null,
      failedAgents,
      error: null,
    };
  } catch (err) {
    return { findings: [], failedAgents, error: err.message };
  }
}


// Tells the reasoning pass what the deterministic half already covers, so it can lean into
// business logic/authz/attack-surface reasoning instead of re-deriving known pattern categories
// — built from each agent's own name/description/category (declared right in its constructor,
// e.g. `super('SSRFProber', 'Detect Server-Side Request Forgery vulnerabilities', 'ssrf')`), not
// a second hand-maintained file, so it can never drift from what sast-engine actually checks: add
// or remove a built-in agent and this list updates itself next scan with no extra step. Kept to
// one line per agent (name + its existing one-sentence description) rather than each pattern's
// full regex/description/fix — the per-rule detail would run to hundreds of entries across 29
// agents, real prompt bloat for a static block repeated on every module + cross-cutting call in
// a scan, where this ~29-line version costs a few hundred tokens.
function buildCoverageSummary(engine) {
  const lines = engine.listBuiltInAgents().map((a) => `- ${a.name} (${a.category}): ${a.description}`);
  return 'Categories already covered by a deterministic pattern-matching engine running in ' +
    'parallel over this same codebase — do not spend effort re-deriving these from scratch; ' +
    'focus on business logic, authorization/access-control reasoning, and attack-surface ' +
    'analysis a fixed rule set structurally cannot do:\n' + lines.join('\n');
}

// Spawns one `claude -p` reasoning call, relays its stream-json live as scan-events exactly
// like every other stage in this app, and resolves with the parsed verdict plus real spend.
//
// Registered in `children` under a synthetic `${scan.runId}::pass${i}` key (tracked on
// scan.moduleRunIds) rather than the scan's own runId, so the WS 'cancel' handler can kill
// every in-flight reasoning call for a scan, not just one child. The key name kept its `mod`
// prefix through the module-based design and back out again; only cancel bookkeeping reads it.
function runReasoningCall({ scan, targetPath, children, send, index, label, systemPrompt, userPrompt, budgetUsd }) {
  return new Promise((resolve) => {
    if (scan.status === 'cancelled') { resolve({ parsed: null, error: null, costUsd: 0 }); return; }

    const args = [
      '-p', userPrompt,
      '--append-system-prompt', systemPrompt,
      '--output-format', 'stream-json',
      '--verbose',
      '--allowedTools', 'Read,Grep,Glob',
      '--permission-mode', 'acceptEdits',
    ];
    // scan.budgetEnabled defaults true (see handleScanMessage) — the Hybrid Scan form's
    // "Budget cap" toggle is the only way to turn this off, an explicit opt-in for when a scan
    // is getting cut short by the cap and the user wants it to finish regardless of cost.
    if (scan.budgetEnabled) args.push('--max-budget-usd', String(budgetUsd));

    const callRunId = `${scan.runId}::mod${index}`;
    const child = spawn('claude', args, { cwd: targetPath, shell: false });
    children.set(callRunId, child);
    scan.moduleRunIds.push(callRunId);

    let stdoutBuffer = '';
    let fullText = '';
    // Captures the final stream-json `result` event — carries `total_cost_usd` (real dollar
    // spend for this call, confirmed empirically — see CLAUDE.md) and, when the process hit its
    // --max-budget-usd cap rather than finishing normally, `subtype: 'error_max_budget_usd'`
    // (also `is_error: true`, `terminal_reason: 'budget_exhausted'`). Used below to tell a real
    // "ran out of budget mid-analysis" from a generic crash, and to report real spend rather
    // than estimating it from token/tool-call counts.
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
        } catch {
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

    const settle = (error) => {
      children.delete(callRunId);
      const costUsd = resultEvent && typeof resultEvent.total_cost_usd === 'number'
        ? resultEvent.total_cost_usd
        : 0;
      // Parse even on a non-zero exit: a call that hit its budget cap mid-way often still
      // emitted a complete JSON block first, and discarding it because the process technically
      // errored throws away work already paid for.
      resolve({ parsed: extractVerdict(fullText), error, costUsd });
    };

    child.on('close', (code) => {
      if (scan.status === 'cancelled') { settle(null); return; }
      if (code === 0) { settle(null); return; }
      if (resultEvent && resultEvent.subtype === 'error_max_budget_usd') {
        settle(`${label} hit its $${budgetUsd} budget cap before finishing — its coverage is incomplete, not a clean "nothing found"`);
        return;
      }
      settle(`${label}: claude exited with code ${code}`);
    });

    child.on('error', (err) => settle(`${label}: failed to spawn claude — ${err.message}`));
  });
}

// Renders the deterministic findings as a numbered worklist for the adjudication pass. The id
// is the finding's index in the array the caller holds, so verdicts map straight back with no
// title matching. Code context is included because it is the thing being judged; the file is
// still named so the model can read past the snippet, which the prompt tells it to do.
function renderAdjudicationWorklist(detFindings, targetPath) {
  return detFindings.map((f, i) => {
    const rel = f.file ? path.relative(targetPath, f.file).split(path.sep).join('/') : '(no file)';
    const loc = f.line ? `${rel}:${f.line}` : rel;
    const code = Array.isArray(f.codeContext) && f.codeContext.length
      ? f.codeContext.map((c) => `    ${c.line != null ? String(c.line).padStart(5) + ' | ' : ''}${c.text}`).join('\n')
      : '    (no code context captured)';
    const flow = f.taintSourceLine && f.line && f.taintSourceLine < f.line
      ? `\n  Dataflow: untrusted input enters at line ${f.taintSourceLine}, reaches the sink at line ${f.line}.`
      : '';
    return `[${i}] ${f.title || f.rule || 'Untitled'}\n`
      + `  Rule: ${f.rule || 'n/a'} | Severity as matched: ${f.severity || 'unknown'} | Location: ${loc}`
      + `${f.verified === true ? ' | already re-checked against surrounding code' : ''}${flow}\n`
      + `  ${(f.description || '').replace(/\s+/g, ' ').trim()}\n`
      + `  Code:\n${code}`;
  }).join('\n\n');
}

// Words that indicate a middleware checks *privilege*, not merely identity. Case-insensitive
// for the vocabulary, case-SENSITIVE for the camelCase predicate shape — folding them into one
// /i regex makes `requireAdmin` match on the bare word `admin` and the distinction collapses.
const PRIVILEGE_WORD_RE = /admin|role|permission|privileg|acl|rbac|scope|claim|staff|superuser|owner|tenant/i;
const PRIVILEGE_PREDICATE_RE = /\b(?:can|is|has|may)[A-Z]/;
const looksPrivileged = (name) => PRIVILEGE_WORD_RE.test(name) || PRIVILEGE_PREDICATE_RE.test(name);

/**
 * Splits the enumerated routes into review shards, riskiest first.
 *
 * Why shard at all: one call cannot genuinely answer four questions about several hundred
 * routes. Long before the dollar cap binds, the context window does — and a full context makes
 * `claude -p` compact, which silently discards its own earlier analysis. So an uncapped single
 * call on a large repo costs more AND still loses coverage, just without saying so.
 *
 * Why shard by attack surface rather than by files: the worklist is the unit of work. An
 * earlier design partitioned by file count, which made cost scale with repo size while cutting
 * straight through related handlers. Grouping by file keeps sibling routes together — the
 * coupon-stacking and refund flaws in the measured fixture are only visible when the routes
 * that share state are reviewed side by side.
 *
 * Why risk-ordered: when there are more routes than shards, the ones that get reviewed should
 * be the ones most likely to be broken, not whichever the filesystem listed first.
 *
 * @returns {{ list: Array<{files: string[]|null, routeCount: number}>, totalRoutes: number,
 *             reviewedRoutes: number, skippedRoutes: number }}
 */
function planReviewShards(surface, detFindings, targetPath, { maxShards }) {
  const routes = surface && Array.isArray(surface.routes) ? surface.routes : [];
  // No HTTP surface at all — a library, a CLI, a worker. One unscoped call over the whole
  // tree, which is exactly the pre-sharding behaviour and the right thing here: there are no
  // routes to divide, and the model should still get to look around.
  if (!routes.length) {
    return { list: [{ files: null, routeCount: 0 }], totalRoutes: 0, reviewedRoutes: 0, skippedRoutes: 0 };
  }

  const findingsPerFile = new Map();
  for (const f of detFindings) {
    if (!f.file) continue;
    const rel = path.relative(targetPath, f.file).split(path.sep).join('/');
    findingsPerFile.set(rel, (findingsPerFile.get(rel) || 0) + 1);
  }
  const sinksPerFile = new Map();
  for (const s of (surface.sinks || [])) {
    sinksPerFile.set(s.file, (sinksPerFile.get(s.file) || 0) + 1);
  }

  // Group routes by the file that declares them, scoring as we go.
  const byFile = new Map();
  for (const r of routes) {
    let g = byFile.get(r.file);
    if (!g) { g = { file: r.file, routes: 0, score: 0 }; byFile.set(r.file, g); }
    g.routes++;
    const mw = Array.isArray(r.middleware) ? r.middleware : [];
    if (!mw.length) {
      g.score += 3;                                   // reachable with no guard at all
    } else if (!mw.some(looksPrivileged)) {
      g.score += 2;                                   // authenticated but never authorized —
    }                                                 // reads as protected, isn't
  }
  for (const g of byFile.values()) {
    // Capped so one enormous file can't monopolise the ordering on volume alone.
    g.score += Math.min(5, sinksPerFile.get(g.file) || 0);
    g.score += Math.min(6, (findingsPerFile.get(g.file) || 0) * 2);
  }

  const groups = [...byFile.values()].sort((a, b) => b.score - a.score || b.routes - a.routes);

  // Pack highest-risk-first into shards. A single file with more routes than the shard size
  // becomes its own oversized shard rather than being split — splitting one router's handlers
  // across two calls is exactly the sibling-context loss this design exists to avoid.
  const list = [];
  let current = null;
  for (const g of groups) {
    if (current && current.routeCount + g.routes > REVIEW_ROUTES_PER_SHARD) current = null;
    if (!current) {
      if (list.length >= maxShards) break;
      current = { files: [], routeCount: 0 };
      list.push(current);
    }
    current.files.push(g.file);
    current.routeCount += g.routes;
    if (current.routeCount >= REVIEW_ROUTES_PER_SHARD) current = null;
  }

  const totalRoutes = routes.length;
  const reviewedRoutes = list.reduce((n, s) => n + s.routeCount, 0);
  return { list, totalRoutes, reviewedRoutes, skippedRoutes: totalRoutes - reviewedRoutes };
}

// Runs the reasoning half of a hybrid scan: two calls, both taking the deterministic half's
// output as input. Returns { findings, adjudications, error, costUsd } — `findings` is a raw
// array of new finding objects from the review pass (turned into Finding records by
// runHybridReasoningScan() via findingFromLLMScan()), `adjudications` is a Map of
// deterministic-finding index → verdict, applied by findingFromSastEngine().
//
// Pass 1, ADJUDICATE, only runs when the deterministic half found something. Pass 2, REVIEW,
// always runs — an empty deterministic result is not evidence the code is clean, it is exactly
// the case where reasoning matters most.
//
// Neither pass partitions the repository. The previous design split the tree into up to 24
// file-count-sized modules and spawned a scoped call per module plus an unscoped cross-cutting
// pass; that made cost scale with repo size and had the expensive engine re-read everything the
// free one had just read. Scope now comes from the enumerated attack surface and the finding
// list, both of which scale with the application's shape rather than its file count.
async function runLLMReasoningScan(scan, targetPath, diffFiles, detFindings, surface, { children, send }) {
  let engine;
  try {
    engine = await loadSastEngine();
  } catch (err) {
    return { findings: [], adjudications: new Map(), error: `Failed to load scan engine: ${err.message}`, costUsd: 0 };
  }

  const readAgent = (name) => {
    const p = agentFilePath(name);
    if (!fs.existsSync(p)) throw new Error(`agents/${name}.md is not available.`);
    return fs.readFileSync(p, 'utf8');
  };

  let reviewPrompt;
  try {
    reviewPrompt = readAgent('scan') + '\n\n' + buildCoverageSummary(engine);
  } catch (err) {
    return { findings: [], adjudications: new Map(), error: err.message, costUsd: 0 };
  }

  scan.moduleRunIds = [];

  // ── Plan the passes ───────────────────────────────────────────────────────
  const adjudicable = [...detFindings.entries()]
    .sort(([, a], [, b]) => severityRank(a.severity) - severityRank(b.severity));
  const adjudicating = adjudicable.slice(0, ADJUDICATE_MAX_FINDINGS);
  const overflow = adjudicable.length - adjudicating.length;

  let adjudicatePrompt = null;
  if (adjudicating.length) {
    try {
      adjudicatePrompt = readAgent('adjudicate');
    } catch (err) {
      send({
        type: 'scan-warning', runId: scan.runId, scanId: scan.id,
        message: `${err.message} Deterministic findings will keep their pattern-engine verdicts without independent review.`,
      });
    }
  }

  // Planned before `total` so the progress bar's denominator is right from the first message —
  // the same reason the deterministic half has onScopeReady (see runDeterministicPatternScan).
  const shards = planReviewShards(surface, detFindings, targetPath, {
    maxShards: scan.budgetEnabled ? REVIEW_MAX_SHARDS : REVIEW_MAX_SHARDS_UNCAPPED,
  });

  const total = (adjudicatePrompt ? 1 : 0) + shards.list.length;
  let done = 0;
  let totalCostUsd = 0;
  const errors = [];
  const progress = () => {
    if (scan.status !== 'cancelled') {
      send({ type: 'scan-progress', runId: scan.runId, scanId: scan.id, engine: 'reasoning', done, total, costUsd: totalCostUsd });
    }
  };
  progress();

  // ── Both passes, concurrently ─────────────────────────────────────────────
  // They share no data with each other: adjudication reads the deterministic
  // findings, review reads the enumerated surface. Both inputs already exist by
  // the time this function is called, so running them in sequence adds the whole
  // of the shorter pass to every scan's wall clock and buys nothing. Measured on
  // a 16-file fixture before this was fixed: adjudication alone took 268s with
  // the review pass only starting afterwards, which made a scan slower than the
  // module-partitioned design this replaced — the opposite of the point.
  const adjudications = new Map();

  const adjudicatePass = async () => {
    if (!adjudicatePrompt) return;
    if (overflow > 0) {
      send({
        type: 'scan-warning', runId: scan.runId, scanId: scan.id,
        message: `${adjudicable.length} deterministic findings exceeded the ${ADJUDICATE_MAX_FINDINGS}-finding adjudication limit — the ${ADJUDICATE_MAX_FINDINGS} most severe were independently reviewed; the remaining ${overflow} keep their pattern-engine verdict and are marked "needs review".`,
      });
    }

    const worklist = renderAdjudicationWorklist(adjudicating.map(([, f]) => f), targetPath);
    const userPrompt = [
      `A deterministic pattern-matching engine reported ${adjudicating.length} finding${adjudicating.length === 1 ? '' : 's'} in this codebase. Decide which are real.`,
      'Read the actual files before deciding — the snippets below are a few lines of context, and what makes a finding real or not is often outside them.',
      `Target directory: ${targetPath}`,
      `Findings to adjudicate:\n\n${worklist}`,
    ].join('\n\n');

    const res = await runReasoningCall({
      scan, targetPath, children, send, index: 0, label: 'Adjudication pass',
      systemPrompt: adjudicatePrompt, userPrompt, budgetUsd: REASONING_ADJUDICATE_BUDGET_USD,
    });
    totalCostUsd += res.costUsd;
    done++;
    progress();
    if (res.error) errors.push(res.error);

    const verdicts = res.parsed && Array.isArray(res.parsed.verdicts) ? res.parsed.verdicts : [];
    for (const v of verdicts) {
      // `id` indexes the sorted slice handed to the model, not detFindings — map it back
      // through `adjudicating` so a verdict can never land on the wrong finding.
      const entry = adjudicating[Number(v.id)];
      if (!entry) continue;
      adjudications.set(entry[0], v);
    }
  };

  // Reviews the surface the pattern engine structurally cannot. Sharded by attack surface —
  // see planReviewShards() for why, and why the shards are risk-ordered rather than arbitrary.
  // (`shards` itself is planned above, before `total`.)
  if (!surface) {
    send({
      type: 'scan-warning', runId: scan.runId, scanId: scan.id,
      message: 'Attack-surface enumeration produced nothing — the review pass will run without a route worklist, which weakens coverage of authorization and business-logic issues.',
    });
  }
  if (shards.skippedRoutes > 0) {
    send({
      type: 'scan-warning', runId: scan.runId, scanId: scan.id,
      message: `${shards.totalRoutes} routes exceeded what ${REVIEW_MAX_SHARDS} review shards can cover — the ${shards.reviewedRoutes} highest-risk were reviewed (unguarded mounts and authenticated-but-not-authorized surfaces first); ${shards.skippedRoutes} were NOT reviewed for authorization or business-logic issues. Turn off the budget cap, or scan a narrower directory, for full coverage.`,
    });
  }

  const runReviewShard = async (shard, index) => {
    // The per-scan ceiling. Checked at dispatch rather than up front so shards already in
    // flight always finish — killing a call mid-analysis wastes what it already spent.
    if (scan.budgetEnabled && totalCostUsd >= REASONING_REVIEW_TOTAL_USD) {
      return { findings: [], skipped: true };
    }

    const parts = [
      'Review this application for security vulnerabilities that a pattern-matching engine cannot find: '
      + 'authorization and access-control gaps, business-logic flaws, and controls that are defined in one '
      + 'place but never actually applied where they are needed. Reason about externally-reachable endpoints '
      + 'the way an attacker interacting with the running application would. No live instance is being hit — '
      + 'this is inferred from static code, so frame findings accordingly.',
    ];

    if (diffFiles) {
      parts.push(`Limit your review to only the following changed files versus the base branch — do not scan anything else in the repository:\n${diffFiles.map((p) => `- ${p}`).join('\n')}`);
    } else if (shard.files && shards.list.length > 1) {
      // Focus, NOT a sandbox. The routes below are this call's responsibility, but answering
      // "what does this handler actually change, and could it belong to someone else" almost
      // always means following the call into a service or model file outside the list. Telling
      // the model it may not read those would defeat the questions it is being asked.
      parts.push(
        'You are reviewing one slice of a larger application. These files hold the routes you '
        + 'are responsible for:\n'
        + shard.files.map((p) => `- ${p}`).join('\n')
        + '\n\nReport findings for these routes only — other slices are being reviewed separately, '
        + 'so do not report issues whose root cause lives in a file outside this list. You may and '
        + 'should read anything in the repository to understand what these routes do.',
      );
    }
    parts.push(`Target directory: ${targetPath}`);

    // The enumerated surface is what bounds this call. It lists each route with its resolved
    // middleware chain, plus whole-app mount and unused-control context, so the model answers
    // questions about a known set of endpoints instead of deciding for itself what to read.
    //
    // Failure here is non-fatal: a review with no worklist is the old unscoped behaviour, which
    // is worse but still works, so it must never abort the scan.
    if (surface) {
      try {
        const worklist = engine.renderWorklist(surface, shard.files || diffFiles || null);
        if (worklist.trim()) parts.push(worklist);
      } catch { /* a malformed worklist must not cost us the shard */ }
    }

    // Telling the review pass what the deterministic half already reported is the other half of
    // making this a hybrid: without it the model spends its budget rediscovering the same
    // hardcoded secret and the same SQL concatenation the free engine already found, and those
    // duplicates then have to be thrown away in the merge. Locations only — full descriptions
    // would be prompt bloat, and the point is avoidance, not review (that was pass 1's job).
    // Scoped to the shard's own files, so a large repo doesn't paste hundreds of irrelevant
    // locations into every call.
    const shardFileSet = shard.files ? new Set(shard.files) : null;
    const relevantDet = detFindings.filter((f) => {
      if (!shardFileSet) return true;
      if (!f.file) return false;
      return shardFileSet.has(path.relative(targetPath, f.file).split(path.sep).join('/'));
    });
    if (relevantDet.length) {
      const already = relevantDet.slice(0, 60).map((f) => {
        const rel = f.file ? path.relative(targetPath, f.file).split(path.sep).join('/') : '(no file)';
        return `- ${f.title || f.rule} @ ${f.line ? `${rel}:${f.line}` : rel}`;
      }).join('\n');
      parts.push(
        'Already reported by the deterministic engine — do NOT report these again, and do not spend '
        + `effort re-deriving them. Report only what is missing from this list:\n${already}`
        + (relevantDet.length > 60 ? `\n(+${relevantDet.length - 60} more of the same kinds)` : ''),
      );
    }

    const res = await runReasoningCall({
      scan, targetPath, children, send,
      // index 0 is the adjudication pass; review shards follow it.
      index: index + 1,
      label: shards.list.length > 1 ? `Review shard ${index + 1}/${shards.list.length}` : 'Review pass',
      systemPrompt: reviewPrompt, userPrompt: parts.join('\n\n'), budgetUsd: REASONING_REVIEW_BUDGET_USD,
    });
    totalCostUsd += res.costUsd;
    done++;
    progress();
    if (res.error) errors.push(res.error);
    return {
      findings: res.parsed && Array.isArray(res.parsed.findings) ? res.parsed.findings : [],
      skipped: false,
    };
  };

  const reviewPass = async () => {
    const out = [];
    let skippedForBudget = 0;
    let next = 0;
    const worker = async () => {
      while (next < shards.list.length && scan.status !== 'cancelled') {
        const i = next++;
        const r = await runReviewShard(shards.list[i], i);
        if (r.skipped) { skippedForBudget++; done++; progress(); continue; }
        out.push(...r.findings);
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(REVIEW_SHARD_CONCURRENCY, shards.list.length) }, worker),
    );
    if (skippedForBudget) {
      send({
        type: 'scan-warning', runId: scan.runId, scanId: scan.id,
        message: `The review pass reached its $${REASONING_REVIEW_TOTAL_USD} per-scan budget — ${skippedForBudget} of ${shards.list.length} shards were skipped and their routes were NOT reviewed. Turn off the budget cap for full coverage.`,
      });
    }
    return out;
  };

  const [, reviewFindings] = await Promise.all([adjudicatePass(), reviewPass()]);

  if (scan.status === 'cancelled') {
    return { findings: [], adjudications, error: null, costUsd: totalCostUsd };
  }

  // Every pass failing is an engine failure; some passing is a degraded scan that still produced
  // real results, reported as a warning rather than swallowed (scan-stderr is discarded
  // client-side, which is why this uses scan-warning — see CLAUDE.md).
  if (errors.length === total) {
    return { findings: [], adjudications, error: errors.join(' | '), costUsd: totalCostUsd };
  }
  if (errors.length) {
    send({ type: 'scan-warning', runId: scan.runId, scanId: scan.id, message: `${errors.length}/${total} reasoning passes had issues: ${errors.join(' | ')}` });
  }
  return { findings: reviewFindings, adjudications, error: null, costUsd: totalCostUsd };
}


const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, moderate: 2, low: 3, informational: 4 };
function severityRank(sev) {
  const r = SEVERITY_RANK[String(sev || '').toLowerCase()];
  return r == null ? 5 : r;
}

// How far apart two hits of the same rule in the same file can be and still be treated as one
// condition rather than two distinct sites. Small on purpose — see the call site.
const ADJACENT_RULE_LINES = 3;

/**
 * Collapse runs of the same rule firing on nearby lines of the same file down to their first
 * occurrence. Findings are grouped by file+rule, sorted by line, and a new group is started
 * whenever the gap to the previous line exceeds ADJACENT_RULE_LINES — so a file-wide condition
 * flagged on four consecutive lines becomes one finding, while the same rule firing at line 12
 * and line 200 stays two.
 */
function dedupeAdjacentSameRule(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = `${f.file}::${f.rule}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  const kept = new Set();
  for (const group of groups.values()) {
    const sorted = [...group].sort((a, b) => (a.line || 0) - (b.line || 0));
    let lastLine = null;
    for (const f of sorted) {
      const line = f.line || 0;
      if (lastLine == null || line - lastLine > ADJACENT_RULE_LINES) kept.add(f);
      lastLine = line;
    }
  }
  // Preserve the engine's own severity ordering rather than the grouping order.
  return findings.filter((f) => kept.has(f));
}

/** Whether a reasoning finding restates one already kept from another reasoning call. */
function isDuplicateOfReasoning(rf, kept) {
  const loc = parseFileLine(rf.file);
  if (!loc.file || loc.line == null) return false;
  return kept.some((k) => {
    const kl = parseFileLine(k.file);
    return kl.file === loc.file && kl.line != null && Math.abs(kl.line - loc.line) <= 2;
  });
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
// Runs sast-engine's dependency audit and returns { findings, error } — raw vuln objects, not
// yet Finding records — rather than calling finish()/fail() directly, since runHybridReasoningScan()
// (SCA as its third concurrent engine, see below) needs every engine's results together before
// creating findings, same reason runDeterministicPatternScan() does. There used to be a second
// caller here too — a standalone SCA Scan page/flow that drove this same engine to completion on
// its own, for a fast dependency-only check with no pattern-matching or reasoning involved. That
// page is gone (SCA now always runs as part of a hybrid scan, never on its own), so this is the
// only caller left. `engine` is passed in already loaded so a hybrid scan only loads sast-engine
// once, same pattern the other two engine functions use.
async function runDeterministicScaScan(engine, scan, targetPath, { send }) {
  let result;
  try {
    result = await engine.runDepsAudit(targetPath);
  } catch (err) {
    return { findings: [], error: `Dependency audit failed: ${err.message}` };
  }

  if (scan.status === 'cancelled') return { findings: [], error: null };

  if (!result.pm) return { findings: [], error: null }; // no supported manifest found — a clean, valid "nothing to report" outcome
  if (result.error) return { findings: [], error: result.error };

  if (result.vulns.length) {
    const lines = result.vulns.map((v) => `[${normalizeSeverity(v.severity)}] \`${v.name}@${v.range}\` — ${v.title}`);
    send({
      type: 'scan-event',
      runId: scan.runId,
      scanId: scan.id,
      event: { type: 'assistant', message: { content: [{ type: 'text', text: lines.join('\n') }] } },
    });
  }

  return { findings: result.vulns, error: null };
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

// Only bind a port when this file is *run* (`npm start` / `node server.js`), not when it is
// `require()`d. The unit tests import this module to exercise the pure decision logic below
// (deriveStatus, dedupeAdjacentSameRule, extractVerdict, ...); importing must never start a
// listener, or every test run would either occupy port 4500 or fail against an already-running
// dev server, and the test process would never exit.
if (require.main === module) {
  server.listen(PORT, HOST, () => {
    // Report the real bind address rather than always claiming localhost — if someone
    // deliberately overrides HOST, the banner should say so instead of hiding it.
    console.log(`Findings Agent App listening on http://${HOST}:${PORT}`);
    if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
      console.log(`WARNING: bound to ${HOST}, not loopback. This app has no authentication and`);
      console.log('         its WebSocket can write to your files. Anyone who can reach this');
      console.log('         port has the same power over this machine as you do.');
    }
  });
}

// Exported purely for testing — nothing in the app requires this module. These are the pure
// (side-effect-free) decision helpers characterization tests lock in, so a later refactor that
// moves them into their own modules can prove behaviour is unchanged.
module.exports = {
  deriveStatus,
  dedupeAdjacentSameRule,
  priorityFromSeverityConfidence,
  normalizeSeverity,
  placeholderTriageRun,
  extractVerdict,
  latestRunByAgent,
  toListItem,
  severityRank,
  parseFileLine,
  isDuplicateOfReasoning,
  csvEscape,
  planReviewShards,
  renderAdjudicationWorklist,
  toScanListItem,
  toAppThreatModelListItem,
  toControlAssessmentListItem,
  isAllowedWsOrigin,
};
