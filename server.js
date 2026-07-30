const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 4500;
const AGENTS_DIR = path.join(__dirname, 'agents');
const AGENT_NAME_RE = /^[a-zA-Z0-9_-]+$/;
const RUN_ID_RE = /^[a-zA-Z0-9_-]+$/;
const BRANCH_NAME_RE = /^[\w./-]+$/;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
// 'reasoning' replaces what used to be separate 'sast'/'dast' scan types — both were really
// just this same LLM reading source and reasoning about it (no real static-analysis tool, no
// live traffic), so calling them out as distinct tool categories was misleading. SCA is kept
// distinct because it's a genuinely different task (checking manifests/lockfiles against
// known-vulnerable packages, not reasoning about code patterns).
const SCAN_TYPES = ['reasoning', 'sca', 'custom'];
// A finding's own scanType is narrower than a scan's — there's no "custom" bucket to
// group findings by, so findings from a custom-type scan fall back to 'reasoning' (the
// closest fit given this tool only ever reads local source, never a live target).
const FINDING_SCAN_TYPES = ['reasoning', 'sca'];
const SCAN_SCOPES = ['full', 'diff'];
// Canned framing prepended to the scan agent's instructions per scan type. 'custom' has none —
// the user's own instruction is the entire prompt for that type (enforced below).
const SCAN_TYPE_FRAMING = {
  reasoning: 'Scan this directory for real, concrete security vulnerabilities in the code, and reason about externally-reachable endpoints and attack surface the way an attacker interacting with the running application could exploit them. No live instance is being hit — this is inferred from static code, so frame findings accordingly.',
  sca: 'Perform a Software Composition Analysis pass: focus on dependency manifests and lockfiles (e.g. package.json/package-lock.json, requirements.txt/poetry.lock, go.mod/go.sum, pom.xml, Gemfile.lock) for known-vulnerable, outdated, or unpinned third-party packages. De-prioritize custom application logic unless it directly relates to a vulnerable dependency.',
  custom: '',
};
// Shipped with the app and load-bearing for other hardcoded UI (the scan flow,
// the Dashboard's pipeline health panel) — editable, but not deletable via the
// Agents screen.
const BUILTIN_AGENTS = ['triage', 'threat_model', 'remediation', 'scan', 'app_threat_model', 'controls_assist'];
// Agent .md files that operate on a whole directory via their own dedicated flow
// (Scans, App Threat Model, Controls Assist) rather than the per-finding stage/branch
// UI — excluded from the per-finding agent dropdown and the SCA "run after scan" pill
// row, but still editable in Agent Configuration (see the `all` query flag below).
const NON_FINDING_AGENTS = ['scan', 'app_threat_model', 'controls_assist'];

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
  if (latest.agent === 'remediation' && latest.verdict && latest.verdict.corrected_code && (v === 'confirmed' || v === 'needs_review')) return 'remediation_generated';
  if (v === 'confirmed' && !latest.verdict.next_agent) return 'remediation_ready';
  if (v === 'confirmed' || v === 'needs_review') return 'in_review';
  return 'in_review';
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
    findings.set(id, {
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
    });
  }
}
seedFindings();

// ---------- in-memory scans store ----------
// A scan is one "scan this directory" invocation of the Scan agent (agents/scan.md).
// It doesn't chain like a per-finding run does — on completion it creates zero or
// more new Finding records (tagged with sourceScanId) and remembers their ids, so
// the Scans view can show "this scan produced N findings" and link through to them.

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

    if (agentName === 'scan') {
      send({ type: 'error', runId, message: 'Use a "scan" message to run the Scan agent against a directory.' });
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

    const args = [
      '-p', userPrompt,
      '--append-system-prompt', systemPrompt,
      '--output-format', 'stream-json',
      '--verbose',
      '--allowedTools', 'Read,Grep',
      '--permission-mode', 'acceptEdits',
    ];

    send({ type: 'started', runId, findingId, agent: agentName });

    const child = spawn('claude', args, { cwd: process.cwd(), shell: false });
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
    for (const [runId, child] of children.entries()) {
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

function handleScanMessage(msg, { children, send }) {
  const runId = String(msg.runId || '').trim();
  if (!RUN_ID_RE.test(runId)) {
    send({ type: 'error', message: 'Invalid or missing runId.' });
    return;
  }
  if (children.has(runId)) {
    send({ type: 'error', runId, message: 'This runId is already active.' });
    return;
  }

  const targetPath = String(msg.path || '').trim();
  const instruction = String(msg.instruction || '').trim();
  const branch = String(msg.branch || '').trim();
  const app = String(msg.app || '').trim();
  const scanType = SCAN_TYPES.includes(msg.scanType) ? msg.scanType : 'reasoning';
  const scope = SCAN_SCOPES.includes(msg.scope) ? msg.scope : 'full';
  const baseBranch = String(msg.baseBranch || '').trim();

  if (!targetPath) {
    send({ type: 'scan-error', runId, message: 'A target directory path is required.' });
    return;
  }
  if (scanType === 'custom' && !instruction) {
    send({ type: 'scan-error', runId, message: 'Custom reasoning pass requires instructions.' });
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

  const scanAgentPath = path.join(AGENTS_DIR, 'scan.md');
  if (!fs.existsSync(scanAgentPath)) {
    send({ type: 'scan-error', runId, message: 'Scan agent (agents/scan.md) is not available.' });
    return;
  }

  let systemPrompt;
  try {
    systemPrompt = fs.readFileSync(scanAgentPath, 'utf8');
  } catch (err) {
    send({ type: 'scan-error', runId, message: `Failed to read scan agent prompt: ${err.message}` });
    return;
  }

  const scan = {
    id: crypto.randomUUID(),
    runId,
    path: targetPath,
    instruction,
    branch: branch || null,
    app: app || null,
    scanType,
    scope,
    baseBranch: scope === 'diff' ? baseBranch : null,
    diffFileCount: diffFiles ? diffFiles.length : null,
    status: 'running',
    error: null,
    findingIds: [],
    startedAt: Date.now(),
    finishedAt: null,
  };
  scans.set(scan.id, scan);
  scanRunIndex.set(runId, scan);

  const promptParts = [];
  if (scanType !== 'custom') promptParts.push(SCAN_TYPE_FRAMING[scanType]);
  if (instruction) promptParts.push(instruction);
  if (diffFiles) {
    promptParts.push(`Limit your review to only the following changed files versus "${baseBranch}" — do not scan anything else in the repository:\n${diffFiles.map((f) => `- ${f}`).join('\n')}`);
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

  send({ type: 'scan-started', runId, scanId: scan.id, path: targetPath });

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
      send({ type: 'scan-event', runId, scanId: scan.id, event });
    }
  });

  child.stderr.on('data', (chunk) => {
    send({ type: 'scan-stderr', runId, scanId: scan.id, data: chunk.toString() });
  });

  child.on('close', (code) => {
    const parsed = extractVerdict(fullText);
    const rawFindings = parsed && Array.isArray(parsed.findings) ? parsed.findings : [];
    const created = [];

    for (const rf of rawFindings) {
      const title = String(rf.title || '').trim();
      const description = String(rf.description || '').trim();
      if (!title || !description) continue; // skip malformed entries rather than fail the whole scan

      const id = crypto.randomUUID();
      const finding = {
        id,
        title,
        severity: SEVERITIES.includes(rf.severity) ? rf.severity : 'medium',
        scanType: FINDING_SCAN_TYPES.includes(scan.scanType) ? scan.scanType : 'reasoning',
        rule: rf.rule ? String(rf.rule).trim() : null,
        file: rf.file ? String(rf.file).trim() : null,
        description,
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
      findings.set(id, finding);
      scan.findingIds.push(id);
      created.push(toListItem(finding));
    }

    if (scan.status !== 'cancelled') {
      scan.status = code === 0 ? 'done' : 'error';
      scan.error = code === 0 ? null : `claude exited with code ${code}`;
    }
    scan.finishedAt = Date.now();
    send({ type: 'scan-done', runId, scanId: scan.id, code, findings: created });
    children.delete(runId);
    scanRunIndex.delete(runId);
  });

  child.on('error', (err) => {
    scan.status = 'error';
    scan.error = err.message;
    scan.finishedAt = Date.now();
    send({ type: 'scan-error', runId, scanId: scan.id, message: `Failed to spawn claude: ${err.message}` });
    children.delete(runId);
    scanRunIndex.delete(runId);
  });
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
