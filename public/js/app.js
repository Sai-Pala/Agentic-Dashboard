
// ---------- icon system (hand-drawn monoline SVGs, no emoji anywhere in the UI) ----------

const ICONS = {
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.8-4.8"/>',
  target: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r=".6" fill="currentColor"/>',
  wrench: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.7 2.7-2-2 2.7-2.7Z"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M3 12h3M18 12h3M4.9 19.1l2.1-2.1M17 7l2.1-2.1"/>',
  hourglass: '<path d="M6.5 3h11M6.5 21h11M7.5 3c0 5 4.5 6 4.5 9s-4.5 4-4.5 9M16.5 3c0 5-4.5 6-4.5 9s4.5 4 4.5 9"/>',
  inbox: '<path d="M3.5 12h4.3l1.8 3h4.8l1.8-3h4.3"/><path d="M3.5 12 5 5h14l1.5 7v6a1 1 0 0 1-1 1H4.5a1 1 0 0 1-1-1v-6Z"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
  checkCircle: '<circle cx="12" cy="12" r="8.5"/><path d="m8 12.3 2.6 2.6 5.2-5.2"/>',
  folder: '<path d="M3 6.5a1.5 1.5 0 0 1 1.5-1.5h4l2 2h8.5a1.5 1.5 0 0 1 1.5 1.5v9a1.5 1.5 0 0 1-1.5 1.5h-14A1.5 1.5 0 0 1 3 17.5v-11Z"/>',
  trending: '<path d="m3 16 6-6 4 4 8-8"/><path d="M15 6h6v6"/>',
  radar: '<circle cx="12" cy="12" r="9"/><path d="M12 12 18 8"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21"/>',
  package: '<path d="M3.5 8.2 12 4l8.5 4.2v7.6L12 20 3.5 15.8V8.2Z"/><path d="M3.5 8.2 12 12l8.5-3.8"/><path d="M12 12v8"/>',
  edit: '<path d="M4 20h4l10-10a2 2 0 0 0 0-2.8L16.8 5a2 2 0 0 0-2.8 0L4 15v5Z"/><path d="m13.5 6.5 4 4"/>',
  branch: '<circle cx="6" cy="4.5" r="2.2"/><circle cx="6" cy="19.5" r="2.2"/><circle cx="18" cy="7.5" r="2.2"/><path d="M6 6.7V17.3"/><path d="M18 9.7A7 7 0 0 1 11 16.5"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6L12 3Z"/><path d="m9 12 2 2 4-4"/>',
  clipboard: '<path d="M8 4h8a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z"/><path d="M9.5 3.5h5a1 1 0 0 1 1 1V6h-7V4.5a1 1 0 0 1 1-1Z"/><path d="m9.5 11 1.5 1.5L14 9M9.5 15.5h5"/>',
  terminal: '<rect x="3" y="4.5" width="18" height="15" rx="1.8"/><path d="m7.5 9.5 3 2.7-3 2.7"/><path d="M13 15.2h4"/>',
  more: '<circle cx="12" cy="5.5" r="1.7" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.7" fill="currentColor" stroke="none"/><circle cx="12" cy="18.5" r="1.7" fill="currentColor" stroke="none"/>',
  arrowRight: '<path d="M4 12h16"/><path d="m13 5 7 7-7 7"/>',
  fastForward: '<path d="m5 5 7 7-7 7"/><path d="m13 5 7 7-7 7"/>',
  // Distinct from each other on purpose (Remediation Loop's advance vs. run-all buttons sit
  // right next to each other at small size — a single chevron vs. a skip-to-end glyph reads
  // clearly apart, where two chevron variants (arrowRight/fastForward above) didn't).
  chevronRight: '<path d="m9 5 7 7-7 7"/>',
  skipForward: '<path d="M6 5v14l10-7L6 5Z"/><path d="M19 5v14"/>',
};
function icon(name, cls) {
  return `<svg class="icon${cls ? ' ' + cls : ''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ''}</svg>`;
}

// ---------- agent metadata (shared across dashboard / timeline / findings) ----------

// 'triage' deliberately excluded — agents/triage.md no longer exists (Triage is a synthetic
// verdict now, not a live agent stage, see CLAUDE.md), so GET /api/agents can never return it;
// including it here permanently capped knownAgentsAvailableCount() at 3/4 on a healthy install.
const KNOWN_AGENTS = ['threat_model', 'remediation', 'verify'];
// Kind is differentiated by icon + label text only, not hue — color in this app is reserved
// for real signal (severity, running/done/error state), not decorative category-tagging.
const AGENT_META = {
  scan: { label: 'Scan', icon: 'radar', color: 'var(--text-dim)', role: 'Reads a directory and creates findings' },
  triage: { label: 'Triage', icon: 'search', color: 'var(--text-dim)', role: 'First pass: real finding or noise, how urgent' },
  threat_model: { label: 'Threat Model', icon: 'target', color: 'var(--text-dim)', role: 'Exploit path, preconditions, blast radius' },
  remediation: { label: 'Remediate', icon: 'wrench', color: 'var(--text-dim)', role: 'Proposes a fix for review — writes nothing' },
  fix: { label: 'Fix', icon: 'edit', color: 'var(--text-dim)', role: 'Writes the proposed fix directly to your code' },
  verify: { label: 'Verify', icon: 'checkCircle', color: 'var(--text-dim)', role: 'Re-checks the live code to confirm a fix actually landed' },
  app_threat_model: { label: 'App Threat Model', icon: 'shield', color: 'var(--text-dim)', role: 'Whole-app architecture-level threat model' },
  controls_assist: { label: 'Control Scan', icon: 'clipboard', color: 'var(--text-dim)', role: 'Whole-app NIST 800-53 control identification for SSP drafting' },
};
function agentMeta(name) {
  return AGENT_META[name] || { label: name, icon: 'gear', color: 'var(--muted)', role: '' };
}
// Health-check count: how many of the 3 built-in pipeline agents' files are present.
// Distinct from agentsList.length, which also includes any custom agents.
function knownAgentsAvailableCount() {
  return KNOWN_AGENTS.filter((a) => agentsList.includes(a)).length;
}

// ---------- scan type metadata (mirrors what server.js's SCAN_TYPE_FRAMING actually does) ----------

// 'reasoning' replaced the old separate 'sast'/'dast' entries — both were just this same LLM
// reading source and reasoning about it, so calling them distinct scanner categories was
// misleading. SCA stays distinct on a per-FINDING basis — Agent Triage's type tabs/columns and
// this chip still tell a dependency finding apart from a code finding — even though there's no
// longer a separate SCA Scan page to kick one off from; a dependency audit now always runs
// alongside pattern-matching and reasoning as part of a single Hybrid Scan (see the Reasoning
// Scan bullet in CLAUDE.md), so every scan RECORD's own scanType is always 'reasoning' now —
// only individual findings still carry 'sca'.
const SCAN_TYPE_META = {
  reasoning: { label: 'Hybrid Scan', icon: 'search', color: 'var(--text-dim)', caption: 'LLM reasoning pass over source — vulnerability patterns and attack surface, no live target is hit' },
  sca: { label: 'SCA', icon: 'package', color: 'var(--text-dim)', caption: 'Dependency manifests & lockfiles for known-vulnerable packages' },
};

// ---------- dom refs ----------

const statusEl = document.getElementById('status');
const findingsTypeTabsEl = document.getElementById('findings-type-tabs');
const findingsTableHeadEl = document.getElementById('findings-table-head');
const findingsTableBodyEl = document.getElementById('findings-table-body');
const findingsSubtitleEl = document.getElementById('findings-subtitle');
const findingsScanFilterBtn = document.getElementById('findings-scan-filter-btn');
const findingsScanFilterMenuEl = document.getElementById('findings-scan-filter-menu');
const addFindingBtn = document.getElementById('add-finding-btn');
const exportCsvBtn = document.getElementById('export-csv-btn');
const contextMenuEl = document.getElementById('context-menu');

const scanPathInput = document.getElementById('scan-path-input');
const scanBranchInput = document.getElementById('scan-branch-input');
const scanAppInput = document.getElementById('scan-app-input');
const scanStartBtn = document.getElementById('scan-start-btn');
const scanLiveContainer = document.getElementById('scan-live-container');
const scanBaseBranchWrap = document.getElementById('scan-base-branch-wrap');
const scanBaseBranchInput = document.getElementById('scan-base-branch-input');

const atmPathInput = document.getElementById('atm-path-input');
const atmBranchInput = document.getElementById('atm-branch-input');
const atmAppInput = document.getElementById('atm-app-input');
const atmInstructionInput = document.getElementById('atm-instruction-input');
const atmStartBtn = document.getElementById('atm-start-btn');

const caPathInput = document.getElementById('ca-path-input');
const caBranchInput = document.getElementById('ca-branch-input');
const caAppInput = document.getElementById('ca-app-input');
const caInstructionInput = document.getElementById('ca-instruction-input');
const caStartBtn = document.getElementById('ca-start-btn');
const caContentEl = document.getElementById('ca-content');

const scanType = 'reasoning';
let scanScope = 'full';
// Whether reasoning-half calls (modules + the cross-cutting pass, see runLLMReasoningScan() in
// server.js) get a --max-budget-usd cap at all. Defaults on (the safe default — every reasoning
// call is bounded); turning it off is an explicit opt-in for when a scan is getting cut short by
// the cap and the user wants it to run to completion regardless of cost.
let scanBudgetEnabled = true;

const stageModalOverlay = document.getElementById('stage-modal-overlay');
const stageModalTitle = document.getElementById('stage-modal-title');
const stageModalAgent = document.getElementById('stage-modal-agent');
const stageModalContext = document.getElementById('stage-modal-context');
const stageModalInstruction = document.getElementById('stage-modal-instruction');

const findingModalOverlay = document.getElementById('finding-modal-overlay');
const findingModalTitle = document.getElementById('finding-modal-title');
const findingModalScanType = document.getElementById('finding-modal-scantype');
const findingModalSeverity = document.getElementById('finding-modal-severity');
const findingModalRule = document.getElementById('finding-modal-rule');
const findingModalFile = document.getElementById('finding-modal-file');
const findingModalCode = document.getElementById('finding-modal-code');
const findingModalPackage = document.getElementById('finding-modal-package');
const findingModalPackageVersion = document.getElementById('finding-modal-package-version');
const findingModalFixedVersion = document.getElementById('finding-modal-fixed-version');
const findingModalEndpoint = document.getElementById('finding-modal-endpoint');
const findingModalMethod = document.getElementById('finding-modal-method');
const findingModalDescription = document.getElementById('finding-modal-description');
const fmFieldsReasoning = document.getElementById('fm-fields-reasoning');
const fmFieldsSca = document.getElementById('fm-fields-sca');

let ws = null;
let agentsList = [];
let findings = [];               // list-item shape from GET /api/findings
let findingsTypeFilter = 'all';  // 'all' | 'reasoning' | 'sca'
let findingsScanFilter = 'all';  // 'all' or a scan id — restricts the table to one scan's findings
let findingsSort = { key: 'severity', dir: 'asc' };
let currentFindingDetailId = null;
let currentView = 'dashboard';
const findingCache = new Map();  // findingId -> full finding record (from GET /api/findings/:id)
const stages = new Map();        // runId -> findingId, just enough to correlate incoming WS messages
const stageConsoles = new Map(); // runId -> live console tracking object for per-finding runs (Triage/Threat Model/Remediation), mirrors scanRuns/appThreatModelRuns/controlAssistRuns but only holds the console fields since that's the only live thing these runs track

let timelineEntries = [];        // flattened run history, newest first
let timelineLoaded = false;
let timelineFilter = 'all';
let timelineUnseenDone = 0;      // completions since the user last looked at the timeline drawer
let timelineDrawerOpen = false;

let scansList = [];              // list-item shape from GET /api/scans
let scansLoaded = false;
let appThreatModelsList = [];    // list-item shape from GET /api/app-threat-models
let appThreatModelsLoaded = false;
let controlAssessmentsList = [];  // list-item shape from GET /api/control-assessments
let controlAssessmentsLoaded = false;
const scanRuns = new Map();      // runId -> live scan run state (mirrors a stage's shape)
const scanDetailCache = new Map(); // scanId -> full scan detail (with findings)

function uid() {
  return (crypto.randomUUID ? crypto.randomUUID() : 'id-' + Math.random().toString(36).slice(2) + Date.now());
}

function truncate(str, n) {
  str = String(str);
  return str.length > n ? str.slice(0, n) + '…' : str;
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function formatRelativeTime(ts) {
  if (!ts) return '';
  const diff = Date.now() - ts;
  const min = Math.floor(diff / 60000);
  if (min < 1) return 'just now';
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function dateGroupLabel(ts) {
  const d = new Date(ts);
  const now = new Date();
  const isSameDay = (a, b) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (isSameDay(d, now)) return 'Today';
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (isSameDay(d, yesterday)) return 'Yesterday';
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function setStatus(connected) {
  statusEl.textContent = connected ? 'connected' : 'disconnected';
  statusEl.className = connected ? 'connected' : 'disconnected';
}

async function loadAgents() {
  const res = await fetch('/api/agents');
  agentsList = await res.json();
  stageModalAgent.innerHTML = '';
  for (const a of agentsList) {
    const opt = document.createElement('option');
    opt.value = a; opt.textContent = a;
    stageModalAgent.appendChild(opt);
  }
}

// Shared by the Scans and SCA pages' scope toggles — same full/diff behavior, just a
// different toggle element, base-branch wrap/input, and where the chosen scope is stored.
function wireScopeToggle(toggleSelector, baseBranchWrapEl, baseBranchInputEl, setScope) {
  document.querySelectorAll(`${toggleSelector} .group-toggle-btn`).forEach((btn) => {
    btn.addEventListener('click', () => {
      const scope = btn.dataset.scope;
      setScope(scope);
      document.querySelectorAll(`${toggleSelector} .group-toggle-btn`).forEach((b) => b.classList.toggle('active', b === btn));
      baseBranchWrapEl.hidden = scope !== 'diff';
      if (scope === 'diff') baseBranchInputEl.focus();
    });
  });
}
wireScopeToggle('#scan-scope-toggle', scanBaseBranchWrap, scanBaseBranchInput, (s) => { scanScope = s; });

document.querySelectorAll('#scan-budget-toggle .group-toggle-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    scanBudgetEnabled = btn.dataset.budget === 'on';
    document.querySelectorAll('#scan-budget-toggle .group-toggle-btn').forEach((b) => b.classList.toggle('active', b === btn));
    document.getElementById('scan-budget-hint').hidden = scanBudgetEnabled;
  });
});

function startAppThreatModel() {
  const targetPath = atmPathInput.value.trim();
  if (!targetPath) {
    alert('Enter a target directory path.');
    return;
  }
  const branch = atmBranchInput.value.trim();
  const app = atmAppInput.value.trim();
  const instruction = atmInstructionInput.value.trim();
  const runId = uid();
  const startTime = Date.now();

  const run = {
    runId, toolCount: 0, fileCount: 0, tokenCount: 0, startTime,
    toolsEl: null, filesEl: null, tokensEl: null, elapsedEl: null,
    elapsedTimer: null,
  };
  appThreatModelRuns.set(runId, run);
  run.elapsedTimer = setInterval(() => updateAppThreatModelElapsed(run), 1000);

  upsertAppThreatModel({ id: null, runId, path: targetPath, app: app || null, branch: branch || null, instruction, status: 'running', verdict: null, error: null, startedAt: startTime, finishedAt: null });
  ws.send(JSON.stringify({ type: 'app_threat_model', runId, path: targetPath, app, branch, instruction }));
}

atmStartBtn.addEventListener('click', startAppThreatModel);

function startControlsAssist() {
  const targetPath = caPathInput.value.trim();
  if (!targetPath) {
    alert('Enter a target directory path.');
    return;
  }
  const branch = caBranchInput.value.trim();
  const app = caAppInput.value.trim();
  const instruction = caInstructionInput.value.trim();
  const runId = uid();
  const startTime = Date.now();

  const run = {
    runId, toolCount: 0, fileCount: 0, tokenCount: 0, startTime,
    toolsEl: null, filesEl: null, tokensEl: null, elapsedEl: null,
    elapsedTimer: null,
  };
  controlAssistRuns.set(runId, run);
  run.elapsedTimer = setInterval(() => updateControlsAssistElapsed(run), 1000);

  upsertControlAssessment({ id: null, runId, path: targetPath, app: app || null, branch: branch || null, instruction, status: 'running', verdict: null, error: null, startedAt: startTime, finishedAt: null });
  ws.send(JSON.stringify({ type: 'controls_assist', runId, path: targetPath, app, branch, instruction }));
}

caStartBtn.addEventListener('click', startControlsAssist);

function connect() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}`);

  ws.addEventListener('open', () => { setStatus(true); renderNavStatus(); if (currentView === 'dashboard') renderDashboard(); });
  ws.addEventListener('close', () => { setStatus(false); renderNavStatus(); if (currentView === 'dashboard') renderDashboard(); setTimeout(connect, 2000); });
  ws.addEventListener('error', () => ws.close());
  ws.addEventListener('message', (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    handleServerMessage(msg);
  });
}

// ---------- nav / view switching ----------

document.querySelectorAll('.nav-item[data-view]').forEach((btn) => {
  btn.addEventListener('click', () => showView(btn.dataset.view));
});
document.getElementById('dash-timeline-link').addEventListener('click', () => openTimelineDrawer('all'));
document.getElementById('dash-scans-link').addEventListener('click', () => showView('scans'));

const NAV_COLLAPSE_KEY = 'appsecops-nav-collapsed';
const navEl = document.getElementById('global-nav');
const navCollapseBtn = document.getElementById('nav-collapse-btn');
function applyNavCollapsed(collapsed) {
  navEl.classList.toggle('collapsed', collapsed);
  navCollapseBtn.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
  navCollapseBtn.querySelector('span').textContent = collapsed ? 'Expand' : 'Collapse';
}
navCollapseBtn.addEventListener('click', () => {
  const collapsed = !navEl.classList.contains('collapsed');
  applyNavCollapsed(collapsed);
  try { localStorage.setItem(NAV_COLLAPSE_KEY, collapsed ? '1' : '0'); } catch (e) {}
});
try { applyNavCollapsed(localStorage.getItem(NAV_COLLAPSE_KEY) === '1'); } catch (e) {}
document.querySelectorAll('.nav-item[data-view]').forEach((btn) => {
  btn.title = btn.querySelector('span').textContent;
});

function showView(view, opts = {}) {
  currentView = view;
  document.getElementById('view-dashboard').hidden = view !== 'dashboard';
  document.getElementById('view-scans').hidden = view !== 'scans';
  document.getElementById('view-settings').hidden = view !== 'settings';
  document.getElementById('view-findings').hidden = view !== 'findings';
  document.getElementById('view-finding-detail').hidden = view !== 'finding-detail';
  document.getElementById('view-threatmodel').hidden = view !== 'threatmodel';
  document.getElementById('view-controls-assist').hidden = view !== 'controls-assist';
  document.getElementById('view-surface').hidden = view !== 'surface';
  document.getElementById('view-reports').hidden = view !== 'reports';
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.view === view));

  if (opts.skipInit) return;

  if (view === 'dashboard') renderDashboard();
  if (view === 'findings') renderFindingsView();
  if (view === 'threatmodel') openThreatModelView();
  if (view === 'controls-assist') renderControlsAssistView();
  if (view === 'surface') openSurfaceView();
  if (view === 'settings') renderSettings();
}

// ---------- dashboard ----------

function renderDashboardHeader() {
  document.getElementById('dash-greeting').textContent = 'Dashboard';
  document.getElementById('dash-date').textContent = new Date().toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
}

function statTile(iconName, value, label, sub, accent) {
  const div = document.createElement('div');
  div.className = 'stat-tile' + (accent ? ' accent-' + accent : '');
  div.innerHTML = `
    <div class="stat-icon">${icon(iconName, 'icon-lg')}</div>
    <div class="stat-value">${escapeHtml(String(value))}</div>
    <div class="stat-label">${escapeHtml(label)}</div>
    ${sub ? `<div class="stat-sub">${escapeHtml(sub)}</div>` : ''}
  `;
  return div;
}

function computeBriefing() {
  const runningScans = scansList.filter((s) => s.status === 'running');
  const running = findings.filter((f) => f.latestRun && f.latestRun.status === 'running');
  const notTriaged = findings.filter((f) => f.status === 'new').length;
  const parts = [];
  if (runningScans.length) {
    parts.push(`Scanning "${truncate(runningScans[0].path, 45)}"${runningScans.length > 1 ? ` (+${runningScans.length - 1} more running)` : ''}`);
  } else if (running.length) {
    const r = running[0];
    parts.push(`${agentMeta(r.latestRun.agent).label} is working on "${truncate(r.title, 50)}"${running.length > 1 ? ` (+${running.length - 1} more running)` : ''}`);
  } else {
    parts.push('No agents currently running');
  }
  parts.push(`${notTriaged} finding${notTriaged === 1 ? '' : 's'} awaiting remediation`);
  parts.push(`${agentsList.length} agent${agentsList.length === 1 ? '' : 's'} available`);
  return parts.join('. ') + '.';
}

function renderDashboard() {
  renderDashboardHeader();

  document.getElementById('dash-briefing-text').textContent = computeBriefing();

  const statsEl = document.getElementById('dash-stats');
  statsEl.innerHTML = '';
  const inProgress = findings.filter((f) => f.latestRun && f.latestRun.status === 'running').length;
  const notTriaged = findings.filter((f) => f.status === 'new').length;
  const inReview = findings.filter((f) => f.status === 'in_review').length;
  const remediationReady = findings.filter((f) => f.status === 'remediation_ready').length;
  const closed = findings.filter((f) => f.status === 'closed').length;
  const runsToday = timelineEntries.filter((e) => dateGroupLabel(e.startedAt) === 'Today').length;
  const totalRuns = timelineEntries.length || findings.reduce((n, f) => n + f.runCount, 0);

  statsEl.appendChild(statTile('hourglass', inProgress, 'In Progress', inProgress ? 'agents running' : '', inProgress ? 'warn' : ''));
  statsEl.appendChild(statTile('inbox', notTriaged, 'Not Started', '', ''));
  statsEl.appendChild(statTile('eye', inReview, 'In Review', '', ''));
  statsEl.appendChild(statTile('checkCircle', remediationReady, 'Remediation Ready', remediationReady ? 'ready to fix' : '', remediationReady ? 'ok' : ''));
  statsEl.appendChild(statTile('folder', findings.length, 'Total Findings', `${closed} closed`, ''));
  statsEl.appendChild(statTile('trending', totalRuns, 'Agent Runs', `${runsToday} today`, 'accent'));

  const agentsEl = document.getElementById('dash-agents');
  agentsEl.innerHTML = '';
  for (const name of agentsList) {
    const meta = agentMeta(name);
    const lastEntry = timelineEntries.find((e) => e.agent === name);
    const row = document.createElement('div');
    row.className = 'agent-row';
    row.innerHTML = `
      <span class="a-icon">${icon(meta.icon)}</span>
      <div class="agent-row-main">
        <div class="agent-row-name">${escapeHtml(meta.label)}</div>
        <div class="agent-row-meta">${escapeHtml(meta.role)}</div>
      </div>
      <div class="agent-row-status">${lastEntry ? `${escapeHtml(truncate(lastEntry.findingTitle, 26))}<br>${formatRelativeTime(lastEntry.startedAt)}` : 'no runs yet'}</div>
    `;
    agentsEl.appendChild(row);
  }
}

// ---------- sidebar status ----------
// The sidebar used to also show a 4-line connected/findings/agents/scans summary block
// (#nav-status) — removed as redundant with the per-page nav badges below, which already
// surface running/attention state contextually. renderNavStatus() is kept as the name every
// call site already uses; it now only refreshes those badges.
function renderNavStatus() {
  renderNavBadges();
}

// ---------- timeline (a slide-in drawer, opened from a clock-icon button on Hybrid Scan and
// Threat Model — not a top-level nav destination) ----------

async function loadTimeline() {
  const res = await fetch('/api/timeline');
  timelineEntries = await res.json();
  timelineLoaded = true;
  renderTimeline();
}

document.getElementById('timeline-refresh').addEventListener('click', loadTimeline);

// presetKind: how a clock-icon button scopes the drawer on open — the pills inside the drawer
// still let the user broaden or switch away from that preset afterward.
function openTimelineDrawer(presetKind) {
  if (presetKind !== undefined) timelineFilter = presetKind;
  timelineDrawerOpen = true;
  document.getElementById('timeline-drawer-backdrop').hidden = false;
  document.getElementById('timeline-drawer').hidden = false;
  document.getElementById('timeline-drawer').classList.add('open');
  timelineUnseenDone = 0;
  renderNavBadges();
  if (!timelineLoaded) loadTimeline(); else renderTimeline();
}

function closeTimelineDrawer() {
  timelineDrawerOpen = false;
  document.getElementById('timeline-drawer').classList.remove('open');
  document.getElementById('timeline-drawer-backdrop').hidden = true;
  document.getElementById('timeline-drawer').hidden = true;
}

document.getElementById('timeline-drawer-close').addEventListener('click', closeTimelineDrawer);
document.getElementById('timeline-drawer-backdrop').addEventListener('click', closeTimelineDrawer);
document.getElementById('scans-clock-btn').addEventListener('click', () => openTimelineDrawer('scan'));
document.getElementById('tm-clock-btn').addEventListener('click', () => openTimelineDrawer('threat_model'));

function renderTimelineFilters() {
  const el = document.getElementById('timeline-filters');
  el.innerHTML = '';
  const makePill = (key, label, color) => {
    const pill = document.createElement('button');
    const isActive = timelineFilter === key;
    pill.className = 'filter-pill' + (isActive ? ' active' : '');
    pill.innerHTML = color ? `<span class="fp-dot" style="background:${color}"></span>${escapeHtml(label)}` : escapeHtml(label);
    pill.addEventListener('click', () => {
      timelineFilter = key;
      renderTimeline();
    });
    el.appendChild(pill);
  };
  makePill('all', 'All', null);
  // One "Hybrid Scan" pill covers every scan record now — pattern-matching, reasoning, and SCA
  // all run as part of the same scan (see the Reasoning Scan bullet in CLAUDE.md), so there's no
  // separate SCA-kind scan record left to filter to; findings still distinguish 'sca' from
  // 'reasoning' individually, but that's an Agent Triage concern, not a Timeline one.
  makePill('scan', 'Hybrid Scan', SCAN_TYPE_META.reasoning.color);
  for (const kind of agentsList) makePill(kind, agentMeta(kind).label, agentMeta(kind).color);

  const subtitleEl = document.getElementById('timeline-drawer-subtitle');
  if (timelineFilter === 'scan') {
    subtitleEl.textContent = 'Hybrid Scan runs, newest first';
  } else if (timelineFilter !== 'all') {
    subtitleEl.textContent = `${agentMeta(timelineFilter).label} runs, newest first`;
  } else {
    subtitleEl.textContent = 'Every scan and agent run, newest first';
  }
}

function timelineStatusBadge(entry) {
  if (entry.status === 'running') return { cls: 'in_review', text: 'running' };
  if (entry.status === 'cancelled') return { cls: 'new', text: 'cancelled' };
  if (entry.status === 'error') return { cls: 'high', text: 'error' };
  if (entry.kind === 'scan') return { cls: 'remediation_ready', text: 'done' };
  const v = entry.verdict && entry.verdict.verdict;
  return { cls: v || 'new', text: v || 'done' };
}

function timelineSummary(entry) {
  if (entry.kind === 'scan') {
    if (entry.status === 'running') return entry.instruction ? `Scanning — ${truncate(entry.instruction, 100)}` : 'Scanning…';
    if (entry.status === 'cancelled') return 'Cancelled';
    if (entry.status === 'error') return entry.error ? truncate(entry.error, 140) : 'Error';
    const n = entry.findingCount || 0;
    return `${n} finding${n === 1 ? '' : 's'} created`;
  }
  if (entry.status === 'running') return entry.instruction ? `Running — ${truncate(entry.instruction, 100)}` : 'Running…';
  if (entry.status === 'cancelled') return 'Cancelled';
  if (entry.status === 'error') return 'Error';
  if (entry.verdict && entry.verdict.reasoning) return truncate(entry.verdict.reasoning, 140);
  if (entry.verdict && entry.verdict.verdict) return `Verdict: ${entry.verdict.verdict}`;
  return 'Completed — no verdict block found';
}

function renderTimeline() {
  renderTimelineFilters();
  const listEl = document.getElementById('timeline-list');
  listEl.innerHTML = '';

  const filtered = timelineFilter === 'all' ? timelineEntries : timelineEntries.filter((e) => e.kind === timelineFilter);
  if (!filtered.length) {
    const empty = document.createElement('div');
    empty.id = 'timeline-empty';
    empty.textContent = 'No activity yet.';
    listEl.appendChild(empty);
    return;
  }

  let lastGroup = null;
  for (const entry of filtered) {
    const group = dateGroupLabel(entry.startedAt);
    if (group !== lastGroup) {
      const groupEl = document.createElement('div');
      groupEl.className = 'timeline-date';
      groupEl.textContent = group;
      listEl.appendChild(groupEl);
      lastGroup = group;
    }

    const meta = agentMeta(entry.kind);
    const badge = timelineStatusBadge(entry);
    const isScan = entry.kind === 'scan';
    const title = isScan ? entry.path : entry.findingTitle;

    const row = document.createElement('div');
    row.className = 'timeline-row' + (isScan ? ' expandable' : '');
    row.style.borderLeftColor = meta.color;
    row.innerHTML = `
      <div style="display:flex; align-items:flex-start; gap:10px; width:100%;">
        <span class="tl-icon" style="color:${meta.color};">${icon(meta.icon)}</span>
        <div class="tl-main">
          <span class="tl-kind" style="color:${meta.color};">${escapeHtml(meta.label)} Agent</span>
          <div class="tl-top">
            <span class="tl-title${isScan ? ' path-text' : ''}">${escapeHtml(title)}</span>
            <span class="badge ${badge.cls}">${escapeHtml(badge.text)}</span>
          </div>
          <div class="tl-summary">${escapeHtml(timelineSummary(entry))}</div>
        </div>
        <div class="tl-time">${escapeHtml(formatRelativeTime(entry.startedAt))}</div>
      </div>
    `;

    if (isScan) {
      row.addEventListener('click', async () => {
        let body = row.querySelector('.timeline-row-body');
        if (body) { body.remove(); return; }
        body = document.createElement('div');
        body.className = 'timeline-row-body';
        body.innerHTML = '<div class="hint">Loading…</div>';
        row.appendChild(body);
        if (!entry.scanId) { body.innerHTML = '<div class="hint">No findings to show yet.</div>'; return; }
        let detail = scanDetailCache.get(entry.scanId);
        if (!detail) {
          detail = await fetch(`/api/scans/${entry.scanId}`).then((r) => r.json());
          scanDetailCache.set(entry.scanId, detail);
        }
        renderScanFindingsBody(body, detail.findings, entry.scanId, detail);
      });
    } else {
      row.addEventListener('click', () => openFindingDetail(entry.findingId));
    }
    listEl.appendChild(row);
  }
}

function upsertTimelineEntry(entry) {
  const idx = timelineEntries.findIndex((e) => e.runId === entry.runId);
  const priorStatus = idx >= 0 ? timelineEntries[idx].status : null;
  if (idx >= 0) timelineEntries[idx] = { ...timelineEntries[idx], ...entry };
  else timelineEntries.unshift(entry);

  const newStatus = idx >= 0 ? timelineEntries[idx].status : timelineEntries[0].status;
  if (priorStatus === 'running' && newStatus !== 'running' && !timelineDrawerOpen) {
    timelineUnseenDone++;
  }

  if (timelineDrawerOpen) renderTimeline();
  if (currentView === 'threatmodel') renderThreatModelView();
  renderNavBadges();
}

// A small dot on each page's clock-icon button (not a single shared nav badge, since Timeline
// is no longer one nav destination) — yellow while that page's own scope has a run in progress
// (derived from scansList/findings, not timelineEntries, so it works before the drawer has ever
// been opened/loaded), green if nothing in that scope is running but something finished
// somewhere since the drawer was last opened (timelineUnseenDone, global — matches the old
// single-badge behavior: opening the drawer for either scope clears it for both).
function updateTimelineClockDots() {
  const setDot = (id, running) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (running) { el.hidden = false; el.className = 'clock-btn-dot running'; }
    else if (timelineUnseenDone > 0) { el.hidden = false; el.className = 'clock-btn-dot completed'; }
    else { el.hidden = true; }
  };
  setDot('scans-clock-dot', scansList.some((s) => s.status === 'running'));
  setDot('tm-clock-dot', findings.some((f) => f.latestRun && f.latestRun.agent === 'threat_model' && f.latestRun.status === 'running'));
}

function renderNavBadges() {
  updateTimelineClockDots();

  const findingsBadge = document.getElementById('nav-badge-findings');
  const openCount = findings.filter((f) => f.status !== 'closed').length;
  if (openCount > 0) {
    findingsBadge.hidden = false;
    findingsBadge.textContent = String(openCount);
    findingsBadge.title = `${openCount} open finding${openCount === 1 ? '' : 's'}`;
  } else {
    findingsBadge.hidden = true;
  }

  const scansBadge = document.getElementById('nav-badge-scans');
  const runningScanCount = scansList.filter((s) => s.status === 'running').length;
  if (runningScanCount > 0) {
    scansBadge.hidden = false;
    scansBadge.className = 'nav-badge running';
    scansBadge.title = `${runningScanCount} scan${runningScanCount === 1 ? '' : 's'} running`;
  } else {
    scansBadge.hidden = true;
  }

  const caBadge = document.getElementById('nav-badge-controls-assist');
  const runningCaCount = controlAssessmentsList.filter((r) => r.status === 'running').length;
  if (runningCaCount > 0) {
    caBadge.hidden = false;
    caBadge.className = 'nav-badge running';
    caBadge.title = `${runningCaCount} control scan${runningCaCount === 1 ? '' : 's'} running`;
  } else {
    caBadge.hidden = true;
  }
}

// ---------- threat model (category x severity heat map + per-finding attack-path report) ----------
// Read-only, cross-finding view derived entirely from timelineEntries (no dedicated
// endpoint) — every finding with a completed Threat Model run, grouped by verdict.owasp
// and laid out as a heat map instead of a card grid: rows = OWASP categories (sorted by
// finding count), columns = the fixed severity scale, each cell shaded by how many findings
// land in that category+severity combo. Clicking a cell renders the matching finding's (or,
// for a cell with more than one, a picker followed by the chosen finding's) attack path as a
// 4-box flow (Attacker -> Preconditions -> Attack Path -> Blast Radius) using the exact prose
// the Threat Model agent wrote — no new agent capability needed, this is purely a different
// way to look at data the agent already produces.

async function openThreatModelView() {
  if (!timelineLoaded) await loadTimeline();
  renderThreatModelView();
}

function latestThreatModelEntries() {
  const byFinding = new Map(); // findingId -> most recent threat_model entry (list is newest-first)
  for (const e of timelineEntries) {
    if (e.kind !== 'threat_model' || !e.findingId) continue;
    if (!byFinding.has(e.findingId)) byFinding.set(e.findingId, e);
  }
  return [...byFinding.values()].filter((e) => e.verdict && ['confirmed', 'needs_review'].includes(e.verdict.verdict));
}

const HEATMAP_SEVERITY_COLS = ['critical', 'high', 'medium', 'low', 'informational'];

function worstOfList(list, getSeverity) {
  let worst = null;
  for (const item of list) {
    const sev = getSeverity(item);
    if (!sev) continue;
    if (worst === null || (SEV_ORDER_MAP[sev] ?? 99) < (SEV_ORDER_MAP[worst] ?? 99)) worst = sev;
  }
  return worst || 'informational';
}

// Shared by both the per-finding Threat Model page and the app-level report's diagram: rows are
// categories (OWASP, sorted by finding/risk count descending), columns are the fixed severity
// scale. Cells only carry data-category/data-sev — callers re-derive the underlying items for a
// clicked cell from their own already-grouped data rather than the DOM, since a cell represents
// a whole category+severity bucket, not a single item.
function buildThreatHeatmap(categories, getSeverity) {
  const headerCells = HEATMAP_SEVERITY_COLS.map((sev) => `<div class="tm-heat-col-label">${severityLabel(sev)}</div>`).join('');
  const rowsHtml = categories.map(([category, list]) => {
    const counts = new Map(HEATMAP_SEVERITY_COLS.map((s) => [s, 0]));
    for (const item of list) {
      const sev = getSeverity(item);
      const key = counts.has(sev) ? sev : 'informational';
      counts.set(key, counts.get(key) + 1);
    }
    const maxCount = Math.max(1, ...HEATMAP_SEVERITY_COLS.map((s) => counts.get(s)));
    const cellsHtml = HEATMAP_SEVERITY_COLS.map((sev) => {
      const count = counts.get(sev);
      const intensity = count ? (0.28 + 0.72 * (count / maxCount)).toFixed(2) : 0;
      return `<button type="button" class="tm-heat-cell${count ? ` has-findings sev-${sev}` : ' empty'}" style="--heat-intensity:${intensity}" data-category="${escapeHtml(category)}" data-sev="${sev}"${count ? '' : ' disabled'}>${count || ''}</button>`;
    }).join('');
    const rowSev = worstOfList(list, getSeverity);
    return `
      <div class="tm-heat-row">
        <div class="tm-heat-row-label sev-${rowSev}" title="${escapeHtml(category)}">${escapeHtml(category)} <span class="tm-heat-row-count">${list.length}</span></div>
        <div class="tm-heat-row-cells">${cellsHtml}</div>
      </div>
    `;
  }).join('');

  return `
    <div class="tm-heatmap">
      <div class="tm-heat-header"><div class="tm-heat-row-label"></div><div class="tm-heat-row-cells">${headerCells}</div></div>
      ${rowsHtml}
    </div>
  `;
}

function allThreatModelEntriesForFinding(findingId) {
  // timelineEntries is newest-first already, so this stays newest-first too.
  return timelineEntries.filter((e) => e.kind === 'threat_model' && e.findingId === findingId && e.verdict);
}

// Which findingIds the per-finding heat map currently represents (its cells only aggregate the
// *latest* confirmed/needs_review run per finding) — used by renderThreatModelDetail() to decide
// whether the run being viewed is actually reflected in the map above it, without re-querying
// the DOM for a specific finding's cell (a cell is a whole category+severity bucket, not a
// per-finding element).
let tmMapFindingIds = new Set();

function renderThreatModelView() {
  const entries = latestThreatModelEntries();
  tmMapFindingIds = new Set(entries.map((e) => e.findingId));
  const contentEl = document.getElementById('tm-content');

  const groups = new Map();
  for (const e of entries) {
    const key = e.verdict.owasp || null;
    const label = key || 'Unclassified';
    if (!groups.has(label)) groups.set(label, []);
    groups.get(label).push(e);
  }
  const categories = [...groups.entries()].sort((a, b) => b[1].length - a[1].length);

  const diagramHtml = entries.length
    ? `<div class="tm-diagram-wrap tm-main-diagram">${buildThreatHeatmap(categories, (e) => e.verdict.severity_confirmed || 'informational')}</div>`
    : '<div class="hint" style="padding:30px 4px;">No findings have a confirmed Threat Model run yet — open a finding and use its "…" agent menu to run Threat Model.</div>';

  contentEl.innerHTML = `
    ${renderAppThreatModelSection()}
    ${diagramHtml}
    <div id="tm-cell-findings" class="tm-cell-findings" hidden></div>
    <div id="tm-detail-panel" class="tm-detail-panel"><div class="hint">Click a cell above to see the report for its findings.</div></div>
  `;

  contentEl.querySelectorAll('.tm-main-diagram .tm-heat-cell.has-findings').forEach((el) => {
    el.addEventListener('click', () => {
      const cellEntries = entries.filter((e) => (e.verdict.owasp || 'Unclassified') === el.dataset.category && (e.verdict.severity_confirmed || 'informational') === el.dataset.sev);
      contentEl.querySelectorAll('.tm-main-diagram .tm-heat-cell').forEach((c) => c.classList.toggle('selected', c === el));
      renderTmCellFindings(cellEntries);
    });
  });
  // Only the summary bar toggles the accordion — the expanded body is a child of .atm-row,
  // but risk cards/heat cells inside it aren't listening on .atm-row-summary so they never
  // trigger a collapse when clicked.
  contentEl.querySelectorAll('.atm-row-summary').forEach((el) => {
    el.addEventListener('click', () => toggleAppThreatModelRow(el.closest('.atm-row').dataset.atmRunId));
  });
  contentEl.querySelectorAll('.atm-risk-card').forEach((el) => {
    el.addEventListener('click', () => {
      const scope = el.closest('.atm-row-body');
      if (!scope) return;
      scope.querySelectorAll('.atm-risk-card').forEach((c) => c.classList.toggle('selected', c === el));
    });
  });
  contentEl.querySelectorAll('.atm-row-body .tm-heat-cell.has-findings').forEach((el) => {
    el.addEventListener('click', () => {
      const scope = el.closest('.atm-row-body');
      if (!scope) return;
      scope.querySelectorAll('.tm-heat-cell').forEach((c) => c.classList.toggle('selected', c === el));
      let first = null;
      scope.querySelectorAll('.atm-risk-card').forEach((card) => {
        const match = card.dataset.owasp === el.dataset.category && card.dataset.severity === el.dataset.sev;
        card.classList.toggle('selected', match);
        if (match && !first) first = card;
      });
      if (first) first.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  });
  wireConsoleToggles(contentEl, appThreatModelRuns, renderThreatModelView);
  reattachAppThreatModelLiveRefs();
  updateTmViewingLabel();
}

// A heat map cell aggregates every finding in one category+severity bucket — for the common
// case of exactly one, jump straight to its attack-path report; otherwise show a small picker
// of finding titles (the "report" the cell represents) so the user chooses which one to read.
function renderTmCellFindings(cellEntries) {
  const listEl = document.getElementById('tm-cell-findings');
  if (!cellEntries.length) return;
  if (cellEntries.length === 1) {
    listEl.hidden = true;
    listEl.innerHTML = '';
    selectThreatModelFinding(cellEntries[0].findingId);
    return;
  }
  listEl.hidden = false;
  listEl.innerHTML = cellEntries.map((e, i) => `<button type="button" class="tm-cell-finding-item${i === 0 ? ' active' : ''}" data-finding-id="${escapeHtml(e.findingId)}">${escapeHtml(e.findingTitle)}</button>`).join('');
  listEl.querySelectorAll('[data-finding-id]').forEach((el) => {
    el.addEventListener('click', () => {
      listEl.querySelectorAll('.tm-cell-finding-item').forEach((b) => b.classList.toggle('active', b === el));
      selectThreatModelFinding(el.dataset.findingId);
    });
  });
  selectThreatModelFinding(cellEntries[0].findingId);
}

// ---------- app-level (whole-directory) threat models ----------
// Independent of the per-finding heat map above: these are holistic, architecture-level
// runs (agents/app_threat_model.md) fired from the "New app threat model" form on this same
// page. Not tied to any finding, so they get their own list + accordion detail (with its own
// heat map built from top_risks) rather than a cell on the per-finding map above.
//
// Live stats: like scan cards, a running row shows tool/file/token counts, elapsed time, and
// a context-window fill bar (`appThreatModelRuns`, runId -> tracking object, mirrors
// `scanRuns`). The tricky part is that `renderThreatModelView()` can rebuild `#tm-content`
// from scratch at any time (e.g. any timeline update while this view is open, per
// upsertTimelineEntry) — including while a run is live. Rather than avoid that rebuild
// entirely, `appThreatModelRowHtml()` bakes the tracking object's *current* counters directly
// into the fresh HTML string (so a rebuild never visually resets progress to zero), and
// `reattachAppThreatModelLiveRefs()` (called at the end of every renderThreatModelView()) then
// re-queries the fresh DOM and re-points the tracking object's cached element refs at it, so
// the next stream-json event's direct DOM mutation (handleAppThreatModelRawEvent, no
// re-render) lands on the currently-attached node instead of a stale detached one.
const appThreatModelRuns = new Map(); // runId -> { toolCount, fileCount, tokenCount, startTime, elapsedTimer, ...cached DOM refs }

function updateAppThreatModelElapsed(run) {
  if (run.elapsedEl) run.elapsedEl.textContent = formatElapsed(Date.now() - run.startTime);
}

function stopAppThreatModelElapsedTimer(run) {
  if (run.elapsedTimer) {
    clearInterval(run.elapsedTimer);
    run.elapsedTimer = null;
  }
  updateAppThreatModelElapsed(run);
}

function handleAppThreatModelRawEvent(run, event) {
  trackRunToolActivity(run, event);
  trackRunTokens(run, event);
  trackConsoleText(run, event);
}

// Which app-level run's row is expanded — a real accordion (one at a time), not a separate
// detail panel elsewhere on the page. Persists across renderThreatModelView() rebuilds since
// appThreatModelRowHtml() reads it directly when building each row's markup.
let expandedAtmRunId = null;

function toggleAppThreatModelRow(runId) {
  expandedAtmRunId = expandedAtmRunId === runId ? null : runId;
  renderThreatModelView();
}

// Shows which run's content is currently expanded in the view header, since two rows for the
// same path (a re-run) look identical at a glance otherwise — easy to lose track of which one
// you're looking at.
function updateTmViewingLabel() {
  const label = document.getElementById('tm-viewing-label');
  const record = expandedAtmRunId ? appThreatModelsList.find((r) => r.runId === expandedAtmRunId) : null;
  if (!record) {
    label.hidden = true;
    return;
  }
  label.hidden = false;
  label.textContent = `Viewing scan: ${record.path}${record.app ? ' · ' + record.app : ''} — ${formatRelativeTime(record.startedAt)}`;
}

function appThreatModelRowHtml(r) {
  const statusCls = r.status === 'running' ? 'in_review' : r.status === 'error' ? 'high' : r.status === 'cancelled' ? 'high' : 'closed';
  const statusText = r.status === 'running' ? 'Running' : r.status === 'error' ? 'Error' : r.status === 'cancelled' ? 'Cancelled' : 'Done';
  const topRisks = r.verdict && Array.isArray(r.verdict.top_risks) ? r.verdict.top_risks : [];
  let worstSev = null;
  for (const risk of topRisks) {
    if (!risk.severity) continue;
    if (worstSev === null || (SEV_ORDER_MAP[risk.severity] ?? 99) < (SEV_ORDER_MAP[worstSev] ?? 99)) worstSev = risk.severity;
  }

  const run = appThreatModelRuns.get(r.runId);
  let liveStatsHtml = '';
  if (r.status === 'running' && run) {
    liveStatsHtml = `
      <div class="scan-stats atm-live-stats">
        <span class="stat"><b class="atm-tools">${run.toolCount}</b> checks</span>
        <span class="stat"><b class="atm-files">${run.fileCount}</b> files read</span>
        <span class="stat"><b class="atm-tokens">${formatTokenCount(run.tokenCount)}</b> tokens</span>
        <span class="stat"><b class="atm-elapsed">${formatElapsed(Date.now() - run.startTime)}</b> elapsed</span>
      </div>
    `;
  }

  const isExpanded = r.runId === expandedAtmRunId;
  const bodyHtml = isExpanded ? `<div class="atm-row-body">${renderAppThreatModelDetail(r)}</div>` : '';

  return `
    <div class="atm-row${isExpanded ? ' expanded' : ''}" data-atm-run-id="${escapeHtml(r.runId)}">
      <div class="atm-row-summary">
        <span class="sev-dot ${escapeHtml(worstSev || 'informational')}"${worstSev ? '' : ' style="opacity:.3;"'}></span>
        <div class="atm-row-main">
          <div class="atm-row-title">${escapeHtml(truncate(r.path, 56))}${r.app ? ' · ' + escapeHtml(r.app) : ''}</div>
          <div class="atm-row-sub">${escapeHtml(formatRelativeTime(r.startedAt))}</div>
          ${liveStatsHtml}
        </div>
        <span class="badge ${statusCls}">${escapeHtml(statusText)}</span>
        ${run ? consoleToggleButtonHtml(run) : ''}
      </div>
      ${run ? consolePanelHtml(run, 'atm-console') : ''}
      ${bodyHtml}
    </div>
  `;
}

function reattachAppThreatModelLiveRefs() {
  for (const run of appThreatModelRuns.values()) {
    const rowEl = document.querySelector(`.atm-row[data-atm-run-id="${run.runId}"]`);
    if (!rowEl) continue;
    run.toolsEl = rowEl.querySelector('.atm-tools');
    run.filesEl = rowEl.querySelector('.atm-files');
    run.tokensEl = rowEl.querySelector('.atm-tokens');
    run.elapsedEl = rowEl.querySelector('.atm-elapsed');
    run.consoleEl = rowEl.querySelector('.atm-console');
  }
}

function renderAppThreatModelSection() {
  if (!appThreatModelsList.length) return '';
  const sorted = appThreatModelsList.slice().sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0));
  const rows = sorted.map((r) => appThreatModelRowHtml(r)).join('');

  return `
    <div class="atm-section">
      <div class="atm-section-title">App-level Threat Models</div>
      <div class="atm-list">${rows}</div>
    </div>
  `;
}

function renderAppThreatModelDetail(record) {
  if (record.status === 'running') {
    return '<div class="hint" style="padding:14px 4px;">Still running…</div>';
  }
  if (record.status === 'cancelled') {
    return '<div class="fd-verdict-reasoning" style="padding:14px 4px;">Cancelled — no report produced.</div>';
  }
  if (record.status === 'error' || !record.verdict) {
    return `<div class="fd-verdict-reasoning" style="padding:14px 4px;">${escapeHtml(record.error || 'Run failed — no report produced.')}</div>`;
  }
  const v = record.verdict;
  const trustBoundariesHtml = (v.trust_boundaries || []).map((b) => `
    <div class="atm-detail-item"><b>${escapeHtml(b.name || '')}</b><div>${escapeHtml(b.description || '')}</div></div>
  `).join('') || '<div class="hint">None identified.</div>';
  const dataFlowsHtml = (v.data_flows || []).map((d) => `
    <div class="atm-detail-item"><b>${escapeHtml(d.name || '')}</b><div>${escapeHtml(d.description || '')}</div></div>
  `).join('') || '<div class="hint">None identified.</div>';
  const risks = v.top_risks || [];
  const risksHtml = risks.map((risk, i) => `
    <div class="atm-risk-card" id="atm-risk-${i}" data-risk-index="${i}" data-owasp="${escapeHtml(risk.owasp || 'Unclassified')}" data-severity="${escapeHtml(risk.severity || 'informational')}">
      <div class="atm-risk-top">
        <span class="badge ${escapeHtml(risk.severity || 'informational')}">${escapeHtml(risk.severity || 'informational')}</span>
        <b>${escapeHtml(risk.title || '')}</b>
      </div>
      <div class="fd-verdict-reasoning">${escapeHtml(risk.description || '')}</div>
      ${risk.owasp || risk.cwe ? `<div class="tm-detail-badges" style="margin-top:6px;">${risk.owasp ? `<span class="scan-type-chip scope-chip">${escapeHtml(risk.owasp)}</span>` : ''}${risk.cwe ? `<span class="scan-type-chip scope-chip">${escapeHtml(risk.cwe)}</span>` : ''}</div>` : ''}
    </div>
  `).join('') || '<div class="hint">No structural risks flagged.</div>';
  const recommendationsHtml = (v.recommendations || []).map((r) => `<li>${escapeHtml(r)}</li>`).join('') || '<li class="hint">None given.</li>';
  const riskCategories = [...risks.reduce((groups, risk) => {
    const key = risk.owasp || 'Unclassified';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(risk);
    return groups;
  }, new Map()).entries()].sort((a, b) => b[1].length - a[1].length);
  const diagramHtml = risks.length ? `<div class="tm-diagram-wrap">${buildThreatHeatmap(riskCategories, (r) => r.severity || 'informational')}</div>` : '';

  return `
    ${diagramHtml}
    <div class="fd-section-title">Summary</div>
    <div class="fd-prose" style="margin-bottom:14px;">${escapeHtml(v.summary || '—')}</div>
    <div class="fd-section-title">Trust boundaries</div>
    <div style="margin-bottom:14px;">${trustBoundariesHtml}</div>
    <div class="fd-section-title">Data flows</div>
    <div style="margin-bottom:14px;">${dataFlowsHtml}</div>
    <div class="fd-section-title">Top risks</div>
    <div style="margin-bottom:14px;">${risksHtml}</div>
    <div class="fd-section-title">Recommendations</div>
    <ul class="atm-recs">${recommendationsHtml}</ul>
  `;
}

// ---------- control assessments (whole-directory NIST 800-53 control identification) ----------
// Same shape and same independent-from-findings relationship as the app-level threat models
// above (agents/controls_assist.md, fired from the "New control scan" form on the
// dedicated Control Scan page) — reuses the identical live-stats/accordion/reattach
// pattern, just with its own tracking map and its own detail renderer since the report shape
// (controls grouped by NIST family, no severity scale) genuinely differs from a threat
// model's risk cards.
const controlAssistRuns = new Map(); // runId -> { toolCount, fileCount, tokenCount, startTime, elapsedTimer, ...cached DOM refs }

function updateControlsAssistElapsed(run) {
  if (run.elapsedEl) run.elapsedEl.textContent = formatElapsed(Date.now() - run.startTime);
}

function stopControlsAssistElapsedTimer(run) {
  if (run.elapsedTimer) {
    clearInterval(run.elapsedTimer);
    run.elapsedTimer = null;
  }
  updateControlsAssistElapsed(run);
}

function handleControlsAssistRawEvent(run, event) {
  trackRunToolActivity(run, event);
  trackRunTokens(run, event);
  trackConsoleText(run, event);
}

// Which control-assessment row is expanded — a real accordion (one at a time), mirrors
// expandedAtmRunId. Persists across renderControlsAssistView() rebuilds since caRowHtml()
// reads it directly when building each row's markup.
let expandedCaRunId = null;

function toggleControlsAssistRow(runId) {
  expandedCaRunId = expandedCaRunId === runId ? null : runId;
  renderControlsAssistView();
}

function caRowHtml(r) {
  const statusCls = r.status === 'running' ? 'in_review' : r.status === 'error' ? 'high' : r.status === 'cancelled' ? 'high' : 'closed';
  const statusText = r.status === 'running' ? 'Running' : r.status === 'error' ? 'Error' : r.status === 'cancelled' ? 'Cancelled' : 'Done';

  const run = controlAssistRuns.get(r.runId);
  let liveStatsHtml = '';
  if (r.status === 'running' && run) {
    liveStatsHtml = `
      <div class="scan-stats atm-live-stats">
        <span class="stat"><b class="ca-tools">${run.toolCount}</b> checks</span>
        <span class="stat"><b class="ca-files">${run.fileCount}</b> files read</span>
        <span class="stat"><b class="ca-tokens">${formatTokenCount(run.tokenCount)}</b> tokens</span>
        <span class="stat"><b class="ca-elapsed">${formatElapsed(Date.now() - run.startTime)}</b> elapsed</span>
      </div>
    `;
  }

  const isExpanded = r.runId === expandedCaRunId;
  const bodyHtml = isExpanded ? `<div class="atm-row-body">${renderControlsAssistDetail(r)}</div>` : '';

  return `
    <div class="atm-row${isExpanded ? ' expanded' : ''}" data-ca-run-id="${escapeHtml(r.runId)}">
      <div class="atm-row-summary">
        <div class="atm-row-main">
          <div class="atm-row-title">${escapeHtml(truncate(r.path, 56))}${r.app ? ' · ' + escapeHtml(r.app) : ''}</div>
          <div class="atm-row-sub">${escapeHtml(formatRelativeTime(r.startedAt))}</div>
          ${liveStatsHtml}
        </div>
        <span class="badge ${statusCls}">${escapeHtml(statusText)}</span>
        ${run ? consoleToggleButtonHtml(run) : ''}
      </div>
      ${run ? consolePanelHtml(run, 'ca-console') : ''}
      ${bodyHtml}
    </div>
  `;
}

function reattachControlsAssistLiveRefs() {
  for (const run of controlAssistRuns.values()) {
    const rowEl = document.querySelector(`.atm-row[data-ca-run-id="${run.runId}"]`);
    if (!rowEl) continue;
    run.toolsEl = rowEl.querySelector('.ca-tools');
    run.filesEl = rowEl.querySelector('.ca-files');
    run.tokensEl = rowEl.querySelector('.ca-tokens');
    run.elapsedEl = rowEl.querySelector('.ca-elapsed');
    run.consoleEl = rowEl.querySelector('.ca-console');
  }
}

function renderControlsAssistSection() {
  if (!controlAssessmentsList.length) return '<div class="hint">No control scans yet — start one above.</div>';
  const sorted = controlAssessmentsList.slice().sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0));
  return `<div class="atm-list">${sorted.map((r) => caRowHtml(r)).join('')}</div>`;
}

const APPLICABILITY_LABELS = {
  app_addressed: 'App addressed', partially_addressed: 'Partially addressed',
  inherited: 'Inherited', not_applicable: 'Not applicable',
};
const IMPLEMENTATION_STATUS_LABELS = {
  implemented: 'Implemented', partially_implemented: 'Partially implemented',
  planned: 'Planned', not_applicable: 'Not applicable',
};

function renderControlsAssistDetail(record) {
  if (record.status === 'running') {
    return '<div class="hint" style="padding:14px 4px;">Still running…</div>';
  }
  if (record.status === 'cancelled') {
    return '<div class="fd-verdict-reasoning" style="padding:14px 4px;">Cancelled — no report produced.</div>';
  }
  if (record.status === 'error' || !record.verdict) {
    return `<div class="fd-verdict-reasoning" style="padding:14px 4px;">${escapeHtml(record.error || 'Run failed — no report produced.')}</div>`;
  }
  const v = record.verdict;
  const controls = v.controls || [];
  const families = [...controls.reduce((groups, c) => {
    const key = c.family || 'Unclassified';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(c);
    return groups;
  }, new Map()).entries()].sort((a, b) => b[1].length - a[1].length);

  const familiesHtml = families.map(([family, list]) => `
    <div class="ca-family-group">
      <div class="ca-family-header">${escapeHtml(family)} <span class="hint">(${list.length})</span></div>
      ${list.map((c) => `
        <div class="ca-control-card">
          <div class="ca-control-top">
            <b>${escapeHtml(c.control_id || '')}</b> ${escapeHtml(c.control_name || '')}
          </div>
          <div class="tm-detail-badges" style="margin:4px 0 6px;">
            ${c.applicability ? `<span class="badge ${escapeHtml(c.applicability)}">${escapeHtml(APPLICABILITY_LABELS[c.applicability] || c.applicability)}</span>` : ''}
            ${c.implementation_status ? `<span class="badge ${escapeHtml(c.implementation_status)}">${escapeHtml(IMPLEMENTATION_STATUS_LABELS[c.implementation_status] || c.implementation_status)}</span>` : ''}
          </div>
          <div class="fd-verdict-reasoning">${escapeHtml(c.narrative || '')}</div>
          ${(c.evidence || []).length ? `<div class="tm-detail-badges" style="margin-top:6px;">${(c.evidence || []).map((e) => `<span class="scan-type-chip scope-chip">${escapeHtml(e)}</span>`).join('')}</div>` : ''}
          ${c.gaps ? `<div class="hint" style="margin-top:6px;">Gap: ${escapeHtml(c.gaps)}</div>` : ''}
        </div>
      `).join('')}
    </div>
  `).join('') || '<div class="hint">No controls identified.</div>';

  const recommendationsHtml = (v.recommendations || []).map((r) => `<li>${escapeHtml(r)}</li>`).join('') || '<li class="hint">None given.</li>';

  return `
    <div class="fd-section-title">System description</div>
    <div class="fd-prose" style="margin-bottom:14px;">${escapeHtml(v.system_description || '—')}</div>
    <div class="fd-section-title">Summary</div>
    <div class="fd-prose" style="margin-bottom:14px;">${escapeHtml(v.summary || '—')}</div>
    <div class="fd-section-title">Controls</div>
    <div style="margin-bottom:14px;">${familiesHtml}</div>
    <div class="fd-section-title">Inherited controls</div>
    <div class="fd-prose" style="margin-bottom:14px;">${escapeHtml(v.inherited_note || '—')}</div>
    <div class="fd-section-title">Recommendations</div>
    <ul class="atm-recs" style="margin-bottom:14px;">${recommendationsHtml}</ul>
    <button class="secondary" type="button" data-action="download-ssp-draft">Download SSP draft (.md)</button>
  `;
}

function downloadTextFile(filename, content) {
  const blob = new Blob([content], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function buildControlAssessmentMarkdown(record) {
  const v = record.verdict;
  const lines = [];
  lines.push(`# SSP draft: ${record.app || record.path}`);
  lines.push('');
  lines.push(`Generated by Control Scan — ${new Date(record.startedAt).toISOString()}`);
  lines.push('');
  lines.push('## System description');
  lines.push(v.system_description || '—');
  lines.push('');
  lines.push('## Summary');
  lines.push(v.summary || '—');
  lines.push('');
  lines.push('## Controls');
  const controls = v.controls || [];
  const families = [...controls.reduce((groups, c) => {
    const key = c.family || 'Unclassified';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(c);
    return groups;
  }, new Map()).entries()];
  for (const [family, list] of families) {
    lines.push('');
    lines.push(`### ${family}`);
    for (const c of list) {
      lines.push('');
      lines.push(`**${c.control_id || ''} — ${c.control_name || ''}**`);
      lines.push(`- Applicability: ${APPLICABILITY_LABELS[c.applicability] || c.applicability || '—'}`);
      lines.push(`- Implementation status: ${IMPLEMENTATION_STATUS_LABELS[c.implementation_status] || c.implementation_status || '—'}`);
      lines.push(`- Narrative: ${c.narrative || '—'}`);
      if ((c.evidence || []).length) lines.push(`- Evidence: ${c.evidence.join(', ')}`);
      if (c.gaps) lines.push(`- Gap: ${c.gaps}`);
    }
  }
  lines.push('');
  lines.push('## Inherited controls');
  lines.push(v.inherited_note || '—');
  lines.push('');
  lines.push('## Recommendations');
  for (const r of (v.recommendations || [])) lines.push(`- ${r}`);
  return lines.join('\n');
}

function renderControlsAssistView() {
  caContentEl.innerHTML = renderControlsAssistSection();
  caContentEl.querySelectorAll('.atm-row-summary').forEach((el) => {
    el.addEventListener('click', () => toggleControlsAssistRow(el.closest('.atm-row').dataset.caRunId));
  });
  caContentEl.querySelectorAll('[data-action="download-ssp-draft"]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const runId = btn.closest('.atm-row').dataset.caRunId;
      const record = controlAssessmentsList.find((r) => r.runId === runId);
      if (!record || !record.verdict) return;
      downloadTextFile(`ssp-draft-${runId}.md`, buildControlAssessmentMarkdown(record));
    });
  });
  wireConsoleToggles(caContentEl, controlAssistRuns, renderControlsAssistView);
  reattachControlsAssistLiveRefs();
}

// findingId: which finding's attack path to show. runId: optional, defaults to its latest run.
function selectThreatModelFinding(findingId, runId) {
  const runs = allThreatModelEntriesForFinding(findingId);
  if (!runs.length) return;
  renderThreatModelDetail(findingId, runId || runs[0].runId);
}

function renderThreatModelDetail(findingId, runId) {
  const runs = allThreatModelEntriesForFinding(findingId);
  const entry = runs.find((e) => e.runId === runId) || runs[0];
  if (!entry) return;
  const inMap = tmMapFindingIds.has(findingId);
  document.getElementById('tm-detail-panel').innerHTML = renderAttackPathFlow(entry, runs, inMap);
  document.getElementById('tm-run-select')?.addEventListener('change', (e) => renderThreatModelDetail(findingId, e.target.value));
  document.getElementById('tm-view-finding-btn')?.addEventListener('click', () => openFindingDetail(findingId));
}

// Navigates to the Threat Model screen and opens one finding's attack path directly —
// used from a finding's "View in Threat Model" run-card link, which may point at an
// older run than the one currently shown on the map (or one whose verdict fell out of
// the map entirely, e.g. a later false_positive re-run superseded it).
async function openThreatModelForFinding(findingId, runId) {
  showView('threatmodel', { skipInit: true });
  if (!timelineLoaded) await loadTimeline();
  renderThreatModelView();
  selectThreatModelFinding(findingId, runId);
}

function renderAttackPathFlow(entry, runs, inMap) {
  const v = entry.verdict;
  const badges = [
    v.severity_confirmed ? `<span class="badge ${escapeHtml(v.severity_confirmed)}">${escapeHtml(v.severity_confirmed)}</span>` : '',
    v.confidence ? `<span class="badge ${escapeHtml(v.confidence)}">${escapeHtml(v.confidence)}</span>` : '',
    v.priority ? `<span class="badge ${escapeHtml(v.priority)}">${escapeHtml(v.priority)}</span>` : '',
    v.asvs ? `<span class="scan-type-chip scope-chip">${escapeHtml(v.asvs)}</span>` : '',
    v.cwe ? `<span class="scan-type-chip scope-chip">${escapeHtml(v.cwe)}</span>` : '',
  ].filter(Boolean).join('');

  const runSelectHtml = runs.length > 1 ? `
    <div class="tm-run-select-wrap">
      <label for="tm-run-select">Run</label>
      <select id="tm-run-select">
        ${runs.map((r) => `<option value="${escapeHtml(r.runId)}" ${r.runId === entry.runId ? 'selected' : ''}>${escapeHtml(r.startedAt ? formatRelativeTime(r.startedAt) : 'unknown time')} — ${escapeHtml(r.verdict.verdict || 'unknown')}</option>`).join('')}
      </select>
    </div>
  ` : '';

  const notInMapHtml = inMap ? '' : `<div class="hint tm-not-in-map-hint">Not shown on the map above — this run's verdict is "${escapeHtml(v.verdict)}".</div>`;

  return `
    <div class="tm-detail-title">${escapeHtml(entry.findingTitle)}</div>
    ${notInMapHtml}
    ${runSelectHtml}
    <div class="tm-detail-badges">${badges}</div>
    <div class="tm-flow">
      <div class="tm-flow-box" style="--box-color:var(--muted);">
        <div class="tm-flow-label">Attacker</div>
        <div class="tm-flow-text">Anyone able to reach the vulnerable code path below</div>
      </div>
      <div class="tm-flow-arrow">→</div>
      <div class="tm-flow-box" style="--box-color:var(--accent);">
        <div class="tm-flow-label">Preconditions</div>
        <div class="tm-flow-text">${escapeHtml(v.preconditions || '—')}</div>
      </div>
      <div class="tm-flow-arrow">→</div>
      <div class="tm-flow-box" style="--box-color:var(--warn);">
        <div class="tm-flow-label">Attack Path</div>
        <div class="tm-flow-text">${escapeHtml(v.attack_narrative || '—')}</div>
      </div>
      <div class="tm-flow-arrow">→</div>
      <div class="tm-flow-box" style="--box-color:var(--err);">
        <div class="tm-flow-label">Blast Radius</div>
        <div class="tm-flow-text">${escapeHtml(v.blast_radius || '—')}</div>
      </div>
    </div>
    <button class="secondary tm-view-finding-btn" id="tm-view-finding-btn" type="button">View finding →</button>
  `;
}

// ---------- scans ----------
// A scan runs sast-engine's deterministic pattern agents (reasoning) or dependency audit
// (sca) against a whole directory and, on completion, creates zero or more new findings
// server-side, each already carrying a triage verdict. It's the entry point of the workflow:
// Scan -> Agent Triage -> Remediation, with Threat Model available afterward as an optional
// deeper-analysis action rather than a gate in front of Remediation.

async function loadScans() {
  const res = await fetch('/api/scans');
  scansList = await res.json();
  scansLoaded = true;
  renderNavStatus();
  if (currentView === 'dashboard') renderDashboard();
}

async function loadAppThreatModels() {
  const res = await fetch('/api/app-threat-models');
  appThreatModelsList = await res.json();
  appThreatModelsLoaded = true;
  if (currentView === 'threatmodel') renderThreatModelView();
}

async function loadControlAssessments() {
  const res = await fetch('/api/control-assessments');
  controlAssessmentsList = await res.json();
  controlAssessmentsLoaded = true;
  if (currentView === 'controls-assist') renderControlsAssistView();
}

// Patches an in-flight or newly-started control assessment record by runId, adding it if
// this is the first message seen for it (mirrors upsertAppThreatModel).
function upsertControlAssessment(patch) {
  const idx = controlAssessmentsList.findIndex((r) => r.runId === patch.runId);
  if (idx >= 0) controlAssessmentsList[idx] = { ...controlAssessmentsList[idx], ...patch };
  else controlAssessmentsList.unshift(patch);
  renderNavBadges();
  if (currentView === 'controls-assist') renderControlsAssistView();
}

// Patches an in-flight or newly-started app-level threat model record by runId, adding it
// if this is the first message seen for it (mirrors upsertTimelineEntry's find-or-unshift).
function upsertAppThreatModel(patch) {
  const idx = appThreatModelsList.findIndex((r) => r.runId === patch.runId);
  if (idx >= 0) appThreatModelsList[idx] = { ...appThreatModelsList[idx], ...patch };
  else appThreatModelsList.unshift(patch);
  if (currentView === 'threatmodel') renderThreatModelView();
}

// `detail` is the full scan record from GET /api/scans/:id — used for the coverage line, which
// needs fields the finding list doesn't carry.
function renderScanFindingsBody(body, scanFindings, scanId, detail) {
  body.innerHTML = '';

  // Which pattern agents this target actually warranted. The live scan card shows the same
  // thing, but only for a scan started in the current tab and only until the page reloads
  // (cards are never rebuilt from scansList). This row is rebuilt from the server every time
  // the drawer opens, so it is the durable answer to "what did that scan actually cover" —
  // which matters most exactly when the scan is no longer in front of you.
  if (detail && detail.agentsRun && (detail.agentsSkipped || []).length) {
    const nSkipped = detail.agentsSkipped.length;
    const cov = document.createElement('div');
    cov.className = 'hint';
    cov.style.cssText = 'padding:6px 14px 2px;';
    cov.title = 'Not applicable here (skipped by their own relevance check):\n'
      + detail.agentsSkipped.map((n) => `• ${n}`).join('\n');
    cov.textContent = `${detail.agentsRun} of ${detail.agentsRun + nSkipped} pattern agents applied to this codebase · ${nSkipped} not applicable`;
    body.appendChild(cov);
  }

  if (!scanFindings.length) {
    const none = document.createElement('div');
    none.className = 'hint';
    none.style.cssText = 'padding:10px 14px;';
    none.textContent = 'No findings produced by this scan.';
    body.appendChild(none);
    return;
  }
  if (scanId) {
    const linkRow = document.createElement('div');
    linkRow.style.cssText = 'padding:2px 14px 8px;';
    linkRow.innerHTML = '<button class="link-btn" type="button">View all in Agent Triage →</button>';
    linkRow.querySelector('button').addEventListener('click', (e) => { e.stopPropagation(); openFindingsFilteredByScan(scanId); });
    body.appendChild(linkRow);
  }
  for (const f of scanFindings) {
    const item = document.createElement('div');
    item.className = 'finding-row';
    item.style.padding = '9px 14px';
    item.innerHTML = `
      <span class="sev-dot ${f.severity}"></span>
      <div class="finding-row-main">
        <div class="finding-row-title">${escapeHtml(f.title)}</div>
        <div class="finding-row-meta"><span class="badge ${f.status}">${escapeHtml(statusLabel(f.status))}</span></div>
      </div>
    `;
    item.addEventListener('click', () => openFindingDetail(f.id));
    body.appendChild(item);
  }
}

function makeScanCard(runId, targetPath, meta, containerEl) {
  const typeMeta = SCAN_TYPE_META[meta.scanType] || SCAN_TYPE_META.reasoning;
  const metaTags = [
    `<span class="scan-type-chip">${escapeHtml(typeMeta.label)}</span>`,
    `<span class="scan-type-chip scope-chip">${meta.scope === 'diff' ? `Diff vs ${escapeHtml(meta.baseBranch)}` : 'Full scan'}</span>`,
  ];
  if (meta.branch) metaTags.push(`<span class="scan-meta-text">${icon('branch')}${escapeHtml(meta.branch)}</span>`);
  if (meta.app) metaTags.push(`<span class="scan-meta-text">${escapeHtml(meta.app)}</span>`);
  if (meta.scanType === 'reasoning' && meta.budgetEnabled === false) {
    metaTags.push(`<span class="scan-meta-text" style="color:var(--warn);" title="Reasoning calls have no --max-budget-usd cap for this scan">No budget cap</span>`);
  }
  // Which pattern agents this target warranted. Scoped to this tab's session: cards are only
  // ever created by startScan() and are never rebuilt from scansList, so a reload loses them.
  // The durable version of this lives on the timeline drawer's scan row
  // (renderScanFindingsBody), which refetches from the server every time it opens.
  const nSkippedAgents = (meta.agentsSkipped || []).length;
  if (meta.agentsRun && nSkippedAgents) {
    const tip = `${meta.agentsRun} of ${meta.agentsRun + nSkippedAgents} pattern agents apply to this codebase.\n\n`
      + `Not applicable here (skipped by their own relevance check):\n`
      + meta.agentsSkipped.map((n) => `• ${n}`).join('\n');
    metaTags.push(`<span class="scan-meta-text" title="${escapeHtml(tip)}">${meta.agentsRun}/${meta.agentsRun + nSkippedAgents} agents</span>`);
  }

  // Hybrid Scan runs three engines in parallel (sast-engine's deterministic pattern agents +
  // a real claude -p reasoning pass + a dependency audit, see server.js's
  // runHybridReasoningScan) and merges their results — this trio of bars is the only place
  // that's visible before findings land. There's no other scanType left that would skip this
  // block (the standalone SCA-only page is gone), but the meta.scanType check stays as a cheap
  // guard rather than assuming every scan record will always be 'reasoning' forever.
  // All three dots/fills share the one monochrome accent — the three engines are told apart
  // by their label text, not by hue (color here is reserved for severity/status signal).
  const engineBarsHtml = meta.scanType === 'reasoning' ? `
    <div class="scan-engine-bars">
      <div class="scan-engine-bar">
        <span class="scan-engine-bar-label"><span class="engine-dot" style="background:var(--text-dim);"></span>Pattern match</span>
        <div class="scan-engine-bar-track"><div class="scan-engine-bar-fill det-fill" style="width:0%; background:var(--text-dim);"></div></div>
        <span class="scan-engine-bar-stat det-stat">Starting…</span>
      </div>
      <div class="scan-engine-bar">
        <span class="scan-engine-bar-label"><span class="engine-dot" style="background:var(--text-dim);"></span>Reasoning</span>
        <div class="scan-engine-bar-track"><div class="scan-engine-bar-fill reasoning-fill" style="width:0%; background:var(--text-dim);"></div></div>
        <span class="scan-engine-bar-stat reasoning-stat">Starting…</span>
      </div>
      <div class="scan-engine-bar">
        <span class="scan-engine-bar-label"><span class="engine-dot" style="background:var(--text-dim);"></span>Dependency audit</span>
        <div class="scan-engine-bar-track"><div class="scan-engine-bar-fill sca-fill" style="width:0%; background:var(--text-dim);"></div></div>
        <span class="scan-engine-bar-stat sca-stat">Starting…</span>
      </div>
    </div>
  ` : '';

  const cardEl = document.createElement('article');
  cardEl.className = 'stage-card scan-card status-running';
  cardEl.dataset.runId = runId;
  cardEl.innerHTML = `
    <div class="stage-header">
      <span class="stage-agent">${icon(typeMeta.icon)}<span class="path-text">${escapeHtml(targetPath)}</span></span>
      <button class="console-toggle-btn" type="button" style="margin-left:auto;" data-console-toggle data-run-id="${escapeHtml(runId)}" title="View model's live reasoning">${icon('terminal')}</button>
    </div>
    <div class="scan-meta-row">${metaTags.join('')}</div>
    ${engineBarsHtml}
    <div class="scan-stats">
      <span class="stat scan-status-stat"><span class="status-dot running"></span><span class="status-text">Starting…</span></span>
      <span class="stat"><b class="ss-tokens">0</b> tokens</span>
      <span class="stat"><b class="ss-tools">0</b> checks</span>
      <span class="stat"><b class="ss-files">0</b> files read</span>
      <span class="stat"><b class="ss-elapsed">0:00</b> elapsed</span>
    </div>
    <pre class="console-panel ss-console" hidden></pre>
    <div class="scan-error-msg" hidden></div>
    <div class="scan-warning-msg" hidden></div>
    <div class="scan-sev-chips"><span class="hint">No candidates yet</span></div>
    <div class="scan-live-findings"></div>
    <div class="scan-results" hidden></div>
    <div class="scan-actions"></div>
  `;
  containerEl.prepend(cardEl);
  return cardEl;
}

function updateScanCardActions(run) {
  const el = run.actionsEl;
  if (!el) return;
  el.innerHTML = '';
  if (run.status === 'running') {
    const btn = document.createElement('button');
    btn.className = 'secondary';
    btn.textContent = 'Stop scan';
    btn.addEventListener('click', () => cancelScanRun(run));
    el.appendChild(btn);
  } else {
    if (run.scanId && run.status === 'done') {
      const viewBtn = document.createElement('button');
      viewBtn.className = 'secondary';
      viewBtn.textContent = 'View in Agent Triage →';
      viewBtn.addEventListener('click', () => openFindingsFilteredByScan(run.scanId));
      el.appendChild(viewBtn);
    }
    const btn = document.createElement('button');
    btn.className = 'secondary';
    btn.textContent = 'Delete';
    btn.addEventListener('click', () => deleteScanRun(run));
    el.appendChild(btn);
  }
}

function cancelScanRun(run) {
  if (run.status !== 'running') return;
  ws.send(JSON.stringify({ type: 'cancel', runId: run.runId }));
  setStageStatus(run, 'cancelled', 'Cancelling…');
  updateScanCardActions(run);
}

async function deleteScanRun(run) {
  if (run.scanId) {
    try { await fetch(`/api/scans/${run.scanId}`, { method: 'DELETE' }); } catch (e) {}
  }
  stopScanElapsedTimer(run);
  scanRuns.delete(run.runId);
  run.cardEl.remove();
  scansList = scansList.filter((s) => s.runId !== run.runId);
  timelineEntries = timelineEntries.filter((e) => e.runId !== run.runId);
  renderNavStatus();
  if (currentView === 'dashboard') renderDashboard();
  if (timelineDrawerOpen) renderTimeline();
}

function renderScanCardResults(run, scanFindings) {
  if (!run.resultsEl) return;
  if (!scanFindings.length) { run.resultsEl.hidden = true; return; }
  run.resultsEl.hidden = false;
  run.resultsEl.innerHTML = '';
  for (const f of scanFindings) {
    const item = document.createElement('div');
    item.className = 'scan-result-row';
    item.innerHTML = `
      <span class="sev-dot ${f.severity}"></span>
      <div class="scan-result-main">
        <div class="scan-result-title">${escapeHtml(f.title)}</div>
        <div class="scan-result-why">${escapeHtml(truncate(f.description || '', 160))}</div>
      </div>
    `;
    item.addEventListener('click', () => openFindingDetail(f.id));
    run.resultsEl.appendChild(item);
  }
}

function formatElapsed(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
}

function updateScanElapsed(run) {
  if (run.elapsedEl) run.elapsedEl.textContent = formatElapsed(Date.now() - run.startTime);
}

function stopScanElapsedTimer(run) {
  if (run.elapsedTimer) {
    clearInterval(run.elapsedTimer);
    run.elapsedTimer = null;
  }
  updateScanElapsed(run);
}

const SEV_VAR = { critical: 'var(--crit)', high: 'var(--err)', medium: 'var(--warn)', low: 'var(--ok)', informational: 'var(--muted)' };
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
const SEV_TAG_RE = /\[(critical|high|medium|low|informational)\]\s+([^\[]*)/gi;

function renderScanSevChips(run) {
  if (!run.chipsEl) return;
  const total = SEV_ORDER.reduce((n, s) => n + run.sevCounts[s], 0);
  if (!total) {
    run.chipsEl.innerHTML = '<span class="hint">No candidates yet</span>';
    return;
  }
  run.chipsEl.innerHTML = SEV_ORDER
    .filter((s) => run.sevCounts[s] > 0)
    .map((s) => `<span class="sev-chip" style="color:${SEV_VAR[s]}; background:color-mix(in srgb, ${SEV_VAR[s]} 16%, transparent);">${run.sevCounts[s]} ${s}</span>`)
    .join('');
}

function trackScanCandidates(run, event) {
  if (event.type !== 'assistant' || !event.message || !Array.isArray(event.message.content)) return;
  let found = false;
  for (const block of event.message.content) {
    if (block.type !== 'text' || !block.text) continue;
    const re = new RegExp(SEV_TAG_RE.source, SEV_TAG_RE.flags);
    let m;
    while ((m = re.exec(block.text))) {
      const sev = m[1].toLowerCase();
      const text = truncate(m[2].replace(/\s+/g, ' ').trim(), 180);
      run.sevCounts[sev] = (run.sevCounts[sev] || 0) + 1;
      found = true;
      if (run.findingsEl && text) {
        const row = document.createElement('div');
        row.className = 'scan-live-row';
        row.innerHTML = `<span class="sev-dot ${sev}"></span><span class="scan-live-text"></span>`;
        row.querySelector('.scan-live-text').textContent = text;
        run.findingsEl.appendChild(row);
        run.findingsEl.scrollTop = run.findingsEl.scrollHeight;
      }
    }
  }
  if (found) renderScanSevChips(run);
}

// Shared by scan cards and app-level threat model rows — both invoke `claude -p` against a
// whole directory and want the same live stats, unlike per-finding runs (deliberately quiet,
// see "No live per-finding streaming view" in CLAUDE.md). Both kinds of `run` tracking objects
// use the same field names (toolCount/toolsEl/fileCount/filesEl/tokenCount/tokensEl) so these
// functions don't need to know which kind they're updating.
function trackRunToolActivity(run, event) {
  if (event.type !== 'assistant' || !event.message || !Array.isArray(event.message.content)) return;
  let sawTool = false;
  for (const block of event.message.content) {
    if (block.type !== 'tool_use') continue;
    sawTool = true;
    run.toolCount++;
    if (block.name === 'Read') run.fileCount++;
  }
  if (!sawTool) return;
  if (run.toolsEl) run.toolsEl.textContent = String(run.toolCount);
  if (run.filesEl) run.filesEl.textContent = String(run.fileCount);
}

function formatTokenCount(n) {
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
  return String(n);
}

function trackRunTokens(run, event) {
  if (event.type !== 'assistant' || !event.message || !event.message.usage) return;
  const u = event.message.usage;
  run.tokenCount += (u.input_tokens || 0) + (u.output_tokens || 0) + (u.cache_creation_input_tokens || 0) + (u.cache_read_input_tokens || 0);
  if (run.tokensEl) run.tokensEl.textContent = formatTokenCount(run.tokenCount);
}

// Feeds the opt-in per-run console panel: extracts the assistant's narrated prose text (not
// tool calls/results — that raw stream-json firehose was tried before and rejected as noise,
// see CLAUDE.md) and appends it both to the run's buffer (survives a re-render) and, if the
// panel is currently attached to the DOM, directly onto it.
function trackConsoleText(run, event) {
  if (event.type !== 'assistant' || !event.message || !Array.isArray(event.message.content)) return;
  let text = '';
  for (const block of event.message.content) {
    if (block.type === 'text' && typeof block.text === 'string') text += block.text;
  }
  if (!text) return;
  run.consoleText = (run.consoleText || '') + text;
  if (run.consoleEl) {
    run.consoleEl.textContent += text;
    run.consoleEl.scrollTop = run.consoleEl.scrollHeight;
  }
}

// Shared markup for the small terminal-icon toggle button and its console panel. Only
// rendered by callers that have a live tracking object for this run this browser session —
// historical/seeded runs never captured any text, so there's nothing to show. Split into two
// functions (rather than one block) because the button belongs inside a flex header row
// alongside other controls, while the panel needs to sit as a full-width block sibling below
// that row — embedding a <pre> inside a nowrap flex row would squeeze it instead of wrapping.
// panelClass distinguishes each surface's panel for its own reattach query.
function consoleToggleButtonHtml(run) {
  return `<button class="console-toggle-btn${run.consoleOpen ? ' active' : ''}" type="button" data-console-toggle data-run-id="${escapeHtml(run.runId)}" title="View model's live reasoning">${icon('terminal')}</button>`;
}
function consolePanelHtml(run, panelClass) {
  return `<pre class="console-panel ${panelClass}" data-run-id="${escapeHtml(run.runId)}"${run.consoleOpen ? '' : ' hidden'}>${escapeHtml(run.consoleText || '')}</pre>`;
}

// Wires every console-toggle button inside a just-rebuilt container. Used by the surfaces
// whose rows get fully torn down and re-rendered on every update (App Threat Model, Control
// Scan, Finding Detail) — scan cards are created once and never rebuilt, so they wire their
// single button directly at creation time instead (see beginScanRun).
function wireConsoleToggles(containerEl, runsMap, rerender) {
  containerEl.querySelectorAll('[data-console-toggle]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const run = runsMap.get(btn.dataset.runId);
      if (!run) return;
      run.consoleOpen = !run.consoleOpen;
      rerender();
    });
  });
}

// Re-points each run's consoleEl at its freshly-rendered panel node after a container's
// innerHTML has been rebuilt (App Threat Model/Control Scan already do this inline alongside
// their other live-stat refs; Finding Detail's stage runs have no other live refs to reattach
// so this is the only one they need).
function reattachConsoleRefs(containerEl, runsMap, panelClass) {
  for (const run of runsMap.values()) {
    run.consoleEl = containerEl.querySelector(`.${panelClass}[data-run-id="${run.runId}"]`) || null;
  }
}

// Updates the "Pattern match" bar from a scan-progress message (deterministic engine only —
// see server.js's runDeterministicPatternScan).
//
// `total` is the count of agents actually relevant to THIS target, not the registered total:
// every agent declares shouldRun(recon), and most repos legitimately skip a dozen or more
// (Roblox, React Native, MCP, RAG, model-scanning — see CLAUDE.md's relevance-gating note).
// Reporting only the survivors as "17/17 agents done" hides that entirely: it reads as though
// 17 is the whole engine, when 15 more were deliberately judged inapplicable. The "N n/a"
// suffix makes the selection visible, and the tooltip names the skipped agents so "why didn't
// it check for X" has an answer without reading the source.
function updateDetBar(run, done, total, skipped) {
  if (!run.detFillEl) return;
  run.detDone = done;
  run.detTotal = total;
  if (Array.isArray(skipped)) run.detSkipped = skipped;
  const pct = total ? Math.round((done / total) * 100) : 0;
  run.detFillEl.style.width = pct + '%';
  run.detFillEl.classList.toggle('done', done >= total && total > 0);
  const nSkipped = (run.detSkipped || []).length;
  run.detStatEl.textContent = total
    ? `${done}/${total} agents done${nSkipped ? ` · ${nSkipped} n/a` : ''}`
    : 'Starting…';
  run.detStatEl.title = nSkipped
    ? `${total} of ${total + nSkipped} agents apply to this codebase.\n\n`
      + `Not applicable here (skipped by their own relevance check):\n`
      + (run.detSkipped || []).map((n) => `• ${n}`).join('\n')
    : '';
}

// Updates the "Dependency audit" bar from a scan-progress {engine:'sca'} message — sent exactly
// once, the moment server.js's runDeterministicScaScan() resolves (see runHybridReasoningScan()),
// independent of the other two engines' own completion. Unlike the pattern-match/reasoning bars,
// there's no real multi-step progress to show for one atomic audit call, so this only ever jumps
// straight from 0% to 100%.
function updateScaBar(run, done, total) {
  if (!run.scaFillEl) return;
  const pct = total ? Math.round((done / total) * 100) : 0;
  run.scaFillEl.style.width = pct + '%';
  run.scaFillEl.classList.toggle('done', done >= total && total > 0);
  run.scaStatEl.textContent = total ? (done >= total ? 'Done' : 'Starting…') : 'Starting…';
}

// Appended to the Reasoning bar's stat text whenever real spend is known (from a scan-progress
// {engine:'reasoning'} message's costUsd — see updateReasoningModuleProgress()). '' before the
// first module/pass has completed, since there's nothing real to report yet.
function reasoningCostSuffix(run) {
  return run.reasoningCostUsd ? ` · $${run.reasoningCostUsd.toFixed(2)}` : '';
}

// Updates the "Reasoning" bar from per-event tool-call activity. This is the fallback display
// for when there's only one reasoning pass to report — which happens when the deterministic
// half found nothing, so there is nothing to adjudicate and only the review pass runs. In that
// case this is an indeterminate-feeling fill that grows with tool-call count and settles at
// 100% once the run reports its own `done`/`error` (see markReasoningBarDone below) rather than
// trying to predict completion from activity alone. With both passes running,
// updateReasoningModuleProgress() below owns this same bar instead — a real done/total beats an
// indeterminate estimate.
function updateReasoningBar(run) {
  if (!run.reasoningFillEl) return;
  if (run.reasoningModulesTotal > 1) return;
  const pct = Math.min(90, run.toolCount * 8);
  run.reasoningFillEl.style.width = pct + '%';
  run.reasoningStatEl.textContent = (run.toolCount
    ? `${run.toolCount} tool call${run.toolCount === 1 ? '' : 's'}`
    : 'Starting…') + reasoningCostSuffix(run);
}

// Updates the "Reasoning" bar from a scan-progress {engine:'reasoning'} message — sent once per
// completed reasoning pass. server.js's runLLMReasoningScan() runs two: an adjudication pass
// over the deterministic half's findings, then a review pass over the enumerated attack surface
// (see CLAUDE.md). A scan whose deterministic half found nothing skips adjudication and reports
// total <= 1 — nothing worth a percentage there, so the bar falls back to updateReasoningBar()'s
// per-event tool-call estimate; real dollar spend (costUsd, aggregated server-side from each
// call's actual stream-json result — not an estimate) is tracked either way, so it's still shown
// once a pass completes even when the pass count isn't interesting enough to display.
function updateReasoningModuleProgress(run, done, total, costUsd) {
  if (!run.reasoningFillEl) return;
  run.reasoningModulesDone = done;
  run.reasoningModulesTotal = total;
  if (typeof costUsd === 'number') run.reasoningCostUsd = costUsd;
  if (total <= 1) { updateReasoningBar(run); return; }
  const pct = Math.round((done / total) * 100);
  run.reasoningFillEl.style.width = pct + '%';
  run.reasoningFillEl.classList.toggle('done', done >= total);
  run.reasoningStatEl.textContent = `${done}/${total} passes done` + reasoningCostSuffix(run);
}

function markReasoningBarDone(run) {
  if (!run.reasoningFillEl) return;
  run.reasoningFillEl.style.width = '100%';
  run.reasoningFillEl.classList.add('done');
}

function handleScanRawEvent(run, event) {
  trackRunToolActivity(run, event);
  trackRunTokens(run, event);
  trackScanCandidates(run, event);
  trackConsoleText(run, event);
  updateReasoningBar(run);
}

// Shared by the Scans and SCA pages — both kick off the exact same underlying WS 'scan'
// message and live-card machinery, just against different containers with a fixed scanType
// for SCA (no scan-type pill needed there since it's the whole point of that page).
function beginScanRun(targetPath, instruction, scanMeta, containerEl) {
  const runId = uid();
  const cardEl = makeScanCard(runId, targetPath, scanMeta, containerEl);
  const startedAt = Date.now();
  const run = {
    runId, path: targetPath, instruction,
    status: 'running',
    cardEl,
    startTime: startedAt,
    toolCount: 0,
    fileCount: 0,
    tokenCount: 0,
    sevCounts: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    toolsEl: cardEl.querySelector('.ss-tools'),
    filesEl: cardEl.querySelector('.ss-files'),
    tokensEl: cardEl.querySelector('.ss-tokens'),
    elapsedEl: cardEl.querySelector('.ss-elapsed'),
    // Per-engine bars. The reasoning bar reuses toolCount/tokenCount below rather than tracking its own copy:
    // the synthetic events the deterministic engine sends never carry tool_use/usage blocks,
    // so trackRunToolActivity()/trackRunTokens() only ever fire for the real reasoning-pass
    // events anyway — toolCount is already effectively "reasoning engine's tool calls".
    detDone: 0,
    detTotal: 0,
    detFillEl: cardEl.querySelector('.det-fill'),
    detStatEl: cardEl.querySelector('.det-stat'),
    reasoningFillEl: cardEl.querySelector('.reasoning-fill'),
    reasoningStatEl: cardEl.querySelector('.reasoning-stat'),
    // SCA is the third engine folded into every Hybrid Scan (see server.js's
    // runHybridReasoningScan) — one atomic dependency-audit call, not a multi-step process, so
    // this bar only ever jumps from 0% ("Starting…") straight to 100% ("Done") — see
    // updateScaBar() below.
    scaFillEl: cardEl.querySelector('.sca-fill'),
    scaStatEl: cardEl.querySelector('.sca-stat'),
    // Set once a scan-progress {engine:'reasoning'} message reports a real total > 1 (a "Full"
    // scope scan whose directory partitioned into more than one module) — see
    // updateReasoningModuleProgress() above for how this changes what drives the bar.
    reasoningModulesDone: 0,
    reasoningModulesTotal: 0,
    // Real dollar spend across every reasoning-half claude -p call so far, aggregated
    // server-side from each call's actual stream-json result.total_cost_usd (see
    // reasoningCostSuffix() above) — not a token-count estimate.
    reasoningCostUsd: 0,
    errorEl: cardEl.querySelector('.scan-error-msg'),
    warningEl: cardEl.querySelector('.scan-warning-msg'),
    chipsEl: cardEl.querySelector('.scan-sev-chips'),
    findingsEl: cardEl.querySelector('.scan-live-findings'),
    resultsEl: cardEl.querySelector('.scan-results'),
    actionsEl: cardEl.querySelector('.scan-actions'),
    consoleText: '',
    consoleOpen: false,
    consoleEl: cardEl.querySelector('.ss-console'),
    elapsedTimer: null,
  };
  scanRuns.set(runId, run);
  cardEl.querySelector('[data-console-toggle]').addEventListener('click', (e) => {
    e.stopPropagation();
    run.consoleOpen = !run.consoleOpen;
    e.currentTarget.classList.toggle('active', run.consoleOpen);
    run.consoleEl.hidden = !run.consoleOpen;
  });
  run.elapsedTimer = setInterval(() => updateScanElapsed(run), 1000);
  updateScanCardActions(run);
  scansList.unshift({ id: null, runId, path: targetPath, instruction, ...scanMeta, status: 'running', error: null, findingIds: [], startedAt, finishedAt: null });
  upsertTimelineEntry({ kind: 'scan', runId, path: targetPath, instruction, ...scanMeta, status: 'running', findingCount: 0, startedAt, finishedAt: null });
  renderNavStatus();
  if (currentView === 'dashboard') renderDashboard();

  ws.send(JSON.stringify({ type: 'scan', runId, path: targetPath, instruction, ...scanMeta }));
  return runId;
}

function startScan() {
  const targetPath = scanPathInput.value.trim();
  if (!targetPath) {
    alert('Enter a target directory path.');
    return;
  }
  const branch = scanBranchInput.value.trim();
  const app = scanAppInput.value.trim();
  const baseBranch = scanBaseBranchInput.value.trim();
  if (scanScope === 'diff' && !baseBranch) {
    alert('Enter a base branch to diff against (e.g. main).');
    return;
  }

  const scanMeta = { branch, app, scanType, scope: scanScope, baseBranch: scanScope === 'diff' ? baseBranch : null, budgetEnabled: scanBudgetEnabled };
  beginScanRun(targetPath, '', scanMeta, scanLiveContainer);
}

scanStartBtn.addEventListener('click', startScan);

function handleScanServerMessage(msg) {
  const run = msg.runId ? scanRuns.get(msg.runId) : null;
  const listItem = msg.runId ? scansList.find((s) => s.runId === msg.runId) : null;

  if (msg.type === 'scan-started') {
    if (run) run.scanId = msg.scanId;
    if (listItem) listItem.id = msg.scanId;
    return;
  }
  if (!run) return;

  if (msg.type === 'scan-progress') {
    if (msg.engine === 'reasoning') updateReasoningModuleProgress(run, msg.done, msg.total, msg.costUsd);
    else if (msg.engine === 'sca') updateScaBar(run, msg.done, msg.total);
    else updateDetBar(run, msg.done, msg.total, msg.skipped);
    return;
  }
  if (msg.type === 'scan-event') {
    handleScanRawEvent(run, msg.event);
    return;
  }
  if (msg.type === 'scan-stderr') {
    return; // CLI-internal chatter, not actionable — still in the raw stream-json toggle's source events if needed
  }
  if (msg.type === 'scan-warning') {
    // A non-fatal note this app itself generated (a module hit its budget cap, one engine
    // errored while the other still succeeded, etc.) — distinct from scan-stderr's raw CLI
    // chatter above, so it's actually shown rather than silently discarded. Doesn't touch
    // run.status or the elapsed timer; the scan is still running (or already succeeded).
    if (run.warningEl) {
      run.warningEl.hidden = false;
      run.warningEl.textContent = run.warningEl.textContent
        ? `${run.warningEl.textContent}\n${msg.message}`
        : msg.message;
    }
    return;
  }
  if (msg.type === 'scan-error') {
    const cancelled = run.status === 'cancelled';
    if (!cancelled) {
      setStageStatus(run, 'error', 'Error');
      if (run.errorEl) { run.errorEl.hidden = false; run.errorEl.textContent = msg.message; }
    } else {
      setStageStatus(run, 'cancelled', 'Cancelled');
    }
    stopScanElapsedTimer(run);
    markReasoningBarDone(run);
    updateScanCardActions(run);
    const finalStatus = cancelled ? 'cancelled' : 'error';
    if (listItem) { listItem.status = finalStatus; listItem.error = cancelled ? null : msg.message; listItem.finishedAt = Date.now(); }
    upsertTimelineEntry({ runId: msg.runId, status: finalStatus, error: cancelled ? null : msg.message, finishedAt: Date.now() });
    if (currentView === 'dashboard') renderDashboard();
    return;
  }
  if (msg.type === 'scan-done') {
    const cancelled = run.status === 'cancelled';
    stopScanElapsedTimer(run);
    markReasoningBarDone(run);
    if (run.detFillEl && run.detTotal) updateDetBar(run, run.detTotal, run.detTotal); // in case the last scan-progress arrives after scan-done
    if (run.scaFillEl) updateScaBar(run, 1, 1); // same fallback — SCA's own scan-progress message could in principle arrive after scan-done too
    const n = msg.findings.length;
    const finalStatus = cancelled ? 'cancelled' : (msg.code === 0 ? 'done' : 'error');
    setStageStatus(run, finalStatus, cancelled ? 'Cancelled' : `${n} finding${n === 1 ? '' : 's'} created`);
    if (run.findingsEl) run.findingsEl.hidden = true;
    renderScanCardResults(run, msg.findings);
    updateScanCardActions(run);
    if (listItem) { listItem.status = finalStatus; listItem.findingIds = msg.findings.map((f) => f.id); listItem.finishedAt = Date.now(); }
    upsertTimelineEntry({ runId: msg.runId, scanId: msg.scanId, status: finalStatus, findingCount: n, finishedAt: Date.now() });
    loadFindings();
    loadScans();
    return;
  }
}

// App-level threat models have no dedicated live-feed card (unlike scans) — they're a
// lightweight background action fired from a single toggle, so all we do here is keep
// appThreatModelsList in sync; the Threat Model screen's "App-level Threat Models" section
// is the only place that renders them, and only re-renders while it's the active view.
function handleAppThreatModelServerMessage(msg) {
  const run = appThreatModelRuns.get(msg.runId);

  if (msg.type === 'app-threat-model-started') {
    upsertAppThreatModel({ runId: msg.runId, id: msg.id });
    return;
  }
  // The hot path — fires many times per run. Mutate the live row's cached DOM refs directly,
  // no upsertAppThreatModel()/re-render here, or the list would flicker/reflow constantly.
  if (msg.type === 'app-threat-model-event') {
    if (run) handleAppThreatModelRawEvent(run, msg.event);
    return;
  }
  if (msg.type === 'app-threat-model-stderr') {
    return;
  }
  if (msg.type === 'app-threat-model-error') {
    if (run) stopAppThreatModelElapsedTimer(run);
    upsertAppThreatModel({ runId: msg.runId, id: msg.id, status: 'error', error: msg.message, finishedAt: Date.now() });
    return;
  }
  if (msg.type === 'app-threat-model-done') {
    if (run) stopAppThreatModelElapsedTimer(run);
    upsertAppThreatModel({ runId: msg.runId, id: msg.id, status: msg.code === 0 && msg.verdict ? 'done' : 'error', verdict: msg.verdict, finishedAt: Date.now() });
    return;
  }
}

function handleControlsAssistServerMessage(msg) {
  const run = controlAssistRuns.get(msg.runId);

  if (msg.type === 'controls-assist-started') {
    upsertControlAssessment({ runId: msg.runId, id: msg.id });
    return;
  }
  // The hot path — fires many times per run. Mutate the live row's cached DOM refs directly,
  // no upsertControlAssessment()/re-render here, or the list would flicker/reflow constantly.
  if (msg.type === 'controls-assist-event') {
    if (run) handleControlsAssistRawEvent(run, msg.event);
    return;
  }
  if (msg.type === 'controls-assist-stderr') {
    return;
  }
  if (msg.type === 'controls-assist-error') {
    if (run) stopControlsAssistElapsedTimer(run);
    upsertControlAssessment({ runId: msg.runId, id: msg.id, status: 'error', error: msg.message, finishedAt: Date.now() });
    return;
  }
  if (msg.type === 'controls-assist-done') {
    if (run) stopControlsAssistElapsedTimer(run);
    upsertControlAssessment({ runId: msg.runId, id: msg.id, status: msg.code === 0 && msg.verdict ? 'done' : 'error', verdict: msg.verdict, finishedAt: Date.now() });
    return;
  }
}

// ---------- findings: type tabs + table ----------

async function loadFindings() {
  const res = await fetch('/api/findings');
  findings = await res.json();
  renderFindingsView();
  renderNavStatus();
  if (currentView === 'dashboard') renderDashboard();
}

function statusLabel(status) {
  return { new: 'Not started', in_review: 'In review', remediation_ready: 'Remediation ready', remediation_generated: 'Remediation generated', verified_fixed: 'Verified fixed', closed: 'Closed' }[status] || status;
}
function severityLabel(sev) { return sev.charAt(0).toUpperCase() + sev.slice(1); }

const SEV_ORDER_MAP = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
const STATUS_ORDER_MAP = { new: 0, in_review: 1, remediation_ready: 2, remediation_generated: 3, closed: 4, verified_fixed: 5 };

const FINDINGS_TYPE_LABEL = { all: 'All', reasoning: 'Hybrid', sca: 'SCA' };
const FINDINGS_COLUMNS = {
  all: [
    { key: 'severity', label: 'Severity', sortable: true },
    { key: 'type', label: 'Type' },
    { key: 'title', label: 'Title', sortable: true },
    { key: 'loop', label: 'Loop', sortable: true },
  ],
  // A reasoning-scan finding can be file-based (a code pattern) or endpoint-based (an
  // attack-surface observation) — the merged 'location' cell shows whichever it has, since
  // there's no longer a separate SAST/DAST split to hang two different columns off of.
  reasoning: [
    { key: 'severity', label: 'Severity', sortable: true },
    { key: 'title', label: 'Title', sortable: true },
    { key: 'location', label: 'Location' },
    { key: 'rule', label: 'Rule / CWE' },
    { key: 'loop', label: 'Loop', sortable: true },
  ],
  // No Remediation Loop column here — an SCA finding's fix is a dependency version bump, not
  // a code edit the Remediation/Verify agents reason about, so Package/Fixed-in above already
  // say what to do and this just shows plain triage status instead of implying a loop that
  // doesn't apply.
  sca: [
    { key: 'severity', label: 'Severity', sortable: true },
    { key: 'title', label: 'Title', sortable: true },
    { key: 'package', label: 'Package' },
    { key: 'fix', label: 'Fixed in' },
    { key: 'status', label: 'Status', sortable: true },
  ],
};

function findingsSortValue(f, key) {
  if (key === 'severity') return SEV_ORDER_MAP[f.severity] ?? 99;
  if (key === 'status' || key === 'loop') return STATUS_ORDER_MAP[f.status] ?? 99;
  if (key === 'title') return f.title.toLowerCase();
  return '';
}

function findingsScanScoped() {
  if (findingsScanFilter === 'all') return findings;
  return findings.filter((f) => f.sourceScanId === findingsScanFilter);
}

function renderFindingsView() {
  renderFindingsScanFilter();
  const scanScoped = findingsScanScoped();
  findingsSubtitleEl.textContent = `${scanScoped.length} finding${scanScoped.length === 1 ? '' : 's'}`
    + (findingsScanFilter !== 'all' ? ` · filtered to 1 scan` : '');
  renderFindingsTypeTabs(scanScoped);
  renderFindingsTable();
}

function scanFilterLabel(s) {
  const kind = s.scanType === 'sca' ? 'SCA scan' : 'Hybrid scan';
  return `${kind} on ${s.path} started ${formatRelativeTime(s.startedAt)}`;
}

// Only scans that actually produced findings still on record are worth offering as a filter —
// a scan that found nothing (or whose findings were all deleted) would just be a dead-end option.
// findingsScanFilter (set by an item click, or programmatically by openFindingsFilteredByScan())
// is the single source of truth — see the bugfix note in git history: reading the old <select>'s
// DOM value back as a fallback silently discarded a filter set via a link instead of the dropdown.
function renderFindingsScanFilter() {
  const scansWithFindings = scansList.filter((s) => s.id && findings.some((f) => f.sourceScanId === s.id));
  scansWithFindings.sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0));

  if (!scansWithFindings.some((s) => s.id === findingsScanFilter)) findingsScanFilter = 'all';
  const current = findingsScanFilter === 'all' ? null : scansWithFindings.find((s) => s.id === findingsScanFilter);
  findingsScanFilterBtn.textContent = current ? truncate(scanFilterLabel(current), 46) : 'All scans';
  findingsScanFilterBtn.title = current ? scanFilterLabel(current) : 'All scans';

  findingsScanFilterMenuEl.innerHTML = '';
  const selectScan = (scanId) => {
    findingsScanFilter = scanId;
    findingsScanFilterMenuEl.hidden = true;
    renderFindingsView();
  };

  const allItem = document.createElement('button');
  allItem.type = 'button';
  allItem.className = 'scan-filter-item' + (findingsScanFilter === 'all' ? ' active' : '');
  allItem.textContent = 'All scans';
  allItem.addEventListener('click', () => selectScan('all'));
  findingsScanFilterMenuEl.appendChild(allItem);

  for (const s of scansWithFindings) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'scan-filter-item' + (findingsScanFilter === s.id ? ' active' : '');
    item.textContent = scanFilterLabel(s);
    item.title = scanFilterLabel(s);
    item.addEventListener('click', () => selectScan(s.id));
    findingsScanFilterMenuEl.appendChild(item);
  }
}

function renderFindingsTypeTabs(scanScoped) {
  findingsTypeTabsEl.innerHTML = '';
  for (const key of ['all', 'reasoning', 'sca']) {
    const count = key === 'all' ? scanScoped.length : scanScoped.filter((f) => f.scanType === key).length;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'group-toggle-btn' + (findingsTypeFilter === key ? ' active' : '');
    btn.innerHTML = `${escapeHtml(FINDINGS_TYPE_LABEL[key])} <span class="gt-count">${count}</span>`;
    btn.addEventListener('click', () => {
      findingsTypeFilter = key;
      renderFindingsView();
    });
    findingsTypeTabsEl.appendChild(btn);
  }
}

// ---------- remediation loop cell (Agent Triage's "Remediation Loop" column) ----------
// Reduces the finding down to where it stands in the Found -> Triaged -> Fixed -> Verified
// pipeline (the same shape documented in CLAUDE.md's "Pipeline shape": Scan -> Agent Triage ->
// Remediation -> Verify), rather than a status-taxonomy badge the user has to already know how
// to read. Threat Model is a separate, optional deep-dive and deliberately doesn't touch this
// (see the Agent Triage context-menu bullet). SCA findings don't get this loop at all (see
// findingLoopCellHtml()) — their fix is "bump the dependency," not a code edit this app's
// agents reason about.
// findingStageRuns() needs each stage's own latest run independently, not just the single
// overall latest — a list-item finding (from GET /api/findings) carries that precomputed as
// `.stageRuns` (see toListItem() in server.js), while a full cached finding (from GET
// /api/findings/:id, e.g. what Finding Detail's context menu passes) only has the raw `.runs`
// array. Normalize so both shapes work.
function findingStageRuns(f) {
  if (f.stageRuns) return f.stageRuns;
  const runs = Array.isArray(f.runs) ? f.runs : [];
  const latestByAgent = (agentName) => {
    for (let i = runs.length - 1; i >= 0; i--) {
      if (runs[i].agent === agentName) return { status: runs[i].status, verdict: runs[i].verdict };
    }
    return null;
  };
  return {
    triage: latestByAgent('triage'),
    remediation: latestByAgent('remediation'),
    fix: latestByAgent('fix'),
    verify: latestByAgent('verify'),
  };
}

// 'remediated' tracks the read-only Remediate proposal; 'fixed' tracks the separate, later Fix
// apply step that writes whatever Remediate proposed. 'fixed' has one extra state beyond the
// usual pending/running/attention/done: 'unavailable', for when Remediate finished but didn't
// propose a specific edit (a legitimate "this needs a human, not a guess" outcome per
// agents/remediation.md) — there's nothing for Fix to apply, so it isn't just "not started yet".
function findingLoopState(f) {
  const stageRuns = findingStageRuns(f);
  let triaged = 'pending';
  let remediated = 'pending';
  let fixed = 'pending';
  let verified = 'pending';

  if (stageRuns.triage) {
    if (stageRuns.triage.status === 'running') triaged = 'running';
    else if (stageRuns.triage.status === 'error' || stageRuns.triage.status === 'cancelled') triaged = 'attention';
    else triaged = 'done';
  }

  if (stageRuns.remediation) {
    if (stageRuns.remediation.status === 'running') remediated = 'running';
    else if (stageRuns.remediation.status === 'error' || stageRuns.remediation.status === 'cancelled') remediated = 'attention';
    else remediated = 'done';
  }

  const plan = stageRuns.remediation && stageRuns.remediation.verdict && stageRuns.remediation.verdict.edit_plan;
  const hasPlan = !!(plan && Array.isArray(plan.files) && plan.files.length);
  if (remediated === 'done' && !hasPlan) fixed = 'unavailable';

  if (stageRuns.fix) {
    if (stageRuns.fix.status === 'running') fixed = 'running';
    else if (stageRuns.fix.verdict && stageRuns.fix.verdict.applied_diff) fixed = 'done';
    else fixed = 'attention'; // errored, cancelled, or somehow finished with nothing applied
  }

  if (stageRuns.verify) {
    if (stageRuns.verify.status === 'running') verified = 'running';
    else if (stageRuns.verify.status === 'error' || stageRuns.verify.status === 'cancelled') verified = 'attention';
    // Read the latest verify run's OWN verdict, not the finding's overall f.status — a later,
    // unrelated Threat Model run also changes f.status (via deriveStatus() in server.js), which
    // used to silently regress "Verified fixed" back to "Not fixed yet" the moment Threat Model
    // was run on an already-verified finding, even though nothing about the fix itself changed.
    else if (stageRuns.verify.verdict && stageRuns.verify.verdict.verdict === 'verified_fixed') verified = 'done';
    else verified = 'attention'; // still_vulnerable / partially_fixed / inconclusive
  }

  return { triaged, remediated, fixed, verified, hasPlan };
}

// The one thing clicking the loop cell's advance button would do next — 'triage' | 'remediate'
// | 'fix' | 'verify' | null (busy, or nothing left to do). Triage issues (never run, or errored)
// come first — nothing else should happen before a finding's been triaged. verified/fixed ===
// 'attention' both map back to 'remediate', not a retry of the same stage: Verify already said
// the fix didn't hold, and a failed Fix likely means the proposed plan went stale against the
// live file — either way the actionable next step is a fresh proposal, not repeating the same
// attempt. 'unavailable' (Remediate proposed nothing to apply) has no further automated step.
function findingLoopNextAction(f) {
  const { triaged, remediated, fixed, verified } = findingLoopState(f);
  if (triaged === 'running' || remediated === 'running' || fixed === 'running' || verified === 'running') return null;
  if (triaged === 'pending' || triaged === 'attention') return 'triage';
  if (verified === 'attention') return 'remediate';
  if (fixed === 'attention') return 'remediate';
  if (remediated === 'pending' || remediated === 'attention') return 'remediate';
  if (fixed === 'unavailable') return null;
  if (fixed === 'pending') return 'fix';
  if (verified === 'pending') return 'verify';
  return null; // verified === 'done' — nothing left
}

function loopTrackHtml(triaged, remediated, fixed, verified) {
  return `
    <div class="loop-track" title="Triaged → Remediated → Fixed → Verified">
      <span class="loop-seg ${triaged}"></span>
      <span class="loop-seg ${remediated}"></span>
      <span class="loop-seg ${fixed === 'unavailable' ? 'pending' : fixed}"></span>
      <span class="loop-seg ${verified}"></span>
    </div>
  `;
}

// Pure status readout — track + label, no buttons. Advancing the loop itself (the Triage/Fix/
// Verify boxes + "run all" button, see fdLoopBoxesHtml()) lives on the finding's own detail
// page now, not in this table at all.
function findingLoopCellHtml(f) {
  // SCA findings need a dependency bump, not a code edit — Package/Fixed-in already say what
  // to do, so this column just shows plain status here instead of a loop that implies an edit
  // this app can't meaningfully make. Only reachable from the "All" type tab, which shares the
  // 'loop' column across both finding types — the dedicated SCA tab uses the plain 'status' key.
  if (f.scanType === 'sca') return findingsCellHtml(f, 'status');
  if (f.status === 'closed') {
    return `<div class="loop-cell"><span class="hint">Closed — not applicable</span></div>`;
  }

  const { triaged, remediated, fixed, verified } = findingLoopState(f);
  const track = loopTrackHtml(triaged, remediated, fixed, verified);

  let statusHtml;
  if (triaged === 'running') {
    statusHtml = `<span class="loop-status-text">Triaging…</span>`;
  } else if (remediated === 'running') {
    statusHtml = `<span class="loop-status-text">Proposing fix…</span>`;
  } else if (fixed === 'running') {
    statusHtml = `<span class="loop-status-text">Applying fix…</span>`;
  } else if (verified === 'running') {
    statusHtml = `<span class="loop-status-text">Verifying…</span>`;
  } else if (triaged === 'attention') {
    statusHtml = `<span class="loop-status-text attention">Triage failed</span>`;
  } else if (verified === 'attention') {
    statusHtml = `<span class="loop-status-text attention">Not fixed yet</span>`;
  } else if (fixed === 'attention') {
    statusHtml = `<span class="loop-status-text attention">Apply failed</span>`;
  } else if (remediated === 'attention') {
    statusHtml = `<span class="loop-status-text attention">Propose failed</span>`;
  } else if (verified === 'done') {
    statusHtml = `<span class="loop-status-text ok">Verified fixed</span>`
      + `<button class="loop-view-diff" type="button" data-view-diff-btn="${escapeHtml(f.id)}" title="View the applied diff">${icon('checkCircle')}View diff</button>`;
  } else if (fixed === 'done') {
    statusHtml = `<span class="loop-status-text accent">Fixed</span>`;
  } else if (fixed === 'unavailable') {
    statusHtml = `<span class="loop-status-text">No fix proposed</span>`;
  } else if (remediated === 'done') {
    statusHtml = `<span class="loop-status-text accent">Fix proposed</span>`;
  } else if (triaged === 'done') {
    statusHtml = `<span class="loop-status-text accent">Triaged</span>`;
  } else {
    statusHtml = `<span class="loop-status-text">Not started</span>`;
  }

  return `<div class="loop-cell">${track}<div class="loop-status-row">${statusHtml}</div></div>`;
}

// Small tag next to a reasoning finding's title showing which of Hybrid Scan's code-analysis
// engines found it — deterministic (sast-engine's pattern agents) or reasoning (agents/scan.md's LLM
// pass), read straight off the synthetic triage verdict's `source` field (see
// findingFromSastEngine()/findingFromLLMScan() in server.js). Colors match the two progress
// bars on the scan card (accent = pattern match, warn = reasoning) so the two surfaces read as
// the same distinction. Absent for manually-added findings (source: 'manual-placeholder') and
// SCA findings (no such distinction applies).
function findingSourceTagHtml(f) {
  const source = f.stageRuns && f.stageRuns.triage && f.stageRuns.triage.verdict && f.stageRuns.triage.verdict.source;
  if (source === 'sast-engine-verifier') {
    return `<span class="finding-source-tag" title="Found by the deterministic pattern-matching engine">Pattern match</span>`;
  }
  if (source === 'reasoning-scan') {
    return `<span class="finding-source-tag" title="Found by the LLM reasoning pass">Reasoning</span>`;
  }
  return '';
}

function findingsCellHtml(f, key) {
  switch (key) {
    case 'severity':
      return `<div class="ft-sev-cell"><span class="sev-dot ${f.severity}"></span>${escapeHtml(severityLabel(f.severity))}</div>`;
    case 'type': {
      const m = SCAN_TYPE_META[f.scanType] || SCAN_TYPE_META.reasoning;
      return `<span class="scan-type-chip">${escapeHtml(m.label)}</span>`;
    }
    case 'title':
      return `<div class="ft-title">${escapeHtml(f.title)}${findingSourceTagHtml(f)}</div>`;
    case 'file':
      return f.file ? `<span class="ft-mono">${escapeHtml(f.file)}</span>` : '<span class="hint">—</span>';
    case 'location':
      if (f.file) return `<span class="ft-mono">${escapeHtml(f.file)}</span>`;
      if (f.endpoint) return `<span class="ft-mono">${escapeHtml(f.endpoint)}${f.method ? ' (' + escapeHtml(f.method.toUpperCase()) + ')' : ''}</span>`;
      return '<span class="hint">—</span>';
    case 'rule':
      return f.rule ? escapeHtml(f.rule) : '<span class="hint">—</span>';
    case 'package':
      return f.packageName ? `${escapeHtml(f.packageName)}${f.packageVersion ? ` <span class="ft-mono">@${escapeHtml(f.packageVersion)}</span>` : ''}` : '<span class="hint">—</span>';
    case 'fix':
      return f.fixedVersion ? `<span class="ft-mono">${escapeHtml(f.fixedVersion)}</span>` : '<span class="hint">—</span>';
    case 'endpoint':
      return f.endpoint ? `<span class="ft-mono">${escapeHtml(f.endpoint)}</span>` : '<span class="hint">—</span>';
    case 'method':
      return f.method ? escapeHtml(f.method.toUpperCase()) : '<span class="hint">—</span>';
    case 'status':
      return `<span class="badge ${f.status}">${escapeHtml(statusLabel(f.status))}</span>`;
    case 'loop':
      return findingLoopCellHtml(f);
    default:
      return '';
  }
}

function renderFindingsTable() {
  const columns = FINDINGS_COLUMNS[findingsTypeFilter] || FINDINGS_COLUMNS.all;

  const scanScoped = findingsScanScoped();
  const rows = (findingsTypeFilter === 'all' ? scanScoped.slice() : scanScoped.filter((f) => f.scanType === findingsTypeFilter));
  rows.sort((a, b) => {
    const va = findingsSortValue(a, findingsSort.key);
    const vb = findingsSortValue(b, findingsSort.key);
    const cmp = va < vb ? -1 : va > vb ? 1 : 0;
    return findingsSort.dir === 'asc' ? cmp : -cmp;
  });
  findingsTableHeadEl.innerHTML = '';
  const headRow = document.createElement('tr');
  for (const col of columns) {
    const th = document.createElement('th');
    th.textContent = col.label;
    th.dataset.col = col.key;
    if (col.sortable) {
      th.classList.add('sortable');
      if (findingsSort.key === col.key) {
        th.classList.add('sorted');
        const arrow = document.createElement('span');
        arrow.className = 'sort-arrow';
        arrow.textContent = findingsSort.dir === 'asc' ? '↑' : '↓';
        th.appendChild(arrow);
      }
      th.addEventListener('click', () => {
        findingsSort = findingsSort.key === col.key
          ? { key: col.key, dir: findingsSort.dir === 'asc' ? 'desc' : 'asc' }
          : { key: col.key, dir: 'asc' };
        renderFindingsTable();
      });
    }
    headRow.appendChild(th);
  }
  headRow.appendChild(document.createElement('th')); // actions column — no label, see ft-actions-col below
  findingsTableHeadEl.appendChild(headRow);

  findingsTableBodyEl.innerHTML = '';
  if (!rows.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = columns.length + 1;
    td.className = 'ft-empty';
    td.textContent = scanScoped.length
      ? 'No findings match this type.'
      : findingsScanFilter !== 'all'
        ? 'No findings from this scan.'
        : 'No findings yet — click "+ Add" to create one, or start a scan from the Dashboard.';
    tr.appendChild(td);
    findingsTableBodyEl.appendChild(tr);
    return;
  }

  for (const f of rows) {
    const tr = document.createElement('tr');
    tr.dataset.findingId = f.id;
    // Row actions column: just the "…" agent menu now — advancing the loop itself (Triage/Fix/
    // Verify boxes + "run all") lives on the finding's own detail page, matching the same 3-dot
    // menu that page uses. The loop cell (findingLoopCellHtml) still shows read-only progress.
    tr.innerHTML = columns.map((col) => `<td data-col="${col.key}">${findingsCellHtml(f, col.key)}</td>`).join('')
      + `<td class="ft-actions-col"><div class="ft-actions-cell">`
      + `<button class="console-toggle-btn" type="button" data-run-agent-btn title="Run agent…">${icon('more')}</button>`
      + `</div></td>`;
    tr.querySelector('[data-run-agent-btn]').addEventListener('click', (e) => {
      e.stopPropagation();
      const rect = e.currentTarget.getBoundingClientRect();
      openFindingContextMenu(rect.right, rect.bottom + 4, f.id, f);
    });
    const viewDiffBtn = tr.querySelector('[data-view-diff-btn]');
    if (viewDiffBtn) {
      viewDiffBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        onViewDiffClick(f.id);
      });
    }
    tr.addEventListener('click', () => openFindingDetail(f.id));
    tr.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      openFindingContextMenu(e.clientX, e.clientY, f.id, f);
    });
    findingsTableBodyEl.appendChild(tr);
  }
}

function updateFindingListItem(findingId, patch) {
  const item = findings.find((f) => f.id === findingId);
  if (item) Object.assign(item, patch);
  if (currentView === 'findings') renderFindingsTable();
  if (currentView === 'finding-detail' && currentFindingDetailId === findingId) renderFindingDetail(findingId);
  if (currentView === 'dashboard') renderDashboard();
}

// ---------- finding loading (used to build context for a fresh agent run) ----------

async function ensureFindingCached(findingId) {
  if (findingCache.has(findingId)) return findingCache.get(findingId);
  const res = await fetch(`/api/findings/${findingId}`);
  if (!res.ok) return null;
  const finding = await res.json();
  findingCache.set(findingId, finding);
  return finding;
}

// The directory a finding's Verify run should re-check against — the target path of the scan
// that originally produced it, if known. null for manually-added findings (verify.md is
// written to handle that gracefully rather than reasoning over the wrong codebase).
function findingSourcePath(finding) {
  if (!finding || !finding.sourceScanId) return null;
  const scan = scansList.find((s) => s.id === finding.sourceScanId);
  return scan ? scan.path : null;
}

// ---------- writing real fixes: the only place an agent touches the user's real files ----------
// Triage is no longer a live stage at all (see CLAUDE.md) — every finding already carries a
// triage verdict from when it was created, so the loop's first stage is always already "done".
// Remediate and Fix are two separate stages now, not one: Remediate is read-only (proposes a
// fix, writes nothing — no confirmation needed) and Fix is the one write-capable step (applies
// exactly what Remediate proposed). Entry points on the loop cell:
//   - The single arrow (onLoopAdvanceClick) runs exactly the *next* stage and stops. One
//     deliberate click per stage. (The 'triage' branch below is a defensive fallback for a
//     finding that somehow has no triage run yet; it shouldn't be reachable in practice.)
//   - The fast-forward button (onLoopRunAllClick) chains Remediate -> Fix -> Verify under one
//     confirm(), for when stepping through individually isn't needed.
// Fix (both standalone and inside "run all") is gated by a native confirm() naming the exact
// target directory and the git-clean requirement — that's the friction point, not a hidden mode
// toggle (an earlier version had a page-level "Read-only" checkbox that silently changed what a
// shared button did, removed as confusing). Remediate and Verify never need that confirmation
// since neither writes. The applied diff itself is never shown in a popup — it renders directly
// on the finding's own detail page (runCardHtml() draws a fix run's applied_diff as a colored
// diff block there), so seeing what changed is "click into the finding," the same way you'd
// read any other run's verdict.
const precheckRunIds = new Set(); // runIds whose flow includes a server-side precheck (path validation, git-clean-tree) that can fail before any run is pushed server-side — see the 'error' handler below, which alerts those failures directly since the generic error-badge treatment has no run to attach to

function confirmApplyWrite(targetPath) {
  return confirm(
    `This writes the proposed fix directly to files in:\n${targetPath}\n\n` +
    `The target must be a clean git working tree (no uncommitted changes) — the run will refuse ` +
    `otherwise. You'll see the resulting diff once it's done. Continue?`
  );
}

async function onLoopAdvanceClick(findingId) {
  const finding = await ensureFindingCached(findingId);
  if (!finding) return;
  const next = findingLoopNextAction(finding);
  if (!next) return;
  if (next === 'triage' || next === 'verify') {
    startStage(findingId, next, buildBaseContext(finding), '');
    return;
  }
  const targetPath = findingSourcePath(finding);
  if (!targetPath) {
    alert('This finding has no known source directory (it wasn\'t produced by a scan), so there\'s nothing to run this stage against.');
    return;
  }
  if (next === 'remediate') {
    startRemediatePreview(findingId, finding, targetPath);
    return;
  }
  // next === 'fix' — the one step that writes.
  if (!confirmApplyWrite(targetPath)) return;
  startRemediateFix(findingId, finding, targetPath);
}

function confirmRunAll(targetPath) {
  return confirm(
    `This proposes a fix, applies it, and verifies it in sequence against:\n${targetPath}\n\n` +
    `Applying the fix directly edits files there, so the target must be a clean git working tree ` +
    `(no uncommitted changes) — the run will refuse otherwise. Continue?`
  );
}

// The loop cell's "run all stages" button — Remediate (propose) -> Fix (apply) -> Verify
// chained under one confirm(), for when stepping through each stage individually isn't needed.
// There's no live Triage sub-call here: every finding already carries a triage verdict from
// when it was created (see CLAUDE.md), and buildBaseContext() already folds that verdict into
// the context string Remediate receives below.
async function onLoopRunAllClick(findingId) {
  const finding = await ensureFindingCached(findingId);
  if (!finding) return;
  const targetPath = findingSourcePath(finding);
  if (!targetPath) {
    alert('This finding has no known source directory (it wasn\'t produced by a scan), so there\'s nothing to run the full pipeline against.');
    return;
  }
  if (!confirmRunAll(targetPath)) return;
  startRemediateAll(findingId, finding, targetPath);
}

// The diff itself lives in the finding's own Agent runs section (runCardHtml() renders any
// remediation run's applied_diff as a colored diff block there) — no separate popup, just jump
// to the page that already shows it.
function onViewDiffClick(findingId) {
  openFindingDetail(findingId);
}

// Mirrors startStage()'s optimistic-placeholder pattern so the run shows as in-progress
// immediately rather than only once it finishes. Read-only — no precheck can fail here beyond
// "is this a real directory", but it's still tracked in precheckRunIds since that failure can
// still happen before any run record exists server-side.
function startRemediatePreview(findingId, finding, targetPath) {
  const runId = uid();
  stages.set(runId, findingId);
  stageConsoles.set(runId, { runId, consoleText: '', consoleOpen: false, consoleEl: null });
  precheckRunIds.add(runId);

  const startedAt = Date.now();
  const context = buildBaseContext(finding);
  upsertTimelineEntry({
    kind: 'remediation', runId, findingId, findingTitle: finding.title, agent: 'remediation',
    status: 'running', instruction: '', verdict: null, startedAt, finishedAt: null,
  });
  finding.runs.push({ runId, agent: 'remediation', status: 'running', verdict: null, startedAt, finishedAt: null });
  if (currentView === 'finding-detail' && currentFindingDetailId === findingId) renderFindingDetail(findingId);

  ws.send(JSON.stringify({ type: 'remediate_preview', runId, findingId, context, instruction: '', path: targetPath }));
}

// The write-capable step — applies whatever the most recent Remediate run proposed. No console
// tracking: this makes no `claude` call at all (see handleRemediateFixMessage in server.js), so
// there's never any narrated text for the console panel to show.
function startRemediateFix(findingId, finding, targetPath) {
  const runId = uid();
  stages.set(runId, findingId);
  precheckRunIds.add(runId);

  const startedAt = Date.now();
  upsertTimelineEntry({
    kind: 'fix', runId, findingId, findingTitle: finding.title, agent: 'fix',
    status: 'running', instruction: '', verdict: null, startedAt, finishedAt: null,
  });
  finding.runs.push({ runId, agent: 'fix', status: 'running', verdict: null, startedAt, finishedAt: null });
  if (currentView === 'finding-detail' && currentFindingDetailId === findingId) renderFindingDetail(findingId);

  ws.send(JSON.stringify({ type: 'remediate_fix', runId, findingId, path: targetPath }));
}

// Only the first stage (Remediate) gets an optimistic client-side placeholder — Fix's and
// Verify's placeholders arrive via the server's own 'started' message once each stage actually
// begins (same dedup pattern startStage()'s comment describes), since we don't yet know whether
// they'll even run (Remediate proposing nothing usable, or Fix failing to apply, both stop the
// chain early).
function startRemediateAll(findingId, finding, targetPath) {
  const remediationRunId = uid();
  const fixRunId = uid();
  const verifyRunId = uid();
  stages.set(remediationRunId, findingId);
  stages.set(fixRunId, findingId);
  stages.set(verifyRunId, findingId);
  stageConsoles.set(remediationRunId, { runId: remediationRunId, consoleText: '', consoleOpen: false, consoleEl: null });
  stageConsoles.set(verifyRunId, { runId: verifyRunId, consoleText: '', consoleOpen: false, consoleEl: null });
  precheckRunIds.add(remediationRunId); // a precheck failure (dirty tree) is tagged with the first stage's runId, since that's the only one with a client-side placeholder before the server responds

  const startedAt = Date.now();
  const context = buildBaseContext(finding);
  upsertTimelineEntry({
    kind: 'remediation', runId: remediationRunId, findingId, findingTitle: finding.title, agent: 'remediation',
    status: 'running', instruction: '', verdict: null, startedAt, finishedAt: null,
  });
  finding.runs.push({ runId: remediationRunId, agent: 'remediation', status: 'running', verdict: null, startedAt, finishedAt: null });
  if (currentView === 'finding-detail' && currentFindingDetailId === findingId) renderFindingDetail(findingId);

  ws.send(JSON.stringify({
    type: 'remediate_all', findingId, remediationRunId, fixRunId, verifyRunId, context, instruction: '', path: targetPath,
  }));
}

// Minimal unified-diff line coloring — no external diff library, consistent with this app's
// no-external-deps aesthetic. Only cares about the leading +/-/@@ marker per line. Used by
// runCardHtml() to render a write-capable remediation run's applied_diff on Finding Detail.
function diffLineHtml(line) {
  let cls = '';
  if (line.startsWith('+++') || line.startsWith('---')) cls = 'meta';
  else if (line.startsWith('+')) cls = 'add';
  else if (line.startsWith('-')) cls = 'del';
  else if (line.startsWith('@@')) cls = 'hunk';
  else if (line.startsWith('diff --git') || line.startsWith('index ')) cls = 'meta';
  return `<div class="diff-line${cls ? ' ' + cls : ''}">${escapeHtml(line) || '&nbsp;'}</div>`;
}

function buildBaseContext(finding) {
  const latestRun = finding.runs && finding.runs.length ? finding.runs[finding.runs.length - 1] : null;
  const parts = [
    `Title: ${finding.title}`,
    `Type: ${finding.scanType || 'reasoning'}`,
    `Severity (as reported by scanner): ${finding.severity}`,
    finding.rule ? `Rule: ${finding.rule}` : '',
    finding.file ? `File: ${finding.file}` : '',
    finding.packageName ? `Package: ${finding.packageName}${finding.packageVersion ? '@' + finding.packageVersion : ''}` : '',
    finding.fixedVersion ? `Fixed version: ${finding.fixedVersion}` : '',
    finding.endpoint ? `Endpoint: ${finding.endpoint}${finding.method ? ' (' + finding.method + ')' : ''}` : '',
    `Description:\n${finding.description}`,
    finding.code ? `Code:\n${finding.code}` : '',
    latestRun && latestRun.verdict ? `Prior ${agentMeta(latestRun.agent).label} verdict:\n${JSON.stringify(latestRun.verdict, null, 2)}` : '',
  ];
  return parts.filter(Boolean).join('\n');
}

// ---------- finding detail (full page) ----------

const fdBodyEl = document.getElementById('fd-body');
const VERDICT_BADGE_FIELDS = ['verdict', 'severity_confirmed', 'confidence', 'priority'];
// corrected_code and edit_plan get their own dedicated renderers (a syntax-highlighted code
// block, and a diff-style preview respectively — see runCardHtml()) instead of the generic
// key/value grid every other field falls into, since dumping a multi-line code string or a
// nested {summary,risk,files:[...]} object through String() there produced unreadable output
// (a wrapped code paragraph with no monospacing, and literally "[object Object]").
const VERDICT_SKIP_FIELDS = new Set([...VERDICT_BADGE_FIELDS, 'reasoning', 'next_agent', 'applied_diff', 'corrected_code', 'edit_plan']);

async function openFindingDetail(findingId) {
  currentFindingDetailId = findingId;
  showView('finding-detail');
  fdBodyEl.innerHTML = '<div class="hint" style="padding:30px 4px;">Loading…</div>';
  const res = await fetch(`/api/findings/${findingId}`);
  if (!res.ok) {
    fdBodyEl.innerHTML = '<div class="hint" style="padding:30px 4px;">Finding not found.</div>';
    return;
  }
  const finding = await res.json();
  findingCache.set(findingId, finding);
  renderFindingDetail(findingId);
}

function renderFindingDetail(findingId) {
  const finding = findingCache.get(findingId);
  if (!finding || currentFindingDetailId !== findingId) return;

  document.getElementById('fd-title').textContent = finding.title;
  document.getElementById('fd-subtitle').textContent =
    `${finding.runs.length} agent run${finding.runs.length === 1 ? '' : 's'} · created ${new Date(finding.createdAt).toLocaleString()}`;

  const typeMeta = SCAN_TYPE_META[finding.scanType] || SCAN_TYPE_META.reasoning;

  const badgesHtml = `
    <div class="fd-badges">
      <span class="badge ${finding.severity}">${escapeHtml(severityLabel(finding.severity))}</span>
      <span class="badge ${finding.status}">${escapeHtml(statusLabel(finding.status))}</span>
      <span class="scan-type-chip">${escapeHtml(typeMeta.label)}</span>
      ${findingSourceTagHtml({ stageRuns: findingStageRuns(finding) })}
    </div>
  `;

  const sourceScan = finding.sourceScanId ? scansList.find((s) => s.id === finding.sourceScanId) : null;
  const scanSourceHtml = sourceScan ? `
    <div class="fd-scan-source">
      Found by scan of <span class="mono">${escapeHtml(truncate(sourceScan.path, 60))}</span>
      <button class="link-btn" type="button" data-action="view-source-scan">View all findings from this scan →</button>
    </div>
  ` : '';

  const metaItems = [];
  if (finding.scanType === 'sca') {
    if (finding.packageName) metaItems.push(['Package', finding.packageName + (finding.packageVersion ? '@' + finding.packageVersion : ''), true]);
    if (finding.fixedVersion) metaItems.push(['Fixed in', finding.fixedVersion, true]);
  }
  // A reasoning-scan finding can be file-based (code pattern) or endpoint-based (attack
  // surface), or occasionally both — no longer gated behind a separate DAST scanType, since
  // that per-finding distinction now lives purely in which optional fields are present.
  if (finding.endpoint) metaItems.push(['Endpoint', finding.endpoint, true]);
  if (finding.method) metaItems.push(['Method', finding.method.toUpperCase(), true]);
  if (finding.file) metaItems.push(['File', finding.file, true]);
  if (finding.rule) metaItems.push(['Rule / CWE', finding.rule, false]);

  const metaHtml = metaItems.length ? `
    <div class="fd-meta-grid">
      ${metaItems.map(([label, value, mono]) => `
        <div class="fd-meta-item">
          <div class="fd-meta-label">${escapeHtml(label)}</div>
          <div class="fd-meta-value${mono ? ' mono' : ''}">${escapeHtml(value)}</div>
        </div>
      `).join('')}
    </div>
  ` : '';

  const descriptionHtml = `
    <div class="fd-section">
      <div class="fd-section-title">Description</div>
      <div class="fd-prose">${escapeHtml(finding.description)}</div>
    </div>
  `;

  const flowHtml = findingFlowHtml(finding);

  const codeHtml = finding.code ? `
    <div class="fd-section">
      <div class="fd-section-title">Code</div>
      <div class="fd-code-wrap">
        <button class="secondary fd-copy-btn" type="button" data-action="copy-code">Copy</button>
        <pre class="code-block"><code>${highlightCode(finding.code)}</code></pre>
      </div>
    </div>
  ` : '';

  const runsHtml = `
    <div class="fd-section">
      <div class="fd-section-title">Agent runs</div>
      ${finding.runs.length
        ? finding.runs.slice().reverse().map(runCardHtml).join('')
        : '<div class="fd-runs-empty">No agent runs yet — use the buttons above to start one.</div>'}
    </div>
  `;

  fdBodyEl.innerHTML = badgesHtml + scanSourceHtml + metaHtml + descriptionHtml + flowHtml + codeHtml + runsHtml;

  const copyBtn = fdBodyEl.querySelector('[data-action="copy-code"]');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(finding.code).then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      });
    });
  }

  const viewSourceScanBtn = fdBodyEl.querySelector('[data-action="view-source-scan"]');
  if (viewSourceScanBtn) {
    viewSourceScanBtn.addEventListener('click', () => openFindingsFilteredByScan(finding.sourceScanId));
  }

  fdBodyEl.querySelectorAll('[data-action="view-threat-model"]').forEach((btn) => {
    btn.addEventListener('click', () => openThreatModelForFinding(findingId, btn.dataset.runId));
  });

  wireConsoleToggles(fdBodyEl, stageConsoles, () => renderFindingDetail(findingId));
  reattachConsoleRefs(fdBodyEl, stageConsoles, 'stage-console');

  renderFindingDetailActions(finding);
}

function openFindingsFilteredByScan(scanId) {
  findingsScanFilter = scanId;
  showView('findings');
}

// Verdict fields are raw snake_case JSON keys (root_cause, nist_800_53, ...) — title-case them
// for display so the row label reads like the fd-meta-grid labels above it, not raw JSON.
function verdictFieldLabel(key) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

// Agent free-text (reasoning/root_cause/evidence/etc.) commonly contains Markdown-ish inline
// code spans and bold the model wrote assuming a Markdown renderer downstream — this app had
// none, so a literal backtick or `**` pair just showed up as stray punctuation. A small
// hand-rolled inline formatter (escape first, then linkify backtick spans and bold — no lists/
// headers/links, this app's verdict fields never use them) fixes that without pulling in an
// external Markdown library, consistent with this app's other hand-rolled renderers
// (highlightCode(), diffLineHtml()).
function formatInlineText(str) {
  return escapeHtml(str)
    .replace(/`([^`]+)`/g, (_, code) => `<code>${code}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, (_, b) => `<strong>${b}</strong>`);
}

// An array field like `evidence`/`verification_steps` joined into one comma-separated run-on
// string reads as a wall of text once items are full sentences (and gets actively confusing
// when an item itself contains a comma, e.g. a SQL snippet or a regex alternation). `evidence`
// specifically (per agents/verify.md's contract: "short file/path or pattern references") is
// code/reference lines, not prose — those render one-per-line in a monospace block, the same
// visual language as the finding's own CODE section, rather than prose bullets. Other long
// arrays (verification_steps and the like — actual sentences) get a real bulleted list instead;
// short arrays (control IDs, single-word tags) stay as an inline comma list, which reads better
// at that size than a list with one item per line.
function verdictArrayHtml(items, key) {
  const strs = items.map((v) => String(v));
  if (key === 'evidence') {
    return `<pre class="code-block fd-verdict-codeblock">${strs.map((s) => escapeHtml(s)).join('\n')}</pre>`;
  }
  const needsList = strs.length > 3 || strs.some((s) => s.length > 30);
  if (!needsList) return formatInlineText(strs.join(', '));
  return `<ul class="fd-verdict-list">${strs.map((s) => `<li>${formatInlineText(s)}</li>`).join('')}</ul>`;
}

// `corrected_code` is a full replacement code snippet — rendered exactly like the finding's own
// CODE section (highlightCode() + .code-block) so it reads as code, not a wrapped paragraph.
function correctedCodeHtml(code) {
  if (!code) return '';
  return `<div class="fd-section-title" style="margin-top:10px;">Proposed fix</div><pre class="code-block"><code>${highlightCode(code)}</code></pre>`;
}

// `edit_plan` is a structured { summary, risk, files: [{ path, edits: [{find, replace}] }] }
// object (or a { path, create/append } companion-file entry) — rendered as a diff-style preview
// (reusing diffLineHtml(), the same renderer applied_diff uses) so "what will Fix write" reads
// the same way as "what did Fix write" does once it's actually run, rather than a raw dump of
// the object.
function editPlanHtml(plan) {
  if (!plan || typeof plan !== 'object') return '';
  const files = Array.isArray(plan.files) ? plan.files : [];
  if (!files.length) return '';
  const summaryHtml = plan.summary
    ? `<div class="fd-verdict-reasoning" style="margin-top:10px;">${formatInlineText(plan.summary)}${plan.risk ? ` <span class="badge ${escapeHtml(String(plan.risk))}">${escapeHtml(String(plan.risk))} risk</span>` : ''}</div>`
    : '';
  const fileBlocks = files.map((f) => {
    const lines = [];
    if (Array.isArray(f.edits)) {
      for (const e of f.edits) {
        String(e.find || '').split('\n').forEach((l) => lines.push('-' + l));
        String(e.replace || '').split('\n').forEach((l) => lines.push('+' + l));
      }
    } else if (f.create) {
      String(f.content || '').split('\n').forEach((l) => lines.push('+' + l));
    } else if (f.append != null) {
      String(f.append).split('\n').forEach((l) => lines.push('+' + l));
    }
    if (!lines.length) return '';
    return `<div class="fd-section-title" style="margin-top:10px;">${escapeHtml(f.path || '')}</div><pre class="diff-block">${lines.map(diffLineHtml).join('')}</pre>`;
  }).join('');
  return summaryHtml + fileBlocks;
}

function runCardHtml(run) {
  const meta = agentMeta(run.agent);
  const timeStr = run.startedAt ? formatRelativeTime(run.startedAt) : '';
  const statusCls = run.status === 'running' ? 'in_review' : (run.status === 'error' || run.status === 'cancelled') ? 'high' : 'closed';
  const statusText = run.status === 'running' ? 'Running' : run.status === 'error' ? 'Error' : run.status === 'cancelled' ? 'Cancelled' : 'Done';

  let verdictHtml = '';
  if (run.verdict && typeof run.verdict === 'object') {
    const v = run.verdict;
    const badgeFields = VERDICT_BADGE_FIELDS.filter((k) => v[k]);
    const otherFields = Object.keys(v).filter((k) => !VERDICT_SKIP_FIELDS.has(k) && v[k] != null && v[k] !== '' && !(Array.isArray(v[k]) && !v[k].length));
    // applied_diff only exists on a write-capable remediation run (the loop cell's advance
    // button) — the one place this app shows real evidence of a file it wrote, so it gets its
    // own colored diff block rather than folding into the generic key/value grid above.
    const appliedDiffHtml = v.applied_diff
      ? `<div class="fd-section-title" style="margin-top:10px;">Applied diff</div><pre class="diff-block">${v.applied_diff.split('\n').map(diffLineHtml).join('')}</pre>`
      : '';
    verdictHtml = `
      ${badgeFields.length ? `<div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px;">${badgeFields.map((k) => `<span class="badge ${escapeHtml(String(v[k]))}">${escapeHtml(String(v[k]))}</span>`).join('')}</div>` : ''}
      ${v.reasoning ? `<div class="fd-verdict-reasoning">${formatInlineText(v.reasoning)}</div>` : ''}
      ${otherFields.length ? `
        <div class="fd-verdict-grid" style="margin-top:8px;">
          ${otherFields.map((k) => `<div class="fd-verdict-item"><b>${escapeHtml(verdictFieldLabel(k))}</b><div class="fd-verdict-value">${Array.isArray(v[k]) ? verdictArrayHtml(v[k], k) : formatInlineText(String(v[k]))}</div></div>`).join('')}
        </div>
      ` : ''}
      ${correctedCodeHtml(v.corrected_code)}
      ${editPlanHtml(v.edit_plan)}
      ${appliedDiffHtml}
    `;
  } else if (run.status === 'error') {
    verdictHtml = '<div class="fd-verdict-reasoning">Run failed — no verdict produced.</div>';
  } else if (run.status === 'running') {
    verdictHtml = '<div class="fd-verdict-reasoning">Still running…</div>';
  }

  const viewInThreatModelHtml = (run.agent === 'threat_model' && run.verdict && typeof run.verdict === 'object')
    ? `<button class="secondary fd-view-tm-btn" type="button" data-action="view-threat-model" data-run-id="${escapeHtml(run.runId)}">View in Threat Model →</button>`
    : '';

  // Only rendered for runs started this browser session — stageConsoles has nothing for
  // seeded/historical runs, so there's no live text to show for them.
  const consoleRun = stageConsoles.get(run.runId);

  return `
    <div class="fd-run-card">
      <div class="fd-run-head">
        <span class="fd-run-agent" style="color:${meta.color};">${icon(meta.icon)}${escapeHtml(meta.label)}</span>
        <span class="badge ${statusCls}">${escapeHtml(statusText)}</span>
        <span class="fd-run-time">${escapeHtml(timeStr)}</span>
        ${consoleRun ? consoleToggleButtonHtml(consoleRun) : ''}
      </div>
      ${consoleRun ? consolePanelHtml(consoleRun, 'stage-console') : ''}
      ${verdictHtml}
      ${viewInThreatModelHtml}
    </div>
  `;
}

// Triage/Fix/Verify boxes for Finding Detail — a box-per-stage view of the exact same linear
// pipeline the Agent Triage table's loop-seg track shows compactly (see findingLoopState()).
// Only one stage is ever actionable at a time (findingLoopNextAction() — a strictly linear
// pipeline), so whichever single box comes back clickable dispatches the same onLoopAdvanceClick()
// the table's old advance button used to call; there's no independent per-stage logic to keep in
// sync with it. Returns '' for SCA findings (no code-edit loop applies — Package/Fixed-in already
// say what to do) and a short note for closed findings, matching findingLoopCellHtml().
function fdLoopBoxesHtml(f) {
  if (f.scanType === 'sca') return '';
  if (f.status === 'closed') return `<div class="hint">Closed — remediation loop not applicable.</div>`;

  const { triaged, remediated, fixed, verified } = findingLoopState(f);
  const next = findingLoopNextAction(f);
  const hasPath = !!findingSourcePath(f);
  const anyRunning = triaged === 'running' || remediated === 'running' || fixed === 'running' || verified === 'running';

  // Each box always shows a short, fixed caption describing what the stage does — not just a
  // hover tooltip — since the boxes alone (icon + one-word status) didn't make it obvious what
  // clicking one would actually do.
  const box = (stage, agentKey, label, caption, runningLabel, state, actionable, actionTitle) => {
    const meta = agentMeta(agentKey);
    const statusText = state === 'running' ? runningLabel
      : state === 'attention' ? (stage === 'verify' ? 'Not fixed' : 'Failed')
      : state === 'unavailable' ? 'No fix proposed'
      : state === 'done' ? 'Done' : 'Not started';
    const clickable = actionable && !anyRunning;
    const title = clickable ? actionTitle
      : state === 'done' ? `${label} complete`
      : state === 'unavailable' ? 'Remediate didn’t propose a specific edit for this finding — nothing to apply'
      : !hasPath && stage !== 'triage' ? 'No known source directory — this finding wasn\'t produced by a scan'
      : '';
    return `
      <button class="fd-loop-box${clickable ? ' clickable' : ''} state-${state}" type="button"
        data-fd-loop-box${clickable ? '' : ' disabled'} title="${escapeHtml(title)}">
        ${icon(meta.icon)}<span class="fd-loop-box-text">
          <span class="fd-loop-box-label">${escapeHtml(label)}</span>
          <span class="fd-loop-box-caption">${escapeHtml(caption)}</span>
          <span class="fd-loop-box-status">${escapeHtml(statusText)}</span>
        </span>
      </button>`;
  };

  const boxesHtml = '<div class="fd-loop-boxes">'
    + box('triage', 'triage', 'Triage', 'Confirms it’s real', 'Triaging…', triaged, next === 'triage', 'Run Triage')
    + box('remediate', 'remediation', 'Remediate', 'Proposes a fix to review', 'Proposing…', remediated, next === 'remediate', 'Propose a fix — nothing written yet')
    + box('fix', 'fix', 'Fix', 'Writes the fix to your code', 'Applying…', fixed, next === 'fix', 'Apply the proposed fix — writes to your code')
    + box('verify', 'verify', 'Verify', 'Re-checks the live code', 'Verifying…', verified, next === 'verify', 'Verify the fix actually landed')
    + '</div>';

  const runAllDisabled = anyRunning || !next || !hasPath;
  const runAllTitle = !hasPath ? 'No known source directory — this finding wasn\'t produced by a scan'
    : !next ? 'Nothing left to run'
    : 'Run all remaining stages';
  const runAllHtml = `<button class="fd-loop-runall-btn" type="button" data-fd-runall="${escapeHtml(f.id)}"${runAllDisabled ? ' disabled' : ''} title="${escapeHtml(runAllTitle)}">${icon('skipForward')}Run all stages</button>`;

  return boxesHtml + runAllHtml;
}

function renderFindingDetailActions(finding) {
  const actionsEl = document.getElementById('fd-header-actions');
  const excluded = finding.scanType === 'sca' ? SCA_EXCLUDED_AGENTS : FIX_FLOW_AGENTS;
  const hasMenuAgents = agentsList.some((a) => !excluded.includes(a));
  const menuBtnHtml = `<button class="console-toggle-btn" type="button" id="fd-agent-menu-btn"${hasMenuAgents ? '' : ' disabled'} title="${hasMenuAgents ? 'Run agent…' : 'No agent actions apply to this finding'}">${icon('more')}</button>`;
  actionsEl.innerHTML = fdLoopBoxesHtml(finding) + menuBtnHtml;

  document.getElementById('fd-agent-menu-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    const rect = e.currentTarget.getBoundingClientRect();
    openFindingContextMenu(rect.right, rect.bottom + 4, finding.id, finding);
  });
  actionsEl.querySelectorAll('[data-fd-loop-box]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      e.currentTarget.disabled = true; // guard against a double-click firing two real runs; the next render (on done/error) replaces this node anyway
      onLoopAdvanceClick(finding.id);
    });
  });
  const runAllBtn = actionsEl.querySelector('[data-fd-runall]');
  if (runAllBtn) {
    runAllBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      e.currentTarget.disabled = true;
      onLoopRunAllClick(finding.id);
    });
  }
}

document.getElementById('fd-back-btn').addEventListener('click', () => showView('findings'));

// ---------- syntax highlighting (hand-rolled, no external deps — universal ----------
// token classes across C-like/Python/etc. syntaxes, not a full per-language grammar) ----------

const HL_KEYWORDS = new Set([
  'function', 'const', 'let', 'var', 'return', 'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
  'import', 'export', 'from', 'as', 'default', 'class', 'extends', 'implements', 'interface', 'new', 'delete', 'typeof',
  'instanceof', 'try', 'catch', 'finally', 'throw', 'async', 'await', 'yield', 'static', 'public', 'private', 'protected',
  'void', 'null', 'true', 'false', 'undefined', 'this', 'super', 'in', 'of',
  'def', 'elif', 'pass', 'lambda', 'with', 'is', 'not', 'and', 'or', 'None', 'True', 'False', 'self', 'raise', 'except',
  'global', 'nonlocal', 'assert',
  'func', 'package', 'go', 'chan', 'defer', 'select', 'range', 'struct', 'type', 'map', 'nil',
  'namespace', 'using', 'fn', 'impl', 'pub', 'mut', 'match', 'loop', 'enum', 'trait', 'mod',
  'int', 'string', 'bool', 'float', 'double', 'char', 'long', 'short', 'unsigned', 'const', 'include', 'define',
]);
const HL_TOKEN_RE = /(\/\/[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(\b\d+(?:\.\d+)?\b)|(\b[A-Za-z_$][A-Za-z0-9_$]*\b)/g;

// ── Attack Surface ──────────────────────────────────────────────────────────
//
// A posture view, not a findings view. Every scan already builds a complete
// structural map of the target — each route with its resolved middleware chain,
// each mount and what guards it, and every security function that exists but is
// never called — and until now that was assembled for the reasoning prompts and
// then discarded. This is the one place the app can answer "what does this
// application expose, and what is protecting it" rather than "what is wrong with
// it", which is a question no list of findings answers.
//
// Fed by GET /api/scans/:id/surface. Only scans run after the feature existed
// carry a map, so an older scan says so plainly instead of rendering empty.

let surfaceScanId = null;
let surfaceData = null;

function openSurfaceView() {
  renderSurfaceScanPicker();
  if (!scansList.length) { loadScans().then(renderSurfaceScanPicker); }
  const done = scansList.filter((s) => s.status === 'done');
  if (!surfaceScanId && done.length) surfaceScanId = done[0].id;
  if (surfaceScanId) loadSurface(surfaceScanId);
  else renderSurfaceView();
}

async function loadSurface(scanId) {
  const el = document.getElementById('surface-content');
  if (el) el.innerHTML = '<div class="placeholder-panel">Loading the map…</div>';
  try {
    const res = await fetch(`/api/scans/${scanId}/surface`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      surfaceData = { unavailable: body.error || 'No attack-surface map for this scan.' };
    } else {
      surfaceData = await res.json();
    }
  } catch (err) {
    surfaceData = { unavailable: err.message };
  }
  renderSurfaceView();
  renderSurfaceScanPicker();
}

function renderSurfaceScanPicker() {
  const btn = document.getElementById('surface-scan-btn');
  const menu = document.getElementById('surface-scan-menu');
  if (!btn || !menu) return;
  const done = scansList.filter((s) => s.status === 'done');
  const current = done.find((s) => s.id === surfaceScanId);
  btn.textContent = current ? scanFilterLabel(current) : (done.length ? 'Select a scan' : 'No completed scans');
  btn.disabled = !done.length;
  menu.innerHTML = done.map((s) =>
    `<button type="button" class="scan-filter-item${s.id === surfaceScanId ? ' active' : ''}" data-scan-id="${s.id}">${escapeHtml(scanFilterLabel(s))}</button>`
  ).join('') || '<div class="scan-filter-empty">Run a scan first.</div>';
  menu.querySelectorAll('[data-scan-id]').forEach((b) => {
    b.onclick = () => { surfaceScanId = b.dataset.scanId; menu.hidden = true; loadSurface(surfaceScanId); };
  });
  btn.onclick = (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; };
}

/**
 * Is this guard chain doing authorization, only authentication, or nothing at all?
 *
 * Takes anything carrying a `middleware` array — a mount OR a single route — so the same
 * three-way classification drives both the mounted-router rows and the per-route rollup in
 * the stat tiles. It used to take a mount only, which is what made the tiles lie about an
 * app with no routers: see renderSurfaceView().
 */
// Words that indicate a middleware decides WHETHER YOU MAY (authorization).
const AUTHZ_WORDS = new Set([
  'admin', 'role', 'roles', 'permission', 'permissions', 'privilege', 'privileged',
  'acl', 'rbac', 'abac', 'scope', 'scopes', 'claim', 'claims', 'owner', 'ownership',
  'tenant', 'grant', 'grants', 'policy', 'policies', 'authorize', 'authorized',
  'authorization', 'can', 'allowed', 'forbid', 'entitlement',
]);
// Words that indicate a middleware decides WHO YOU ARE (authentication).
const AUTHN_WORDS = new Set([
  'auth', 'authenticate', 'authenticated', 'authentication', 'login', 'logged',
  'session', 'jwt', 'token', 'bearer', 'identity', 'passport', 'oidc', 'saml',
  'user', 'account', 'signin', 'signed', 'apikey', 'credentials',
]);

/** Split a middleware name into lowercase words: requireAdmin -> [require, admin]. */
function guardNameSegments(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((s) => s.toLowerCase());
}

/**
 * Is this guard chain doing authorization, only authentication, or nothing at all?
 *
 * Takes anything carrying a `middleware` array — a mount OR a single route — so the same
 * classification drives both the mounted-router rows and the per-route stat tiles.
 *
 * Two things here were wrong in ways that both pointed the SAME direction — making an
 * unprotected surface look protected, which is the only direction that really matters:
 *
 * 1. Any middleware at all counted as authentication, so a route whose only middleware was
 *    `helmet` or `bodyParser` rendered amber "authenticated, not authorized" instead of red
 *    "no guard". Parsing a request body is not a guard.
 * 2. The privilege test was an UNANCHORED substring regex, so incidental letter runs promoted
 *    ordinary middleware to full authorization and rendered the reassuring green "guarded" —
 *    suppressing the warning entirely. Real examples that matched: `validateOracle` and
 *    `oracleClient` (contain "acl"), `scopedLogger` and `descope` ("scope"), `reclaimSession`
 *    and `disclaimerBanner` ("claim"), `rolexTimer` ("role").
 *
 * Now the name is split into words and matched against explicit vocabularies. A middleware
 * whose words match NEITHER vocabulary is treated as not-a-guard: in a security view an
 * unrecognised name is not evidence of protection, and "no guard" is the safe way to be
 * wrong — it invites a look, where a false green does not.
 *
 * Two limitations remain, both known and both preferred to the alternatives:
 *  - A name with no case or delimiter boundaries (`REQUIREADMIN`, `requireadmin`) cannot be
 *    split, so it matches nothing and reads as "no guard". That is a false RED — noisy, but
 *    it errs toward inspection. Reintroducing prefix/suffix matching to catch it would also
 *    re-admit `scopedLogger` (starts with "scope") into the false-green bucket, which is the
 *    failure this fix exists to remove.
 *  - Some words are genuinely ambiguous: `telemetryScope` classifies as authz because "scope"
 *    really is an authorization word in OAuth/JWT terms. Word-splitting cannot tell an OAuth
 *    scope from a telemetry scope, and dropping "scope"/"claim" from the vocabulary would
 *    miss real `requireScope`/`checkClaims` guards. Residual, and narrower than the eight
 *    incidental matches the substring regex produced.
 */
function guardKindOf(node) {
  const raw = node && node.middleware;
  // Tolerate a malformed surface payload rather than throwing mid-render.
  const mw = Array.isArray(raw) ? raw : [];
  if (!mw.length) return 'none';
  const words = mw.flatMap(guardNameSegments);
  if (words.some((w) => AUTHZ_WORDS.has(w))) return 'authz';
  if (words.some((w) => AUTHN_WORDS.has(w))) return 'authn';
  return 'none';
}

function surfaceGuardBadge(kind) {
  if (kind === 'none') return '<span class="surface-badge crit">no guard</span>';
  if (kind === 'authn') return '<span class="surface-badge warn">authenticated, not authorized</span>';
  return '<span class="surface-badge ok">guarded</span>';
}

function surfaceRouteRowsHtml(list) {
  return list.map((r) => `
    <div class="surface-route">
      <span class="surface-method ${escapeHtml(String(r.method || '').toLowerCase())}">${escapeHtml(r.method || '')}</span>
      <span class="surface-path">${escapeHtml(r.path || '')}</span>
      <span class="surface-mw">${(r.middleware || []).length ? r.middleware.map(escapeHtml).join(', ') : '<em>no route guard</em>'}</span>
      <span class="surface-loc">${escapeHtml(r.file || '')}:${r.line}</span>
    </div>`).join('');
}

function renderSurfaceView() {
  const el = document.getElementById('surface-content');
  if (!el) return;

  if (!surfaceData) {
    el.innerHTML = '<div class="placeholder-panel">Run a scan, then pick it above to see the map of what it exposes.</div>';
    return;
  }
  if (surfaceData.unavailable) {
    el.innerHTML = `<div class="placeholder-panel">${escapeHtml(surfaceData.unavailable)}</div>`;
    return;
  }

  const mounts = (surfaceData.mounts || []).filter((m) => m.prefix && m.mounted);
  const routes = surfaceData.routes || [];
  const unused = (surfaceData.securityFunctions || []).filter((f) => f.callCount === 0);

  // Which mount, if any, owns a route. Same substring heuristic the mount rows use — a route
  // is attributed to the mount whose router filename appears in the route's own file path.
  const ownerOf = (r) => mounts.find((m) => r.file && m.mounted && r.file.includes(m.mounted)) || null;
  // A route's effective guard chain is its mount's middleware plus its own: a route with no
  // guard of its own sitting behind an authenticated mount is still authenticated.
  const routeKind = (r) => {
    const owner = ownerOf(r);
    return guardKindOf({ middleware: [...((owner && owner.middleware) || []), ...(r.middleware || [])] });
  };

  // These counts are derived from ROUTES, not mounts. Deriving them from mounts meant an app
  // that registers its routes directly on `app` — no express.Router() anywhere, which is a
  // completely ordinary way to write one — reported "0 with no guard" in the safe green while
  // every one of its endpoints was in fact unguarded. A security view stating the reassuring
  // opposite of the truth is worse than one that says nothing.
  const unguarded = routes.filter((r) => routeKind(r) === 'none').length;
  const authnOnly = routes.filter((r) => routeKind(r) === 'authn').length;

  const stats = `
    <div class="stat-grid surface-stats">
      <div class="stat-tile"><div class="stat-value">${routes.length}</div><div class="stat-label">Endpoints</div></div>
      <div class="stat-tile"><div class="stat-value">${mounts.length}</div><div class="stat-label">Mounted routers</div></div>
      <div class="stat-tile"><div class="stat-value" style="color:${unguarded ? 'var(--crit)' : 'var(--ok)'}">${unguarded}</div><div class="stat-label">Unguarded endpoints</div></div>
      <div class="stat-tile"><div class="stat-value" style="color:${authnOnly ? 'var(--warn)' : 'var(--ok)'}">${authnOnly}</div><div class="stat-label">Authenticated only</div></div>
      <div class="stat-tile"><div class="stat-value" style="color:${unused.length ? 'var(--warn)' : 'var(--ok)'}">${unused.length}</div><div class="stat-label">Unapplied controls</div></div>
      <div class="stat-tile"><div class="stat-value">${(surfaceData.sinks || []).length}</div><div class="stat-label">Dangerous operations</div></div>
    </div>`;

  const mountRows = mounts.map((m) => {
    const kind = guardKindOf(m);
    const owned = routes.filter((r) => r.file && m.mounted && r.file.includes(m.mounted));
    return `
      <div class="surface-mount ${kind}">
        <div class="surface-mount-head">
          <span class="surface-prefix">${escapeHtml(m.prefix)}</span>
          <span class="surface-arrow">→</span>
          <span class="surface-router">${escapeHtml(m.mounted)}</span>
          ${surfaceGuardBadge(kind)}
          <span class="surface-count">${owned.length} route${owned.length === 1 ? '' : 's'}</span>
        </div>
        <div class="surface-guards">${m.middleware.length ? m.middleware.map((g) => `<code>${escapeHtml(g)}</code>`).join(' → ') : '<span class="surface-none">nothing</span>'}</div>
        ${owned.length ? `<div class="surface-routes">${surfaceRouteRowsHtml(owned)}</div>` : ''}
      </div>`;
  }).join('');

  // Routes that belong to no mount. Previously these rendered nowhere at all — routes were
  // only ever emitted nested inside a mount row — so an app with no express.Router() showed
  // "19 Endpoints" in the tiles above and then listed none of them. Grouped by guard kind so
  // the unguarded ones lead, reusing the same .surface-mount colour-coded block as above.
  const unmounted = routes.filter((r) => !ownerOf(r));
  const unmountedGroups = ['none', 'authn', 'authz']
    .map((kind) => ({ kind, list: unmounted.filter((r) => routeKind(r) === kind) }))
    .filter((g) => g.list.length);

  const unmountedHtml = unmounted.length ? `
    <div class="panel">
      <div class="panel-title">Directly registered routes</div>
      <div class="surface-note">Registered straight on the app object rather than through a mounted router, so no mount-level middleware applies — whatever guards these is on the route itself.</div>
      ${unmountedGroups.map((g) => `
        <div class="surface-mount ${g.kind}">
          <div class="surface-mount-head">
            ${surfaceGuardBadge(g.kind)}
            <span class="surface-count">${g.list.length} route${g.list.length === 1 ? '' : 's'}</span>
          </div>
          <div class="surface-routes">${surfaceRouteRowsHtml(g.list)}</div>
        </div>`).join('')}
    </div>` : '';

  const unusedHtml = unused.length ? `
    <div class="panel">
      <div class="panel-title">Security controls that are never applied</div>
      <div class="surface-note">Each of these was written to enforce something and currently enforces nothing.</div>
      ${unused.map((f) => `
        <div class="surface-unused">
          <code>${escapeHtml(f.name)}()</code>
          <span class="surface-loc">${escapeHtml(f.file)}:${f.line}</span>
          <span class="surface-badge warn">0 call sites</span>
        </div>`).join('')}
    </div>` : '';

  el.innerHTML = `
    <div class="surface-target">${escapeHtml(surfaceData.path || '')}${surfaceData.fileCount ? ` · ${surfaceData.fileCount} files` : ''}</div>
    ${stats}
    ${mounts.length ? `
    <div class="panel">
      <div class="panel-title">Mounted routers</div>
      ${mountRows}
    </div>` : ''}
    ${unmountedHtml}
    ${!routes.length ? `
    <div class="panel">
      <div class="panel-title">Mounted routers</div>
      <div class="surface-note">No HTTP routes were detected in this codebase — it may be a library, CLI, or worker rather than a service.</div>
    </div>` : ''}
    ${unusedHtml}
  `;
}

/**
 * Render a dataflow finding as the path the value actually takes, rather than
 * as the single line where it happened to end up.
 *
 * A cross-line finding is the one kind this app produces where the *location* is
 * genuinely not the explanation: "SQL injection at line 20" is unactionable
 * without knowing that line 18 read a query parameter and line 19 concatenated
 * it. The engine already knows both ends (`flow.sourceLine` / `flow.sinkLine`)
 * and every line between them; before this it was all discarded at render time
 * and the user saw one number.
 *
 * Only appears when the finding carries a `flow` — pattern findings that fit on
 * one line have no path to draw, and forcing one would be noise.
 */
function findingFlowHtml(finding) {
  const flow = finding.flow;
  if (!flow || !Array.isArray(flow.lines) || !flow.lines.length) return '';

  const rows = flow.lines.map((l) => {
    const isSource = l.n === flow.sourceLine;
    const isSink = l.n === flow.sinkLine;
    const cls = isSource ? 'flow-line source' : isSink ? 'flow-line sink' : 'flow-line';
    const marker = isSource ? '▸' : isSink ? '▸' : ' ';
    const label = isSource ? '<span class="flow-tag source">user input enters</span>'
      : isSink ? '<span class="flow-tag sink">reaches the sink</span>'
      : '';
    return `<div class="${cls}">`
      + `<span class="flow-marker">${marker}</span>`
      + `<span class="flow-num">${l.n}</span>`
      + `<span class="flow-code">${highlightCode(l.text)}</span>`
      + label
      + '</div>';
  }).join('');

  const span = flow.sinkLine - flow.sourceLine;
  return `
    <div class="fd-section">
      <div class="fd-section-title">Data flow</div>
      <div class="flow-summary">Untrusted input enters at line ${flow.sourceLine} and reaches a dangerous operation ${span} line${span === 1 ? '' : 's'} later, with nothing validating it in between.</div>
      <div class="flow-block">${rows}</div>
    </div>
  `;
}

function highlightCode(code) {
  let out = '';
  let lastIndex = 0;
  HL_TOKEN_RE.lastIndex = 0;
  let m;
  while ((m = HL_TOKEN_RE.exec(code))) {
    if (m.index > lastIndex) out += escapeHtml(code.slice(lastIndex, m.index));
    const [full, comment, string, number, word] = m;
    if (comment) out += `<span class="tok-comment">${escapeHtml(comment)}</span>`;
    else if (string) out += `<span class="tok-string">${escapeHtml(string)}</span>`;
    else if (number) out += `<span class="tok-number">${escapeHtml(number)}</span>`;
    else if (word && HL_KEYWORDS.has(word)) out += `<span class="tok-keyword">${escapeHtml(word)}</span>`;
    else out += escapeHtml(full);
    lastIndex = m.index + full.length;
  }
  if (lastIndex < code.length) out += escapeHtml(code.slice(lastIndex));
  return out;
}

// Launching a run doesn't render a live tool/token stats feed — that UI (Analysis/
// Conclusion per stage) was removed along with the old finding-detail panel. It does,
// however, feed the opt-in console panel (see stageConsoles/consoleToggleButtonHtml above)
// if the user chooses to open it. Results land in Timeline and update both the Findings
// table and, if this finding's detail page is open, its Agent runs section, via
// refreshFindingAfterRun() -> updateFindingListItem(); stages/stageConsoles just track
// enough state to correlate incoming WS messages back to the right run.
function startStage(findingId, agent, context, instruction) {
  const finding = findingCache.get(findingId);
  const runId = uid();

  stages.set(runId, findingId);
  stageConsoles.set(runId, { runId, consoleText: '', consoleOpen: false, consoleEl: null });

  const startedAt = Date.now();
  upsertTimelineEntry({
    kind: agent, runId, findingId, findingTitle: finding ? finding.title : '(finding)', agent,
    status: 'running', instruction, verdict: null, startedAt, finishedAt: null,
  });

  // Optimistically drop a "running" placeholder into the cached finding's run
  // history so the detail page (if open on this finding) shows it starting
  // immediately, rather than staying blank until the run actually finishes.
  if (finding) {
    finding.runs.push({ runId, agent, status: 'running', verdict: null, startedAt, finishedAt: null });
    if (currentView === 'finding-detail' && currentFindingDetailId === findingId) renderFindingDetail(findingId);
  }

  const runMsg = { type: 'run', runId, findingId, agent, context, instruction };
  // Verify always needs live-directory access to confirm a fix landed. 'triage' is included
  // here only as a leftover from when the loop's step arrow could still trigger a live Triage
  // call — it no longer can (see CLAUDE.md), so this branch is effectively unreachable now, but
  // harmless to leave since the server has no triage.md to spawn regardless.
  if (agent === 'verify' || agent === 'triage') {
    const path = findingSourcePath(finding);
    if (path) runMsg.path = path;
  }
  ws.send(JSON.stringify(runMsg));
  return runId;
}

// ---------- websocket message handling ----------

function handleServerMessage(msg) {
  if (msg.type && msg.type.indexOf('app-threat-model') === 0) {
    handleAppThreatModelServerMessage(msg);
    return;
  }
  if (msg.type && msg.type.indexOf('controls-assist') === 0) {
    handleControlsAssistServerMessage(msg);
    return;
  }
  if (msg.type && msg.type.indexOf('scan') === 0) {
    handleScanServerMessage(msg);
    return;
  }

  const findingId = msg.runId ? stages.get(msg.runId) : null;

  if (msg.type === 'error' && !findingId) {
    alert(msg.message);
    return;
  }
  if (!findingId) return;

  if (msg.type === 'started') {
    // startStage()/startRemediatePreview()/startRemediateFix() push their own optimistic
    // "running" placeholder before sending, so this is a no-op duplicate-check for those.
    // startRemediateAll()'s Fix and Verify stages are the exception — they can't get a
    // placeholder at click-time since the chain doesn't yet know whether they'll even run
    // (Remediate proposing nothing usable, or Fix failing to apply, both stop it early) — push
    // one now if it's missing.
    const finding = findingCache.get(findingId);
    if (finding && !finding.runs.some((r) => r.runId === msg.runId)) {
      finding.runs.push({ runId: msg.runId, agent: msg.agent, status: 'running', verdict: null, startedAt: Date.now(), finishedAt: null });
      if (currentView === 'finding-detail' && currentFindingDetailId === findingId) renderFindingDetail(findingId);
    }
    return;
  }
  if (msg.type === 'event') {
    // No live stats UI for per-finding runs (see CLAUDE.md) — the only thing fed here is the
    // opt-in console panel's text buffer, via the same trackConsoleText() scans/whole-app runs use.
    const consoleRun = stageConsoles.get(msg.runId);
    if (consoleRun) trackConsoleText(consoleRun, msg.event);
    return;
  }
  if (msg.type === 'stderr') {
    return; // CLI-internal chatter, not actionable
  }
  if (msg.type === 'error') {
    // A write-flow precheck failure (not a git repo, dirty tree, etc.) never gets a run pushed
    // server-side, so there's nothing for the normal error badge to attach to — surface it
    // directly instead of leaving the user staring at a run that silently vanishes.
    if (precheckRunIds.has(msg.runId)) {
      precheckRunIds.delete(msg.runId);
      alert(msg.message);
    }
    upsertTimelineEntry({ runId: msg.runId, status: 'error', finishedAt: Date.now() });
    refreshFindingAfterRun(findingId);
    return;
  }
  if (msg.type === 'done') {
    upsertTimelineEntry({ runId: msg.runId, status: msg.code === 0 ? 'done' : 'error', verdict: msg.verdict, finishedAt: Date.now() });
    precheckRunIds.delete(msg.runId);
    refreshFindingAfterRun(findingId);
    return;
  }
}

async function refreshFindingAfterRun(findingId) {
  // Re-pull the finding so the Findings table row and (if open) the finding
  // detail page's Agent runs section reflect the just-finished run without
  // a full page reload.
  const res = await fetch(`/api/findings/${findingId}`);
  if (!res.ok) return;
  const finding = await res.json();
  findingCache.set(findingId, finding);
  updateFindingListItem(findingId, {
    status: finding.status,
    runCount: finding.runs.length,
    latestRun: finding.runs.length ? (({ agent, status, verdict }) => ({ agent, status, verdict }))(finding.runs[finding.runs.length - 1]) : null,
    stageRuns: findingStageRuns(finding),
  });
}

// Still used by scan cards (cardEl/status-dot/status-text are their DOM too).
function setStageStatus(stage, status, text) {
  stage.status = status;
  stage.cardEl.classList.remove('status-running', 'status-done', 'status-error');
  stage.cardEl.classList.add('status-' + (status === 'cancelled' ? 'error' : status));
  const dot = stage.cardEl.querySelector('.status-dot');
  dot.classList.remove('running', 'done', 'error', 'cancelled');
  dot.classList.add(status);
  const statusText = stage.cardEl.querySelector('.status-text');
  statusText.classList.remove('running', 'done', 'error', 'cancelled');
  statusText.classList.add(status);
  statusText.textContent = text;
}

// ---------- context menus ----------

// Triage/Remediation/Verify each have their own dedicated control now — the Remediation Loop
// column's step arrow and "run all stages" button (see findingLoopCellHtml()) — so this menu no
// longer lists them; it's just Threat Model (a separate, optional deep-dive that deliberately
// doesn't sit on that path — see CLAUDE.md's Pipeline shape) plus whatever custom agents exist.
const FIX_FLOW_AGENTS = ['triage', 'remediation', 'fix', 'verify'];
// SCA findings additionally lose Threat Model too — none of the four per-finding code-analysis
// agents apply to a dependency version bump (already named in the Package/Fixed-in columns), so
// nothing in FIX_FLOW_AGENTS or Threat Model is offered, leaving only custom agents (if any).
const SCA_EXCLUDED_AGENTS = [...FIX_FLOW_AGENTS, 'threat_model'];

// `finding` is optional — pass it when the caller already has one (a table row's own object, or
// Finding Detail's cached object) so SCA findings can have Threat Model filtered out of the menu
// without an extra fetch. Omit it and the menu falls back to showing every eligible agent.
function openFindingContextMenu(x, y, findingId, finding) {
  contextMenuEl.innerHTML = '';
  const addItem = (label, disabled, onClick) => {
    const btn = document.createElement('button');
    btn.textContent = label;
    btn.disabled = !!disabled;
    btn.addEventListener('click', () => { closeContextMenu(); onClick(); });
    contextMenuEl.appendChild(btn);
  };
  const runAgentItem = (agentName) => {
    addItem(`Run ${agentMeta(agentName).label}…`, false, async () => {
      const f = await ensureFindingCached(findingId);
      if (f) openFreshStageModal(findingId, agentName, buildBaseContext(f));
    });
  };

  // One menu item per agent declared on the Agents screen (agentsList — built-in plus any
  // custom agents; 'scan' is already filtered out server-side), minus the fix-flow agents
  // (always) and Threat Model (SCA findings only). Every path here opens the stage modal rather
  // than running an agent immediately — the AppSec tester reviews context/instructions and
  // explicitly clicks "Start stage" before anything executes, so there's always a deliberate
  // action behind a run, not an implicit auto-fix.
  const isSca = finding && finding.scanType === 'sca';
  const excluded = isSca ? SCA_EXCLUDED_AGENTS : FIX_FLOW_AGENTS;
  const eligibleAgents = agentsList.filter((a) => !excluded.includes(a));

  if (!eligibleAgents.length) {
    addItem(isSca ? 'No agent actions apply — update the package instead' : 'No agents available', true, () => {});
  } else {
    for (const agentName of eligibleAgents) runAgentItem(agentName);
  }

  positionAndShowMenu(x, y);
}

function positionAndShowMenu(x, y) {
  contextMenuEl.hidden = false;
  const rect = contextMenuEl.getBoundingClientRect();
  const left = Math.min(x, window.innerWidth - rect.width - 8);
  const top = Math.min(y, window.innerHeight - rect.height - 8);
  contextMenuEl.style.left = Math.max(8, left) + 'px';
  contextMenuEl.style.top = Math.max(8, top) + 'px';
}

function closeContextMenu() { contextMenuEl.hidden = true; }

document.addEventListener('click', (e) => {
  if (!contextMenuEl.hidden && !contextMenuEl.contains(e.target)) closeContextMenu();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeContextMenu(); closeStageModal(); closeFindingModal();
    if (timelineDrawerOpen) closeTimelineDrawer();
  }
});

// ---------- stage modal (continue / re-run / branch / fresh run w/ instructions) ----------

let stageModalState = null;

// Verify is the one agent whose behavior depends on something not visible in the editable
// context textarea (the cwd it gets spawned with) — this makes that visible so starting a
// Verify run isn't a black box about whether it can actually check live code.
function updateStageModalVerifyHint() {
  const hintEl = document.getElementById('stage-modal-verify-hint');
  if (stageModalAgent.value !== 'verify' || !stageModalState) { hintEl.hidden = true; return; }
  const finding = findingCache.get(stageModalState.findingId);
  const path = findingSourcePath(finding);
  hintEl.hidden = false;
  hintEl.textContent = path
    ? `Will re-check the live code at: ${path}`
    : 'No known source directory for this finding — review will be based on the saved snippet only.';
}
stageModalAgent.addEventListener('change', updateStageModalVerifyHint);

function openFreshStageModal(findingId, agent, context) {
  stageModalState = { findingId };
  stageModalTitle.textContent = `Run ${agentMeta(agent).label} with instructions`;
  stageModalAgent.value = agentsList.includes(agent) ? agent : agentsList[0];
  stageModalContext.value = context;
  stageModalInstruction.value = '';
  stageModalOverlay.hidden = false;
  stageModalInstruction.focus();
  updateStageModalVerifyHint();
}

function closeStageModal() {
  stageModalOverlay.hidden = true;
  stageModalState = null;
}

document.getElementById('stage-modal-cancel').addEventListener('click', closeStageModal);
stageModalOverlay.addEventListener('click', (e) => { if (e.target === stageModalOverlay) closeStageModal(); });

document.getElementById('stage-modal-start').addEventListener('click', () => {
  if (!stageModalState) return;
  const { findingId } = stageModalState;
  startStage(findingId, stageModalAgent.value, stageModalContext.value, stageModalInstruction.value);
  closeStageModal();
});

// ---------- add-finding modal ----------

function updateFindingModalTypeFields() {
  const type = findingModalScanType.value;
  fmFieldsReasoning.hidden = type !== 'reasoning';
  fmFieldsSca.hidden = type !== 'sca';
}

function openFindingModal() {
  findingModalTitle.value = '';
  findingModalScanType.value = 'reasoning';
  findingModalSeverity.value = 'medium';
  findingModalRule.value = '';
  findingModalFile.value = '';
  findingModalCode.value = '';
  findingModalPackage.value = '';
  findingModalPackageVersion.value = '';
  findingModalFixedVersion.value = '';
  findingModalEndpoint.value = '';
  findingModalMethod.value = '';
  findingModalDescription.value = '';
  updateFindingModalTypeFields();
  findingModalOverlay.hidden = false;
  findingModalTitle.focus();
}
function closeFindingModal() { findingModalOverlay.hidden = true; }

findingsScanFilterBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  findingsScanFilterMenuEl.hidden = !findingsScanFilterMenuEl.hidden;
});
document.addEventListener('click', (e) => {
  if (!findingsScanFilterMenuEl.hidden && !e.target.closest('.scan-filter-dropdown')) {
    findingsScanFilterMenuEl.hidden = true;
  }
});

addFindingBtn.addEventListener('click', openFindingModal);
document.getElementById('finding-modal-cancel').addEventListener('click', closeFindingModal);
findingModalOverlay.addEventListener('click', (e) => { if (e.target === findingModalOverlay) closeFindingModal(); });
findingModalScanType.addEventListener('change', updateFindingModalTypeFields);

document.getElementById('finding-modal-save').addEventListener('click', async () => {
  const title = findingModalTitle.value.trim();
  const description = findingModalDescription.value.trim();
  if (!title || !description) {
    alert('Title and description are required.');
    return;
  }
  const res = await fetch('/api/findings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      title,
      scanType: findingModalScanType.value,
      severity: findingModalSeverity.value,
      rule: findingModalRule.value.trim() || null,
      file: findingModalFile.value.trim() || null,
      code: findingModalCode.value.trim() || null,
      packageName: findingModalPackage.value.trim() || null,
      packageVersion: findingModalPackageVersion.value.trim() || null,
      fixedVersion: findingModalFixedVersion.value.trim() || null,
      endpoint: findingModalEndpoint.value.trim() || null,
      method: findingModalMethod.value.trim() || null,
      description,
    }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    alert(body.error || 'Failed to create finding.');
    return;
  }
  const finding = await res.json();
  findingCache.set(finding.id, finding);
  closeFindingModal();
  await loadFindings();
  await openFindingDetail(finding.id);
});

// ---------- csv export ----------

exportCsvBtn.addEventListener('click', () => {
  window.open('/api/findings/export.csv', '_blank');
});

// ---------- settings / theme ----------

const THEME_KEY = 'appsecops-theme';
const navThemeBtn = document.getElementById('nav-theme-btn');
const navThemeLabel = document.getElementById('nav-theme-label');

function applyTheme(theme) {
  if (theme === 'light') document.documentElement.dataset.theme = 'light';
  else delete document.documentElement.dataset.theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
  renderThemeToggle();
}

function renderThemeToggle() {
  const current = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
  navThemeLabel.textContent = current === 'light' ? 'Light theme' : 'Dark theme';
  navThemeBtn.title = current === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
  navThemeBtn.setAttribute('aria-checked', current === 'dark' ? 'true' : 'false');
}

navThemeBtn.addEventListener('click', () => {
  const current = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
  applyTheme(current === 'light' ? 'dark' : 'light');
});
renderThemeToggle();

function renderSettings() {
  renderThemeToggle();
  const env = document.getElementById('settings-env');
  env.innerHTML = `
    <div class="hint">Findings and scans are stored in-memory on the server and reset whenever it restarts — there's no database yet.</div>
    <div class="hint">Scans run <code>claude</code> against whatever directory path you give them, using this machine's own filesystem permissions — this app does not sandbox or restrict which directories can be scanned. Only point it at directories you trust reading.</div>
    <div class="hint">${agentsList.length} per-finding agent${agentsList.length === 1 ? '' : 's'} available (${knownAgentsAvailableCount()}/${KNOWN_AGENTS.length} core) · ${escapeHtml(String(scansList.length))} scan${scansList.length === 1 ? '' : 's'} run this session.</div>
  `;
}

async function clearSession() {
  if (!confirm('Clear this session? This permanently deletes every finding, scan, app-level threat model, and control assessment on the server. This cannot be undone.')) return;
  const res = await fetch('/api/session/clear', { method: 'POST' });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    alert(body.error || 'Failed to clear session.');
    return;
  }
  // Reset every client-side cache/list to match the now-empty server, and tear down any
  // still-ticking elapsed timers so they don't keep firing against removed DOM/records.
  findings = [];
  findingCache.clear();
  scansList = [];
  appThreatModelsList = [];
  controlAssessmentsList = [];
  timelineEntries = [];
  timelineLoaded = false;
  scanDetailCache.clear();
  for (const run of scanRuns.values()) stopScanElapsedTimer(run);
  scanRuns.clear();
  for (const run of appThreatModelRuns.values()) stopAppThreatModelElapsedTimer(run);
  appThreatModelRuns.clear();
  for (const run of controlAssistRuns.values()) stopControlsAssistElapsedTimer(run);
  controlAssistRuns.clear();
  scanLiveContainer.innerHTML = '';
  expandedAtmRunId = null;
  expandedCaRunId = null;
  timelineUnseenDone = 0;
  renderNavStatus();
  if (currentView === 'dashboard') renderDashboard();
  if (currentView === 'findings') renderFindingsView();
  if (timelineDrawerOpen) renderTimeline();
  if (currentView === 'threatmodel') renderThreatModelView();
  if (currentView === 'controls-assist') renderControlsAssistView();
}

document.getElementById('clear-session-btn').addEventListener('click', clearSession);

// ---------- init ----------

async function init() {
  await loadAgents();
  await loadFindings();
  await loadScans();
  await loadAppThreatModels();
  await loadControlAssessments();
  await loadTimeline();
  showView('dashboard');
  connect();
}
init();
