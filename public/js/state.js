/**
 * The app's shared mutable state
 * ==============================
 *
 * One plain object rather than module-level `let`s, because ES modules forbid assigning to an
 * imported binding — `state.findings = [...]` works from any module, `findings = [...]` cannot.
 * Deliberately dumb: no reactivity, no subscriptions. Views re-render because a caller says so.
 */

export const state = {
  ws: null,

  agentsList: [],

  // Findings: list-item shape from GET /api/findings.
  findings: [],
  findingsTypeFilter: 'all',   // 'all' | 'reasoning' | 'sca'
  findingsScanFilter: 'all',   // 'all' or a scan id
  findingsSort: { key: 'severity', dir: 'asc' },
  currentFindingDetailId: null,
  currentView: 'dashboard',

  // Timeline: flattened run history, newest first.
  timelineEntries: [],
  timelineLoaded: false,
  timelineFilter: 'all',
  timelineUnseenDone: 0,       // completions since the drawer was last opened
  timelineDrawerOpen: false,

  // Scans: list-item shape from GET /api/scans.
  scansList: [],
  scansLoaded: false,
  scanScope: 'full',
  // Off means reasoning calls get no --max-budget-usd at all. On is the safe default.
  scanBudgetEnabled: true,

  surfaceScanId: null,
  surfaceData: null,

  stageModalState: null,

  // Caches and per-run tracking objects shared across module boundaries.
  findingCache: new Map(),     // findingId -> full record from GET /api/findings/:id
  scanDetailCache: new Map(),  // scanId -> full scan detail (with findings)
  stages: new Map(),           // runId -> findingId, to correlate incoming WS messages
  stageConsoles: new Map(),    // runId -> console tracking object for a per-finding run
  scanRuns: new Map(),         // runId -> live scan card tracking object
  // runIds whose flow has a server-side precheck (path validation, git-clean tree) that can
  // fail before any run record exists server-side, so there is no run to hang an error badge on.
  precheckRunIds: new Set(),
};
