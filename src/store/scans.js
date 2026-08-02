/**
 * The in-memory scans store and its list mapper. A scan is one whole-directory invocation; it
 * does not chain like a finding's runs do, it just remembers the findings it produced.
 * Session-lifetime only — lost on restart.
 */

const scans = new Map();        // id -> scan record
const scanRunIndex = new Map(); // runId -> scan record, for O(1) lookup on done/error/cancel

/**
 * The authoritative wire shape of a scan. Two in-memory fields are deliberately absent:
 * `moduleRunIds` (cancel bookkeeping) and `surface` (large; served by its own endpoint, since
 * the scan list is fetched on nearly every view).
 */
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
    budgetEnabled: scan.budgetEnabled !== false,
    reasoningCostUsd: scan.reasoningCostUsd,
    // Which pattern agents this target warranted. Persisted rather than only relayed live:
    // "which agents were judged inapplicable" is part of what a scan covered, and a card
    // rebuilt after a reload should not silently imply the engine ran whole.
    agentsRun: scan.agentsRun,
    agentsSkipped: scan.agentsSkipped || [],
  };
}

module.exports = { scans, scanRunIndex, toScanListItem };
