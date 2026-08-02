/**
 * The `scan` WebSocket message: validate the target, create the scan record, and hand off to
 * the hybrid scanner with finish/fail callbacks that own the record's terminal state.
 */

const fs = require('fs');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const { RUN_ID_RE, BRANCH_NAME_RE, SCAN_TYPES, SCAN_SCOPES } = require('../config');
const { scans, scanRunIndex } = require('../store/scans');
const { runHybridReasoningScan } = require('../services/scanner');

function handleScanMessage(msg, { children, send, ownScanRunIds }) {
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
  // Read as `!== false` so an older client that never sends the field still gets the safe default.
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
  // Claim it for this connection: closing a socket must not cancel another tab's scan.
  if (ownScanRunIds) ownScanRunIds.add(runId);

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

  // The pipeline is async, so an unhandled rejection here would take the whole process down
  // (Node exits on unhandled rejections) and strand the scan at status 'running' forever —
  // which also makes POST /api/session/clear 409 permanently. Route it to the same failure
  // sink the engines already use, so the client gets a scan-error instead of silence.
  // Invoked inside .then() rather than passed to Promise.resolve(): a synchronous throw would
  // otherwise happen before the promise wraps it and escape the catch entirely.
  Promise.resolve()
    .then(() => runHybridReasoningScan(scan, targetPath, diffFiles, { children, send, finish, fail }))
    .catch((err) => fail(err && err.message ? err.message : String(err)));
}

module.exports = { handleScanMessage };
