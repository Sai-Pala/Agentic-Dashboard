/**
 * Hybrid Scan: three engines over one directory, merged into findings.
 *
 * The deterministic half runs FIRST, not alongside the reasoning half — it costs seconds and
 * nothing, and both reasoning passes take its output as their input. Running them concurrently
 * makes the expensive engine re-read the whole tree knowing nothing about what the free one
 * just found: a union, not a hybrid. SCA shares no data with either and runs throughout.
 */

const path = require('path');

const { loadSastEngine } = require('./sast-engine');
const { severityRank } = require('./taxonomy');
const { parseFileLine, isDuplicateOfReasoning, dedupeAdjacentSameRule } = require('./merge');
const { runDeterministicPatternScan } = require('./engines/deterministic');
const { runDeterministicScaScan } = require('./engines/sca');
const { runLLMReasoningScan } = require('./engines/reasoning');
const {
  findings,
  toListItem,
  findingFromSastEngine,
  findingFromDepVuln,
  findingFromLLMScan,
} = require('../store/findings');

async function runHybridReasoningScan(scan, targetPath, diffFiles, { children, send, finish, fail }) {
  let engine;
  try {
    engine = await loadSastEngine();
  } catch (err) {
    fail(`Failed to load scan engine: ${err.message}`);
    return;
  }

  // SCA is the fastest of the three by far, so it signals its own completion the moment it
  // resolves rather than waiting for the others.
  const scaPromise = runDeterministicScaScan(engine, scan, targetPath, { send }).then((result) => {
    if (scan.status !== 'cancelled') {
      send({ type: 'scan-progress', runId: scan.runId, scanId: scan.id, engine: 'sca', done: 1, total: 1 });
    }
    return result;
  });

  const detResult = await runDeterministicPatternScan(engine, scan, targetPath, diffFiles, { send });

  if (scan.status === 'cancelled') return;

  // The only description of the application's shape the app has, and posture information no
  // findings list conveys. Surfaced by the Attack Surface page.
  if (detResult.surface) scan.surface = detResult.surface;

  // Runs before adjudication so the reasoning pass reviews N distinct issues rather than N
  // restatements of one — both cheaper and more accurate.
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

  // Drop a reasoning finding landing within a couple of lines of a deterministic one in the
  // same file. Findings with no resolvable line always survive — there is nothing to compare.
  const detLocations = collapsedDet
    .map((f) => ({ file: f.file ? path.relative(targetPath, f.file).split(path.sep).join('/') : null, line: f.line }))
    .filter((l) => l.file);
  const isDuplicateOfDeterministic = (rf) => {
    const loc = parseFileLine(rf.file);
    if (!loc.file || loc.line == null) return false;
    return detLocations.some((d) => d.file === loc.file && d.line != null && Math.abs(d.line - loc.line) <= 2);
  };

  // Sorted most-severe-first so that when two calls disagree on severity for one issue, the
  // surviving copy is the more severe reading rather than whichever finished first.
  const keptLlm = [];
  for (const rf of [...llmResult.findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))) {
    const title = String(rf.title || '').trim();
    const description = String(rf.description || '').trim();
    if (!title || !description) continue; // skip malformed entries rather than fail the scan
    if (isDuplicateOfDeterministic(rf)) continue;
    if (isDuplicateOfReasoning(rf, keptLlm)) continue;
    keptLlm.push(rf);
    const finding = findingFromLLMScan(rf, scan);
    findings.set(finding.id, finding);
    scan.findingIds.push(finding.id);
    created.push(toListItem(finding));
  }

  // SCA findings are package/version-keyed, so nothing above can match them: all survive.
  for (const v of scaResult.findings) {
    const finding = findingFromDepVuln(v, scan);
    findings.set(finding.id, finding);
    scan.findingIds.push(finding.id);
    created.push(toListItem(finding));
  }

  scan.reasoningCostUsd = llmResult.costUsd || 0;
  finish(created);
}

module.exports = { runHybridReasoningScan };
