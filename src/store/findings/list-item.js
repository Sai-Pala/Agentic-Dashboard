/**
 * The light wire shape of a finding, as every list view receives it.
 */

const { latestRunByAgent } = require('./status');

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
    flow: finding.flow || null,
    // What the app did to this finding after the engine emitted it — severity rewritten, closed
    // as a false positive, siblings collapsed into it. Null when nothing happened, which is the
    // common case, so the wire shape stays light.
    disposition: finding.disposition || null,
  };
}

module.exports = { toListItem };
