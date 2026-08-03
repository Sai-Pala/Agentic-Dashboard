/**
 * The findings CSV export: every finding plus its latest verdict fields, one row each.
 */

const { findings } = require('./state');
const { scans } = require('../scans');

const COLUMNS = [
  'id', 'title', 'scan_type', 'status', 'severity', 'rule', 'file',
  'package_name', 'package_version', 'fixed_version', 'endpoint', 'method',
  'verdict', 'severity_confirmed', 'confidence', 'priority',
  'owasp', 'cwe', 'nist_800_53',
  'root_cause', 'fix_guidance', 'effort',
  'run_count', 'latest_agent', 'source_scan_path', 'created_at',
];

function csvEscape(value) {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function buildFindingsCsv() {
  const rows = [COLUMNS.join(',')];
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
  return rows.join('\r\n');
}

module.exports = { csvEscape, buildFindingsCsv };
