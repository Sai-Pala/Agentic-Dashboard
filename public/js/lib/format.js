/**
 * Pure formatting helpers
 *
 * Value-in, string-out. No DOM, no app state, no imports — deliberately, so this module stays
 * importable from Node and unit-testable directly. Anything that touches the document belongs
 * in lib/html.js.
 */

export function uid() {
  return (crypto.randomUUID ? crypto.randomUUID() : 'id-' + Math.random().toString(36).slice(2) + Date.now());
}

export function truncate(str, n) {
  str = String(str);
  return str.length > n ? str.slice(0, n) + '…' : str;
}

export function formatRelativeTime(ts) {
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

export function dateGroupLabel(ts) {
  const d = new Date(ts);
  const now = new Date();
  const isSameDay = (a, b) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (isSameDay(d, now)) return 'Today';
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (isSameDay(d, yesterday)) return 'Yesterday';
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function formatElapsed(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
}

export function formatTokenCount(n) {
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
  return String(n);
}

export function statusLabel(status) {
  return { new: 'Not started', in_review: 'In review', remediation_ready: 'Remediation ready', remediation_generated: 'Remediation generated', verified_fixed: 'Verified fixed', closed: 'Closed' }[status] || status;
}

export function severityLabel(sev) { return sev.charAt(0).toUpperCase() + sev.slice(1); }

// Verdict fields are raw snake_case JSON keys (root_cause, nist_800_53, ...) — title-case them
// for display so the row label reads like the fd-meta-grid labels above it, not raw JSON.
export function verdictFieldLabel(key) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

// A scan record as one line of prose, used by every place that offers scans as a choice
// (Agent Triage's per-scan filter, the Attack Surface picker).
export function scanFilterLabel(s) {
  const kind = s.scanType === 'sca' ? 'SCA scan' : 'Hybrid scan';
  return `${kind} on ${s.path} started ${formatRelativeTime(s.startedAt)}`;
}
