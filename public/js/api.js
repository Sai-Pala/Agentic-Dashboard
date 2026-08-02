/**
 * Every REST call the client makes
 * ================================
 *
 * One function per endpoint. Callers get parsed data (or a small {ok, ...} envelope where the
 * failure body matters); no module outside this file calls fetch().
 */

export function getAgents() {
  return fetch('/api/agents').then((r) => r.json());
}

export function getFindings() {
  return fetch('/api/findings').then((r) => r.json());
}

/** Full finding record, or null if it no longer exists. */
export async function getFinding(id) {
  const res = await fetch(`/api/findings/${id}`);
  if (!res.ok) return null;
  return res.json();
}

export async function postFinding(body) {
  const res = await fetch('/api/findings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    return { ok: false, error: err.error || 'Failed to create finding.' };
  }
  return { ok: true, finding: await res.json() };
}

export function getTimeline() {
  return fetch('/api/timeline').then((r) => r.json());
}

export function getScans() {
  return fetch('/api/scans').then((r) => r.json());
}

export function getScan(id) {
  return fetch(`/api/scans/${id}`).then((r) => r.json());
}

export async function deleteScan(id) {
  try { await fetch(`/api/scans/${id}`, { method: 'DELETE' }); } catch (e) {}
}

/** The persisted attack-surface manifest. A scan older than the feature carries none. */
export async function getScanSurface(id) {
  const res = await fetch(`/api/scans/${id}/surface`);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    return { ok: false, error: body.error || 'No attack-surface map for this scan.' };
  }
  return { ok: true, surface: await res.json() };
}

export async function postSessionClear() {
  const res = await fetch('/api/session/clear', { method: 'POST' });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    return { ok: false, error: body.error || 'Failed to clear session.' };
  }
  return { ok: true };
}

export const FINDINGS_CSV_URL = '/api/findings/export.csv';
