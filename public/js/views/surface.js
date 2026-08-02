/**
 * Attack Surface
 * ==============
 *
 * A posture view, not a findings view: what a scanned codebase exposes and what guards it.
 * Reports no vulnerabilities and makes no LLM call — it renders the manifest every scan
 * already builds (GET /api/scans/:id/surface). Scoped to one completed scan at a time.
 */

import { state } from '../state.js';
import { getScanSurface } from '../api.js';
import { escapeHtml } from '../lib/html.js';
import { scanFilterLabel } from '../lib/format.js';
import { loadScans } from './scans/index.js';
import { guardKindOf, surfaceGuardBadge } from './surface-guards.js';

export function openSurfaceView() {
  renderSurfaceScanPicker();
  if (!state.scansList.length) { loadScans().then(renderSurfaceScanPicker); }
  const done = state.scansList.filter((s) => s.status === 'done');
  if (!state.surfaceScanId && done.length) state.surfaceScanId = done[0].id;
  if (state.surfaceScanId) loadSurface(state.surfaceScanId);
  else renderSurfaceView();
}

export async function loadSurface(scanId) {
  const el = document.getElementById('surface-content');
  if (el) el.innerHTML = '<div class="placeholder-panel">Loading the map…</div>';
  try {
    const res = await getScanSurface(scanId);
    state.surfaceData = res.ok ? res.surface : { unavailable: res.error };
  } catch (err) {
    state.surfaceData = { unavailable: err.message };
  }
  renderSurfaceView();
  renderSurfaceScanPicker();
}

export function renderSurfaceScanPicker() {
  const btn = document.getElementById('surface-scan-btn');
  const menu = document.getElementById('surface-scan-menu');
  if (!btn || !menu) return;
  const done = state.scansList.filter((s) => s.status === 'done');
  const current = done.find((s) => s.id === state.surfaceScanId);
  btn.textContent = current ? scanFilterLabel(current) : (done.length ? 'Select a scan' : 'No completed scans');
  btn.disabled = !done.length;
  menu.innerHTML = done.map((s) =>
    `<button type="button" class="scan-filter-item${s.id === state.surfaceScanId ? ' active' : ''}" data-scan-id="${s.id}">${escapeHtml(scanFilterLabel(s))}</button>`
  ).join('') || '<div class="scan-filter-empty">Run a scan first.</div>';
  menu.querySelectorAll('[data-scan-id]').forEach((b) => {
    b.onclick = () => { state.surfaceScanId = b.dataset.scanId; menu.hidden = true; loadSurface(state.surfaceScanId); };
  });
  btn.onclick = (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; };
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

export function renderSurfaceView() {
  const el = document.getElementById('surface-content');
  if (!el) return;

  const surfaceData = state.surfaceData;
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

  // Which mount owns a route — a display heuristic (router filename appearing in the route's
  // own path), not the engine's own resolution.
  const ownerOf = (r) => mounts.find((m) => r.file && m.mounted && r.file.includes(m.mounted)) || null;
  // A route's effective chain is its mount's middleware plus its own.
  const routeKind = (r) => {
    const owner = ownerOf(r);
    return guardKindOf({ middleware: [...((owner && owner.middleware) || []), ...(r.middleware || [])] });
  };

  // These tiles count ROUTES, not mounts. Counting mounts made an app that registers routes
  // directly on `app` — no express.Router() anywhere — report "0 with no guard" in the safe
  // green while every one of its endpoints was unguarded.
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

  // Routes belonging to no mount get their own panel, grouped by guard kind so the unguarded
  // ones lead — otherwise they would be counted in the tiles and listed nowhere.
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
