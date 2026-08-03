/**
 * Cross-screen notifications.
 *
 * A shared component often needs a screen to react — a finished run should refresh the findings
 * list, append to the timeline, and re-render the detail pane if it happens to be open. Wiring
 * that with imports points `components/` at `views/`, which is backwards: a component is meant to
 * be usable by any screen, and importing one makes it usable by exactly that screen.
 *
 * So components announce what happened and do not know who listens; screens subscribe in their
 * own `wire*()` function. Dependencies point one way — `views/` -> `components/` -> `events.js` —
 * and this module imports nothing at all, which is what keeps the client out of one big
 * mutually-dependent cluster. test/module-graph ratchets that cluster size — an import added
 * here would show up there as a regression.
 *
 * Subscribe during wiring, before any data loads. main.js already orders it that way.
 */

/** event name -> handlers, in registration order. */
const handlers = new Map();

export function on(event, handler) {
  const list = handlers.get(event) || [];
  list.push(handler);
  handlers.set(event, list);
}

/**
 * Fire and forget. A throwing handler must not stop the others: these are UI refreshes, and one
 * screen failing to redraw should not silently cancel the rest.
 */
export function emit(event, ...args) {
  for (const handler of handlers.get(event) || []) {
    try {
      handler(...args);
    } catch (err) {
      console.error(`events: handler for "${event}" threw`, err);
    }
  }
}

/** Sequential and awaited, for the cases where the caller depends on the refresh completing. */
export async function emitAsync(event, ...args) {
  for (const handler of handlers.get(event) || []) {
    try {
      await handler(...args);
    } catch (err) {
      console.error(`events: async handler for "${event}" threw`, err);
    }
  }
}

/**
 * The full set, named in one place so a typo is a visible diff rather than a listener that
 * silently never fires.
 */
export const EVENTS = {
  /** Reload the findings list from the server. Awaited. */
  FINDINGS_RELOAD: 'findings:reload',
  /** (findingId, patch) — patch one row in place, no refetch. */
  FINDING_UPDATED: 'finding:updated',
  /** (findingId) — navigate to the detail view. Awaited. */
  DETAIL_OPEN: 'finding-detail:open',
  /** (findingId) — re-render detail if it is showing that finding; the view decides. */
  DETAIL_REFRESH: 'finding-detail:refresh',
  /** (entry) — insert or update a timeline row. */
  TIMELINE_UPSERT: 'timeline:upsert',
  /** (scanId) — show the findings list scoped to one scan. */
  FINDINGS_FILTER_BY_SCAN: 'findings:filter-by-scan',

  // --- socket ---
  // ws.js owns the connection, not the reactions to it. Without these it had to import the
  // scans view and the runs component in order to dispatch, while both imported it back to
  // send — the same loop as the router's.
  /** (msg) — a `scan-*` frame. */
  WS_SCAN_MESSAGE: 'ws:scan-message',
  /** (msg) — any other frame: run lifecycle, errors. */
  WS_RUN_MESSAGE: 'ws:run-message',
  /** (connected: boolean) — socket opened or closed. */
  WS_STATUS: 'ws:status',
};
