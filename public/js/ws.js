/**
 * WebSocket connection and message dispatch
 * =========================================
 *
 * One socket for every kind of run. Scan messages carry their own `scan-*` type names so they
 * never collide with the generic per-finding run lifecycle; dispatch splits on that prefix and
 * hands each half to the view that owns it.
 */

import { state } from './state.js';
import { renderNavStatus } from './nav.js';
import { emit, EVENTS } from './events.js';

export function send(msg) {
  state.ws.send(JSON.stringify(msg));
}

function setStatus(connected) {
  const el = document.getElementById('status');
  el.textContent = connected ? 'connected' : 'disconnected';
  el.className = connected ? 'connected' : 'disconnected';
}

/**
 * The `scan-*` reply family is routed separately on purpose: the server gives scans their own
 * message types so the generic runId-keyed handlers cannot collide with them.
 */
function handleServerMessage(msg) {
  if (msg.type && msg.type.indexOf('scan') === 0) {
    emit(EVENTS.WS_SCAN_MESSAGE, msg);
    return;
  }
  emit(EVENTS.WS_RUN_MESSAGE, msg);
}

export function connect() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  state.ws = new WebSocket(`${proto}//${location.host}`);

  state.ws.addEventListener('open', () => {
    setStatus(true); renderNavStatus();
    emit(EVENTS.WS_STATUS, true);
  });
  state.ws.addEventListener('close', () => {
    setStatus(false); renderNavStatus();
    emit(EVENTS.WS_STATUS, false);
    setTimeout(connect, 2000);
  });
  state.ws.addEventListener('error', () => state.ws.close());
  state.ws.addEventListener('message', (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    handleServerMessage(msg);
  });
}
