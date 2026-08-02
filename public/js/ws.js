/**
 * WebSocket connection and message dispatch
 * =========================================
 *
 * One socket for every kind of run. Scan messages carry their own `scan-*` type names so they
 * never collide with the generic per-finding run lifecycle; dispatch splits on that prefix and
 * hands each half to the view that owns it.
 */

import { state } from './state.js';
import { renderNavStatus } from './router.js';
import { renderDashboard } from './views/dashboard.js';
import { handleScanServerMessage } from './views/scans/index.js';
import { handleFindingRunMessage } from './components/runs.js';

export function send(msg) {
  state.ws.send(JSON.stringify(msg));
}

function setStatus(connected) {
  const el = document.getElementById('status');
  el.textContent = connected ? 'connected' : 'disconnected';
  el.className = connected ? 'connected' : 'disconnected';
}

function handleServerMessage(msg) {
  if (msg.type && msg.type.indexOf('scan') === 0) {
    handleScanServerMessage(msg);
    return;
  }
  handleFindingRunMessage(msg);
}

export function connect() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  state.ws = new WebSocket(`${proto}//${location.host}`);

  state.ws.addEventListener('open', () => {
    setStatus(true); renderNavStatus();
    if (state.currentView === 'dashboard') renderDashboard();
  });
  state.ws.addEventListener('close', () => {
    setStatus(false); renderNavStatus();
    if (state.currentView === 'dashboard') renderDashboard();
    setTimeout(connect, 2000);
  });
  state.ws.addEventListener('error', () => state.ws.close());
  state.ws.addEventListener('message', (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    handleServerMessage(msg);
  });
}
