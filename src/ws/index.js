/**
 * WebSocket setup: origin check, per-connection child-process tracking, message dispatch, and
 * the cancel/close cleanup that keeps run bookkeeping honest.
 */

const { WebSocketServer } = require('ws');

const { PORT } = require('../config');
const { isAllowedWsOrigin } = require('./origin');
const { runIndex } = require('../store/findings');
const { scanRunIndex } = require('../store/scans');
const { handleScanMessage } = require('./scan');
const { handleRunMessage } = require('./run');
const {
  handleRemediatePreviewMessage,
  handleRemediateFixMessage,
  handleRemediateAllMessage,
} = require('./fix');

function handleCancel(msg, { children }) {
  const runId = String(msg.runId || '');
  const child = children.get(runId);
  const indexed = runIndex.get(runId);
  if (indexed && indexed.run.status === 'running') {
    indexed.run.status = 'cancelled';
    indexed.run.finishedAt = Date.now();
  }
  const scanIndexed = scanRunIndex.get(runId);
  if (scanIndexed && scanIndexed.status === 'running') {
    scanIndexed.status = 'cancelled';
    scanIndexed.finishedAt = Date.now();
  }
  // A cancelled scan returns before ever reaching finish()/fail(), the two places that normally
  // clear this entry, so cancel is the only signal it will ever get.
  if (scanIndexed) scanRunIndex.delete(runId);
  // A scan's reasoning calls are registered under synthetic `${runId}::modN` keys, never the
  // scan's own runId, so the lookup above finds none of them.
  if (scanIndexed && Array.isArray(scanIndexed.moduleRunIds)) {
    for (const modRunId of scanIndexed.moduleRunIds) {
      const modChild = children.get(modRunId);
      if (modChild) modChild.kill();
    }
  }
  if (child) child.kill();
}

function handleClose({ children }) {
  // Mark every still-running scan cancelled directly rather than per-child: a scan's children
  // are keyed by synthetic module ids, so the runId-keyed lookups below miss them. (They are
  // still killed unconditionally by the loop after this one.)
  for (const [runId, scanIndexed] of scanRunIndex.entries()) {
    if (scanIndexed.status === 'running') {
      scanIndexed.status = 'cancelled';
      scanIndexed.finishedAt = Date.now();
    }
    scanRunIndex.delete(runId);
  }
  for (const [runId, child] of children.entries()) {
    const indexed = runIndex.get(runId);
    if (indexed && indexed.run.status === 'running') {
      indexed.run.status = 'cancelled';
      indexed.run.finishedAt = Date.now();
    }
    child.kill();
  }
  children.clear();
}

function attachWebSocketServer(server) {
  const wss = new WebSocketServer({
    server,
    verifyClient: ({ origin, req }) => {
      if (isAllowedWsOrigin(origin, PORT)) return true;
      console.warn(`Rejected WebSocket connection from disallowed origin: ${origin} (${req.socket.remoteAddress})`);
      return false;
    },
  });

  wss.on('connection', (ws) => {
    const children = new Map(); // runId -> ChildProcess, per connection

    const send = (payload) => {
      if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(payload));
    };
    const ctx = { children, send };

    ws.on('message', (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch (err) {
        send({ type: 'error', message: 'Malformed message.' });
        return;
      }

      switch (msg.type) {
        case 'cancel': return handleCancel(msg, ctx);
        case 'scan': return handleScanMessage(msg, ctx);
        case 'remediate_preview': return handleRemediatePreviewMessage(msg, ctx);
        case 'remediate_fix': return handleRemediateFixMessage(msg, ctx);
        case 'remediate_all': return handleRemediateAllMessage(msg, ctx);
        case 'run': return handleRunMessage(msg, ctx);
        default: return undefined; // unknown types are ignored, never fatal
      }
    });

    ws.on('close', () => handleClose(ctx));
  });

  return wss;
}

module.exports = { attachWebSocketServer };
