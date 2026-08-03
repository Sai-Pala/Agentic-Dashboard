/**
 * POST /api/session/clear — wipe every in-memory store back to empty. No reseed.
 */

const express = require('express');

const { findings, runIndex } = require('../store/findings');
const { scans, scanRunIndex } = require('../store/scans');

const router = express.Router();

// Refuses while anything is running: the per-connection `children` map lives inside the
// WebSocket connection scope and is not reachable from a REST route, so a still-running child
// could not be killed here even if we wanted to.
router.post('/api/session/clear', (req, res) => {
  const anyRunning = [...findings.values()].some((f) => f.runs.some((r) => r.status === 'running'))
    || [...scans.values()].some((s) => s.status === 'running');
  if (anyRunning) {
    res.status(409).json({ error: 'Cancel or wait for running scans/agent runs to finish before clearing the session.' });
    return;
  }
  findings.clear();
  runIndex.clear();
  scans.clear();
  scanRunIndex.clear();
  res.json({ ok: true });
});

module.exports = router;
