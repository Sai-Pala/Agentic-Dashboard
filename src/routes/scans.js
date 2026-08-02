/**
 * /api/scans — the scan list, one scan with its findings, its attack-surface manifest, delete.
 */

const express = require('express');

const { scans, toScanListItem } = require('../store/scans');
const { findings, toListItem } = require('../store/findings');

const router = express.Router();

router.get('/api/scans', (req, res) => {
  const list = [...scans.values()].sort((a, b) => b.startedAt - a.startedAt).map(toScanListItem);
  res.json(list);
});

router.get('/api/scans/:id', (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json({
    ...toScanListItem(scan),
    findings: scan.findingIds.map((id) => findings.get(id)).filter(Boolean).map(toListItem),
  });
});

/**
 * The structural map a scan produced. Its own endpoint rather than a field on the scan: the
 * manifest for a large repo dwarfs the scan summary, and the scan list is fetched on nearly
 * every view. Only the Attack Surface page pays for it.
 */
router.get('/api/scans/:id/surface', (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  if (!scan.surface) {
    res.status(404).json({ error: 'This scan has no attack-surface map. Only scans run after the feature was added carry one.' });
    return;
  }
  res.json({ scanId: scan.id, path: scan.path, app: scan.app, startedAt: scan.startedAt, ...scan.surface });
});

router.delete('/api/scans/:id', (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  // A plain REST route cannot reach the per-connection `children` map to kill child processes.
  if (scan.status === 'running') {
    res.status(409).json({ error: 'Cancel the scan before deleting it.' });
    return;
  }
  scans.delete(req.params.id);
  res.json({ ok: true });
});

module.exports = router;
