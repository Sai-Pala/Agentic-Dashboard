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
    // Deliberately does not name a cause. A missing map means the scan predates the feature OR
    // enumeration failed during the run, and this route cannot tell which — the previous wording
    // asserted the first, so an engine failure was reported to the user as an age problem.
    res.status(404).json({ error: 'No attack-surface map was stored for this scan. It either ran before this feature existed, or enumeration did not complete.' });
    return;
  }
  res.json({
    scanId: scan.id, path: scan.path, app: scan.app, startedAt: scan.startedAt,
    ...scan.surface,
    // What the scan looked at and what it dropped. Separate from the surface manifest: one
    // describes the application, the other describes the scan of it.
    coverage: scan.coverage || null,
    reviewCoverage: scan.reviewCoverage || null,
    // DORMANT BLOCK — everything from here to `suppression` is written only by the parked
    // engines/deterministic.js, so on every scan the app produces today `run` is null and the
    // rest are empty. The Insights screen drops each section when its data is absent, so this
    // degrades to a shorter page rather than to a page of zeroes. Served regardless, because
    // scans recorded before the Opengrep swap still carry it.
    agents: {
      run: scan.agentsRun ?? null,
      skipped: scan.agentsSkipped || [],
      failed: scan.agentsFailed || [],
      // Every agent the engine has, with what happened to it — including the ones gated out.
      roster: scan.agentRoster || [],
    },
    // The facts the engine's gating decisions were made on. Published beside the roster because
    // `shouldRun()` returns a bare boolean: this is the evidence, not the stated reason.
    recon: scan.engineRecon || null,
    suppression: scan.suppression || null,
    // What the merge removed or rewrote between the engines and the findings list.
    dispositions: scan.dispositions || null,
  });
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
