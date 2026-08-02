/**
 * /api/findings — list, create, CSV export, one finding.
 */

const express = require('express');
const crypto = require('crypto');

const { FINDING_SCAN_TYPES } = require('../config');
const { SEVERITIES, placeholderTriageRun } = require('../services/taxonomy');
const { findings, toListItem, deriveStatus, buildFindingsCsv } = require('../store/findings');

const router = express.Router();

router.get('/api/findings', (req, res) => {
  const list = [...findings.values()]
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(toListItem);
  res.json(list);
});

router.post('/api/findings', (req, res) => {
  const body = req.body || {};
  const title = String(body.title || '').trim();
  const description = String(body.description || '').trim();
  if (!title || !description) {
    res.status(400).json({ error: 'title and description are required' });
    return;
  }

  const id = crypto.randomUUID();
  const finding = {
    id,
    title,
    severity: SEVERITIES.includes(body.severity) ? body.severity : 'medium',
    scanType: FINDING_SCAN_TYPES.includes(body.scanType) ? body.scanType : 'reasoning',
    rule: body.rule ? String(body.rule).trim() : null,
    file: body.file ? String(body.file).trim() : null,
    description,
    code: body.code ? String(body.code) : null,
    packageName: body.packageName ? String(body.packageName).trim() : null,
    packageVersion: body.packageVersion ? String(body.packageVersion).trim() : null,
    fixedVersion: body.fixedVersion ? String(body.fixedVersion).trim() : null,
    endpoint: body.endpoint ? String(body.endpoint).trim() : null,
    method: body.method ? String(body.method).trim() : null,
    status: 'new',
    createdAt: Date.now(),
    runs: [],
  };
  // A manually-added finding has no source directory to check anything against, so it gets a
  // neutral placeholder verdict rather than a real one.
  if (finding.scanType === 'reasoning') {
    finding.runs.push(placeholderTriageRun(finding.severity));
  }
  finding.status = deriveStatus(finding);
  findings.set(id, finding);
  res.status(201).json(finding);
});

// Must stay registered before `/api/findings/:id`, or Express matches this as that route with
// id="export.csv" and 404s.
router.get('/api/findings/export.csv', (req, res) => {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="findings-export-${Date.now()}.csv"`);
  res.send(buildFindingsCsv());
});

router.get('/api/findings/:id', (req, res) => {
  const finding = findings.get(req.params.id);
  if (!finding) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json(finding);
});

module.exports = router;
