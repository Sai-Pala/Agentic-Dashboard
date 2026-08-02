/**
 * /api/agents — the list of per-finding agents the UI can offer.
 *
 * Read-only. Editing an agent means editing prompts/<name>.md on disk; there was once a browser
 * admin screen with POST/PUT/DELETE behind it, and both the screen and those routes are gone.
 */

const express = require('express');
const fs = require('fs');

const { PROMPTS_DIR, NON_FINDING_AGENTS } = require('../config');

const router = express.Router();

router.get('/api/agents', (req, res) => {
  const names = fs.readdirSync(PROMPTS_DIR)
    .filter((f) => f.endsWith('.md'))
    .map((f) => f.replace(/\.md$/, ''));

  // `?all=1` wants every prompt file; everywhere else wants only the per-finding agents, since
  // scan and adjudicate operate on a whole run and can't be started against one finding.
  if (req.query.all) return res.json(names);
  res.json(names.filter((n) => !NON_FINDING_AGENTS.includes(n)));
});

module.exports = router;
