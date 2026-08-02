/**
 * /api/agents — CRUD over the agent prompt files in prompts/.
 */

const express = require('express');
const fs = require('fs');

const { PROMPTS_DIR, AGENT_NAME_RE, BUILTIN_AGENTS, NON_FINDING_AGENTS, agentFilePath } = require('../config');

const router = express.Router();

router.get('/api/agents', (req, res) => {
  const files = fs.readdirSync(PROMPTS_DIR).filter((f) => f.endsWith('.md'));
  const names = files.map((f) => f.replace(/\.md$/, ''));
  // `?all=1` wants every agent file; everywhere else wants only per-finding agents.
  if (req.query.all) {
    res.json(names);
    return;
  }
  res.json(names.filter((n) => !NON_FINDING_AGENTS.includes(n)));
});

router.get('/api/agents/:name', (req, res) => {
  const { name } = req.params;
  if (!AGENT_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid agent name.' });
  const filePath = agentFilePath(name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent not found.' });
  const content = fs.readFileSync(filePath, 'utf8');
  res.json({ name, content, isBuiltIn: BUILTIN_AGENTS.includes(name) });
});

router.post('/api/agents', (req, res) => {
  const { name, content } = req.body || {};
  if (typeof name !== 'string' || !AGENT_NAME_RE.test(name)) {
    return res.status(400).json({ error: 'Agent name must match ^[a-zA-Z0-9_-]+$.' });
  }
  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Agent content must not be empty.' });
  }
  const filePath = agentFilePath(name);
  if (fs.existsSync(filePath)) return res.status(409).json({ error: 'An agent with this name already exists.' });
  fs.writeFileSync(filePath, content, 'utf8');
  res.status(201).json({ name });
});

router.put('/api/agents/:name', (req, res) => {
  const { name } = req.params;
  const { content } = req.body || {};
  if (!AGENT_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid agent name.' });
  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Agent content must not be empty.' });
  }
  const filePath = agentFilePath(name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent not found.' });
  fs.writeFileSync(filePath, content, 'utf8');
  res.json({ name });
});

router.delete('/api/agents/:name', (req, res) => {
  const { name } = req.params;
  if (!AGENT_NAME_RE.test(name)) return res.status(400).json({ error: 'Invalid agent name.' });
  if (BUILTIN_AGENTS.includes(name)) {
    return res.status(403).json({ error: 'Built-in pipeline agents cannot be deleted.' });
  }
  const filePath = agentFilePath(name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Agent not found.' });
  fs.unlinkSync(filePath);
  res.json({ ok: true });
});

module.exports = router;
