// GOLDEN-MASTER FIXTURE — deliberately insecure test input. See README.md in this directory.
// Frozen: editing this file shifts line numbers and breaks the recorded snapshots.
const express = require('express');
const { exec } = require('child_process');
const db = require('./db');
const { requireAdmin } = require('./auth');

const app = express();
const adminRouter = express.Router();
const publicRouter = express.Router();

// Mounted with only authentication, never authorization — requireAdmin below is never applied.
app.use('/admin', requireUser, adminRouter);
app.use('/public', publicRouter);

// Same-line SQL injection: concatenated request input straight into a query.
publicRouter.get('/search', (req, res) => {
  db.query(`SELECT * FROM items WHERE name LIKE '%${req.query.q}%'`, (e, r) => res.json(r));
});

// Cross-line taint flow: source, then sink two lines later.
publicRouter.get('/ping', (req, res) => {
  const host = req.query.host;
  const cmd = 'ping -c 1 ' + host;
  exec(cmd, (e, out) => res.send(out));
});

// Parameterized — must NOT be reported. Guards the engine's precision, not just its recall.
publicRouter.get('/safe', (req, res) => {
  db.query('SELECT * FROM items WHERE id = ?', [req.query.id], (e, r) => res.json(r));
});

adminRouter.get('/users', (req, res) => res.json(db.allUsers()));

function requireUser(req, res, next) {
  if (!req.headers.authorization) return res.status(401).end();
  next();
}

app.listen(3000);
module.exports = app;
