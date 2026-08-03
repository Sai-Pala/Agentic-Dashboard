// GOLDEN-MASTER FIXTURE — deliberately insecure test input. See README.md in this directory.
// Frozen: editing this file shifts line numbers and breaks the recorded snapshots.

// Defined and exported, but never applied to any route. This is the UnusedGuardAgent case:
// a reviewer reading this file sees an authorization layer that does not exist in practice.
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).end();
  next();
}

// Safe helper that exists while callers use the unsafe alternative.
function safeQuery(sql, params) {
  return { sql, params };
}

const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';

module.exports = { requireAdmin, safeQuery, JWT_SECRET };
