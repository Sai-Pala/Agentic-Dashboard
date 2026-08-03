/**
 * Guard-chain classification for the Attack Surface page
 *
 * Decides whether a mount or route is doing authorization, only authentication, or nothing.
 * The middle case is the one this exists to surface: a surface guarded by authentication but
 * never authorization reads as protected to a reviewer while only ever checking *who* you are.
 *
 * Note this is a deliberately separate, simpler implementation from the engine's own privilege
 * check — it is a display-time classification over an already-computed manifest, not a
 * detection rule, so the two are not kept in sync.
 */

/** Split a middleware name into lowercase words: requireAdmin -> [require, admin]. */
function guardNameSegments(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((s) => s.toLowerCase());
}

/**
 * Is this guard chain doing authorization, only authentication, or nothing at all?
 *
 * Takes anything carrying a `middleware` array — a mount OR a single route — so the same
 * classification drives both the mounted-router rows and the per-route stat tiles.
 *
 * Matching is on WHOLE WORDS split out of the name, never substrings, and against explicit
 * vocabularies. Both rules exist to stop an unprotected surface reading as protected, the only
 * direction of error that matters here:
 *  - A substring test promotes ordinary middleware to full authorization and renders the
 *    reassuring green "guarded": `validateOracle` contains "acl", `scopedLogger` contains
 *    "scope", `reclaimSession` contains "claim", `rolexTimer` contains "role".
 *  - Middleware matching NEITHER vocabulary is not a guard. `helmet` and `bodyParser` are not
 *    authentication, and in a security view an unrecognised name is not evidence of protection.
 *
 * Two accepted limitations, both erring toward inspection rather than false comfort:
 *  - A name with no case or delimiter boundary (`requireadmin`) cannot be split, so it reads as
 *    "no guard" — a false red. Prefix matching would fix it and re-admit `scopedLogger` to the
 *    false-green bucket, which is the worse trade.
 *  - `telemetryScope` classifies as authz, because "scope" really is an authorization word in
 *    OAuth/JWT terms. Dropping it would miss real `requireScope`/`checkClaims` guards.
 */
export function guardKindOf(node) {
  const raw = node && node.middleware;
  // Tolerate a malformed surface payload rather than throwing mid-render.
  const mw = Array.isArray(raw) ? raw : [];
  if (!mw.length) return 'none';
  const words = mw.flatMap(guardNameSegments);
  if (words.some((w) => AUTHZ_WORDS.has(w))) return 'authz';
  if (words.some((w) => AUTHN_WORDS.has(w))) return 'authn';
  return 'none';
}

export function surfaceGuardBadge(kind) {
  if (kind === 'none') return '<span class="surface-badge crit">no guard</span>';
  if (kind === 'authn') return '<span class="surface-badge warn">authenticated, not authorized</span>';
  return '<span class="surface-badge ok">guarded</span>';
}

// Words that indicate a middleware decides WHETHER YOU MAY (authorization).
const AUTHZ_WORDS = new Set([
  'admin', 'role', 'roles', 'permission', 'permissions', 'privilege', 'privileged',
  'acl', 'rbac', 'abac', 'scope', 'scopes', 'claim', 'claims', 'owner', 'ownership',
  'tenant', 'grant', 'grants', 'policy', 'policies', 'authorize', 'authorized',
  'authorization', 'can', 'allowed', 'forbid', 'entitlement',
]);

// Words that indicate a middleware decides WHO YOU ARE (authentication).
const AUTHN_WORDS = new Set([
  'auth', 'authenticate', 'authenticated', 'authentication', 'login', 'logged',
  'session', 'jwt', 'token', 'bearer', 'identity', 'passport', 'oidc', 'saml',
  'user', 'account', 'signin', 'signed', 'apikey', 'credentials',
]);
