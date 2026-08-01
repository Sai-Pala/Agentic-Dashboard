/**
 * Guard-chain classification for the Attack Surface page
 * =====================================================
 *
 * Decides whether a mount or route is doing authorization, only authentication, or nothing.
 * The middle case is the one this exists to surface: a surface guarded by authentication but
 * never authorization reads as protected to a reviewer while only ever checking *who* you are.
 *
 * Note this is a deliberately separate, simpler implementation from the engine's own privilege
 * check — it is a display-time classification over an already-computed manifest, not a
 * detection rule, so the two are not kept in sync.
 *
 * Moved verbatim out of the single inline <script> during the Phase 4 split.
 */

/** Split a middleware name into lowercase words: requireAdmin -> [require, admin]. */
export function guardNameSegments(name) {
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
 * Two things here were wrong in ways that both pointed the SAME direction — making an
 * unprotected surface look protected, which is the only direction that really matters:
 *
 * 1. Any middleware at all counted as authentication, so a route whose only middleware was
 *    `helmet` or `bodyParser` rendered amber "authenticated, not authorized" instead of red
 *    "no guard". Parsing a request body is not a guard.
 * 2. The privilege test was an UNANCHORED substring regex, so incidental letter runs promoted
 *    ordinary middleware to full authorization and rendered the reassuring green "guarded" —
 *    suppressing the warning entirely. Real examples that matched: `validateOracle` and
 *    `oracleClient` (contain "acl"), `scopedLogger` and `descope` ("scope"), `reclaimSession`
 *    and `disclaimerBanner` ("claim"), `rolexTimer` ("role").
 *
 * Now the name is split into words and matched against explicit vocabularies. A middleware
 * whose words match NEITHER vocabulary is treated as not-a-guard: in a security view an
 * unrecognised name is not evidence of protection, and "no guard" is the safe way to be
 * wrong — it invites a look, where a false green does not.
 *
 * Two limitations remain, both known and both preferred to the alternatives:
 *  - A name with no case or delimiter boundaries (`REQUIREADMIN`, `requireadmin`) cannot be
 *    split, so it matches nothing and reads as "no guard". That is a false RED — noisy, but
 *    it errs toward inspection. Reintroducing prefix/suffix matching to catch it would also
 *    re-admit `scopedLogger` (starts with "scope") into the false-green bucket, which is the
 *    failure this fix exists to remove.
 *  - Some words are genuinely ambiguous: `telemetryScope` classifies as authz because "scope"
 *    really is an authorization word in OAuth/JWT terms. Word-splitting cannot tell an OAuth
 *    scope from a telemetry scope, and dropping "scope"/"claim" from the vocabulary would
 *    miss real `requireScope`/`checkClaims` guards. Residual, and narrower than the eight
 *    incidental matches the substring regex produced.
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

/**
 * Is this guard chain doing authorization, only authentication, or nothing at all?
 *
 * Takes anything carrying a `middleware` array — a mount OR a single route — so the same
 * three-way classification drives both the mounted-router rows and the per-route rollup in
 * the stat tiles. It used to take a mount only, which is what made the tiles lie about an
 * app with no routers: see renderSurfaceView().
 */
// Words that indicate a middleware decides WHETHER YOU MAY (authorization).
export const AUTHZ_WORDS = new Set([
  'admin', 'role', 'roles', 'permission', 'permissions', 'privilege', 'privileged',
  'acl', 'rbac', 'abac', 'scope', 'scopes', 'claim', 'claims', 'owner', 'ownership',
  'tenant', 'grant', 'grants', 'policy', 'policies', 'authorize', 'authorized',
  'authorization', 'can', 'allowed', 'forbid', 'entitlement',
]);

// Words that indicate a middleware decides WHO YOU ARE (authentication).
export const AUTHN_WORDS = new Set([
  'auth', 'authenticate', 'authenticated', 'authentication', 'login', 'logged',
  'session', 'jwt', 'token', 'bearer', 'identity', 'passport', 'oidc', 'saml',
  'user', 'account', 'signin', 'signed', 'apikey', 'credentials',
]);
