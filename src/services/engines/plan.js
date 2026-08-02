/**
 * Prompt planning for the reasoning half: how the review pass is sharded, and how the
 * deterministic findings and the engine's own coverage are rendered into prompt text.
 */


const { REVIEW_ROUTES_PER_SHARD } = require('../../config');
const { toRepoRelative } = require('../paths');

/**
 * Tells the reasoning pass what the deterministic half already covers. Built from each agent's
 * own constructor arguments rather than a second hand-maintained list, so it can never drift
 * from what the engine actually checks.
 *
 * `skipped` and `failed` are load-bearing, not decoration. This text ends with "do not spend
 * effort re-deriving these", so every name in the covered list steers the expensive pass AWAY
 * from a vulnerability class. Listing all built-in agents unconditionally — as this did — tells
 * the model that injection, XSS and secrets are handled on a codebase where half the agents were
 * gated out by shouldRun() and the rest matched almost nothing. Neither half then looks, and the
 * hole is created by the handoff rather than by either engine.
 *
 * An agent that was skipped or that errored is therefore reported as an explicit GAP: the
 * reasoning pass is the only thing that can still cover it.
 *
 * @param {object} engine  loaded sast-engine
 * @param {{skipped?: string[], failed?: string[]}} [coverage]
 */
function buildCoverageSummary(engine, coverage = {}) {
  const skipped = new Set(coverage.skipped || []);
  // failedAgents entries read "AgentName (reason)" — key on the name alone.
  const failed = new Set((coverage.failed || []).map((f) => String(f).split(' (')[0]));

  const all = engine.listBuiltInAgents();
  const ran = all.filter((a) => !skipped.has(a.name) && !failed.has(a.name));
  const gaps = all.filter((a) => skipped.has(a.name) || failed.has(a.name));

  const covered = 'Categories already covered by a deterministic pattern-matching engine that '
    + 'ran over this same codebase — do not spend effort re-deriving these from scratch; focus '
    + 'on business logic, authorization/access-control reasoning, and attack-surface analysis a '
    + 'fixed rule set structurally cannot do:\n'
    + ran.map((a) => `- ${a.name} (${a.category}): ${a.description}`).join('\n');

  if (!gaps.length) return covered;

  return covered + '\n\n'
    + 'NOT covered by the deterministic engine on this codebase — these agents did not run or '
    + 'did not complete, so nothing has checked these classes. You are the only pass that can. '
    + 'Treat them as in scope rather than already handled:\n'
    + gaps.map((a) => `- ${a.name} (${a.category}): ${a.description}`).join('\n');
}

/**
 * Numbers the deterministic findings for the adjudication pass. The id is the finding's index
 * in the array the caller holds, so verdicts map straight back with no title matching.
 */
function renderAdjudicationWorklist(detFindings, targetPath) {
  return detFindings.map((f, i) => {
    const rel = toRepoRelative(targetPath, f.file) || '(no file)';
    const loc = f.line ? `${rel}:${f.line}` : rel;
    const code = Array.isArray(f.codeContext) && f.codeContext.length
      ? f.codeContext.map((c) => `    ${c.line != null ? String(c.line).padStart(5) + ' | ' : ''}${c.text}`).join('\n')
      : '    (no code context captured)';
    const flow = f.taintSourceLine && f.line && f.taintSourceLine < f.line
      ? `\n  Dataflow: untrusted input enters at line ${f.taintSourceLine}, reaches the sink at line ${f.line}.`
      : '';
    return `[${i}] ${f.title || f.rule || 'Untitled'}\n`
      + `  Rule: ${f.rule || 'n/a'} | Severity as matched: ${f.severity || 'unknown'} | Location: ${loc}`
      + `${f.verified === true ? ' | already re-checked against surrounding code' : ''}${flow}\n`
      + `  ${(f.description || '').replace(/\s+/g, ' ').trim()}\n`
      + `  Code:\n${code}`;
  }).join('\n\n');
}

// Words indicating a middleware checks *privilege*, not merely identity. The vocabulary is
// case-insensitive while the camelCase predicate shape is case-SENSITIVE — folding them into
// one /i regex makes `requireAdmin` match on the bare word `admin` and the distinction
// (authenticated vs authorized) collapses.
const PRIVILEGE_WORD_RE = /admin|role|permission|privileg|acl|rbac|scope|claim|staff|superuser|owner|tenant/i;
const PRIVILEGE_PREDICATE_RE = /\b(?:can|is|has|may)[A-Z]/;
const looksPrivileged = (name) => PRIVILEGE_WORD_RE.test(name) || PRIVILEGE_PREDICATE_RE.test(name);

/**
 * Choose which deterministic findings get an adjudication slot.
 *
 * Severity order alone is not a good selector, because severity here is a static per-pattern
 * constant rather than a judgement about this occurrence. The most prolific rule wins on volume:
 * twenty `high` unpinned-GitHub-Action findings consumed the budget ahead of everything else
 * while more interesting findings were displayed unreviewed.
 *
 * Two passes. The first takes at most `maxPerRule` of any one rule, in severity order, so the
 * slots spread across distinct issues. The second spends whatever is left over on the remainder,
 * still in severity order — an under-filled budget helps nobody, so the cap shapes the priority
 * without ever shrinking the total.
 *
 * @param {Array<[number, object]>} adjudicable  [originalIndex, finding], already severity-sorted
 * @returns {Array<[number, object]>} the chosen subset, severity order preserved
 */
function selectForAdjudication(adjudicable, maxTotal, maxPerRule) {
  const perRule = new Map();
  const chosen = [];
  const deferred = [];

  for (const entry of adjudicable) {
    const rule = entry[1].rule || entry[1].title || 'unknown';
    const used = perRule.get(rule) || 0;
    if (used < maxPerRule && chosen.length < maxTotal) {
      perRule.set(rule, used + 1);
      chosen.push(entry);
    } else {
      deferred.push(entry);
    }
  }

  for (const entry of deferred) {
    if (chosen.length >= maxTotal) break;
    chosen.push(entry);
  }

  // Restore severity order: the deferred tail was appended after the capped head.
  return chosen.sort((a, b) => adjudicable.indexOf(a) - adjudicable.indexOf(b));
}

/**
 * Splits the enumerated routes into review shards, riskiest first.
 *
 * Sharded by attack surface rather than by files because the worklist is the unit of work, and
 * grouped BY FILE because sibling handlers must be reviewed together — flaws in routes that
 * share state are only visible side by side. Risk-ordered so that when there are more routes
 * than shards, the reviewed ones are the likeliest to be broken rather than whichever the
 * filesystem listed first.
 *
 * @returns {{ list: Array<{files: string[]|null, routeCount: number}>, totalRoutes: number,
 *             reviewedRoutes: number, skippedRoutes: number }}
 */
function planReviewShards(surface, detFindings, targetPath, { maxShards }) {
  const routes = surface && Array.isArray(surface.routes) ? surface.routes : [];
  // No HTTP surface at all — a library, a CLI, a worker. One unscoped call over the whole tree.
  if (!routes.length) {
    return { list: [{ files: null, routeCount: 0 }], totalRoutes: 0, reviewedRoutes: 0, skippedRoutes: 0 };
  }

  const findingsPerFile = new Map();
  for (const f of detFindings) {
    if (!f.file) continue;
    const rel = toRepoRelative(targetPath, f.file);
    findingsPerFile.set(rel, (findingsPerFile.get(rel) || 0) + 1);
  }
  const sinksPerFile = new Map();
  for (const s of (surface.sinks || [])) {
    sinksPerFile.set(s.file, (sinksPerFile.get(s.file) || 0) + 1);
  }

  const byFile = new Map();
  for (const r of routes) {
    let g = byFile.get(r.file);
    if (!g) { g = { file: r.file, routes: 0, score: 0 }; byFile.set(r.file, g); }
    g.routes++;
    const mw = Array.isArray(r.middleware) ? r.middleware : [];
    if (!mw.length) {
      g.score += 3;                                   // reachable with no guard at all
    } else if (!mw.some(looksPrivileged)) {
      g.score += 2;                                   // authenticated but never authorized —
    }                                                 // reads as protected, isn't
  }
  for (const g of byFile.values()) {
    // Capped so one enormous file can't monopolise the ordering on volume alone.
    g.score += Math.min(5, sinksPerFile.get(g.file) || 0);
    g.score += Math.min(6, (findingsPerFile.get(g.file) || 0) * 2);
  }

  const groups = [...byFile.values()].sort((a, b) => b.score - a.score || b.routes - a.routes);

  // A single file with more routes than the shard size becomes its own oversized shard rather
  // than being split: splitting one router's handlers across two calls is exactly the
  // sibling-context loss this design exists to avoid.
  const list = [];
  let current = null;
  for (const g of groups) {
    if (current && current.routeCount + g.routes > REVIEW_ROUTES_PER_SHARD) current = null;
    if (!current) {
      if (list.length >= maxShards) break;
      current = { files: [], routeCount: 0 };
      list.push(current);
    }
    current.files.push(g.file);
    current.routeCount += g.routes;
    if (current.routeCount >= REVIEW_ROUTES_PER_SHARD) current = null;
  }

  const totalRoutes = routes.length;
  const reviewedRoutes = list.reduce((n, s) => n + s.routeCount, 0);
  return { list, totalRoutes, reviewedRoutes, skippedRoutes: totalRoutes - reviewedRoutes };
}

module.exports = { buildCoverageSummary, renderAdjudicationWorklist, planReviewShards, selectForAdjudication };
