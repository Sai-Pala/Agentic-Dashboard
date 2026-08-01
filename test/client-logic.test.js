'use strict';

/**
 * client-logic.test.js — Phase 0 characterization tests for public/index.html's decision logic.
 *
 * WHAT THESE TESTS ARE
 * --------------------
 * These are CHARACTERIZATION tests, not specification tests. Their job is to pin down what the
 * client code does TODAY, exactly as it does it, so that a later refactor (Phase 4: splitting
 * index.html's single ~3,800-line <script> block into real ES modules) can prove it changed
 * nothing behavioural.
 *
 * Consequently: where current behaviour looks wrong, these tests assert the WRONG value and
 * carry a `CONCERN:` comment describing the problem. Do not "fix" a failing assertion by
 * changing the expectation to what the code ought to do — if a fix is intended, change
 * index.html deliberately and update the assertion in the same commit, so the diff shows a
 * behaviour change was chosen rather than drifted into.
 *
 * HOW THE FUNCTIONS GET HERE
 * --------------------------
 * index.html's script is not a module and touches the DOM at its top level, so it cannot be
 * required or eval'd wholesale in Node. test/helpers/extract-client-fns.js parses it with
 * @babel/parser, slices out only the named top-level declarations listed below, and evaluates
 * those in a bare `node:vm` context with no `document` and no app globals. See that file's
 * header for the full rationale.
 *
 * The harness throws loudly if a named declaration disappears — during the refactor that is a
 * real signal about what moved, so do not silence it by deleting names from TARGETS.
 *
 * LIFESPAN
 * --------
 * Once Phase 4 lands, the `extract(TARGETS)` call below collapses into ordinary `import`
 * statements and test/helpers/extract-client-fns.js is deleted (along with the `plain()` /
 * `isTypeError()` cross-realm shims, which only exist because of the vm). The assertions
 * themselves survive that change untouched — that is the point of writing them against
 * behaviour rather than against wiring.
 *
 * NOT COVERED (deliberately): anything that touches the DOM. `escapeHtml()` builds a detached
 * <div> and reads `.innerHTML`, so it cannot run without a DOM and is not a pure function to
 * lift; `diffLineHtml()`, `highlightCode()`, `loopTrackHtml()`, `findingLoopCellHtml()` and
 * `fdLoopBoxesHtml()` all either call it or emit markup. There is no `parseFileLine()` on the
 * client at all — that helper lives in server.js, outside this file's scope.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { extract } = require('./helpers/extract-client-fns.js');

// Every top-level declaration lifted out of index.html. Pure constants are included because
// the functions close over them (SEV_ORDER_MAP / STATUS_ORDER_MAP / AGENT_META).
const TARGETS = [
  'guardKindOf',
  // guardKindOf's own dependencies. It used to be self-contained with an inline regex; the
  // fix for the substring-matching false-authz bug split the vocabulary out into these three
  // declarations, so they have to be lifted alongside it or it throws at call time.
  'guardNameSegments',
  'AUTHZ_WORDS',
  'AUTHN_WORDS',
  'findingStageRuns',
  'findingLoopState',
  'findingLoopNextAction',
  'findingsSortValue',
  'scanFilterLabel',
  // NOTE: formatRelativeTime / verdictFieldLabel / truncate / statusLabel / severityLabel /
  // formatElapsed / formatTokenCount used to be extracted here too. Phase 4 step 2 moved them
  // into public/js/util/format.js, so they are now imported as real module exports instead —
  // see `format` below. Each name that leaves this list is a name the harness no longer has to
  // fake, and the harness is deleted entirely once the list is empty (PHASE4-PLAN.md §4).
  'worstOfList',
  'agentMeta',
  'SEV_ORDER_MAP',
  'STATUS_ORDER_MAP',
  'AGENT_META',
];

// Real module exports, imported directly — no extraction, no vm realm, no shims. As the Phase
// 4 split proceeds, names migrate from `extract(TARGETS)` into imports like this one, and the
// test bodies below are unchanged either way because both sources are merged into `C`.
// Node can require() an ES module as long as it has no top-level await, which these do not.
const format = require('../public/js/util/format.js');

// scanFilterLabel is still extracted from app.js but calls formatRelativeTime, which now lives
// in a module the bare vm context cannot see. Seed it so the extracted function can resolve it.
// This is the shape of every remaining step: as a dependency moves out, whatever still depends
// on it gets that binding injected until it moves too.
const extracted = extract(TARGETS, { bindings: { formatRelativeTime: format.formatRelativeTime } });

// __meta is non-enumerable, so an object spread silently drops it — carry it across explicitly.
const C = { ...extracted, ...format, __meta: extracted.__meta };

/**
 * Objects created inside the vm context carry that realm's Object.prototype, not the host's,
 * so `deepStrictEqual` rejects them as "same structure but not reference-equal" even when the
 * data matches. Normalize through JSON before any structural comparison. Identity assertions
 * (e.g. "returns the same object, not a copy") deliberately skip this.
 */
const plain = (v) => JSON.parse(JSON.stringify(v));

/**
 * Same cross-realm problem for errors: a TypeError thrown inside the vm is not an `instanceof`
 * the host's TypeError. Match on `name` instead.
 */
const isTypeError = (err) => err.name === 'TypeError';

// ---------------------------------------------------------------------------
// Fixture builders. `mkStageRuns` uses the precomputed `.stageRuns` shape that
// GET /api/findings returns (toListItem() in server.js); `mkRuns` uses the raw
// `.runs` array shape that GET /api/findings/:id returns. Both must behave the
// same — see the "both input shapes" describe block.
// ---------------------------------------------------------------------------
const NO_STAGES = { triage: null, remediation: null, fix: null, verify: null };
const mkStageRuns = (over) => ({ stageRuns: { ...NO_STAGES, ...over } });
const mkRuns = (runs) => ({ runs });

const TRIAGE_DONE = { status: 'done', verdict: { verdict: 'confirmed' } };
const REMEDIATION_WITH_PLAN = {
  status: 'done',
  verdict: { edit_plan: { files: [{ path: 'src/a.js', find: 'x', replace: 'y' }] } },
};
const REMEDIATION_NO_PLAN = { status: 'done', verdict: { corrected_code: 'safe();', edit_plan: null } };
const FIX_APPLIED = { status: 'done', verdict: { verdict: 'applied', applied_diff: '--- a\n+++ b\n+safe();' } };
const VERIFY_FIXED = { status: 'done', verdict: { verdict: 'verified_fixed' } };

// ===========================================================================
describe('extraction harness', () => {
  test('every targeted declaration is still present at the top level of index.html', () => {
    // extract() throws on a miss, so reaching here already proves it. Assert the shapes so a
    // declaration that survives in name but changes kind (function -> arrow const, say) shows up.
    assert.equal(C.__meta.length, TARGETS.length);
    for (const name of TARGETS) {
      assert.ok(name in C, `${name} was not exported by the harness`);
    }
  });

  test('the harness fails loudly, not silently, when a function name disappears', () => {
    assert.throws(
      () => extract(['guardKindOf', 'aFunctionThatDoesNotExist']),
      /aFunctionThatDoesNotExist/,
      'a missing declaration must throw by name — swallowing it would let the suite pass while testing nothing'
    );
  });

  test('extracted functions run with no DOM available at all', () => {
    // Proves the vm context is genuinely bare: if any of these had reached for `document`,
    // it would have thrown a ReferenceError rather than returned a value.
    assert.equal(typeof C.guardKindOf({ middleware: [] }), 'string');
    assert.equal(typeof C.findingLoopState(mkStageRuns({})), 'object');
  });
});

// ===========================================================================
// guardKindOf — three-way guard classification.
//
// The security stakes are asymmetric here. 'authn' means "this surface is authenticated but
// nothing checks WHAT the caller may do", which is the case CLAUDE.md calls out as more
// dangerous than a bare unguarded mount: a reviewer reading auth.js sees a hardened system.
// So the boundary between 'authn' and 'authz' is the one that must not drift.
// ===========================================================================
describe('guardKindOf — three-way guard classification', () => {
  test('a node with no middleware array at all is unguarded', () => {
    assert.equal(C.guardKindOf({}), 'none');
    assert.equal(C.guardKindOf({ middleware: undefined }), 'none');
  });

  test('an empty middleware array is unguarded', () => {
    assert.equal(C.guardKindOf({ middleware: [] }), 'none');
  });

  test('a null or undefined node is unguarded rather than a crash', () => {
    assert.equal(C.guardKindOf(null), 'none');
    assert.equal(C.guardKindOf(undefined), 'none');
  });

  test('an authentication guard reads as authenticated-not-authorized', () => {
    // The security-critical classification: something checks WHO you are, nothing checks
    // whether you MAY. More dangerous than no guard at all, because it reads as protected.
    assert.equal(C.guardKindOf({ middleware: ['requireUser'] }), 'authn');
  });

  test('every recognisable authentication-only guard lands on authn, never authz', () => {
    for (const mw of [
      'requireUser',
      'requireAuth',
      'isLoggedIn',
      'authenticate',
      'ensureSignedIn',
      'jwtVerify',
      'session',
      'passport',
      'verifyToken',
      'checkSession',
    ]) {
      assert.equal(C.guardKindOf({ middleware: [mw] }), 'authn', `${mw} must classify as authn`);
    }
  });

  test('a privilege-vocabulary guard is authorization', () => {
    assert.equal(C.guardKindOf({ middleware: ['requireAdmin'] }), 'authz');
  });

  test('privilege words promote a guard to authz when they are real name segments', () => {
    for (const word of ['admin', 'role', 'permission', 'acl', 'rbac', 'scope', 'claim', 'owner', 'tenant']) {
      assert.equal(C.guardKindOf({ middleware: [word] }), 'authz', `bare "${word}" must be authz`);
      // Separated by a delimiter or camelCase, it is still a real segment of the name.
      assert.equal(C.guardKindOf({ middleware: [`require_${word}_check`] }), 'authz');
    }
    assert.equal(C.guardKindOf({ middleware: ['checkPermissions'] }), 'authz');
    assert.equal(C.guardKindOf({ middleware: ['hasRole'] }), 'authz');
    assert.equal(C.guardKindOf({ middleware: ['tenantGuard'] }), 'authz');
  });

  test('classification is case-insensitive where the name can be split into words', () => {
    for (const mw of ['requireAdmin', 'RequireAdmin', 'require_admin', 'REQUIRE_ADMIN', 'require-admin']) {
      assert.equal(C.guardKindOf({ middleware: [mw] }), 'authz', `${mw} must be authz`);
    }
    assert.equal(C.guardKindOf({ middleware: ['CheckRBAC'] }), 'authz');
  });

  test('KNOWN LIMITATION: a name with no word boundaries cannot be split, so it reads as none', () => {
    // `REQUIREADMIN` / `requireadmin` have no case or delimiter transition, so segmentation
    // yields one token that matches no vocabulary entry. This is a false RED — noisy, but it
    // errs toward inspection, and the alternative (prefix/suffix matching) would re-admit
    // `scopedLogger` and friends into the false-GREEN bucket this fix exists to eliminate.
    // Recorded deliberately so the trade-off is visible rather than looking like an oversight.
    assert.equal(C.guardKindOf({ middleware: ['REQUIREADMIN'] }), 'none');
    assert.equal(C.guardKindOf({ middleware: ['requireadmin'] }), 'none');
  });

  test('one privileged entry anywhere in a chain promotes the whole chain to authz', () => {
    assert.equal(C.guardKindOf({ middleware: ['requireAuth', 'requireAdmin'] }), 'authz');
    assert.equal(C.guardKindOf({ middleware: ['requireAdmin', 'requireAuth'] }), 'authz');
    assert.equal(C.guardKindOf({ middleware: ['a', 'b', 'c', 'checkRole'] }), 'authz');
  });

  test('a blank middleware entry does not lift a route out of "no guard"', () => {
    // REGRESSION GUARD (was a CONCERN, fixed): presence alone used to be enough.
    assert.equal(C.guardKindOf({ middleware: [''] }), 'none');
  });

  test('REGRESSION: non-auth middleware is NOT mistaken for authentication', () => {
    // WAS A BUG: guardKindOf treated the mere PRESENCE of any middleware as authentication, so
    // a route whose only middleware was body parsing, CORS or rate limiting rendered the amber
    // "authenticated, not authorized" badge instead of red "no guard" — an entirely
    // unauthenticated route reading one notch safer than it is. Parsing a body is not a guard.
    for (const mw of ['bodyParser', 'helmet', 'compression', 'rateLimiter', 'corsMiddleware', 'requestLogger']) {
      assert.equal(C.guardKindOf({ middleware: [mw] }), 'none', `${mw} must not read as a guard`);
    }
  });

  test('REGRESSION: incidental letter runs are NOT mistaken for authorization', () => {
    // WAS A BUG, and in the dangerous direction: the vocabulary was an unanchored substring
    // regex, so these all matched and rendered the reassuring green "guarded" badge —
    // actively SUPPRESSING the authenticated-not-authorized warning a reviewer needs.
    // Now the name is split into words, so a letter run inside an unrelated word cannot match.
    assert.equal(C.guardKindOf({ middleware: ['validateOracle'] }), 'none'); // was "acl"
    assert.equal(C.guardKindOf({ middleware: ['oracleClient'] }), 'none'); // was "acl"
    assert.equal(C.guardKindOf({ middleware: ['scopedLogger'] }), 'none'); // was "scope"
    assert.equal(C.guardKindOf({ middleware: ['disclaimerBanner'] }), 'none'); // was "claim"
    assert.equal(C.guardKindOf({ middleware: ['rolexTimer'] }), 'none'); // was "role"
    assert.equal(C.guardKindOf({ middleware: ['descope'] }), 'none'); // was "scope"
    // reclaimSession legitimately contains the word "session", so authn is correct here —
    // it is no longer wrongly promoted to authz.
    assert.equal(C.guardKindOf({ middleware: ['reclaimSession'] }), 'authn');
  });

  test('RESIDUAL: a genuinely ambiguous word still classifies by its dictionary meaning', () => {
    // `telemetryScope` splits to [telemetry, scope], and "scope" really IS an authorization
    // word in OAuth/JWT terms — word-splitting cannot tell an OAuth scope from a telemetry
    // scope. Dropping "scope"/"claim" from the vocabulary would miss real requireScope and
    // checkClaims guards, which is the worse trade. So this one stays wrong, deliberately and
    // narrowly: 1 residual case where the substring regex produced 8.
    assert.equal(C.guardKindOf({ middleware: ['telemetryScope'] }), 'authz');
  });

  test('REGRESSION: a non-array middleware value degrades instead of throwing', () => {
    // WAS A BUG: `(node && node.middleware) || []` guarded absence but not type, so a malformed
    // surface payload crashed the whole render.
    assert.doesNotThrow(() => C.guardKindOf({ middleware: 'requireAdmin' }));
    assert.equal(C.guardKindOf({ middleware: 'requireAdmin' }), 'none');
    assert.equal(C.guardKindOf({ middleware: 42 }), 'none');
  });

  test('an unrecognised guard name reads as "no guard", the safe direction to be wrong', () => {
    // A name we cannot classify is not evidence of protection. Red invites a look; a false
    // green does not. This is a deliberate bias, so it gets an explicit test.
    assert.equal(C.guardKindOf({ middleware: ['mw1'] }), 'none');
    assert.equal(C.guardKindOf({ middleware: ['doTheThing'] }), 'none');
  });
});

// ===========================================================================
// findingStageRuns — normalizes the two finding shapes into per-stage latest runs.
// ===========================================================================
describe('findingStageRuns — normalizing both finding shapes', () => {
  test('a precomputed .stageRuns is returned verbatim and short-circuits .runs entirely', () => {
    // Note the precedence: .stageRuns wins even when a richer .runs array is also present.
    const precomputed = { ...NO_STAGES };
    const f = { stageRuns: precomputed, runs: [{ agent: 'triage', status: 'done', verdict: {} }] };
    assert.equal(C.findingStageRuns(f), precomputed, 'must be the same object, not a copy');
  });

  test('a raw .runs array is reduced to the latest run per pipeline stage', () => {
    const f = mkRuns([
      { runId: '1', agent: 'triage', status: 'done', verdict: { verdict: 'confirmed' } },
      { runId: '2', agent: 'remediation', status: 'done', verdict: { edit_plan: { files: [{ path: 'a' }] } } },
      { runId: '3', agent: 'fix', status: 'done', verdict: { verdict: 'applied', applied_diff: '+x' } },
      { runId: '4', agent: 'verify', status: 'done', verdict: { verdict: 'verified_fixed' } },
    ]);
    assert.deepEqual(plain(C.findingStageRuns(f)), {
      triage: { status: 'done', verdict: { verdict: 'confirmed' } },
      remediation: { status: 'done', verdict: { edit_plan: { files: [{ path: 'a' }] } } },
      fix: { status: 'done', verdict: { verdict: 'applied', applied_diff: '+x' } },
      verify: { status: 'done', verdict: { verdict: 'verified_fixed' } },
    });
  });

  test('only status and verdict survive — runId and fullText are dropped', () => {
    const got = C.findingStageRuns(mkRuns([{ runId: 'r1', agent: 'triage', status: 'done', verdict: {}, fullText: 'lots of prose' }]));
    assert.deepEqual([...Object.keys(got.triage)], ['status', 'verdict']);
  });

  test('when a stage ran more than once the LAST run in the array wins', () => {
    const got = C.findingStageRuns(mkRuns([
      { agent: 'fix', status: 'error', verdict: null },
      { agent: 'fix', status: 'done', verdict: { applied_diff: 'd' } },
    ]));
    assert.deepEqual(plain(got.fix), { status: 'done', verdict: { applied_diff: 'd' } });
  });

  test('non-pipeline agents are ignored entirely', () => {
    const got = C.findingStageRuns(mkRuns([
      { agent: 'threat_model', status: 'done', verdict: { owasp: 'A01' } },
      { agent: 'scan', status: 'done', verdict: {} },
    ]));
    assert.deepEqual(plain(got), NO_STAGES);
  });

  test('a stage that never ran is null, not undefined — all four keys always present', () => {
    assert.deepEqual(plain(C.findingStageRuns({})), NO_STAGES);
    assert.deepEqual(plain(C.findingStageRuns(mkRuns([]))), NO_STAGES);
  });

  test('a malformed .runs that is not an array degrades to all-null instead of throwing', () => {
    assert.deepEqual(plain(C.findingStageRuns({ runs: 'not an array' })), NO_STAGES);
    assert.deepEqual(plain(C.findingStageRuns({ runs: null })), NO_STAGES);
  });

  test('EQUIVALENCE: both finding shapes drive findingLoopState to the same result', () => {
    // This is the invariant Phase 4 must not break — the list view and the detail view read
    // different payload shapes and must agree about where a finding stands.
    const runs = [
      { runId: '1', agent: 'triage', status: 'done', verdict: { verdict: 'confirmed' } },
      { runId: '2', agent: 'remediation', status: 'done', verdict: { edit_plan: { files: [{ path: 'a' }] } } },
      { runId: '3', agent: 'fix', status: 'done', verdict: { applied_diff: '+x' } },
      { runId: '4', agent: 'verify', status: 'done', verdict: { verdict: 'verified_fixed' } },
    ];
    const rawShape = mkRuns(runs);
    const listShape = { stageRuns: C.findingStageRuns(rawShape) };

    assert.deepEqual(plain(C.findingLoopState(rawShape)), plain(C.findingLoopState(listShape)));
    assert.equal(C.findingLoopNextAction(rawShape), C.findingLoopNextAction(listShape));
    assert.deepEqual(plain(C.findingLoopState(rawShape)), {
      triaged: 'done', remediated: 'done', fixed: 'done', verified: 'done', hasPlan: true,
    });
  });
});

// ===========================================================================
// findingLoopState — the Remediation Loop state machine.
// ===========================================================================
describe('findingLoopState — per-stage states', () => {
  test('a brand-new finding with no runs at all is pending on every stage', () => {
    assert.deepEqual(plain(C.findingLoopState(mkStageRuns({}))), {
      triaged: 'pending', remediated: 'pending', fixed: 'pending', verified: 'pending', hasPlan: false,
    });
  });

  test('a finished triage run marks triaged done', () => {
    assert.equal(C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE })).triaged, 'done');
  });

  test('a running stage reads as running, not done', () => {
    assert.equal(C.findingLoopState(mkStageRuns({ triage: { status: 'running' } })).triaged, 'running');
    assert.equal(C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: { status: 'running' } })).remediated, 'running');
    assert.equal(C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, fix: { status: 'running' } })).fixed, 'running');
    assert.equal(C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, verify: { status: 'running' } })).verified, 'running');
  });

  test('an errored or cancelled triage/remediation/verify run reads as attention', () => {
    for (const status of ['error', 'cancelled']) {
      assert.equal(C.findingLoopState(mkStageRuns({ triage: { status } })).triaged, 'attention');
      assert.equal(C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: { status } })).remediated, 'attention');
      assert.equal(
        C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: FIX_APPLIED, verify: { status } })).verified,
        'attention'
      );
    }
  });

  test('any other terminal status counts as done, not attention', () => {
    // CONCERN: the branch is `running` / `error|cancelled` / else-done, so an unrecognised
    // status string silently reads as a completed stage.
    assert.equal(C.findingLoopState(mkStageRuns({ triage: { status: 'weird-new-status' } })).triaged, 'done');
  });

  // --- the edit_plan / applied_diff distinction --------------------------------
  test('a remediation run carrying an edit_plan with files sets hasPlan and leaves fixed pending', () => {
    const s = C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN }));
    assert.equal(s.remediated, 'done');
    assert.equal(s.hasPlan, true);
    assert.equal(s.fixed, 'pending');
  });

  test('remediation that proposed no edit_plan makes fixed unavailable, not pending', () => {
    // "Nothing to apply" is a real outcome, distinct from "not started yet".
    const s = C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: REMEDIATION_NO_PLAN }));
    assert.equal(s.remediated, 'done');
    assert.equal(s.hasPlan, false);
    assert.equal(s.fixed, 'unavailable');
  });

  test('an edit_plan with an empty or missing files list counts as no plan', () => {
    for (const editPlan of [{ files: [] }, {}, { files: null }]) {
      const s = C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: { status: 'done', verdict: { edit_plan: editPlan } } }));
      assert.equal(s.hasPlan, false, `edit_plan ${JSON.stringify(editPlan)} must not count as a plan`);
      assert.equal(s.fixed, 'unavailable');
    }
  });

  test('a still-running remediation does not yet make fixed unavailable', () => {
    // 'unavailable' is gated on remediated === 'done', so an in-flight proposal stays pending.
    assert.equal(C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: { status: 'running' } })).fixed, 'pending');
  });

  test('fixed is done ONLY when the latest fix run carries a real applied_diff', () => {
    const s = C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: FIX_APPLIED }));
    assert.equal(s.fixed, 'done');
  });

  test('a completed fix run with no applied_diff reads as attention, not done', () => {
    // The invariant that keeps the UI honest: showing "Fixed" and offering "Verify the fix"
    // when nothing was written would be actively misleading.
    const s = C.findingLoopState(mkStageRuns({
      triage: TRIAGE_DONE,
      remediation: REMEDIATION_WITH_PLAN,
      fix: { status: 'done', verdict: { verdict: 'not_applied' } },
    }));
    assert.equal(s.fixed, 'attention');
  });

  test('a fix run with an empty-string applied_diff also reads as attention', () => {
    const s = C.findingLoopState(mkStageRuns({
      triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: { status: 'done', verdict: { applied_diff: '' } },
    }));
    assert.equal(s.fixed, 'attention');
  });

  test('a fix run with a null verdict reads as attention', () => {
    const s = C.findingLoopState(mkStageRuns({
      triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: { status: 'error', verdict: null },
    }));
    assert.equal(s.fixed, 'attention');
  });

  test('CURRENT BEHAVIOUR: a fix run overrides unavailable, even with no plan behind it', () => {
    // CONCERN (benign today, fragile later): the fix branch reassigns `fixed` unconditionally,
    // so an applied fix following a plan-less remediation reads 'done' while hasPlan stays
    // false. Unreachable through the UI (Fix is gated on a usable plan server-side) but the
    // two fields disagree, so anything reading hasPlan as a proxy for "was fixable" would be wrong.
    const s = C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: REMEDIATION_NO_PLAN, fix: FIX_APPLIED }));
    assert.equal(s.fixed, 'done');
    assert.equal(s.hasPlan, false);
  });

  // --- verify -------------------------------------------------------------------
  test('verified is done only on a verdict of verified_fixed', () => {
    const base = { triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: FIX_APPLIED };
    assert.equal(C.findingLoopState(mkStageRuns({ ...base, verify: VERIFY_FIXED })).verified, 'done');
  });

  test('still_vulnerable, partially_fixed and inconclusive all read as attention', () => {
    const base = { triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: FIX_APPLIED };
    for (const verdict of ['still_vulnerable', 'partially_fixed', 'inconclusive']) {
      assert.equal(C.findingLoopState(mkStageRuns({ ...base, verify: { status: 'done', verdict: { verdict } } })).verified, 'attention');
    }
  });

  test('a completed verify run with no verdict object reads as attention', () => {
    const base = { triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: FIX_APPLIED };
    assert.equal(C.findingLoopState(mkStageRuns({ ...base, verify: { status: 'done', verdict: null } })).verified, 'attention');
  });

  test('CURRENT BEHAVIOUR: findingLoopState ignores finding.status entirely, including closed', () => {
    // The "a closed finding shows no loop" rule is enforced by the renderers
    // (findingLoopCellHtml / fdLoopBoxesHtml), NOT by the state machine. Locking that division
    // of labour: if Phase 4 moves the closed check into findingLoopState, this test catches it.
    const closed = {
      status: 'closed',
      stageRuns: { ...NO_STAGES, triage: { status: 'done', verdict: { verdict: 'false_positive' } } },
    };
    assert.deepEqual(plain(C.findingLoopState(closed)), {
      triaged: 'done', remediated: 'pending', fixed: 'pending', verified: 'pending', hasPlan: false,
    });
    assert.equal(C.findingLoopNextAction(closed), 'remediate');
  });
});

// ===========================================================================
// findingLoopNextAction — reduces the state to the single next automatable step.
//
// NOTE ON SIGNATURE: despite reading like `next(state)`, this takes the FINDING and calls
// findingLoopState() itself. Passing it a state object returns 'triage' (every field is
// undefined, so triaged !== 'running' and the pending/attention check falls through). Phase 4
// should preserve the finding-in signature or update every caller.
// ===========================================================================
describe('findingLoopNextAction — the single next step', () => {
  const next = (over) => C.findingLoopNextAction(mkStageRuns(over));

  test('an untriaged finding is sent to triage first', () => {
    assert.equal(next({}), 'triage');
  });

  test('an errored triage is retried before anything else can happen', () => {
    assert.equal(next({ triage: { status: 'error' } }), 'triage');
    assert.equal(next({ triage: { status: 'cancelled' } }), 'triage');
  });

  test('any running stage blocks the loop — nothing is offered while work is in flight', () => {
    assert.equal(next({ triage: { status: 'running' } }), null);
    assert.equal(next({ triage: TRIAGE_DONE, remediation: { status: 'running' } }), null);
    assert.equal(next({ triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: { status: 'running' } }), null);
    assert.equal(next({ triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: FIX_APPLIED, verify: { status: 'running' } }), null);
  });

  test('a triaged finding with no proposal yet goes to remediate', () => {
    assert.equal(next({ triage: TRIAGE_DONE }), 'remediate');
  });

  test('an errored remediation is retried as remediate', () => {
    assert.equal(next({ triage: TRIAGE_DONE, remediation: { status: 'error' } }), 'remediate');
  });

  test('a proposed but unapplied plan goes to fix', () => {
    assert.equal(next({ triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN }), 'fix');
  });

  test('an applied fix goes to verify', () => {
    assert.equal(next({ triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: FIX_APPLIED }), 'verify');
  });

  test('a fully verified finding has nothing left to do', () => {
    assert.equal(next({ triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: FIX_APPLIED, verify: VERIFY_FIXED }), null);
  });

  test('verified === attention maps BACK to remediate, not to another verify', () => {
    // Verify already said the fix did not hold; re-checking the same unfixed state would just
    // return the same answer, so the actionable step is a fresh proposal.
    const base = { triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN, fix: FIX_APPLIED };
    for (const verdict of ['still_vulnerable', 'partially_fixed', 'inconclusive']) {
      assert.equal(next({ ...base, verify: { status: 'done', verdict: { verdict } } }), 'remediate');
    }
    assert.equal(next({ ...base, verify: { status: 'error' } }), 'remediate');
  });

  test('fixed === attention maps BACK to remediate, not to a retry of fix', () => {
    // A failed apply usually means the plan went stale against the live file, so repeating the
    // identical apply would fail identically.
    const base = { triage: TRIAGE_DONE, remediation: REMEDIATION_WITH_PLAN };
    assert.equal(next({ ...base, fix: { status: 'done', verdict: { verdict: 'not_applied' } } }), 'remediate');
    assert.equal(next({ ...base, fix: { status: 'error', verdict: null } }), 'remediate');
  });

  test('fixed === unavailable resolves to null — there is nothing left to automate', () => {
    assert.equal(next({ triage: TRIAGE_DONE, remediation: REMEDIATION_NO_PLAN }), null);
  });

  test('unavailable outranks a pending verify — the loop stops rather than verifying an unapplied fix', () => {
    assert.equal(C.findingLoopState(mkStageRuns({ triage: TRIAGE_DONE, remediation: REMEDIATION_NO_PLAN })).verified, 'pending');
    assert.equal(next({ triage: TRIAGE_DONE, remediation: REMEDIATION_NO_PLAN }), null);
  });

  test('PRECEDENCE: verified attention is checked before fixed attention and before remediated', () => {
    // Both map to 'remediate' today so the ordering is unobservable through the return value.
    // Asserted anyway: if the branches ever return different actions, this pins which wins.
    const bothAttention = {
      triage: TRIAGE_DONE,
      remediation: REMEDIATION_WITH_PLAN,
      fix: { status: 'error', verdict: null },
      verify: { status: 'done', verdict: { verdict: 'still_vulnerable' } },
    };
    const s = C.findingLoopState(mkStageRuns(bothAttention));
    assert.equal(s.fixed, 'attention');
    assert.equal(s.verified, 'attention');
    assert.equal(next(bothAttention), 'remediate');
  });

  test('CURRENT BEHAVIOUR: passing a state object instead of a finding silently returns triage', () => {
    // CONCERN: the signature reads like next(state) but is next(finding). A caller confusing
    // the two gets a plausible-looking 'triage' rather than an error.
    const state = { triaged: 'done', remediated: 'done', fixed: 'done', verified: 'done' };
    assert.equal(C.findingLoopNextAction(state), 'triage');
  });
});

// ===========================================================================
// Sort comparators and small pure formatters.
// ===========================================================================
describe('findingsSortValue and the order maps', () => {
  test('severity sorts most severe first', () => {
    assert.deepEqual(
      ['critical', 'high', 'medium', 'low', 'informational'].map((severity) => C.findingsSortValue({ severity }, 'severity')),
      [0, 1, 2, 3, 4]
    );
  });

  test('an unknown severity sorts last via the 99 fallback', () => {
    assert.equal(C.findingsSortValue({ severity: 'catastrophic' }, 'severity'), 99);
    assert.equal(C.findingsSortValue({ severity: undefined }, 'severity'), 99);
  });

  test('STATUS_ORDER_MAP ordering is exactly new < in_review < remediation_ready < remediation_generated < closed < verified_fixed', () => {
    assert.deepEqual(plain(C.STATUS_ORDER_MAP), {
      new: 0, in_review: 1, remediation_ready: 2, remediation_generated: 3, closed: 4, verified_fixed: 5,
    });
    // CONCERN: verified_fixed (5) sorts AFTER closed (4), so the most-resolved findings land
    // below dismissed ones on an ascending status sort. Plausibly deliberate, recorded as-is.
  });

  test('SEV_ORDER_MAP ordering is exactly critical..informational', () => {
    assert.deepEqual(plain(C.SEV_ORDER_MAP), { critical: 0, high: 1, medium: 2, low: 3, informational: 4 });
  });

  test('the loop column sorts by the same status order as the status column', () => {
    // The loop cell is a different rendering of the same underlying status, and both header
    // keys deliberately share STATUS_ORDER_MAP.
    for (const status of Object.keys(C.STATUS_ORDER_MAP)) {
      assert.equal(C.findingsSortValue({ status }, 'loop'), C.findingsSortValue({ status }, 'status'));
    }
  });

  test('an unknown status sorts last via the 99 fallback', () => {
    assert.equal(C.findingsSortValue({ status: 'mystery' }, 'status'), 99);
  });

  test('title sorts case-insensitively via lowercasing', () => {
    assert.equal(C.findingsSortValue({ title: 'ZeBra' }, 'title'), 'zebra');
  });

  test('an unsortable column key yields the empty string, collapsing all rows to equal', () => {
    assert.equal(C.findingsSortValue({ severity: 'high', title: 'x' }, 'location'), '');
    assert.equal(C.findingsSortValue({}, 'package'), '');
  });
});

describe('worstOfList', () => {
  test('returns the most severe entry regardless of list order', () => {
    const sev = (i) => i.s;
    assert.equal(C.worstOfList([{ s: 'low' }, { s: 'critical' }, { s: 'medium' }], sev), 'critical');
    assert.equal(C.worstOfList([{ s: 'critical' }, { s: 'low' }], sev), 'critical');
  });

  test('falsy severities are skipped, not treated as a level', () => {
    assert.equal(C.worstOfList([{ s: null }, { s: 'high' }, { s: undefined }, { s: '' }], (i) => i.s), 'high');
  });

  test('an empty list, or one with no usable severities, falls back to informational', () => {
    assert.equal(C.worstOfList([], (i) => i.s), 'informational');
    assert.equal(C.worstOfList([{ s: null }], (i) => i.s), 'informational');
  });

  test('CURRENT BEHAVIOUR: an unrecognised severity string is returned verbatim if it is first', () => {
    // CONCERN: unknown values rank 99 (worst-last) but the first item always seats itself as
    // the running worst, so a single junk value is echoed straight back out as if it were a
    // real severity level.
    assert.equal(C.worstOfList([{ s: 'bogus' }], (i) => i.s), 'bogus');
    // ...yet any known severity beats it, because 99 loses every comparison.
    assert.equal(C.worstOfList([{ s: 'bogus' }, { s: 'informational' }], (i) => i.s), 'informational');
  });
});

describe('label and format helpers', () => {
  test('verdictFieldLabel title-cases snake_case verdict keys', () => {
    assert.equal(C.verdictFieldLabel('root_cause'), 'Root Cause');
    assert.equal(C.verdictFieldLabel('fix_guidance'), 'Fix Guidance');
    assert.equal(C.verdictFieldLabel('owasp'), 'Owasp');
    assert.equal(C.verdictFieldLabel('verification_steps'), 'Verification Steps');
    assert.equal(C.verdictFieldLabel(''), '');
  });

  test('CURRENT BEHAVIOUR: acronym and numeric keys are title-cased naively', () => {
    // CONCERN (cosmetic): renders as "Nist 800 53" / "Cwe" rather than "NIST 800-53" / "CWE".
    assert.equal(C.verdictFieldLabel('nist_800_53'), 'Nist 800 53');
    assert.equal(C.verdictFieldLabel('cwe'), 'Cwe');
    assert.equal(C.verdictFieldLabel('asvs'), 'Asvs');
  });

  test('statusLabel maps every known status to prose and passes unknowns through raw', () => {
    assert.equal(C.statusLabel('new'), 'Not started');
    assert.equal(C.statusLabel('in_review'), 'In review');
    assert.equal(C.statusLabel('remediation_ready'), 'Remediation ready');
    assert.equal(C.statusLabel('remediation_generated'), 'Remediation generated');
    assert.equal(C.statusLabel('verified_fixed'), 'Verified fixed');
    assert.equal(C.statusLabel('closed'), 'Closed');
    assert.equal(C.statusLabel('something_new'), 'something_new');
  });

  test('every status in STATUS_ORDER_MAP has a prose label — the two maps stay in step', () => {
    for (const status of Object.keys(C.STATUS_ORDER_MAP)) {
      assert.notEqual(C.statusLabel(status), status, `${status} has no prose label`);
    }
  });

  test('severityLabel capitalises, and throws on a nullish severity', () => {
    assert.equal(C.severityLabel('critical'), 'Critical');
    assert.equal(C.severityLabel('informational'), 'Informational');
    assert.equal(C.severityLabel(''), '');
    // CONCERN: no nullish guard, unlike statusLabel's `|| status` fallback.
    assert.throws(() => C.severityLabel(null), isTypeError);
    assert.throws(() => C.severityLabel(undefined), isTypeError);
  });

  test('truncate appends an ellipsis only past the limit, and stringifies non-strings first', () => {
    assert.equal(C.truncate('abcdef', 3), 'abc…');
    assert.equal(C.truncate('abc', 3), 'abc');
    assert.equal(C.truncate('abcd', 3), 'abc…');
    assert.equal(C.truncate(12345, 3), '123…');
    // CONCERN (cosmetic): nullish input becomes the literal text "null"/"undefined".
    assert.equal(C.truncate(null, 3), 'nul…');
    assert.equal(C.truncate(undefined, 3), 'und…');
  });

  test('formatElapsed renders m:ss and clamps negatives to zero', () => {
    assert.equal(C.formatElapsed(0), '0:00');
    assert.equal(C.formatElapsed(1000), '0:01');
    assert.equal(C.formatElapsed(59999), '0:59');
    assert.equal(C.formatElapsed(60000), '1:00');
    assert.equal(C.formatElapsed(90000), '1:30');
    assert.equal(C.formatElapsed(-5000), '0:00');
    // CONCERN (cosmetic): minutes never roll over into hours.
    assert.equal(C.formatElapsed(3600000), '60:00');
  });

  test('formatTokenCount switches to k above 999 and drops a trailing .0', () => {
    assert.equal(C.formatTokenCount(0), '0');
    assert.equal(C.formatTokenCount(999), '999');
    assert.equal(C.formatTokenCount(1000), '1k');
    assert.equal(C.formatTokenCount(1500), '1.5k');
    assert.equal(C.formatTokenCount(1550), '1.6k'); // toFixed rounds
    // CONCERN (cosmetic): no M suffix, so large counts read as e.g. "1000k".
    assert.equal(C.formatTokenCount(999999), '1000k');
  });

  test('agentMeta returns the registered entry for a known agent', () => {
    assert.deepEqual(plain(C.agentMeta('fix')), {
      label: 'Fix', icon: 'edit', color: 'var(--text-dim)', role: 'Writes the proposed fix directly to your code',
    });
    assert.equal(C.agentMeta('remediation').label, 'Remediate');
    assert.equal(C.agentMeta('controls_assist').label, 'Control Scan');
  });

  test('agentMeta falls back to the raw name for an unregistered custom agent', () => {
    assert.deepEqual(plain(C.agentMeta('my_custom_agent')), {
      label: 'my_custom_agent', icon: 'gear', color: 'var(--muted)', role: '',
    });
  });

  test('every fix-flow stage has agent metadata', () => {
    for (const agent of ['triage', 'remediation', 'fix', 'verify']) {
      assert.ok(agent in C.AGENT_META, `${agent} is missing from AGENT_META`);
    }
  });
});

describe('relative time and scan filter labels', () => {
  // Offsets from "now" rather than fixed timestamps, since formatRelativeTime reads Date.now().
  const ago = (ms) => Date.now() - ms;

  test('a falsy timestamp renders as the empty string', () => {
    assert.equal(C.formatRelativeTime(0), '');
    assert.equal(C.formatRelativeTime(null), '');
    assert.equal(C.formatRelativeTime(undefined), '');
  });

  test('sub-minute is "just now", then m / h / d buckets', () => {
    assert.equal(C.formatRelativeTime(ago(0)), 'just now');
    assert.equal(C.formatRelativeTime(ago(30 * 1000)), 'just now');
    assert.equal(C.formatRelativeTime(ago(60 * 1000)), '1m ago');
    assert.equal(C.formatRelativeTime(ago(59 * 60 * 1000)), '59m ago');
    assert.equal(C.formatRelativeTime(ago(60 * 60 * 1000)), '1h ago');
    assert.equal(C.formatRelativeTime(ago(23 * 60 * 60 * 1000)), '23h ago');
    assert.equal(C.formatRelativeTime(ago(24 * 60 * 60 * 1000)), '1d ago');
    assert.equal(C.formatRelativeTime(ago(3 * 24 * 60 * 60 * 1000)), '3d ago');
  });

  test('CURRENT BEHAVIOUR: a future timestamp reads as "just now" rather than a negative age', () => {
    assert.equal(C.formatRelativeTime(Date.now() + 100000), 'just now');
  });

  test('scanFilterLabel names SCA scans distinctly and calls everything else a Hybrid scan', () => {
    assert.equal(
      C.scanFilterLabel({ scanType: 'sca', path: '/srv/app', startedAt: ago(60 * 60 * 1000) }),
      'SCA scan on /srv/app started 1h ago'
    );
    assert.equal(
      C.scanFilterLabel({ scanType: 'reasoning', path: '/srv/app', startedAt: ago(0) }),
      'Hybrid scan on /srv/app started just now'
    );
    // Anything not literally 'sca' is labelled Hybrid, including an absent scanType.
    assert.equal(
      C.scanFilterLabel({ path: '/srv/app', startedAt: ago(0) }),
      'Hybrid scan on /srv/app started just now'
    );
  });

  test('a scan with no startedAt renders a trailing "started " with nothing after it', () => {
    // CONCERN (cosmetic): formatRelativeTime returns '' for a missing timestamp and the
    // template does not account for that.
    assert.equal(C.scanFilterLabel({ scanType: 'sca', path: '/srv/app' }), 'SCA scan on /srv/app started ');
  });
});
