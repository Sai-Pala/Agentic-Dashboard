/**
 * Every tunable constant in the app, in one place.
 * Nothing here imports app code, so anything may require this module.
 */

const path = require('path');

const PORT = process.env.PORT || 4500;
// Loopback by default. There is no auth anywhere in this app and the WebSocket can write to
// the user's files, so "reachable" means "can write". Overriding HOST needs auth first.
const HOST = process.env.HOST || '127.0.0.1';

const ROOT_DIR = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const PROMPTS_DIR = path.join(ROOT_DIR, 'prompts');

// Agent names are joined into a filesystem path; run ids are used as Map keys and echoed back.
const AGENT_NAME_RE = /^[a-zA-Z0-9_-]+$/;
const RUN_ID_RE = /^[a-zA-Z0-9_-]+$/;
// A branch name is interpolated into a git argument (`${baseBranch}...HEAD`). execFileSync means
// no shell, but a value starting with `-` is still read by git as an OPTION rather than a ref, so
// the leading dash is excluded explicitly. `..` is excluded too: it is illegal in a refname and
// path-traversal-shaped. Neither is a legal branch name, so nothing valid is lost.
const BRANCH_NAME_RE = /^(?!-)(?!.*\.\.)[\w./-]+$/;

const PRIORITIES = ['p0', 'p1', 'p2', 'p3'];
// Scan RECORDS are all hybrid now — the standalone SCA page is gone and there is one dispatch.
// Leaving 'sca' here let a hand-crafted WebSocket message run both paid reasoning passes under
// an "SCA scan" label. Findings are a separate axis and still have an 'sca' kind, below.
const SCAN_TYPES = ['reasoning'];
const FINDING_SCAN_TYPES = ['reasoning', 'sca'];
const SCAN_SCOPES = ['full', 'diff'];

// Per-call caps for the reasoning half. Neither pass scales with repo size (adjudication
// scales with finding count, review with endpoint count), so worst-case spend is the sum of
// these by construction — except for review, where the cap is per *shard* and the per-scan
// ceiling below is what bounds the total.
const REASONING_ADJUDICATE_BUDGET_USD = 1.5;
const REASONING_REVIEW_BUDGET_USD = 3.5;
// Bounds the reasoning half as a whole: adjudication and every review shard both add
// into the same running total, so this is not review-only despite where it sits.
const REASONING_TOTAL_USD = 8.0;

// The review pass shards by attack surface because the *context window*, not the dollar cap,
// is the binding constraint: `claude -p` responds to a full context by compacting, silently
// discarding its own earlier analysis. Raising the budget alone buys a bigger bill and the
// same missing coverage.
const REVIEW_ROUTES_PER_SHARD = 40;
const REVIEW_MAX_SHARDS = 6;
// With the budget cap off the user has explicitly chosen completeness over cost; this higher
// ceiling remains only as a runaway backstop.
const REVIEW_MAX_SHARDS_UNCAPPED = 24;
const REVIEW_SHARD_CONCURRENCY = 3;

// Hang detector, not a work budget: every pattern agent walks the whole file list, so its work
// scales with repo size. Anything still running at this point is stuck, not slow.
const DETERMINISTIC_AGENT_TIMEOUT_MS = 180_000;

// Past this the adjudication prompt stops being a review and becomes a haystack. Findings over
// the cap keep their pattern-engine verdict and the shortfall is reported, never dropped.
const ADJUDICATE_MAX_FINDINGS = 40;

// Shipped with the app and load-bearing for hardcoded UI — editable, not deletable.
// Whole-directory agents — hidden from the per-finding UI.
const NON_FINDING_AGENTS = ['scan', 'adjudicate'];

function agentFilePath(name) {
  return path.join(PROMPTS_DIR, `${name}.md`);
}

module.exports = {
  PORT,
  HOST,
  PUBLIC_DIR,
  PROMPTS_DIR,
  AGENT_NAME_RE,
  RUN_ID_RE,
  BRANCH_NAME_RE,
  PRIORITIES,
  SCAN_TYPES,
  FINDING_SCAN_TYPES,
  SCAN_SCOPES,
  REASONING_ADJUDICATE_BUDGET_USD,
  REASONING_REVIEW_BUDGET_USD,
  REASONING_TOTAL_USD,
  REVIEW_ROUTES_PER_SHARD,
  REVIEW_MAX_SHARDS,
  REVIEW_MAX_SHARDS_UNCAPPED,
  REVIEW_SHARD_CONCURRENCY,
  DETERMINISTIC_AGENT_TIMEOUT_MS,
  ADJUDICATE_MAX_FINDINGS,
  NON_FINDING_AGENTS,
  agentFilePath,
};
