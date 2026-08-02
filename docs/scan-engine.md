# The scan engine

One scan ("Hybrid Scan", internally `scanType: 'reasoning'`) runs **three engines over the same
directory** and merges their results. The display name and the internal value differ
deliberately — "reasoning" still names the LLM engine, which is only one of the three.

```
                    ┌─ deterministic (sast-engine)  ── findings + surface ─┐
runHybridReasoningScan ─┤                                                  ├─ merge/dedupe
                    └─ SCA (dependency audit) ─────────────────────────────┘
                             │
                             └─ reasoning (claude -p) ── runs AFTER deterministic,
                                                          takes its output as input
```

The ordering is the point: **the free engine's output is what scopes the expensive one.** An
earlier design ran them independently, which meant the paid engine re-read every file the free
one had just read while knowing nothing about what it found — a union of two engines, not a
hybrid.

## 1. Deterministic half

`runDeterministicPatternScan()`. 31 regex/heuristic pattern agents, a structural
`UnusedGuardAgent`, and a second-pass `VerifierAgent` that confirms or downgrades findings by
reading surrounding code. No LLM call anywhere in this half.

### Relevance gating

Only agents relevant to the target run, decided by each agent's `shouldRun(recon)` against
`ReconAgent`'s output. Measured: Express + `pg` → 17 of 32 agents; `openai` +
`@modelcontextprotocol/sdk` → 25; Rojo/Wally + `.luau` → 15; langchain + chromadb → 21. Recon
itself costs 3–35ms. Nothing was deleted — every agent still runs where it applies.

Three traps here:

- **A recon signal must mirror what the consuming agent actually reads.** A signal that doesn't
  match the agent's real input gates the agent off its own evidence. `ReconAgent` collects the
  same file lists and dependency names the agents themselves open.
- **Filenames are matched case-insensitively.** `CLAUDE.md` vs `claude.md`, `AGENTS.md` vs
  `agents.md` — the convention is not consistent, and a case miss silently disables the agent.
- **`AgentConfigScanner` and `MemoryPoisoningAgent` gate on `agentConfigs`; `AgenticSecurityAgent`,
  `ManagedAgentScanner`, `AgentAttestationAgent` and `AgenticSupplyChainAgent` deliberately do
  not.** The first pair treat the config file *as* their subject (a poisoned `CLAUDE.md` is the
  threat). The second group assess whether the *application* is agentic — and a `CLAUDE.md` only
  means someone edits the repo with an assistant. Gating that second group on `agentConfigs`
  fires them on the large and growing share of repos that merely contain an assistant config.

Gating is surfaced in the UI, not just the logs — the progress bar reports `17/17 agents done ·
15 n/a` with a tooltip naming each skipped agent, and the scan record carries
`agentsRun`/`agentsSkipped`. A bar reading "17/17" alone reads as though 17 is the whole engine.

The progress bar's denominator comes from `options.onScopeReady(realTotal, skippedNames)`,
invoked after `shouldRun` filtering and before any agent completes. Seeding it from
`orchestrator.agents.length` instead leaves the bar permanently stalled at e.g. `27/29`, since a
skipped agent's slot can never be filled.

### Per-agent deadline

`DETERMINISTIC_AGENT_TIMEOUT_MS` is 180s, not the orchestrator's 30s default. Every agent walks
the whole file list, so its work scales with repo size while a fixed deadline does not. It is a
hang detector, not a work budget.

### Two agents that differ in kind

- **`SecretsAgent`** runs `SECRET_PATTERNS` over **working-tree files**. Before it, that list had
  one consumer — `GitHistoryScanner`, which greps `git log --max-count=50` — so a non-git
  directory found nothing, a secret committed 51 commits ago was invisible, and a secret never
  committed could not be found by construction. It also implements the `requiresEntropyCheck`
  flag that 11 patterns declared with nothing acting on it. Specific-prefix patterns (`AKIA…`,
  `sk_live_…`) report unconditionally; generic ones are filtered by Shannon entropy plus
  placeholder and env-reference detection.
- **`TaintFlowAgent`** is the only agent that is not line-local.
  `BaseAgent.scanFileWithPatterns()` tests each regex against one physical line, so every other
  agent needs source and sink on the *same* line — which ordinary code isn't. It tracks
  variables from request data through assignment, concatenation, template literals and
  destructuring into seven sink families. Intra-procedural only; resets taint at function
  boundaries; clears taint through sanitizers and casts; and **only fires when the source is on
  an earlier line than the sink**, so it is purely additive and never restates a same-line
  finding.

### TaintFlowAgent precision — do not simplify

The agent would otherwise flag correctly-written code, which is the failure mode that matters
most: a scanner that cries wolf on the exact patterns developers are told to write gets ignored.

1. **`safeWhen` per sink** suppresses a hit when the call shape is safe regardless of taint —
   `PARAMETERIZED_QUERY` (a quoted statement literal followed by a bindings argument;
   deliberately *not* matching a template literal, which is the bug) and `ARGV_ARRAY_CALL`
   (`execFile`/`spawn` with an argv array, no shell).
2. **Literal ternaries and bare comparisons clear taint** — `req.query.x === 'a' ? 'a' : 'b'`
   collapses input to a fixed set; a boolean carries no payload.
3. **`_applyGuard()` clears taint for early-return-validated variables**, and clears **only the
   variables named in the condition**. A guard on `parsed.hostname` says nothing about a
   different variable fetched later — which is exactly the SSRF-allowlist-bypass this engine
   must keep finding. Any rework must preserve that distinction specifically.

Comment-stripping must stay quote-aware (`stripLineComment()`): a naive `//` strip truncates
`https://…` mid-URL and silently drops the flow through it.

## 2. Reasoning half

`runLLMReasoningScan()`. Two `claude -p` passes, run **concurrently with each other** but
**after** the deterministic half, since both take its output as input.

- **Adjudicate** (`agents/adjudicate.md`, `REASONING_ADJUDICATE_BUDGET_USD` = $1.50) takes the
  deterministic findings with code context and decides which are real. This removes false
  positives, which pattern matching structurally cannot do for itself — it matches *syntax*, not
  *meaning*, so it cannot tell a genuine SQL injection from a parameterized query sitting next to
  a string concatenation.

  **Nothing is ever dropped.** A finding called `false_positive` still gets created and stays
  inspectable in Agent Triage, just at `status: 'closed'`. A wrong adjudication costs visibility,
  not evidence. `adjudicate.md` is explicitly told to prefer `needs_review` whenever evidence is
  incomplete. Bounded at `ADJUDICATE_MAX_FINDINGS` (40, most-severe-first); the shortfall is
  reported in a `scan-warning`, not silently ignored.

- **Review** (`agents/scan.md`, `REASONING_REVIEW_BUDGET_USD` = $3.50 **per shard**,
  `REASONING_REVIEW_TOTAL_USD` = $8 per scan) takes the enumerated attack surface and asks the
  authorization and business-logic questions no fixed rule set can express. It is also handed the
  deterministic findings' locations under a "do NOT report these again" instruction — that
  avoidance is the other half of what makes this a hybrid rather than two independent scans.

### Why review is sharded

**The budget cap was never the binding constraint.** One call cannot genuinely answer four
questions about several hundred routes, and long before the dollar cap binds, the *context
window* does. `claude -p` responds to a full context by compacting, which silently discards its
own earlier analysis — so removing the cap buys a larger bill and the same missing coverage
without saying so. Bounding routes per call is the only thing that actually fixes it.

Routes are grouped **by file** (sibling handlers must be reviewed together — coupon-stacking and
refund flaws are only visible when routes sharing state are seen side by side), scored by risk
(no middleware `+3`; middleware present but none matching a privilege vocabulary `+2` — the
authenticated-but-not-authorized case that reads as protected and isn't), then packed
highest-risk-first into shards of `REVIEW_ROUTES_PER_SHARD` (40). A file with more routes than
that becomes its own oversized shard rather than being split.

40 keeps the measured 31-route fixture a single shard — identical cost and behaviour to before
sharding existed. Capped: `REVIEW_MAX_SHARDS` (6, ~240 routes). Uncapped (the form's toggle, an
explicit choice of completeness over cost): `REVIEW_MAX_SHARDS_UNCAPPED` (24).
`REVIEW_SHARD_CONCURRENCY` is 3. Overflow is reported in a `scan-warning` naming how many routes
were **not** reviewed.

A shard's file list is **focus, not a sandbox**: the prompt says these are its routes and it
should not report issues rooted in files another shard owns, but explicitly permits reading
anything in the repo — answering "could this data belong to someone else" almost always means
following a call into a service or model file elsewhere. A target with no HTTP surface yields
one unscoped shard.

### Cost

Neither pass scales with repo size — adjudication scales with finding count, review with
endpoint count. Worst-case spend is the sum of the per-call caps by construction, which is what
removed the need for a per-scan ceiling.

Spend is **aggregated, not estimated**: each call's real `total_cost_usd` sums into
`totalCostUsd`, rides live on `scan-progress`, and persists as `scan.reasoningCostUsd`.

Budget exhaustion is detected distinctly rather than swallowed as a clean "nothing found" — the
CLI exits non-zero with a `result` event carrying `subtype: 'error_max_budget_usd'`. Findings
reported before the cutoff are **kept**, because the scan paid for those tokens either way.

The cap is a per-scan toggle (`msg.budgetEnabled`, read as `!== false` so an old client still
gets the safe default). With it off, `--max-budget-usd` is omitted entirely rather than passed as
an enormous number, so the exhaustion path simply never triggers.

## 3. SCA half

`runDeterministicScaScan()` → sast-engine's `runDepsAudit()`, which shells out to whichever
package manager's audit tool is present (`npm audit --json`, `yarn`, `pnpm`, `pip-audit`,
`bundle-audit`), auto-detected from lockfiles. Ignores scope entirely — a dependency audit always
reads the whole manifest.

**A failed audit is reported as a failure, not a clean result** (`assertNoAuditError()`). `npm`
exits non-zero for two unrelated reasons — "vulnerabilities found" (expected) and "couldn't run
the audit at all" (a failure) — and writes JSON to stdout in *both* cases. The original
`if (err.stdout)` check treated a broken audit as a successful one and returned an empty list
with `error: null`. Measured: a repo with no lockfile reported **0** dependency findings while
carrying **11** real advisories, 2 critical. Anything not positively identifiable as a real
report now throws. A directory with no manifest at all is still a clean `pm: null` outcome —
"nothing to audit" is a legitimate result.

It signals its own completion the moment it resolves rather than waiting on the others, since
it's typically far the fastest.

## Merging

`runHybridReasoningScan()` awaits all three, then dedupes on three axes (`lib/merge.js`):

1. **Reasoning vs deterministic** — a reasoning finding within 2 lines of a deterministic one in
   the same file is dropped. Anything without a resolvable line (most business-logic findings,
   and every SCA finding, which is package-keyed) always survives.
2. **Reasoning vs reasoning** (`isDuplicateOfReasoning()`) — titles vary far too much between
   calls for text comparison ("requireAuth … applied to zero routes" vs "Payment, order, and
   profile endpoints registered without requireAuth"), but they land on the same line
   consistently, so **location is the signal**. Findings are sorted most-severe-first before
   deduping, so when two calls disagree on severity the surviving copy is the more severe
   reading.
3. **Deterministic vs itself** (`dedupeAdjacentSameRule()`) — collapses a rule firing on
   *consecutive* lines. **Adjacency is load-bearing**: three separate SQL injections in one file
   are three real findings and must stay three, so distance is what separates "one condition
   observed repeatedly" from "several distinct sites".

Together these took redundant rows from 23% to 16% of a run. All three have unit tests covering
the measured duplicates plus explicit "must not collapse" guards.

If one or two engines error, the scan still succeeds on whatever came back, with a
`scan-warning` per failure. It fails outright only if all three do.

## enumerate.js — attack-surface enumeration

Not a scanner: reports no vulnerabilities, makes no LLM call. It extracts what *exists* — every
HTTP route with its resolved middleware chain, every mount and its guards, every dangerous sink,
and every security-relevant function with its real call count.

Computed once per run onto `context.surface` (accepting `options.surface` when the caller already
built one, so it is never computed twice), and persisted onto the scan record as `scan.surface`.

Three consumers:

1. **The reasoning review pass**, as an explicit worklist with four questions per route. This
   exists because "review these files for vulnerabilities" produces a skim — the model reports
   what looks interesting. Authorization and business-logic flaws are not interesting-looking;
   they are *absences*, found only by asking the same question about every endpoint.
   **Enumeration converts free reading into forced answers.** ~1,300 tokens on the 31-route
   fixture, bounded per section (`WORKLIST_MAX_ROUTES`/`_MOUNTS`/`_UNUSED`/`_SINKS_PER_KIND`)
   with an explicit "+N more not reviewed" line, so a large app cannot spend a call's whole
   budget on its own instructions.
2. **`UnusedGuardAgent`**, which turns the manifest into findings no line-local rule can produce,
   because the evidence is an absence spread across the tree: `SECURITY_CONTROL_NEVER_APPLIED`,
   `SAFE_HELPER_NEVER_USED`, `PRIVILEGED_ROUTER_MOUNTED_UNGUARDED`, and
   `PRIVILEGED_SURFACE_AUTHENTICATED_NOT_AUTHORIZED` — the "admin gated by `requireUser` while
   `requireAdmin` sits unused" case, reported at the **mount** (where the middleware has to be
   added), and more dangerous than having no control at all because a reviewer reading `auth.js`
   sees a hardened system.
3. **The Attack Surface page**, which reads `scan.surface` back and renders it directly.

### Extraction traps

Extraction runs off a real parse tree (`ast-extract.js`, `@babel/parser`), falling back to the
regex path **per file** when a file won't parse, so a syntax error degrades one file instead of
blanking it. `options.forceRegex` still selects the regex path, which is how the two were diffed.

The migration happened because every extraction bug found was the same category — a regex losing
to syntax: routes enumerated out of `/* */` doc comments and out of string literals, `__dirname`
inside `path.join(__dirname, …)` read as a security guard, `https://` truncated by
comment-stripping. Measured on this repo: **7 phantom routes removed, 0 real ones lost**; sinks
275 → 158 (the regex matched function *definitions* like `async function query(sql)` as SQL
calls).

Four traps, each silent and severe if reversed:

- **A non-computed member property (`db.verifyPassword`) MUST count as a reference.** Excluding
  it as "a property, not a variable" reports every function reached through a CommonJS namespace
  import as never called.
- **Reference counting must exclude a function's own body** — a recursive helper nothing else
  calls is still unused.
- **It must exclude *multi-line* `module.exports = { … }` blocks.** An earlier version excluded
  only the first line, which made every exported function look called and silently defeated the
  whole check.
- **The privilege vocabulary needs a case-insensitive regex while the camelCase predicate check
  (`canX`/`isX`) needs a case-sensitive one.** Folding them into one `/i` regex stops
  `requireAdmin` matching `admin`.

Confidence is capped at medium for the unused-function rules, since textual reference counting
cannot see a function invoked dynamically or wired by a framework decorator.

## Scope

A `diff`-scope scan narrows both the deterministic half (`options.onlyFiles`) and the review
pass's worklist to the changed-file list. Adjudication is unaffected — it reviews findings, not
files. SCA ignores scope entirely.

## Live streaming

Both halves stream through the same `scan-event` type, interleaved in whatever order they
arrive; the client's parser doesn't care which produced a line. The deterministic half has no LLM
narrating, so `onAgentDone` synthesizes an assistant-text-shaped event carrying the same
`[severity] message` format the reasoning half emits naturally. Tool/token counters reflect only
the reasoning half's real activity.

`scan-warning` is distinct from `scan-stderr` (raw CLI chatter, silently discarded client-side)
and renders as an amber banner, appended rather than replaced. This distinction exists because
the partial-failure summary *was* originally sent as `scan-stderr` and therefore silently
dropped — a real induced failure produced no visible signal anywhere in the UI despite the server
correctly describing it.
