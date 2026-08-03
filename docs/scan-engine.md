# The scan engine

One scan ("Hybrid Scan", internally `scanType: 'reasoning'`) runs **three engines over the same
directory** and merges their results. The display name and the internal value differ
deliberately — "reasoning" still names the LLM engine, which is only one of the three.

```
                    ┌─ deterministic (Opengrep) ──── findings ─────────────┐
runHybridReasoningScan ─┤                                                  ├─ merge/dedupe
                    └─ SCA (dependency audit) ─────────────────────────────┘
                             │
                             ├─ enumerate.js ─────── attack surface (sast-engine)
                             │
                             └─ reasoning (claude -p) ── runs AFTER deterministic,
                                                          takes its output as input
```

The ordering is the point: **the free engine's output is what scopes the expensive one.** An
earlier design ran them independently, which meant the paid engine re-read every file the free
one had just read while knowing nothing about what it found — a union of two engines, not a
hybrid.

The attack surface is drawn separately now, and that is a change worth noticing: it used to
arrive as a by-product of the pattern engine's `runAll()`. Opengrep is a rule runner, not a
framework-aware mapper, and never will be — so `scanner.js` calls `engine.enumerateSurface()`
directly. Losing that silently would be expensive, because the review pass is *sharded* by these
routes; with no surface it reviews the whole tree unscoped.

## 1. Deterministic half — Opengrep

`runOpengrepScan()` (`src/services/engines/opengrep.js`). Shells out to the `opengrep` binary
with `--config p/default --taint-intrafile --json`, and maps each result into the same finding
shape the rest of the pipeline already consumed. No LLM call anywhere in this half.

**Opengrep rather than Semgrep for exactly one reason:** `--taint-intrafile`, inter-procedural
taint tracking within a file, which Semgrep keeps behind its paid tier. They are otherwise the
same engine — a fork, same licence, byte-identical output on the benchmark (23 findings, none
unique to either). Verified on a purpose-built case where `req.body` enters in one function and
reaches `exec()` in another: Semgrep and plain Opengrep find nothing; Opengrep with the flag
finds it.

That is the whole point of moving off regex. `/exec\(.*\+/` cannot know whether the thing being
concatenated is attacker-controlled; a taint rule fires only when it actually is.

Measured on DVNA against that repo's own documentation: the old regex engine found 3 of the 10
vulnerabilities a fixed rule set should be able to find. Opengrep found 6, in 5 seconds instead
of 210, with no rules written.

### Traps in the Opengrep half

- **A rule that failed to run is a coverage hole, not a clean result.** `report.errors` is
  turned into a `scan-warning` naming how many rules or files went unchecked. This is the same
  invariant the old failed-agent reporting existed for, and it is the one a scanner cannot drop.
- **Exit code 1 means "findings were reported" and is success here.** This app decides what
  blocks, not the scanner. Only codes above 1 are real failures.
- **The locale must be forced to UTF-8.** Opengrep aborts with a `UnicodeDecodeError` on any rule
  file containing a non-ASCII character — an em dash in a `message:` field is enough — when the
  inherited locale is ASCII.
- **`report.paths.scanned` is ground truth for coverage.** It is what the engine actually parsed,
  so the coverage manifest is built from it rather than re-derived.
- **More rule packs is not more coverage.** Measured: adding `p/security-audit`, `p/javascript`,
  `p/nodejs` and `p/owasp-top-ten` to `p/default` produced *fewer* findings (12 vs 23) and lost
  every XSS result. `p/default` stays a single deliberate choice.

There is no `VerifierAgent` on this path, so `finding.verified` is always `null` — "not checked",
never "unverified". That is why Opengrep findings land at `needs_review` rather than being
treated as suspect, and why the adjudication pass matters more than it used to.

---

## 1b. DORMANT — the vendored pattern engine

Everything in this section describes `runDeterministicPatternScan()` in
`src/services/engines/deterministic.js`, which **nothing has called since the Opengrep swap.**
It is parked rather than deleted: its 11 AI/agentic agents have no Opengrep equivalent, and the
overlap between the two engines has not been measured. Do not delete it until it has been.

Read this section as history unless you are re-wiring that engine. Everything it says about
`agentsRun`/`agentsSkipped`, the roster, recon, and the per-agent progress bar is accurate *for
that engine* and inert today — the Insights screen's "Pattern agents" and "Detected stack"
sections render nothing on a current scan for exactly this reason.

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

- **Adjudicate** (`prompts/adjudicate.md`, `REASONING_ADJUDICATE_BUDGET_USD` = $1.50) takes the
  deterministic findings with code context and decides which are real. This removes false
  positives, which pattern matching structurally cannot do for itself — it matches *syntax*, not
  *meaning*, so it cannot tell a genuine SQL injection from a parameterized query sitting next to
  a string concatenation.

  **Nothing is ever dropped.** A finding called `false_positive` still gets created and stays
  inspectable in Agent Triage, just at `status: 'closed'`. A wrong adjudication costs visibility,
  not evidence. `adjudicate.md` is explicitly told to prefer `needs_review` whenever evidence is
  incomplete. Bounded at `ADJUDICATE_MAX_FINDINGS` (40, most-severe-first); the shortfall is
  reported in a `scan-warning`, not silently ignored.

- **Review** (`prompts/scan.md`, `REASONING_REVIEW_BUDGET_USD` = $3.50 **per shard**,
  `REASONING_TOTAL_USD` = $8 per scan) takes the enumerated attack surface and asks the
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
   the same file is **merged into it, not dropped**. Two engines independently flagging one
   location is the strongest signal this app produces, so neither half may be discarded in favour
   of the other: the pattern hit carries the structured fields (rule, CWE, code context, taint
   span) and the reasoning finding carries the explanation of *why* it is exploitable, which is
   the half a human actually needs. They become one finding whose triage verdict records
   `corroborated: true`.

   One reasoning finding per pattern hit — the first match wins, so a cluster of reasoning
   findings cannot all collapse onto one line. Anything without a resolvable line (most
   business-logic findings, and every SCA finding, which is package-keyed) always survives as its
   own finding.
2. **Reasoning vs reasoning** (`isDuplicateOfReasoning()`) — titles vary far too much between
   calls for text comparison ("requireAuth … applied to zero routes" vs "Payment, order, and
   profile endpoints registered without requireAuth"), but they land on the same line
   consistently, so **location is the signal**. Findings are sorted most-severe-first before
   deduping, so when two calls disagree on severity the surviving copy is the more severe
   reading.
3. **Deterministic vs itself** (`groupAdjacentSameRule()`) — collapses a rule firing repeatedly
   within `ADJACENT_RULE_LINES` (3), anchored to the group's first line so a group can never
   drift. **Adjacency is load-bearing**: three separate SQL injections in one file
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
narrating, so it synthesizes an assistant-text-shaped event carrying the same `[severity] message`
format the reasoning half emits naturally. That frame lives in one place —
`sendScanText()` in `src/services/engines/emit.js`, shared by Opengrep, SCA and the dormant
pattern engine — because it nests four deep and a malformed one fails *silently*: the client
drops it and the scan reads as having produced no output. Tool/token counters reflect only
the reasoning half's real activity.

`scan-warning` is distinct from `scan-stderr` (raw CLI chatter, silently discarded client-side)
and renders as an amber banner, appended rather than replaced. This distinction exists because
the partial-failure summary *was* originally sent as `scan-stderr` and therefore silently
dropped — a real induced failure produced no visible signal anywhere in the UI despite the server
correctly describing it.

## Reference: every tunable number

| constant | value | controls |
|---|---|---|
| `REASONING_ADJUDICATE_BUDGET_USD` | 1.50 | cap on the adjudication pass |
| `REASONING_REVIEW_BUDGET_USD` | 3.50 | cap per review **shard** |
| `REASONING_TOTAL_USD` | 8.00 | ceiling across the whole reasoning half (adjudication + review) |
| `ADJUDICATE_MAX_FINDINGS` | 40 | findings per adjudication call |
| `REVIEW_ROUTES_PER_SHARD` | 40 | routes per review shard |
| `REVIEW_MAX_SHARDS` | 6 | shards with the budget cap on (~240 routes) |
| `REVIEW_MAX_SHARDS_UNCAPPED` | 24 | shards with the cap off |
| `REVIEW_SHARD_CONCURRENCY` | 3 | shards running at once |
| `OPENGREP_BIN` | `opengrep` | binary to spawn; override to pin a path |
| `OPENGREP_CONFIG` | `p/default` | the rule pack — see "more packs is not more coverage" above |
| `OPENGREP_TIMEOUT_MS` | 300000 | hang detector for the whole Opengrep run |
| `DETERMINISTIC_AGENT_TIMEOUT_MS` | 180000 | per-agent hang detector — **dormant**, see §1b |
| `WORKLIST_MAX_ROUTES` / `_MOUNTS` | 60 / 60 | worklist section caps |
| `WORKLIST_MAX_UNUSED` | 40 | unused-control lines in a worklist |
| `WORKLIST_MAX_SINKS_PER_KIND` | 30 | sink lines per kind |
| `MAX_FLOW_DISTANCE` | 60 | taint source→sink line distance |
| `MIN_ENTROPY` | 3.0 | Shannon bits/char for generic secrets |
| `ADJACENT_RULE_LINES` | 3 | same-rule collapse distance |
| dedup proximity | 2 | reasoning-vs-pattern line distance |

## Reference: failure modes

The engine works to distinguish **"found nothing"** from **"couldn't look."** Those look
identical in a naive scanner and are the most dangerous thing a security tool can confuse.

| what happens | result |
|---|---|
| 1 of 3 engines fails | succeeds on the other two + warning |
| 3 of 3 engines fail | scan fails |
| 1 of N reasoning passes fails | succeeds on the survivors + "1/N passes had issues" |
| every reasoning pass fails | treated as the whole engine failing |
| budget exhausted mid-call | keeps partial findings, says coverage incomplete |
| Opengrep not installed / not on PATH | scan fails with an install hint naming `OPENGREP_BIN` |
| Opengrep reports rule or parse errors | **warning naming how many files/rules were NOT checked** |
| Opengrep emits unparseable JSON | reported as an engine failure, never as zero findings |
| a pattern agent times out (§1b, dormant) | **warning naming it + "these classes were NOT checked"** |
| more than 40 pattern findings | 40 most severe adjudicated; rest keep their pattern verdict + warning |
| more routes than 6 shards hold | highest-risk reviewed; warning names how many were not |
| per-scan review ceiling hit | remaining shards skipped + warning; findings so far kept |
| `prompts/adjudicate.md` missing | findings keep their pattern verdicts + warning; review still runs |
| audit tool broken | throws → warning (**never** a silent zero) |
| a file won't parse | that file falls back to regex |
| enumeration fails entirely | scan continues without a worklist + warning |

## Reference: how to add things

**A detection rule** — write Opengrep/Semgrep YAML. Prefer a `mode: taint` rule with
`pattern-sources` and `pattern-sinks` over a syntactic `pattern`: taint is the reason this engine
was chosen, and a syntactic rule reintroduces exactly the false positives the adjudication pass
now pays to close. Point `OPENGREP_CONFIG` at a directory to run local rules alongside a pack.

**A pattern rule / a whole agent (§1b, dormant)** — these still work if you re-wire
`deterministic.js`, but nothing runs them today. Rule: find the right agent under
`sast-engine/rules/<domain>/` and add `{ rule, title, regex, severity, cwe, owasp, description,
fix }`; the regex is tested against **one line**. Agent: new file under the same tree extending
`BaseAgent`, implement `shouldRun(recon)` and `analyze(context)`, register it in
`sast-engine/rules/index.js`. `context` gives you `rootPath`, `files`, `recon`, `options`,
`surface`.

**A taint sink or source** — `sast-engine/rules/web/taint-flow-agent.js`: `SINKS[]` for a new
dangerous operation, `TAINT_SOURCE` for a new way untrusted data enters.

**What the AI is asked** — `prompts/scan.md` is the system prompt; the per-call user prompt is
built in `runLLMReasoningScan()`; the worklist text is `renderWorklist()` in `enumerate.js`.

## Known limits

Stated plainly, because a tool that hides these is worse than one that doesn't have them.

- **No call graph across files.** Opengrep's `--taint-intrafile` does follow a value from a
  handler into a helper *in the same file* — that is why it was chosen over Semgrep. What none of
  it crosses is a file boundary: a value tainted in `routes/user.js`, passed to a helper in
  `services/db.js`, and used dangerously there is not tracked. (The dormant pattern engine's
  taint was weaker still — intra-*procedural*, resetting at every function boundary.)
- **Enumeration is structural, not semantic.** Routes registered dynamically — a loop over a
  config array, a decorator, a generated router — won't appear, because there is no static route
  string to read.
- **Tuned for JavaScript/TypeScript.** Other languages get the generic patterns and the
  dependency audit, not the route/taint/guard analysis.
- **The reasoning half varies between runs.** The deterministic half is byte-identical every
  time; the AI pass is not.
- **Unused-control detection counts references textually.** A function invoked dynamically reads
  as unused — hence the medium-confidence cap.
- **Business logic remains the hardest class.** Multi-step flaws (a refund exceeding the original
  charge, a coupon redeemable twice) are found by the reasoning half or not at all.
