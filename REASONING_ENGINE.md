# How the Scan Engine Works

This document explains the backend mechanics of **Reasoning Scan** end-to-end — both halves:
the deterministic pattern-matching engine (`sast-engine/`, vendored from the open-source
`ship-safe` project) and the LLM reasoning engine (real `claude -p` calls against
`agents/scan.md`). They run concurrently against the same directory and their results are
merged. Everything here lives in `server.js` unless noted.

---

## 1. The big picture: two engines, one scan

```
                        ┌─────────────────────────────┐
                        │   User clicks "Start scan"   │
                        └──────────────┬──────────────┘
                                       │
                          handleScanMessage() validates
                          path / scope, creates a scan
                          record, then calls:
                                       │
                          runHybridReasoningScan()
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 │                                            │
                 ▼                                            ▼
   ┌───────────────────────────┐              ┌───────────────────────────────┐
   │   DETERMINISTIC HALF       │              │      REASONING HALF           │
   │   runDeterministicPattern  │              │      runLLMReasoningScan()    │
   │   Scan()   (section 2)     │              │      (sections 3-6)           │
   │                            │              │                                │
   │  sast-engine/: 29 regex/   │              │  Real claude -p calls against  │
   │  heuristic pattern agents  │              │  agents/scan.md — module-      │
   │  + VerifierAgent           │              │  scoped, budget-capped,        │
   │                            │              │  concurrency-limited           │
   │  No LLM. Fast, consistent. │              │                                │
   └─────────────┬──────────────┘              └────────────────┬───────────────┘
                 │                                               │
                 └─────────────────────┬─────────────────────────┘
                                       ▼
                     Promise.all() waits for BOTH to finish
                     (section 7 covers exactly how they merge)
                                       │
                                       ▼
                   Findings created, triaged, sent to the
                   Agent Triage table — tagged "Pattern
                   match" or "Reasoning" per source
```

---

## 2. The deterministic half (`sast-engine/`)

`runDeterministicPatternScan()` builds an `Orchestrator` and calls its `runAll()`. This is pure
JS pattern-matching plus a second-pass code-context check — no LLM anywhere in this half.

### 2a. Recon first — mapping the attack surface

Before any pattern agent runs, `ReconAgent` walks the directory once and builds a `recon` object:
languages, frameworks (Next.js, Roblox/Luau, Supabase, ...), API routes, auth patterns, databases,
cloud providers, CI/CD config, Docker/Terraform/Kubernetes presence, env/config files. This isn't
a security finding itself — it's context every other agent (and the framework-relevance filter
below) reads.

### 2b. Discovering files once, shared by every agent

`discoverFiles()` runs a single `fast-glob` pass respecting `SKIP_DIRS` / `SKIP_EXTENSIONS` /
`SKIP_FILENAMES` / `.gitignore` / `.sast-engineignore` / `MAX_FILE_SIZE` — the same file list every
one of the 29 agents then scans, so file discovery isn't repeated 29 times. A **"diff" scope**
scan additionally restricts this list up front to `options.onlyFiles` (the changed-file list),
before any agent sees it.

### 2c. Framework-relevance filtering (`shouldRun(recon)`)

Not every agent applies to every repo — `mobile-scanner` only makes sense on a mobile codebase,
`supabase-rls-agent` only if Supabase is actually in use, and 11 other agents have their own
`shouldRun(recon)` guard. `orchestrator.runAll()` filters the full 29-agent list down to
`relevantAgents` using this check **before** running anything:

```
  All 29 registered agents
  ┌─────────────────────────────────────┐
  │ InjectionTester, AuthBypassAgent,     │
  │ SSRFProber, MobileScanner,            │      shouldRun(recon) per agent
  │ SupabaseRLSAgent, ...                 │  ────────────────────────────▶
  └─────────────────────────────────────┘

  relevantAgents = 27       (e.g. this repo has no mobile code,
  (2 skipped)                no Supabase usage — those 2 agents
                              are filtered out, not run and marked
                              "0 findings")
```

> **A real bug this uncovered:** `runDeterministicPatternScan()` used to seed the "Pattern match"
> progress bar's `total` from `orchestrator.agents.length` — always 29, the full registered count
> — **before** this filtering happened. Any agent `shouldRun` skipped could never be counted by
> `onAgentDone`, so the bar permanently stalled below 100% (reproduced live: stuck at `27/29` for
> the rest of the scan) even though the deterministic half had already finished. Fixed by adding
> an `options.onScopeReady(relevantAgents.length)` callback, fired right after filtering and
> before the per-agent loop starts — `runDeterministicPatternScan()` uses it to correct `total`
> (and re-sends `scan-progress` with the corrected value) so the bar's denominator always matches
> what will actually run.

### 2d. Running the pattern agents (chunked concurrency)

`relevantAgents` run in chunks of `DEFAULT_CONCURRENCY` (6) via `Promise.allSettled`, each with a
`DEFAULT_TIMEOUT` (30s) per-agent ceiling:

```
  relevantAgents = [A1, A2, A3, A4, A5, A6, A7, A8, ...]
                     └──────── chunk of 6 ────────┘  └─ next chunk ─▶

  Promise.allSettled([A1.analyze(), ..., A6.analyze()])
       │
       ▼
  each settled result → onAgentDone(agentResult, findings)
       │                        │
       │                        ├─▶ send scan-progress {engine:'deterministic', done, total}
       │                        └─▶ send scan-event with one "[severity] file:line — title"
       │                            line per finding this agent found (narration-shaped, so
       │                            the client's existing severity-tag parser needs no changes)
       ▼
  a rejected/timed-out agent still counts toward `done` and still calls onAgentDone
  (with 0 findings + an error note) — one slow/broken agent can't stall the bar forever
```

Each pattern agent (`InjectionTester`, `AuthBypassAgent`, `SSRFProber`, ...) is just an array of
`{ rule, title, regex, severity, cwe, owasp, description, fix }` objects matched line-by-line
against every file (`scanFileWithPatterns()` in `base-agent.js`) — this is the "coverage" that
`buildCoverageSummary()` (section 4a) later tells the reasoning half about, by reading each
agent's own `name`/`description`/`category` rather than the pattern arrays themselves.

### 2e. The Verifier pass — confirm or downgrade

After every agent finishes and results are deduplicated, `VerifierAgent.verify()` re-checks
**critical/high severity findings only** (medium/low/informational are left as `verified: null`
— "not checked," not "unverified") by reading a 30-line window of real code around each finding:

```
  For each critical/high finding:
    ┌─ Is it in dead code (after a return/throw)?  ──▶ verified: false
    ├─ Is the value static/hardcoded, no user input? ──▶ verified: false
    ├─ Is there sanitization/validation upstream?    ──▶ verified: false
    ├─ Does user input reach it with no sanitization? ──▶ verified: true
    ├─ Is it inside a try/catch error handler?        ──▶ verified: false
    └─ None of the above match clearly                ──▶ verified: null (undetermined)

  Unverified (false) findings get downgraded one confidence level
  (high → medium → low) — the finding still survives, just less confident.
```

This is what feeds each deterministic finding's synthetic Triage verdict (section 7): `verified
=== true` → `confirmed`, anything else → `needs_review`.

### 2f. Confidence tuning and sort

One more deterministic pass adjusts confidence for context that's often noise: findings in test
files, doc files (`.md`/`.txt`/...), example/sample/demo paths, or on comment lines all get
downgraded (rarely upgraded). Findings are then sorted critical → high → medium → low →
informational and returned to `server.js`, which — per finding — synthesizes a Finding record
(`findingFromSastEngine()`) with a `triage` run already attached.

---

## 3. The reasoning half: turning a directory into scoped "modules"

The reasoning half used to make **one unscoped `claude -p` call over the entire target
directory**. That scales both token spend and hallucination surface directly with repo size —
nothing bounds how far the model can roam on a large codebase. So on a **"Full" scope** scan, the
directory gets partitioned into small, bounded chunks first.

```
  Target directory                       fast-glob enumerates every real file
  ┌─────────────────────┐                (respects sast-engine's own SKIP_DIRS /
  │ src/                │                SKIP_EXTENSIONS / SKIP_FILENAMES / .gitignore
  │   routes/            │   ────────▶   — the same "real code" definition the
  │     admin.js         │                deterministic engine uses)
  │     users.js         │
  │     ...(38 more)     │                        │
  │   services/          │                        ▼
  │     payments.js      │            ┌───────────────────────┐
  │   models/            │            │  flat list of every    │
  │     user.js          │            │  real file, as a       │
  │ lib/                 │            │  relative path          │
  │   utils.js           │            └───────────┬───────────┘
  │ package.json         │                        │
  └─────────────────────┘                        ▼
```

### 3a. Recursive size-based splitting (`splitFileGroup()`)

Files are grouped by path segment. Any group over `REASONING_MODULE_MAX_FILES` (30) gets split
one level deeper — not by directory *count*, by actual *file count*. This matters: a repo whose
only top-level entry is `src/` would see **zero benefit** from directory-based splitting (that
one "module" is still the whole codebase) — so if grouping by the current segment doesn't
separate anything, the algorithm tries the *next* segment instead of giving up.

```
depth 0:  { "src": 46 files }                  1 group, 46 > 30 → too big
              │
              │  grouping by depth-0 segment didn't separate anything
              │  (everything is under "src") — try depth 1 instead
              ▼
depth 1:  { "routes": 40, "services": 5, "models": 1 }     3 groups now!
              │                                             services + models
              │                                             are fine (< 30)
              ▼                                             routes is still 40 > 30
depth 2:  routes/ has no further subdirectories —
          grouping produces only 1 bucket again → give up,
          accept routes/ as one 40-file module as-is
          (bounded by --max-budget-usd regardless of size)

          Capped at REASONING_MODULE_SPLIT_MAX_DEPTH (3) levels of recursion.
```

### 3b. Bin-packing merge (small groups bundled together)

The reverse problem also matters: a repo with a dozen tiny directories (2-3 files each)
shouldn't spawn a dozen processes. Groups are sorted **smallest-first** and greedily packed into
buckets capped at `REASONING_MODULE_MAX_FILES` each — by actual size, not by arbitrary directory
order — up to `REASONING_MODULE_MAX` (24) total buckets.

```
  raw groups (smallest first):
  [ models:1 ]  [ smalldir3:2 ]  [ services:5 ]  [ smalldir1:2 ]  [ routes:40 ]

  bin-pack into buckets (≤ 30 files each):

  ┌───────────────────────────────────────────┐   ┌────────────────────┐
  │ Bucket A: models(1) + smalldir3(2) +        │   │ Bucket B:          │
  │ services(5) + smalldir1(2) = 10 files       │   │ routes(40) — too    │
  │ (all bundled — none alone was worth its      │   │ big to merge with   │
  │ own process)                                 │   │ anything, own       │
  └───────────────────────────────────────────┘   │ bucket regardless    │
                                                     └────────────────────┘

  A tiny repo naturally collapses into ONE bucket this way — there's no
  special-cased "skip partitioning" branch, it just falls out of the algorithm.
```

Each resulting module's `paths` is the **literal list of relative file paths** it covers (not a
directory reference) — the model gets an exact manifest instead of needing its own `Glob` call
to discover what's in scope, the same explicit-file-list style the diff-scope flow already used.

---

## 4. One scoped call per module, plus one unscoped "cross-cutting" pass

```
   modules = [ BucketA, BucketB, ... ]
                     │
                     │  a cross-cutting pass is appended too —
                     │  the ONE call that sees the whole tree
                     ▼
   modules = [ BucketA, BucketB, ..., { crosscut: true } ]
                     │
                     ▼
   ┌─────────────────────────────────────────────────────────────┐
   │             CONCURRENCY-LIMITED QUEUE (worker pool)           │
   │                                                                │
   │   at most REASONING_MODULE_CONCURRENCY (3) run at once        │
   │                                                                │
   │   ┌────────┐   ┌────────┐   ┌────────┐                       │
   │   │worker 1│   │worker 2│   │worker 3│   ◀── pulls the next   │
   │   └───┬────┘   └───┬────┘   └───┬────┘      queued module     │
   │       │            │            │            when it finishes  │
   │       ▼            ▼            ▼                              │
   │   claude -p     claude -p    claude -p                         │
   │   (Bucket A)    (Bucket B)   (crosscut)                        │
   └─────────────────────────────────────────────────────────────┘
```

### What each kind of call actually sees

```
  ┌─────────────────────────────┐      ┌─────────────────────────────┐
  │   MODULE CALL (Bucket A)     │      │   CROSS-CUTTING PASS          │
  │                               │      │                                │
  │  "Limit your review to only  │      │  "This is a cross-cutting      │
  │  the following files:        │      │  architectural pass — do NOT   │
  │   - models/user.js           │      │  re-review file internals in   │
  │   - services/payments.js     │      │  depth. Check whether           │
  │   - ...                      │      │  protections defined in one    │
  │  do not read or reason about │      │  place are applied everywhere  │
  │  anything outside them."     │      │  they should be — does every    │
  │                               │      │  route needing auth actually   │
  │  Same agents/scan.md system   │      │  invoke the middleware, not    │
  │  prompt. Sees ONLY its file   │      │  just have it defined nearby?" │
  │  list — cannot see whether    │      │                                │
  │  a middleware defined         │      │  Same system prompt, full      │
  │  elsewhere is even used.      │      │  Read/Grep/Glob access to the  │
  │                               │      │  ENTIRE tree — the one call    │
  │  Budget: $0.50                │      │  that can actually connect     │
  │  (REASONING_MODULE_BUDGET_USD)│      │  "defined here" to "used (or   │
  │                               │      │  not used) over there."        │
  │                               │      │                                │
  │                               │      │  Budget: $0.75                 │
  │                               │      │  (REASONING_CROSSCUT_BUDGET_USD)│
  └─────────────────────────────────┘      └─────────────────────────────────┘
```

> **Why bother with the cross-cutting pass?** Verified with a real side-by-side test: a route
> wired to a decoy `logRequest` middleware instead of the real `requireAdminAuth` (both defined
> in a separate file). The module-scoped call, seeing only the route file, *still* flagged it —
> via naming heuristics — but at `confidence: medium`, hedging "I could not confirm what
> logRequest actually does." The cross-cutting pass confirmed the same finding at
> `confidence: high` by grepping the whole repo and proving the real middleware has **zero call
> sites**. So its actual value is confidence + precision, not rescuing a total miss — module
> calls turned out to be more resilient than originally feared, but the cross-cutting pass still
> closes a real gap.

### 4a. Telling the model what's already covered (`buildCoverageSummary()`)

Every module call **and** the cross-cutting pass gets one more thing appended to its system
prompt, right after `agents/scan.md`'s own content: a short summary of what the deterministic
half (section 2) already checks, so the reasoning half spends its budget on business logic/
authz/attack-surface reasoning instead of re-deriving known pattern categories a regex already
covers for free.

```
  sast-engine/agents/index.js              Nothing is written by hand for this —
  ┌───────────────────────────────┐        it's the exact string already passed
  │  listBuiltInAgents()           │        to each agent's OWN constructor call:
  │   → [{name, description,       │  ◀───
  │       category}, ...]          │           super('SSRFProber',
  └───────────────┬─────────────────┘               'Detect Server-Side Request
                  │                                    Forgery vulnerabilities',
                  ▼                                  'ssrf')
  buildCoverageSummary(engine)  in server.js
  formats all 29 into one line each:

    "- SSRFProber (ssrf): Detect Server-Side Request Forgery vulnerabilities
     - AuthBypassAgent (auth): Detect authentication and authorization
       vulnerabilities
     - InjectionTester (injection): Detect injection vulnerabilities across
       all classes
     ...(26 more)"
                  │
                  ▼
       appended to systemPrompt — the SAME block goes into every
       module call and the cross-cutting pass for this scan
```

Two things this deliberately is **not**:

```
  NOT a second hand-maintained file          NOT the full per-rule detail
  ──────────────────────────────             ──────────────────────────────
  A separate doc listing "what             Each pattern's full regex +
  sast-engine covers" would drift          description + fix text (what
  the moment someone adds/edits an         findingFromSastEngine() actually
  agent in sast-engine/agents/ and         uses) would run to hundreds of
  forgets to update it. Reading            entries across 29 agents — real
  name/description/category straight       prompt bloat for a block repeated
  off the live agent objects means         on every module + crosscut call.
  it literally cannot go stale.            One line per agent keeps the
                                            whole thing to ~29 lines.
```

Cost: ~800 tokens total (verified), a small **fixed** cost per scan that doesn't scale with repo
size — unlike the module-partitioning cost above, which does. Cheap enough that it's added
unconditionally, on both "full" and "diff" scope scans, regardless of the Budget cap toggle.

---

## 5. What comes back from each reasoning call

Every `claude -p` process streams `stream-json` events. The server watches for two things:

```
  stdout stream (one JSON object per line)
  ─────────────────────────────────────────────────────────▶  time
  {type:"system"}  {type:"assistant", ...text...}  {type:"assistant", ...text...}  {type:"result"}
        │                    │                              │                          │
        │                    │                              │                          │
        ▼                    ▼                              ▼                          ▼
   relayed live as    text accumulated into        text accumulated,          captured as
   scan-event to      `fullText` (this is           narration relayed         `resultEvent` —
   the browser        where the trailing            live too                 the FINAL word on
   (live narration)   ```json block ends up)                                  how this call ended
```

When the process closes:

```
                     ┌─────────────────────────────┐
                     │  extractVerdict(fullText)     │
                     │  regexes out the fenced        │
                     │  ```json { "findings": [...] } │
                     │  block                          │
                     └───────────────┬─────────────────┘
                                     │
                     ┌───────────────┴────────────────┐
                     │                                  │
              exit code 0                        exit code ≠ 0
                     │                                  │
                     ▼                                  ▼
          normal success — findings          check resultEvent.subtype:
          kept as-is                                    │
                                          ┌──────────────┴──────────────┐
                                          │                              │
                              "error_max_budget_usd"           anything else
                                          │                              │
                                          ▼                              ▼
                          "hit its $0.50 budget cap        "claude exited with
                          before finishing — coverage       code N" (generic)
                          may be incomplete" — ANY
                          findings it did report are
                          still kept, not discarded
```

This distinction matters: before it was added, a budget-capped module that ran out of money
before writing its JSON block just silently produced **zero findings with no error at all** —
indistinguishable from "scanned this and found nothing." Now it's a visible, specific warning.

---

## 6. Cost tracking, the budget toggle, and cancellation

Every `result` event carries a real `total_cost_usd` field — actual dollar spend for that one
call, not a token-count estimate. The server sums this across every module + the cross-cutting
pass:

```
  Bucket A  ──▶ $0.31  ┐
  Bucket B  ──▶ $0.44  ├──▶  totalCostUsd = $1.12  ──▶  scan.reasoningCostUsd
  crosscut  ──▶ $0.37  ┘         │                       (persisted, GET /api/scans/:id)
                                  │
                                  ▼
                    sent live via scan-progress
                    {engine:'reasoning', done, total, costUsd}
                                  │
                                  ▼
                    Reasoning bar shows:
                    "2/3 modules done · $1.12"
```

The **Budget cap** toggle (top-right of the New Reasoning Scan form) controls whether
`--max-budget-usd` is passed to `claude -p` **at all**:

```
  Toggle: On  (default)          Toggle: Off
  ────────────────────           ──────────────────────────
  args.push(                     --max-budget-usd flag is
    '--max-budget-usd',          simply never added to the
    '0.50'                       spawned args — the call
  )                              runs until IT decides to
                                  stop, however long/expensive
  Every call is bounded.         that takes.
  Safe default.                  Explicit opt-in — shown as
                                  a small amber "No budget
                                  cap" chip on the scan card.
```

With the cap off, the budget-exhaustion detection path (section 5) simply never triggers —
there's no cap to exhaust — everything else about cost tracking still works exactly the same.

Because a "Full" scope scan can have several `claude` processes in flight at once, each one is
tracked under its own synthetic key instead of the scan's own `runId`:

```
  children Map (all in-flight claude processes, keyed by id):

    "abc123::mod0"     ──▶  Bucket A's claude process
    "abc123::mod1"     ──▶  Bucket B's claude process
    "abc123::mod2"     ──▶  crosscut's claude process

  scan.moduleRunIds = ["abc123::mod0", "abc123::mod1", "abc123::mod2"]

  On {type:"cancel", runId:"abc123"}:
    1. mark scan.status = 'cancelled'
    2. walk scan.moduleRunIds, kill() every child found in `children`
       (none of them are reachable via "abc123" directly — that's the
       whole reason moduleRunIds exists)
```

The deterministic half never spawns a child process (it's synchronous JS, no subprocess to
kill), so cancelling mid-scan is really only about stopping in-flight `claude -p` calls and
suppressing further `scan-event`/`scan-progress` relaying from the deterministic loop.

---

## 7. Merging the two halves into findings

`runHybridReasoningScan()` `Promise.all()`s both engines, then:

```
  detResult.findings ──▶ findingFromSastEngine() ──▶ Finding + synthetic triage run
                                                        (verdict from VerifierAgent's
                                                         `verified` field — see 2e)

  llmResult.findings ──▶ dedup check first:
    for each reasoning finding, does its file+line sit within 2 lines of
    a deterministic finding in the SAME file?
      │
      ├─ yes → drop it (same underlying issue, no need to show twice)
      │
      └─ no  → findingFromLLMScan() ──▶ Finding + synthetic triage run
               (verdict, severity_confirmed, confidence, priority, owasp,
                asvs, cwe, nist_800_53 — ALL assigned by scan.md itself,
                since the same call that found the issue also triaged it)

  Findings with no resolvable file+line (most business-logic/attack-surface
  findings) always survive dedup — there's nothing to compare them against.
```

The two synthetic triage verdicts are **not** built the same way, and this is a known,
documented asymmetry rather than an oversight:

```
  Deterministic finding's triage             Reasoning finding's triage
  ─────────────────────────────              ─────────────────────────────
  verdict: VerifierAgent's `verified`        verdict: scan.md's own real
    (true → confirmed, else →                  triage assessment (confirmed /
    needs_review — see section 2e)             needs_review / false_positive /
                                                duplicate)
  owasp/cwe: from the matched pattern        owasp/asvs/cwe/nist_800_53: all
    (real, deterministic)                      real — the model doing the
  asvs: always null                            reasoning also fills in the
  nist_800_53: always []                       full framework mapping
    (sast-engine has no mapping                 in the same pass
    for either — a known gap)
```

If one engine errors out entirely, the scan still succeeds on the other's results alone (a
`scan-warning` — not `scan-stderr`, see below — flags which one failed). If only *some* reasoning
modules fail while others succeed, the scan still succeeds on the surviving modules' findings.

A dedicated `scan-warning` WS message type exists for exactly this class of note (module/engine
partial failures, budget-exhaustion summaries) — distinct from `scan-stderr` (raw CLI stderr
chatter, silently discarded client-side). This was added after a real gap: before it existed,
these informational notes were themselves sent as `scan-stderr` and therefore silently dropped
by the client too, so a genuine partial failure produced no visible signal anywhere in the UI.

---

## Summary: the constants that shape all of this

| Constant                             | Value  | Half           | Meaning                                                        |
|---------------------------------------|--------|----------------|------------------------------------------------------------------|
| `DEFAULT_CONCURRENCY`                 | 6      | Deterministic  | Pattern agents run in chunks of this many at once                |
| `DEFAULT_TIMEOUT`                     | 30s    | Deterministic  | Per-agent ceiling before it's treated as failed                  |
| `BUILT_IN_AGENT_COUNT`                | 29     | Deterministic  | Total registered pattern agents (before shouldRun filtering)     |
| `REASONING_MODULE_MAX_FILES`          | 30     | Reasoning      | Target files per module before split/merge kicks in               |
| `REASONING_MODULE_SPLIT_MAX_DEPTH`    | 3      | Reasoning      | How many directory levels an oversized group can be split        |
| `REASONING_MODULE_MAX`                | 24     | Reasoning      | Hard cap on total modules after bin-packing merge                 |
| `REASONING_MODULE_BUDGET_USD`         | $0.50  | Reasoning      | Per-module dollar cap (when the toggle is on)                     |
| `REASONING_CROSSCUT_BUDGET_USD`       | $0.75  | Reasoning      | Cross-cutting pass's dollar cap (higher — samples the whole tree) |
| `REASONING_MODULE_CONCURRENCY`        | 3      | Reasoning      | Max claude processes running at once for one scan                 |

`DEFAULT_CONCURRENCY`/`DEFAULT_TIMEOUT`/`BUILT_IN_AGENT_COUNT` are defined in
`sast-engine/agents/orchestrator.js`/`index.js`; the `REASONING_*` constants are defined at the
top of `server.js`, alongside the code that uses them.

One more piece has no tunable constant because it isn't meant to be tuned — `buildCoverageSummary()`
derives its content live from `sast-engine/agents/index.js`'s `listBuiltInAgents()` every scan, so
it always matches whatever agents are actually registered (built-in or plugin) with no separate
value to keep in sync.
