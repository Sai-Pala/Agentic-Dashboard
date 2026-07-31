# How the Reasoning Engine Works

This document explains the backend mechanics of **Reasoning Scan** — specifically the LLM
("reasoning") half of it. For the deterministic half (`sast-engine/`'s 29 pattern agents), see
`CLAUDE.md`. Everything here lives in `server.js` unless noted, and the agent's own instructions
live in `agents/scan.md`.

---

## 1. The big picture: two engines, one scan

Every Reasoning Scan actually runs **two independent engines concurrently** against the same
directory, then merges their output. This file is only about the right-hand side.

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
   │   Scan()                   │              │      (this document)          │
   │                            │              │                                │
   │  sast-engine/: 29 regex/   │              │  Real claude -p calls against  │
   │  heuristic pattern agents  │              │  agents/scan.md — module-      │
   │  + VerifierAgent           │              │  scoped, budget-capped,        │
   │                            │              │  concurrency-limited           │
   │  No LLM. Fast, consistent. │              │  (see sections 2-5 below)      │
   └─────────────┬──────────────┘              └────────────────┬───────────────┘
                 │                                               │
                 └─────────────────────┬─────────────────────────┘
                                       ▼
                     Promise.all() waits for BOTH to finish
                                       │
                                       ▼
                    Dedup: drop a reasoning finding whose
                    file+line sits within 2 lines of a
                    deterministic finding (parseFileLine())
                                       │
                                       ▼
                   Findings created, triaged, sent to the
                   Agent Triage table — tagged "Pattern
                   match" or "Reasoning" per source
```

---

## 2. Turning a directory into scoped "modules"

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

### 2a. Recursive size-based splitting (`splitFileGroup()`)

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

### 2b. Bin-packing merge (small groups bundled together)

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

## 3. One scoped call per module, plus one unscoped "cross-cutting" pass

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

---

## 4. What comes back from each call

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

## 5. Cost tracking and the budget toggle

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

With the cap off, the budget-exhaustion detection path (section 4) simply never triggers —
there's no cap to exhaust — everything else about cost tracking still works exactly the same.

---

## 6. Cancellation

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

---

## Summary: the constants that shape all of this

| Constant                             | Value  | Meaning                                                        |
|---------------------------------------|--------|------------------------------------------------------------------|
| `REASONING_MODULE_MAX_FILES`          | 30     | Target files per module before split/merge kicks in              |
| `REASONING_MODULE_SPLIT_MAX_DEPTH`    | 3      | How many directory levels an oversized group can be split       |
| `REASONING_MODULE_MAX`                | 24     | Hard cap on total modules after bin-packing merge                |
| `REASONING_MODULE_BUDGET_USD`         | $0.50  | Per-module dollar cap (when the toggle is on)                    |
| `REASONING_CROSSCUT_BUDGET_USD`       | $0.75  | Cross-cutting pass's dollar cap (higher — samples the whole tree)|
| `REASONING_MODULE_CONCURRENCY`        | 3      | Max claude processes running at once for one scan                |

All defined at the top of `server.js`, alongside the code that uses them.
