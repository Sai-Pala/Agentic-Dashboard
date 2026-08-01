# How the Scan Engine Works

Everything that happens between clicking **Start scan** and seeing findings in Agent Triage.

Each section gives the plain explanation first and the technical detail underneath, so you can
read the top of any section and understand it, or read all of it and be able to change the code.

---

## Contents

- [Part 1 — Orientation](#part-1--orientation)
  - [1.1 The file map](#11-the-file-map)
  - [1.2 The whole picture](#12-the-whole-picture)
  - [1.3 A scan, second by second](#13-a-scan-second-by-second)
- [Part 2 — Step 0: the map of the app](#part-2--step-0-the-map-of-the-app)
  - [2.1 What an AST is, concretely](#21-what-an-ast-is-concretely)
  - [2.2 What the map contains](#22-what-the-map-contains)
  - [2.3 Where the AST lives, and what it did not touch](#23-where-the-ast-lives-and-what-it-did-not-touch)
- [Part 3 — Engine A: pattern matching](#part-3--engine-a-pattern-matching)
  - [3.1 The line-local ceiling](#31-the-line-local-ceiling)
  - [3.2 TaintFlowAgent — following values](#32-taintflowagent--following-values)
  - [3.3 SecretsAgent — credentials](#33-secretsagent--credentials)
  - [3.4 UnusedGuardAgent — absences](#34-unusedguardagent--absences)
  - [3.5 VerifierAgent — the second opinion](#35-verifieragent--the-second-opinion)
- [Part 4 — Engine B: reasoning](#part-4--engine-b-reasoning)
- [Part 5 — Engine C: dependency audit](#part-5--engine-c-dependency-audit)
- [Part 6 — Putting it together](#part-6--putting-it-together)
  - [6.1 Deduplication](#61-deduplication)
  - [6.2 What a finding carries](#62-what-a-finding-carries)
  - [6.3 Live progress over WebSocket](#63-live-progress-over-websocket)
- [Part 7 — Reference](#part-7--reference)
  - [7.1 Every tunable number](#71-every-tunable-number)
  - [7.2 Failure modes](#72-failure-modes)
  - [7.3 How to add things](#73-how-to-add-things)
  - [7.4 Known limits](#74-known-limits)

---

# Part 1 — Orientation

## 1.1 The file map

The engine is smaller than it feels. This is all of it:

```
  server.js                      orchestrates everything, spawns claude, merges results
    │
    └── sast-engine/
         ├── enumerate.js         builds "the manifest" — the map of the app
         │    └── ast-extract.js  the ONLY file that touches the parser
         │
         ├── agents/
         │    ├── orchestrator.js      runs all agents, dedupes, calls the verifier
         │    ├── recon-agent.js       detects frameworks, finds files
         │    ├── verifier-agent.js    second-pass confirm/downgrade
         │    │
         │    ├── injection-tester.js      ┐
         │    ├── auth-bypass-agent.js     │  31 pattern agents.
         │    ├── secrets-agent.js         │  Each owns a list of regexes
         │    ├── taint-flow-agent.js      │  for one topic.
         │    ├── api-fuzzer.js            │
         │    └── … 26 more …              ┘
         │    └── unused-guard-agent.js    1 structural agent (reads the manifest)
         │
         ├── commands/deps.js         dependency audit
         └── remediation-apply.js     the only code that writes to disk

  agents/scan.md                  the system prompt for the AI pass
```

Import direction is strictly one-way — nothing lower reaches back up:

```
   @babel/parser ──► ast-extract.js ──► enumerate.js ──┬──► orchestrator.js
                                                       └──► server.js
```

## 1.2 The whole picture

**Plain version.** Three independent checks run at the same time against your directory. They
don't wait for each other. When all three finish, results are combined, duplicates removed, and
what's left becomes your findings.

Before they start, a fast fourth step builds a *map* of the application. It finds no bugs — but
two of the checks use it to do their jobs better.

```
                    ┌──────────────────────────────────────┐
                    │   You click "Start scan" on a path    │
                    └──────────────────┬───────────────────┘
                                       │
                    ┌──────────────────▼───────────────────┐
                    │  STEP 0: BUILD THE MAP               │
                    │  routes • guards • sinks • functions  │
                    │  (finds no bugs — just a map)         │
                    └──────────────────┬───────────────────┘
                                       │ manifest
             ┌─────────────────────────┴─────────────────────────┐
             │                                                   │
   ┌─────────▼─────────┐                              ┌──────────▼─────────┐
   │  A. PATTERN       │                              │  C. DEPENDENCY     │
   │     MATCHING      │                              │     AUDIT          │
   │                   │                              │                    │
   │  only the agents  │                              │  npm/pip/bundle    │
   │  relevant to this │                              │  audit shell-out   │
   │  target — 17 of   │                              │  ~3 s, $0.00       │
   │  32 on a plain    │                              │  deterministic     │
   │  Express app      │                              │                    │
   │  ~3-6 s, $0.00    │                              └──────────┬─────────┘
   │  IDENTICAL every  │                                         │
   │  single run       │                                         │
   └─────────┬─────────┘                                         │
             │                                                   │
             │ findings + manifest                               │
             ▼                                                   │
   ┌─────────────────────────────────────────────────┐           │
   │  B. REASONING (Claude) — TWO CONCURRENT PASSES   │           │
   │                                                  │           │
   │  ┌───────────────────┐  ┌────────────────────┐  │           │
   │  │ B1. ADJUDICATE    │  │ B2. REVIEW         │  │           │
   │  │ agents/           │  │ agents/scan.md     │  │           │
   │  │   adjudicate.md   │  │                    │  │           │
   │  │                   │  │ input: the         │  │           │
   │  │ input: A's        │  │ manifest worklist  │  │           │
   │  │ findings + code   │  │ + A's locations    │  │           │
   │  │                   │  │   ("skip these")   │  │           │
   │  │ "which are real?" │  │                    │  │           │
   │  │                   │  │ finds authz and    │  │           │
   │  │ kills false       │  │ business-logic     │  │           │
   │  │ positives         │  │ flaws              │  │           │
   │  │ cap $1.50         │  │ cap $3.50          │  │           │
   │  └───────────────────┘  └────────────────────┘  │           │
   │  measured: 271 s, $1.88 for both                 │           │
   └─────────┬───────────────────────────────────────┘           │
             │                                                   │
             │      ┌──────────────────────────────────────┐     │
             └──────►         MERGE + DEDUPLICATE          ◄──────┘
                    │         3 axes (see 6.1)             │
                    └──────────────────┬───────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │  Findings, each already triaged      │
                    └─────────────────────────────────────┘
```

**The ordering is the whole design.** A is free and finishes in seconds, so it runs *first* and
its output becomes B's input. An earlier version ran A and B concurrently, blind to each other,
and reconciled them afterwards with a dedupe step — that is a union of two scanners, not a
hybrid. It also meant B re-read every file A had just read while knowing nothing about what A
had found there.

**Technical version.** `handleScanMessage()` → `runHybridReasoningScan()`:

| | function | LLM? | deterministic? | when |
|---|---|---|---|---|
| A | `runDeterministicPatternScan()` | no | yes — byte-identical every run | first, awaited |
| B | `runLLMReasoningScan()` | yes | no | after A; two passes under `Promise.all` |
| C | `runDeterministicScaScan()` | no | yes | background throughout |

If one or two fail the scan still succeeds on what came back, with a `scan-warning`. It fails
outright only if all three fail.

## 1.3 A scan, second by second

Measured against a 16-file fixture that produced 68 pattern findings:

```
  t=0s     scan-started              ─────────────────────────────────────────
           │
  t=0s     ├────────────────────────────────────────┐
           │                                        │
           ▼                                        ▼
         build manifest + pattern agents          SCA audit
           │  parse every file, extract             │  (shares no data with
           │  routes/sinks; run only the            │   either half — just
           │  agents relevant to this target        │   awaited at the end)
  t=3s     │                                      ✓ done
           │
  t=3s   ✓ 17/17 agents + verifier done, 68 findings
           │
           │ findings + manifest
           │
  t=3s     ├────────────────────────┬───────────────────────────┐
           │                        │                           │
           ▼                        ▼                           │
        B1 ADJUDICATE            B2 REVIEW                      │
        40 findings              the route worklist             │
           │                        │                           │
           │ …streaming narration…  │ …streaming narration…     │
           │                        │                           │
  t=220s ✓ done  $0.91              │                           │
                                    │                           │
  t=271s                          ✓ done  $0.97                 │
                                    │                           │
           └────────────────────────┴───────────────────────────┘
                                   │
  t=271s                    MERGE + DEDUPE
                                   │
  t=271s                    scan-done  ────────────────────────────────────
```

Wall clock is `A + max(B1, B2)`, not `A + B1 + B2`. The two passes share no data with *each
other* — only with A, which has already finished — so sequencing them would add the shorter
one's runtime to every scan and buy nothing. Before this was fixed, adjudication alone took
268 s with the review pass only *starting* afterwards, which made a scan slower than the
module-partitioned design it replaced.

Note the shape: **two of the three engines are done in under 10 seconds.** The wall-clock cost of
a scan is almost entirely the AI pass.

---

# Part 2 — Step 0: the map of the app

**Plain version.** Before looking for anything wrong, the engine writes down what's *there*:
every URL the app answers, what security checks sit in front of each one, every place it touches
a database or filesystem or runs a command, and every security function with a count of how many
times it's actually used.

This is a map, not an audit. Nothing here is a finding.

It exists because of a subtle failure. Tell an AI "review this code for vulnerabilities" and it
reads like a smart person skimming — it reports what looks *interesting*. But the most dangerous
bugs are boring to look at. A missing ownership check isn't a suspicious line; it's the *absence*
of one. You only find those by asking the same few questions about every endpoint, methodically.
A checklist forces that.

## 2.1 What an AST is, concretely

The engine used to read code as **text**. Now it reads it as a **tree**. Same code, two
representations:

```
   YOUR CODE:     app.use('/api/admin', requireUser, admin)


   AS TEXT (what a regex sees) — one long string, no structure:
   ┌───────────────────────────────────────────────────────┐
   │ a p p . u s e ( ' / a p i / a d m i n ' , r e q u ... │
   └───────────────────────────────────────────────────────┘
     the regex must guess from punctuation: "quote after app.use?
     then some words separated by commas?"


   AS A TREE (what @babel/parser returns):

        CallExpression
        ├── callee: MemberExpression
        │            ├── object:   Identifier  "app"
        │            └── property: Identifier  "use"
        └── arguments:
             ├── [0] StringLiteral  "/api/admin"   ◄── the mount path
             ├── [1] Identifier     "requireUser"  ◄── a guard
             └── [2] Identifier     "admin"        ◄── the router
```

The tree already *knows* `"/api/admin"` is a string and that `requireUser` sits directly in the
argument list. The regex had to infer both, and that inference is where every extraction bug came
from:

```
  ┌─ the code ─────────────────────┬─ regex concluded ──┬─ the tree knows ─────┐
  │ /* app.get('/admin', auth) */  │ a real endpoint!   │ it's a Comment       │
  │ code: "app.get('/search'…)"    │ a real endpoint!   │ it's a StringLiteral │
  │ path.join(__dirname,'public')  │ __dirname = guard  │ it's a nested arg    │
  │ `https://${host}`              │ // starts a comment│ it's a template      │
  │ function f(){ … f() … }        │ f has a caller     │ it's f's own body    │
  │ module.exports = {\n requireX  │ a USE of requireX  │ it's an export list  │
  └────────────────────────────────┴────────────────────┴──────────────────────┘
```

Measured when the AST replaced the regex on this repo: **7 phantom endpoints removed, 0 real
endpoints lost.** Sinks dropped 275 → 158, mostly because the regex was matching function
*definitions* (`async function query(sql)`) as if they were SQL calls.

**How a file is processed:**

```
   for each .js / .ts / .jsx / .tsx file:
        │
        ├─ parseFile(content) ──► tree?  ──yes──► walk it: visit every node,
        │                                          record routes / mounts /
        │                                          sinks / definitions / uses
        │
        └───────────────────► null ──► fall back to the old regex path
                              (syntax error, exotic dialect)
                              ONE file degrades — never the whole run
```

Measured on this repo: **44 files, 44 parsed, 0 fallbacks.** The fallback exists for safety, not
because it fires.

The walk itself is one recursive function: visit a node, then visit its children. Land on a
`CallExpression` whose callee is `app.use` → record a mount. Land on a `FunctionDeclaration` →
record a definition. That is genuinely all it does.

**One correctness trap, silent and severe if reversed.** A non-computed member property
(`db.verifyPassword`) **must** count as a reference. Excluding it as "a property, not a variable"
sounds principled and reports every function reached through a CommonJS namespace import as never
called — the most common shape in the codebase. This was caught only by diffing the AST manifest
against the regex manifest before switching over.

## 2.2 What the map contains

```
   manifest = {
     routes: [
       { method: 'GET', path: '/:id', file: 'routes/orders.js', line: 9,
         middleware: ['requireUser'], inlineHandler: true }
     ],
     mounts: [
       { prefix: '/api/admin', mounted: 'admin', middleware: ['requireUser'] }
     ],
     sinks: [
       { kind: 'sql', file: 'routes/reports.js', line: 12 }
     ],
     securityFunctions: [
       { name: 'requireAdmin', file: 'middleware/auth.js', line: 41,
         callCount: 0, externalCallCount: 0 }      ◄── never applied!
     ],
   }
```

Rendered for a scan, it looks like this:

```
   ROUTES ─────────────────────────────────────────────────────────
     GET  /:id          orders.js:9    guards: [requireUser]
     POST /:id/refund   orders.js:56   guards: [requireUser]
     POST /backup       admin.js:10    guards: []          ◄── nothing!

   MOUNTS ─────────────────────────────────────────────────────────
     /api/orders  ──► orders    guards: []
     /api/admin   ──► admin     guards: [requireUser]      ◄── auth, but
                                                                not authz
   SECURITY FUNCTIONS ─────────────────────────────────────────────
     requireUser            14 uses
     requireAdmin            0 uses   ◄── written, never applied
     requireBillingService   0 uses   ◄── written, never applied
     safeMerge               0 uses   ◄── written, never applied
```

Three consumers:

1. **`UnusedGuardAgent`** reads `callCount === 0` and produces findings.
2. **The reasoning prompt** turns it into a per-route checklist (see Part 4).
3. **The Attack Surface page**, via `GET /api/scans/:id/surface`. The manifest is
   stored on the scan record so the map survives after the scan finishes — it is
   the only description the app has of the *shape* of the target, which is
   posture information no findings list conveys:

```
   ATTACK SURFACE                          31 endpoints · 7 routers

   ┌────────────┬────────────┬──────────────┬──────────────────┬─────────────┐
   │ 31         │ 7          │ 5            │ 2                │ 4           │
   │ Endpoints  │ Routers    │ NO GUARD     │ AUTHENTICATED    │ Unapplied   │
   │            │            │              │ ONLY             │ controls    │
   └────────────┴────────────┴──────────────┴──────────────────┴─────────────┘

   ▌/api/account → account   NO GUARD                          7 routes
    guards: nothing
      POST /signup          no route guard      account.js:12
      POST /login           no route guard      account.js:19
      POST /settings        requireUser         account.js:28

   ▌/api/admin  → admin     AUTHENTICATED, NOT AUTHORIZED      5 routes
    guards: requireUser

   CONTROLS NEVER APPLIED
     requireAdmin()            auth.js:41    0 call sites
     requireBillingService()   auth.js:52    0 call sites
```

   A left border colours each mount by `guardKindOf()`: red for no middleware at
   all, amber when the chain authenticates but never checks privilege, green when
   a privilege check is present. That middle case is the one worth surfacing —
   it reads as protected in review and lets every logged-in user reach the
   surface.

The orchestrator computes it once and puts it on `context.surface`, accepting `options.surface`
when the caller already built one — so it is never computed twice in a scan.

## 2.3 Where the AST lives, and what it did not touch

Worth stating plainly, because the engine has grown a lot:

**The AST changed exactly one thing.** It is confined to `ast-extract.js`, which has exactly one
importer. Delete that file and `enumerate.js` falls back to regex; everything else keeps working.

| | touched by the AST work? |
|---|---|
| The 31 pattern agents | **no** — still regex, still line-by-line |
| `TaintFlowAgent` | **no** — still its own regex state machine |
| `VerifierAgent` | **no** |
| Dependency audit | **no** |
| Merge / dedupe / triage / remediation loop | **no** |
| `enumerate.js` extraction | yes — this is the whole change |

---

# Part 3 — Engine A: pattern matching

**Plain version.** Think of 32 specialists, each expert in one narrow thing. One only looks for
hardcoded API keys. One only for SQL injection. One only checks XML parser settings. Each reads
every file and reports what it recognises. Fast, free, identical every run.

**Technical version.** `runDeterministicPatternScan()` calls `buildOrchestratorAsync(path)` then
`orchestrator.runAll(path, {onlyFiles, onAgentDone})`.

```
   ReconAgent          detect frameworks, discover files
        │
        ▼
   filter agents       shouldRun(recon) — a repo with no mobile code
        │              doesn't run the mobile scanner
        ▼
   onScopeReady(N)     tell the UI the REAL denominator  ◄── see note
        │
        ▼
   run agents in parallel, chunked by concurrency, each with a timeout
        │
        │  each finishing agent ──► onAgentDone ──► live scan-event
        ▼
   dedupe
        │
        ▼
   VerifierAgent       second pass over critical/high findings
```

> **Why `onScopeReady` exists.** Many agents are skipped by `shouldRun`. If the progress bar's
> denominator is the *registered* agent count, it permanently reads `27/32` — indistinguishable
> from a hung scan. The real total is sent before any agent completes.

> **An agent that doesn't finish is reported, not counted as clean.** The orchestrator has
> always recorded `success: false` for an agent that errored or timed out — but nothing read
> that field. The agent contributed zero findings, the progress bar still advanced, and no
> warning was emitted. So a scan that *could not finish* checking for SQL injection looked
> byte-for-byte like a scan that found none. On a small repo no agent came close to the
> deadline, which is why this survived; it only becomes likely at scale. It now emits a
> `scan-warning` naming each failed agent and stating that those classes were **not checked**,
> and the deadline is 180 s rather than the vendored 30 s default — every agent walks the whole
> file list, so its work scales with repo size while the deadline did not. Treat 180 s as a
> hang detector, not a work budget.

## 3.0.1 Relevance gating: why 32 agents doesn't mean 32 run

`BaseAgent.shouldRun()` defaults to `return true`. For a long time only three agents overrode it
meaningfully, which meant a plain Express API paid, on every scan, for a full Roblox/Luau pass, a
React Native Hermes bytecode pass, and every AI/agentic/MCP/RAG/model-scanning agent — none of
which could match anything in it.

Two of those were gated on signals `ReconAgent` **already computed and then discarded**: it
detects the Roblox toolchain (Rojo/Wally project files, `.rbxl*`/`.rbxm*`) and `react-native`,
while `RobloxSecurityAgent` and `HermesSecurityAgent` returned `true` regardless.

`ReconAgent` now also collects `mcpConfigs`, `aiFrameworks`, `vectorStores`, `agentConfigs` and
`modelFiles`, deliberately mirroring the exact filenames and dependency names the consuming
agents themselves open — a signal that doesn't match what an agent actually reads is worse than
no signal at all, because it gates the agent off its own input.

```
   TARGET                              AGENTS THAT RUN     WHY
   ─────────────────────────────────────────────────────────────────────
   Express + pg                        17 / 32   no AI, no mobile, no Roblox
   openai + @modelcontextprotocol/sdk  25 / 32   MCP + LLM + Agentic* on;
                                                 RAG off (no vector store)
   wally.toml + .luau                  15 / 32   Roblox on, every AI off,
                                                 npm-only agents off
   langchain + chromadb (Python)       21 / 32   RAG on via requirements.txt,
                                                 MCP correctly off
```

**Nothing was deleted.** Every agent is still registered and still runs wherever it applies.
Recon itself costs 3–35 ms.

Two traps worth keeping:

- **Filenames must be matched case-insensitively.** `CLAUDE.md` vs `claude.md`, `AGENTS.md` vs
  `agents.md` — the convention is not consistent, and a case miss silently disables the agent
  rather than failing loudly. This was caught only because a test target with a `CLAUDE.md`
  reported `agentConfigs = 0`.
- **"Has an assistant config" is not "is an agentic app."** `AgentConfigScanner` and
  `MemoryPoisoningAgent` gate on `agentConfigs` because the config file *is* their subject — a
  poisoned `CLAUDE.md` is the threat they detect. `AgenticSecurityAgent`, `ManagedAgentScanner`,
  `AgentAttestationAgent` and `AgenticSupplyChainAgent` deliberately do **not**, because they
  assess whether the *application* is agentic. A `CLAUDE.md` only means someone edits the repo
  with an assistant, and that describes a large and growing share of all repos.

## 3.1 The line-local ceiling

This is the single most important thing to understand about this engine.

```
   LINE-LOCAL — the whole bug fits on one line, so a regex sees it:

       db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)
                 └──────────── all of it, right here ──────────┘   ✓ caught


   CROSS-LINE — the same bug, spread out. Every line looks innocent:

       const id  = req.query.id;              ← user input arrives
       const sql = "SELECT ... id = " + id;   ← it travels
       db.query(sql);                         ← it arrives somewhere dangerous
                                                  ✗ no single line looks wrong
```

`BaseAgent.scanFileWithPatterns()` tests each regex against **one physical line**. No number of
extra rules fixes the second case — it's the shape of the machine, not a gap in the rule list.
That is precisely why the other two engines exist.

## 3.2 TaintFlowAgent — following values

The one pattern agent that deliberately breaks the one-line rule.

**Plain version.** It tracks a value from where untrusted data enters to where something
dangerous happens with it, even when those are far apart.

```
   line 12:  const raw    = req.query.url;      ● TAINTED   (source)
   line 13:  const parsed = new URL(raw);       ● still tainted (propagated)
   line 14:  if (!ALLOWED.includes(parsed.host))
   line 15:      return res.status(400);        ○ `parsed` cleared by the guard
   line 16:                                       …but `raw` was never checked
   line 17:  axios.get(raw);                    ▲ SINK reached with taint ✗ REPORT
```

That example is the whole design in miniature. The guard clears taint **only for the variable it
names**. `raw` is still tainted, so line 17 is still reported — and that is a real vulnerability
class: you validate one thing, then use another.

**The state machine, per variable:**

```
                 assigned from req.query/body/params
        ┌──────────────────────────────────────────┐
        │                                          ▼
   ┌─────────┐   assigned from a tainted var   ┌─────────┐
   │  CLEAN  │◄──────────────────────────────► │ TAINTED │
   └─────────┘                                 └─────────┘
        ▲                                          │
        │  parseInt() / Number() / validator.      │ reaches a sink
        │  literal ternary / anchored-regex guard  │ on a LATER line
        │  / reassigned to a constant              ▼
        └───────────────────────────────────  ✗ FINDING

   ALL taint resets at each function / route-handler boundary.
```

**Sinks it watches:**

| family | example |
|---|---|
| sql | `db.query(...)` |
| command | `exec(...)`, `spawn(...)` |
| filesystem | `readFile`, `sendFile`, `unlink` |
| code-eval | `eval`, `new Function` |
| ssrf | `axios.get`, `fetch` |
| xss | `res.send(...)` with HTML |
| redirect | `res.redirect(...)` |

**Precision mechanisms** — these stop it flagging *correct* code, which is the failure mode that
gets a scanner switched off:

| mechanism | stops flagging |
|---|---|
| `safeWhen` per sink | `db.query('… WHERE x = ?', [v])` — bound parameters |
| | `execFile('tar', ['-xzf', f])` — argv array, no shell |
| literal ternary / comparison | `req.query.r === 'year' ? 'year' : 'month'` |
| `_applyGuard()` | `if (!/^[a-f0-9]{32}$/.test(id)) return …` |

**Guard strength depends on the sink.** Not all validation is equal, and treating it as equal is
how a scanner misses the interesting half of SSRF:

```
   full.startsWith(DOC_ROOT)       ← the correct, complete fix for path
                                     containment      ⇒ clears taint for `path`

   target.startsWith('https://')   ← says NOTHING about the host.
                                     https://169.254.169.254/ passes it and
                                     reaches cloud metadata
                                                      ⇒ does NOT clear for `ssrf`
```

Guards are classified into kinds (`anchored-regex`, `allowlist`, `validator-lib`, `format-test`,
`prefix`) and each sink declares which kinds it accepts. Taint is *marked* rather than deleted,
because whether a guard was sufficient cannot be known until you see what the value reaches.

**Only the dangerous argument counts.** For every sink here that is the first one — the SQL
statement, the command, the path, the URL. Checking all arguments reports
`fs.writeFileSync(safePath, userContent)` as path traversal, which is the wrong vulnerability at
a correctly guarded call site.

Scope limits, deliberate: intra-procedural only, resets at function boundaries, gives up beyond
`MAX_FLOW_DISTANCE` (60 lines), and **only fires when the source line is earlier than the sink
line** — so it is purely additive and never restates a same-line finding.

**The flow is shown, not just the line.** Every cross-line finding carries `flow`
(`sourceLine`, `sinkLine`, and the lines between), rendered on Finding Detail:

```
   DATA FLOW
   Untrusted input enters at line 24 and reaches a dangerous operation 4 lines
   later, with nothing validating it in between.

   ▸ 24  const target = String(req.body.url || '');      USER INPUT ENTERS
     25  if (!target.startsWith('https://')) {
     26    return res.status(400).json({ error: 'https only' });
     27  }
   ▸ 28  const probe = await axios.get(target, …);       REACHES THE SINK
```

This is the one finding class where the *location* is not the explanation: "SSRF at line 28" is
unactionable without seeing that line 24 read a URL from the body and the only check in between
was a scheme prefix. Capped at a 25-line span — beyond that it is a wall of code, not an
explanation.

> One subtlety that must survive any rewrite: comment-stripping is **quote-aware**. A naive `//`
> strip truncates `https://…` at the protocol slashes and silently drops every flow through it.

## 3.3 SecretsAgent — credentials

**Plain version.** Finds credentials committed in code. Before it existed, secret detection ran
only against git history — so a non-git folder found nothing, and a secret that was never
committed (still live, never reviewed) could not be found at all.

**The filter pipeline:**

```
   a line matches a secret pattern
        │
        ├─ is it in an example/fixture file?      ──► downgrade to low
        ├─ is the value a placeholder?            ──► drop
        │     ("your-api-key-here", "REPLACE_ME", "xxxxx")
        ├─ is it read from the environment?       ──► drop
        │     (process.env, os.getenv, ENV[...])
        ├─ pattern needs entropy AND value is     ──► drop
        │  low-entropy? (Shannon < 3.0)
        │
        └──────────────────────────────────────►  ✗ REPORT (value masked)
```

Specific-prefix patterns (`AKIA…`, `sk_live_…`, `SG.…`) skip the entropy check — the prefix is
already proof. Generic ones (`apiKey = "…"`) require it.

**One rule deliberately bypasses two of those filters**, flagged `insecureDefault`:

```
   process.env.JWT_SECRET || 'dev-only-change-me'
   └────────── looks like config ─────────┘  └── but THIS is the live key
                                                  whenever the var is unset
```

Every other secret pattern skips lines containing `process.env` — reasonably, since that usually
means "reads from config." So this whole class was invisible. It's also exempt from the
placeholder filter, on the reasoning that a *guessable* default is worse than a high-entropy one,
not better.

## 3.4 UnusedGuardAgent — absences

**Plain version.** Reports security controls that exist but are never used. A codebase containing
`requireAdmin` that never applies it is *more* dangerous than one that never had it — a reviewer
reading the auth file sees a hardened system.

```
   auth.js      function requireAdmin(req,res,next){ ... }   ← written
                                                               ↓
   server.js    app.use('/api/admin', requireUser, admin)    ← never applied
                                       └────┬────┘
                                    authenticates ("you are someone")
                                    but never authorizes ("you may do this")

   ⇒ every logged-in customer can reach every admin route
```

**Decision logic:**

```
   for each security function in the manifest:
        callCount > 0 ?  ──yes──► skip
             │no
             ├─ enforcement-named (requireX, ensureX, authorize…)
             │       └──► SECURITY_CONTROL_NEVER_APPLIED      [high]
             └─ safety-named (safeX, sanitizeX, escapeX…)
                     └──► SAFE_HELPER_NEVER_USED              [medium]

   for each mount in the manifest:
        privileged-looking prefix? (admin|internal|manage|ops…)
             ├─ no middleware at all
             │       └──► PRIVILEGED_ROUTER_MOUNTED_UNGUARDED [high]
             └─ has middleware, but none is a privilege check,
                and the app defines one somewhere
                     └──► PRIVILEGED_SURFACE_AUTHENTICATED_
                          NOT_AUTHORIZED                      [high]
```

The last one is reported **at the mount, not at the unused control**, because the mount is where
the middleware has to be added.

Confidence is capped at **medium** for the unused-function rules: reference counting cannot see a
function invoked dynamically or wired by a framework decorator, so certainty would be
overclaiming.

## 3.5 VerifierAgent — the second opinion

**Plain version.** After the pattern agents finish, a second pass re-reads the code *around* each
serious finding and decides whether it still looks real. It can't delete findings, but it
downgrades them and attaches a reason — so anything you can dismiss in five seconds arrives
pre-labelled with why.

```
   finding: "Path traversal at sendFile"      ← from a line-local rule
        │
        ▼  read the 30 lines around it
   ┌──────────────────────────────────────────────────────┐
   │  if (!/^[a-f0-9]{32}$/.test(id))                     │
   │      return res.status(400)…      ← anchored check,  │
   │  res.sendFile(path.join(ROOT,id)) ← so only valid    │
   └──────────────────────────────────────────────────────┘
        │
        ▼
   verified: false
   note: "an anchored format check or allowlist guard rejects invalid
          values upstream, before this line runs"
```

**Check order** (first match wins, so the note names the real reason):

```
   1. in dead code (after return/throw)?      → not verified
   2. value is static/hardcoded, no input?    → not verified
   3. anchored validation guard upstream?     → not verified  ◄── narrow, strong
   4. generic sanitization upstream?          → not verified  ◄── broad, weak
   5. user input present, no sanitization?    → VERIFIED
   6. inside error handling?                  → not verified
   otherwise                                  → undetermined
```

Step 3 is deliberately narrower than step 4 — it requires an *anchored* regex test or an
allowlist check that returns/throws. A bare `.test(` would match far too much. Putting it in the
verifier rather than patching one regex fixes the class for **every** pattern agent at once.

---

# Part 4 — Engine B: reasoning

**Plain version.** This is Claude actually reading the code. It does two jobs, in two calls that
run at the same time: it decides which of the pattern engine's findings are real, and it looks
for what no fixed rule list can find — business-logic mistakes, authorization gaps, protections
defined in one file and never applied in another.

Both calls take Engine A's output as input. That is what makes this a hybrid rather than two
scanners run side by side.

```
   ENGINE A FINISHED (seconds, free)
        │
        ├──────────── findings ─────────┐        ┌──── manifest ────┐
        │                               │        │                  │
        ▼                               ▼        ▼                  │
   ┌─────────────────────────┐   ┌──────────────────────────────┐   │
   │ B1. ADJUDICATE          │   │ B2. REVIEW                   │   │
   │ agents/adjudicate.md    │   │ agents/scan.md               │   │
   │                         │   │                              │   │
   │ "Here are 40 findings   │   │ "Here is every route, its    │   │
   │  with their code.       │   │  middleware chain, every     │   │
   │  Which are real?"       │   │  mount, and every control    │   │
   │                         │   │  defined but never applied.  │   │
   │ reads the real files —  │   │  Answer 4 questions per      │   │
   │ the thing that makes a  │   │  route."                     │   │
   │ finding real is often   │   │                              │   │
   │ outside the snippet     │   │ + "these locations are       │   │
   │                         │   │    already reported — do     │   │
   │ ≤$1.50                  │   │    NOT report them again"    │   │
   │                         │   │ ≤$3.50                       │   │
   └───────────┬─────────────┘   └──────────────┬───────────────┘   │
               │                                │                   │
        verdicts per finding            new findings                │
        confirmed / needs_review        (authz, business logic)     │
        / false_positive                                            │
               └────────────────┬───────────────┘                   │
                                ▼                                   │
                          MERGE ◄───────────────────────────────────┘
```

**Why cost stops scaling with repo size.** B1 scales with *finding count*, B2 with *endpoint
count*. Neither scales with how many files you have, so a large codebase costs roughly what a
small one does. That is what removed the need for a per-scan spending ceiling: worst case is now
the sum of the two per-call caps, by construction.

## 4.1 What B1 (adjudicate) is for

Pattern matching has one structural weakness: it matches *syntax*, not *meaning*. It cannot tell
a real SQL injection from a parameterized query that happens to sit near a string concatenation.
That is not a fixable bug in the rules — it is what a regex is.

So the model is handed the findings and asked to check them against the real code. Measured on a
16-file fixture, 40 findings adjudicated in 220 s for $0.91, of which **10 were closed as false
positives** — every one correctly:

```
   CLOSED, AND WHY
   ───────────────────────────────────────────────────────────────────────
   "Route without auth check" on /login   →  it IS the endpoint that
                                             establishes authentication
   "Route without auth check" on /signup  →  registration cannot require
                                             an account — and by the way,
                                             line 13 accepts `role` from
                                             the body, which IS a real bug
   "SQL string concatenation"             →  that line contains no SQL; it
                                             is a tar shell command. The
                                             real command injection there
                                             is already findings 0 and 7
   "Hardcoded AWS access key"             →  AKIAIOSFODNN7EXAMPLE is the
                                             key AWS publishes in its own
                                             docs. The real credential is
                                             the DB password in store.js
   "HTTP header injection"                →  res.setHeader throws on CR/LF,
                                             so the response cannot split
   "Path traversal"                       →  line above rejects anything
                                             not matching /^[a-f0-9]{32}$/
```

Notice the pattern: several closures also *point at the genuine defect on the same line*. That is
the difference between suppressing a finding and understanding it.

**Nothing is ever deleted.** A `false_positive` verdict flows into the finding's synthetic
`triage` run, and `deriveStatus()` maps that to `status: 'closed'` — still created, still in the
table, still openable. A wrong adjudication costs visibility, not evidence. `adjudicate.md` is
also told explicitly to prefer `needs_review` over `false_positive` whenever the evidence is
incomplete, because closing a real vulnerability is a far worse outcome than leaving a false one
for a human to dismiss in ten seconds.

Bounded at **40 findings** per call (`ADJUDICATE_MAX_FINDINGS`), taken most-severe-first. Past
that, a prompt stops being a review and becomes a haystack. The overflow keeps its pattern-engine
verdict and the shortfall is reported in a `scan-warning` — never silently dropped.

## 4.2 What B2 (review) is for

**The worklist** from Step 0 — every route and sink, plus whole-app mount context — with four
questions it must answer per route:

```
   ## Enumerated attack surface
   Work through it item by item — do not skim for whatever looks most
   interesting, because the flaws that matter do not look interesting.

   ### Routes (5)
   For EACH route, answer all four before moving on:
     1. Who can reach it? (unauthenticated / any logged-in user / admin only)
     2. What request data does it trust without validating?
     3. What does it read or change, and could that belong to someone else?
     4. Is the authorization check the right one, or only authentication?

   - GET  /:id          orders.js:9    middleware: requireUser
   - POST /:id/refund   orders.js:56   middleware: requireUser
   …
   ### Mounts (whole app, for context)
   - /api/orders -> orders   guards: none
   ### Security functions defined but never called (whole app)
   - requireAdmin()  middleware/auth.js:41
```

### Why the review pass is sharded, and why removing the cap would not have worked

The obvious question is whether the review pass just needs a bigger budget. It does not, and
this is worth being precise about because the intuition is wrong in an expensive way.

```
   ONE CALL, 800 ROUTES, NO BUDGET CAP
        │
        ├─ worklist: fine, a few thousand tokens
        │
        ├─ but answering "who can reach it / what does it trust /
        │  could that data belong to someone else / is the check
        │  the right one" means READING 800 handlers plus the
        │  services they call
        │
        ▼
   context window fills
        │
        ▼
   claude -p COMPACTS  ← does not fail loudly
        │
        ▼
   the first ~300 routes' analysis is discarded
        │
        ▼
   result: bigger bill, SAME missing coverage, no warning
```

The dollar cap was never the binding constraint — **attention and context** are. Bounding the
routes per call is the only thing that fixes it, so `planReviewShards()` does that.

Shards are grouped **by file**, because sibling handlers have to be reviewed together: the
coupon-stacking and refund flaws above are only visible when routes that share state are seen
side by side. A file with more routes than one shard holds becomes its own oversized shard
rather than being split.

Shards are ordered **by risk**, because when there are more routes than shards, the ones that
get reviewed should be the ones most likely to be broken:

```
   SCORE PER FILE
     no middleware at all                      +3 per route
     middleware present, none privilege-like   +2 per route   ← reads as
                                                                protected, isn't
     dangerous sinks in the file               +1 each (max 5)
     existing pattern findings in the file     +2 each (max 6)
```

At 31 routes (the measured fixture) this is **one shard** — identical cost and behaviour to
before sharding existed. At 300 routes it is 6 shards covering the 240 highest-risk, with a
warning naming the 60 that were not reviewed. Turning the budget cap off raises the limit to
24 shards and drops the per-scan ceiling — an explicit choice of completeness over cost.

A shard's file list is **focus, not a sandbox.** The prompt says these are the routes it owns
and that it should not report issues rooted outside them (another shard owns those), but it may
read anything in the repository — answering "could this belong to someone else" almost always
means following the call into a service or model file elsewhere. A target with no HTTP surface
at all (library, CLI, worker) yields one unscoped shard.

Cost: ~1,300 tokens on the 31-route fixture. **Bounded, not fixed** — every section has a hard
cap (`WORKLIST_MAX_ROUTES`, `_MOUNTS`, `_UNUSED`, `_SINKS_PER_KIND`) and emits an explicit
"+N more not reviewed" line on overflow, so a large application cannot spend a call's entire
budget on its own instructions before reading a line of code. This worklist is also what
*replaced* module partitioning as the scoping mechanism: it grows with endpoint count, so a
single call can cover a whole repository without roaming.

On that same fixture B2 returned 7 findings, none of them duplicating Engine A:

```
   critical  Coupon stacking + unvalidated quantity drive the order total
             negative, turning /pay into a wallet credit
   critical  Refund amount taken from the body with no cap, paid-state
             check, or idempotency guard
   high      IDOR: GET /orders/:id returns any user's order
   high      POST /orders/:id/pay acts on another user's order
   medium    Host allowlist bypassable via redirects
   medium    Report queries not scoped to the requesting user
   medium    GraphQL filter object passed to Mongo, unauthenticated
```

Every one is an *absence* — a check that should exist and doesn't. None is findable by a regex,
and none was found by Engine A.

## 4.3 What this replaced

The previous design partitioned the target into up to 24 file-count-sized modules, ran one scoped
call per module plus an unscoped cross-cutting pass, three at a time, each with a scaled dollar
cap and a `$12` per-scan ceiling on top (`partitionReasoningModules()`, `splitFileGroup()`,
`moduleBudgetUsd()` — all deleted).

It worked, and it was a real improvement over the single unscoped call before it. But it solved
"bound the model's context" by **subdividing the input** rather than by **deriving scope from the
deterministic engine's output** — so cost still scaled with repo size, and the two engines stayed
blind to each other.

**Budgets are still measured, not guessed.** A flat `$0.50` cap was **not saving money**: a scan
that hit the cap cost `$2.31` and threw away its conclusion, while the same scan uncapped
completed at `$2.24`. You pay for the tokens either way; a cutoff just discards the answer.

```
   budget exhausted mid-call
        │
        ▼
   CLI exits non-zero, final event has:
        subtype: 'error_max_budget_usd'
        total_cost_usd: <real dollars>
        │
        ▼
   keep every finding reported before the cutoff,
   and say "coverage may be incomplete"
        │
        ▼           ✗ NOT the same as "nothing found"
   scan-warning
```

Each pass registers its child process under `${scan.runId}::mod${i}`, so cancelling a scan kills
both in-flight calls rather than just one.

---

# Part 5 — Engine C: dependency audit

**Plain version.** Checks your installed packages against known-vulnerable versions — what
`npm audit` does, auto-detecting whichever package manager you use.

**Technical version.** `runDepsAudit()` shells out to `npm audit --json` / yarn / pnpm /
`pip-audit` / `bundle-audit`, detected from lockfiles. Ignores scan scope entirely — a dependency
audit always reads the whole manifest. Signals its own completion the moment it resolves rather
than waiting on the other two.

**One trap worth knowing.** `npm` exits non-zero for two unrelated reasons — "vulnerabilities
found" (expected) and "couldn't run the audit at all" (a failure) — and writes JSON to stdout in
*both* cases:

```
   repo with no lockfile
        │
        ▼
   npm audit fails ──► error JSON on STDOUT (not stderr!)
        │
        ├─ OLD: saw stdout, parsed it, found no "vulnerabilities" key,
        │       returned []  ⇒ reported 0 findings
        │       …while the repo carried 11 real advisories, 2 critical
        │
        └─ NOW: assertNoAuditError() throws unless the payload is
                positively identifiable as a real report
                ⇒ surfaces as a scan-warning
```

A directory with no manifest at all is still a legitimately clean result — "nothing to audit" is
a valid outcome, distinct from "the audit broke."

---

# Part 6 — Putting it together

## 6.1 Deduplication

Three engines looking at the same code report the same problem three different ways. Each is
removed differently.

```
   ┌─ AXIS 1 ── reasoning vs pattern ────────────────────────────────┐
   │  Both spotted the same SQL injection.                           │
   │  Rule: drop the reasoning one if it lands within 2 lines of a   │
   │        pattern finding in the same file.                        │
   │  Findings with no resolvable line (business logic, SCA) always  │
   │  survive — there is nothing to compare them against.            │
   └─────────────────────────────────────────────────────────────────┘

   ┌─ AXIS 2 ── reasoning vs reasoning ──────────────────────────────┐
   │  Retained from the module design, where several independent     │
   │  calls routinely reported one issue 2-3x. With a single review  │
   │  pass it rarely fires, but still guards one call repeating      │
   │  itself. Titles differ wildly for the same issue:               │
   │    "requireAuth applied to zero routes"                         │
   │    "Payment, order and profile endpoints registered without …"  │
   │  ⇒ text comparison is useless; LOCATION is the signal.          │
   │  Sorted most-severe-first, so when two calls disagree           │
   │  (critical vs medium) the surviving copy is the worse reading.  │
   └─────────────────────────────────────────────────────────────────┘

   ┌─ AXIS 3 ── pattern vs itself ───────────────────────────────────┐
   │      app.use(...)  ← "no security headers"   ┐                  │
   │      app.use(...)  ← "no security headers"   │ collapse to one  │
   │      app.use(...)  ← "no security headers"   ┘                  │
   │  Collapsed only when within 3 lines. ADJACENCY IS LOAD-BEARING: │
   │  three SQL injections in one file are three real findings and   │
   │  must stay three. Distance separates "one condition observed    │
   │  repeatedly" from "several distinct sites".                     │
   └─────────────────────────────────────────────────────────────────┘
```

## 6.2 What a finding carries

Every finding arrives **already triaged** — there is no separate triage step to wait for. Where
that verdict comes from depends on which engine found it.

```
   PATTERN ENGINE ────────────────────────────────────────────────
       VerifierAgent output becomes the triage verdict
           verified      ⇒ verdict: "confirmed"
           not verified  ⇒ verdict: "needs_review"
           source: 'sast-engine-verifier'
       ⚠ cwe/owasp come from the rule that matched;
         asvs is null and nist_800_53 is empty — no mapping data

   REASONING ENGINE ──────────────────────────────────────────────
       the model triages what it finds in the same call
           full verdict + real owasp / asvs / cwe / nist mapping
           source: 'reasoning-scan'

   DEPENDENCY AUDIT ──────────────────────────────────────────────
       no triage run at all — the fix is "bump the version",
       so it never enters the remediation loop
```

That framework-mapping asymmetry is known and accepted, not hidden. A pattern-engine finding sits
with incomplete compliance mapping until a later Remediation or Threat-Model pass fills it in.

**Then the finding enters the remediation loop:**

```
   Found ──► Triaged ──► Remediated ──► Fixed ──► Verified
              (auto)      (propose)     (apply)   (re-check)
                             │             │
                        read-only     the ONLY step
                        no writes     that writes to disk,
                                      gated by a clean
                                      git working tree
```

## 6.3 Live progress over WebSocket

```
   browser                                server
      │  {type:'scan', runId, path, …}      │
      │ ───────────────────────────────────►│
      │                                      │
      │  scan-started                        │
      │ ◄────────────────────────────────────│
      │  scan-progress {engine:'sca',   1/1} │  each engine reports
      │  scan-progress {engine:'det',  7/17} │  its own progress
      │  scan-progress {engine:'reason',1/2, costUsd}
      │ ◄────────────────────────────────────│
      │  scan-event   (narration lines)      │  interleaved from ALL
      │ ◄────────────────────────────────────│  engines + both passes
      │  scan-warning (amber banner)         │  non-fatal notes
      │ ◄────────────────────────────────────│
      │  scan-done    {findings: [...]}      │
      │ ◄────────────────────────────────────│
```

`scan-event` is the same shape from every source. The pattern engine has no LLM narrating, so it
*synthesizes* assistant-text-shaped events carrying `[severity] message` lines — which is why the
browser's live feed works identically for all three without knowing the difference.

`scan-warning` is a **separate type from `scan-stderr`** for a real reason: the "one engine failed
but we recovered" summary used to be sent as `scan-stderr`, which the client silently discards
along with raw CLI chatter. A correctly-detected failure produced no visible signal anywhere.

---

# Part 7 — Reference

## 7.1 Every tunable number

| constant | value | what it controls |
|---|---|---|
| `REASONING_ADJUDICATE_BUDGET_USD` | 1.50 | cap on the adjudication pass |
| `REASONING_REVIEW_BUDGET_USD` | 3.50 | cap per review **shard** |
| `REASONING_REVIEW_TOTAL_USD` | 8.00 | ceiling across all review shards |
| `ADJUDICATE_MAX_FINDINGS` | 40 | findings per adjudication call |
| `REVIEW_ROUTES_PER_SHARD` | 40 | routes per review shard |
| `REVIEW_MAX_SHARDS` | 6 | shards with the budget cap on (~240 routes) |
| `REVIEW_MAX_SHARDS_UNCAPPED` | 24 | shards with the cap off |
| `REVIEW_SHARD_CONCURRENCY` | 3 | shards running at once |
| `DETERMINISTIC_AGENT_TIMEOUT_MS` | 180 000 | per-agent hang detector |
| `WORKLIST_MAX_ROUTES` / `_MOUNTS` | 60 / 60 | worklist section caps |
| `WORKLIST_MAX_UNUSED` | 40 | unused-control lines in a worklist |
| `WORKLIST_MAX_SINKS_PER_KIND` | 30 | sink lines per kind |
| `MAX_FLOW_DISTANCE` | 60 | taint source→sink line distance |
| `MIN_ENTROPY` | 3.0 | Shannon bits/char for generic secrets |
| `ADJACENT_RULE_LINES` | 3 | same-rule collapse distance |
| dedup proximity | 2 | reasoning-vs-pattern line distance |

## 7.2 Failure modes

The engine works hard to distinguish **"found nothing"** from **"couldn't look."** Those look
identical in a naive scanner and are the most dangerous thing a security tool can confuse.

| what happens | result |
|---|---|
| 1 of 3 engines fails | succeeds on the other two + warning |
| 3 of 3 engines fail | scan fails |
| 1 of N reasoning passes fails | succeeds on the survivors + "1/N passes had issues" |
| every reasoning pass fails | treated as the whole engine failing |
| budget exhausted mid-call | keeps partial findings, says coverage incomplete |
| a pattern agent times out | **warning naming it + "these classes were NOT checked"** |
| more than 40 pattern findings | 40 most severe adjudicated; rest keep their pattern verdict + warning |
| more routes than 6 shards hold | highest-risk reviewed; warning names how many were not |
| per-scan review ceiling hit | remaining shards skipped + warning; findings so far kept |
| `agents/adjudicate.md` missing | findings keep their pattern verdicts + warning; review still runs |
| audit tool broken | throws → warning (**never** a silent zero) |
| a file won't parse | that file falls back to regex |
| enumeration fails entirely | scan continues without a worklist + warning |

## 7.3 How to add things

```
   ADD A PATTERN RULE
     → find the right agent in sast-engine/agents/
     → add { rule, title, regex, severity, cwe, owasp, description, fix }
     → remember: the regex is tested against ONE LINE
     → then run a self-scan and check it produces no noise on real code

   ADD A WHOLE AGENT
     → new file in sast-engine/agents/, extend BaseAgent
     → implement shouldRun(recon) and analyze(context)
     → register it in agents/index.js (2 lines)
     → context gives you: rootPath, files, recon, options, surface

   ADD A SINK OR SOURCE TO TAINT TRACKING
     → sast-engine/agents/taint-flow-agent.js
     → SINKS[] for a new dangerous operation
     → TAINT_SOURCE for a new way untrusted data enters

   CHANGE WHAT THE AI IS ASKED
     → agents/scan.md is the system prompt
     → the per-call user prompt is built in runLLMReasoningScan()
     → the worklist text is renderWorklist() in enumerate.js
```

## 7.4 Known limits

Stated plainly, because a tool that hides these is worse than one that doesn't have them.

- **No call graph.** Taint is intra-procedural: a value tainted in a handler, passed to a helper,
  and used dangerously *inside that helper* is not tracked across the boundary. Measured evidence
  says this is a smaller gap than it sounds — CodeQL, which *has* a full interprocedural call
  graph, scored the same cross-line recall on the same code, because most of what remains is
  missing-check and business-logic bugs that no dataflow analysis finds.
- **Enumeration is structural, not semantic.** It parses properly now, but routes registered
  dynamically — a loop over a config array, a decorator, a generated router — still won't appear,
  because there is no static route string to read.
- **Tuned for JavaScript/TypeScript.** Other languages get the generic patterns and the
  dependency audit, not the route/taint/guard analysis.
- **The reasoning half varies between runs.** The deterministic half is byte-identical every time;
  the AI pass is not. It finds the same *vulnerabilities* far more consistently than it produces
  the same *text*, but it is not reproducible in the strict sense.
- **Unused-control detection counts references textually.** A function invoked dynamically reads
  as unused. Hence the medium-confidence cap.
- **Business logic remains the hardest class.** Multi-step flaws — a refund exceeding the original
  charge, a coupon redeemable twice — are found by the reasoning half or not at all.
