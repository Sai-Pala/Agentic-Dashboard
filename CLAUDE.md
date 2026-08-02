# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## What this is

A local, single-user AppSec tool. It scans a target directory for security findings, then walks
each finding through a fix pipeline. Two things run the scan: a deterministic pattern engine
(`sast-engine/`, no LLM) and `claude -p` reasoning passes. Results merge into one finding list,
streamed live to a browser UI over WebSocket.

Everything is in-memory and session-lifetime. There is no database, no auth, no build step.

## Commands

```bash
npm install
npm start     # node server.js — http://localhost:4500
npm test      # node --test "test/**/*.test.js" — 478 tests, ~30s
```

`claude auth status` must succeed before any LLM-backed feature works; the server spawns the
CLI non-interactively and does not handle auth itself.

There is no lint script and no build step. `public/` is served as-is — the client is native ES
modules (`<script type="module">`), so **adding a bundler would be a regression**, not an
upgrade.

## Repo map

Layered: routes are controllers, services hold the logic, store holds the data. The browser
side has no routes or database, so it only grows the layer it has — views.

```
server.js               ~40 lines: build the app, mount routers, attach ws, listen.
src/
  config.js             every constant and every tunable number
  routes/               controllers — parse the request, call a service, respond
    agents  findings  scans  session  timeline
  services/             logic, no req/res
    scanner.js          orchestrates the three engines and merges them
    engines/            deterministic.js  reasoning.js  sca.js  plan.js (shard planning)
    claude.js           spawning `claude -p`, relaying stream-json
    remediation.js      the fix flow
    sast-engine.js      loads the vendored ESM engine via dynamic import()
    merge.js  taxonomy.js  verdict.js
  store/                the in-memory data
    findings/           state  status  list-item  factories  flow  csv  (index re-exports)
    scans.js
  ws/                   index.js (dispatch) + scan  run  fix  origin

public/
  index.html            markup only
  app.css
  js/
    main.js             entry point: wiring order, nothing else
    state.js            the shared mutable state — one object, see docs/ui.md
    api.js  ws.js  router.js
    views/              one folder or file per screen
      dashboard  scans/  findings/  finding-detail/  surface  timeline  settings
    components/         UI used by more than one view
      loop/ (state cell boxes actions)  runs  modals  menu  console
    lib/                format  html  icons  highlight  meta

sast-engine/            vendored from `ship-safe` (MIT — see sast-engine/LICENSE). Real ESM.
                        rules/ holds the pattern agents. See docs/scan-engine.md.
prompts/*.md            agent system prompts, passed via --append-system-prompt.
                        See docs/agents.md.
test/                   node:test characterization suites. See "Testing" below.
```

Two names that used to collide: `prompts/` holds LLM prompt files, `sast-engine/rules/` holds
regex pattern rules. Both were called `agents/` once; they are unrelated.

## The pipeline

`Scan → Triage → Remediate → Fix → Verify`

**No agent ever runs automatically.** Every stage requires an explicit click, so there is always
an audit trail before anything executes against a finding.

| Stage | What it does | LLM? | Writes? |
|---|---|---|---|
| Scan | Finds issues across a directory | partly | no |
| Triage | Confirms the finding is real | **no** — synthesized at creation time | no |
| Remediate | Proposes a fix (`fix_guidance`, `corrected_code`, `edit_plan`) | yes | no |
| Fix | Applies the proposed `edit_plan` | **no** — deterministic | **yes** |
| Verify | Re-checks the live code | yes | no |

Two of these are synthetic agents with no `.md` file:

- **Triage** — every finding gets a triage verdict pushed onto `finding.runs` at creation time,
  from the engine's `VerifierAgent` output, from the reasoning pass's own assessment, or as a
  neutral placeholder for a manually-added finding. Without it the pipeline's first stage would
  point at a stage that cannot run.
- **Fix** — makes no `claude` call at all. It reads whatever `edit_plan` the most recent
  Remediate run proposed and applies *that*. This is why Remediate and Fix are separate stages:
  a human sees the proposed edit before anything is written.

SCA findings (dependency audit) skip the loop entirely — the fix is "bump the version", not a
code edit.

## Data model

Two session-lifetime `Map`s under `src/store/`, both reset on restart, both starting empty (there is
no seed data).

- **`findings`** — each finding owns a `runs` array. A run record (`{runId, agent, status,
  verdict, fullText}`) is how the pipeline persists *and* how chaining works: when starting a
  stage, the client embeds the finding's fields and the most recent run's full verdict JSON, so
  each agent sees what the previous one concluded rather than re-deriving it. A scan-produced
  finding also carries `sourceScanId`.
- **`scans`** — one invocation, not a pipeline, so no `runs` chain. `toScanListItem()` is the
  authoritative shape. Two fields are deliberately kept off it: `moduleRunIds` (cancel
  bookkeeping) and `surface` (the full attack-surface manifest — large, fetched on demand by
  `GET /api/scans/:id/surface`).

Deleting a scan leaves its findings in place with a now-dangling `sourceScanId`.
`findingSourcePath()` returns `null` rather than throwing, but such a finding silently loses the
ability to run Fix or a live-code Verify.

REST: `/api/findings` (+ `POST`, `/:id`, `/export.csv`), `/api/scans` (+ `/:id`, `/:id/surface`,
`DELETE`), `/api/agents`, `/api/timeline`, `POST /api/session/clear`.

WebSocket message types: `run`, `scan`, `remediate_preview`, `remediate_fix`, `remediate_all`,
`cancel`. Scan messages use a distinct `scan-*` reply family (`scan-started`/`-event`/`-stderr`/
`-warning`/`-error`/`-done`) so the client's generic `runId`-keyed handlers cannot collide with
them.

## Conventions that must not break

These are load-bearing. Each has cost real bugs before.

1. **`agent` names and `runId`s from client messages are validated against `^[a-zA-Z0-9_-]+$`**
   before use — the agent name is joined into a filesystem path. Do not relax either.
2. **The server binds loopback only** (`HOST`, default `127.0.0.1`). A bare `server.listen(PORT)`
   binds every interface and puts this unauthenticated surface on the local network.
3. **The WebSocket validates `Origin`.** The same-origin policy does not cover WebSockets, so
   without this any page the user visits can drive the fix flow and write to their repo
   (cross-site WebSocket hijacking). Loopback binding does not help — the request comes from the
   user's own browser.
4. **Nothing reaches disk from inside a `claude` invocation.** No agent gets `Edit`/`Write`.
   The one function that writes (`applyRemediationPlan`) is a separate, later step a human
   triggers after reading the proposal.
5. **Fix requires a clean git working tree** (`checkCleanGitTarget`). Every edit that lands is
   then inspectable via `git diff` and revertible via `git checkout`, entirely outside this app.
6. **Path containment uses `root + path.sep`**, never a bare `startsWith` — `/repo-evil` passes a
   bare prefix check against `/repo`.
7. **A scan engine that fails is reported, not counted as clean.** An agent that errors or times
   out emits a `scan-warning` naming the vulnerability classes that were *not checked*. A tool
   that shows "no findings" when it could not look is the one failure mode a security tool
   cannot afford.

Deeper per-area invariants live in `docs/scan-engine.md` (extraction and gating traps) and
`docs/agents.md` (the verdict contract).

## Security posture

Local single-user dev tool, trusted by its one user. Beyond the loopback bind and the Origin
check above, there is no auth on the WebSocket or REST endpoints, and `--permission-mode
acceptEdits` is set for a fast loop.

The trust boundary is deliberate and wide: **any directory path the client sends** is gated only
by "does this exist and is it a directory". The engine reads arbitrary files under it, and the
SCA half shells out to the detected package manager's audit command with it as `cwd`. That is
consistent with "local tool, one trusted user" — do not add auth-free network exposure without
revisiting it.

Treat Fix as the highest-trust action in the app.

## Testing

`test/` holds **characterization** tests: they lock in *current* behaviour, not desired
behaviour. A failure means behaviour changed — fine only if that was the point of the edit. Do
not "fix" a failing assertion by changing the source unless the change is deliberate. Where
recorded behaviour looks like a latent bug it is asserted as-is with a `CONCERN:` comment.

| Suite | Covers |
|---|---|
| `server-logic` | pure decision logic in server.js / lib |
| `client-logic` | client pure functions, lifted from the module tree |
| `remediation-apply` | plan validation and the path-containment guards |
| `rest-api` | the REST surface against a real booted server |
| `engine-golden` | sast-engine output against fixtures |
| `ws-scan-protocol` | WebSocket message validation and framing |
| `ws-fix-flow` | the preview / apply / chained fix handlers |
| `coverage` | the file-coverage manifest — what a scan read and what it dropped |
| `scan-report` | the agent roster and recon summary behind the Insights screen |
| `finding-disposition` | severity rewrites, closures, and collapsed siblings |
| `scan-handoff` | what the deterministic engine tells the reasoning pass |
| `module-graph` | client import cycles and cluster size (Tarjan SCC) |

Two things to know before believing a red run:

- **There is a cost tripwire.** The WS suites assert that no scan record, finding, or agent run
  was created — because the only way past the validation gates is to spawn a real `claude -p`
  run costing real money. Never add a test that exercises a valid agent name end to end.
- **The suite is load-sensitive.** The REST suite boots a real server and has hit its 90s
  timeout under heavy parallel load while binding in ~1s standalone. A timeout there is worth
  re-running serially before diagnosing it as a regression.

There is no automated test for the live WebSocket streaming flow — that is verified manually in
the browser.

## Self-scanning

This app can scan itself, and `.sast-engineignore` exists because of what happens when it does:
the pattern agents' own rule definitions are literal vulnerable-code strings, so the engine
reports its own rule files as findings. The ignore file excludes `sast-engine/rules/` and
`sast-engine/utils/` plus `test/fixtures/`, and deliberately does **not** exclude
`enumerate.js`, `ast-extract.js`, or `remediation-apply.js` — those hold real logic worth
scanning.

## Not yet built

- Disk persistence — every store is in-memory and resets on restart
- CSV *ingestion* (export exists at `GET /api/findings/export.csv`)
- The **Reports** screen — a placeholder with no data and no endpoint
- ASVS / NIST 800-53 mapping for deterministic findings (see docs/agents.md)
- **Threat Model** and **Control Scan** were removed for maintainability and are planned to
  return. Nothing in the codebase references them; rebuild rather than revert.
