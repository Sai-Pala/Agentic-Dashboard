# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A local Node app that invokes Claude Code headless (`claude -p`) as a set of specialized
AppSec agents, streams their reasoning live to a browser UI over WebSocket, and parses a
structured JSON verdict out of each run. The UI is a "mission control" style app with a
global left nav (Dashboard / Timeline / Findings), plus Settings tucked in the nav footer:

- **Dashboard** — the scan kickoff form lives here (there is no separate Scans view; "combine
  Scans into Dashboard, let me kick off scans from the main screen" was an explicit design
  request): a target-directory input, a row of toggleable agent pills ("run after scan") plus
  an "+ instructions" textarea toggle, and a Start button — followed by stat tiles (in
  progress, not started, in review, remediation ready, total findings, total agent runs) and
  an Agents panel (the 3 per-finding pipeline agents only — Scan is deliberately not listed
  there, see below). The connection/findings-count/agents-ready/scans-count status that used
  to live in a dedicated Dashboard panel now lives in the sidebar instead (`#nav-status`,
  rendered by `renderNavStatus()`) so it's visible from every view, not just Dashboard.
  Starting a scan appends a live card to `#scan-live-container` (2-column grid) on this same
  view and optimistically pushes into both `scansList` and `timelineEntries` so the briefing
  and Timeline update before the server round-trip completes.
- **Timeline** — every scan *and* every per-finding agent run, newest first, date-grouped,
  filterable by a `kind` tag (`scan` / `triage` / `threat_model` / `remediation`,
  color-coded via `AGENT_META` in `index.html`). Updates live via `upsertTimelineEntry()` —
  no refetch needed. Scan rows are expandable in place (click toggles a `.timeline-row-body`
  showing the findings that scan produced, reusing `renderScanFindingsBody()`); agent-run
  rows instead navigate to that finding in Findings on click. `GET /api/timeline`
  server-side now merges `findings` runs and `scans` into one array tagged with `kind`
  before sorting by `startedAt` — see `handleScanMessage`'s sibling code in that endpoint.
- **Findings** — Kanban board (`renderKanban()`), not a sidebar: findings render as cards in
  columns grouped either by status or by severity (toggle at the top of the view,
  `findingsGroupBy`). Clicking a card opens a modal (`#finding-detail-overlay`) with the
  finding's full detail and its agent pipeline rendered as connected stage cards, each
  showing a curated **Analysis** (the agent's own reasoning prose) / **Conclusion** (the
  parsed verdict) summary — raw `stream-json` is available behind a collapsed toggle, not
  shown by default. An "Export" button (`GET /api/findings/export.csv`) downloads all
  findings + latest verdicts.
- **Settings** — a nav-footer entry (not a top-level nav item, deliberately tucked away),
  with a Dark/Light theme toggle (`applyTheme()`, persisted to `localStorage` under
  `appsecops-theme`, applied flash-free by an inline `<script>` at the very top of `<head>`
  that reads `localStorage` before any CSS renders) and an Environment panel that states
  plainly, in-product, that scans run with this machine's own filesystem permissions and
  are not sandboxed to any directory allowlist.

**Pipeline shape**: `Scan → Findings → Remediation` is the conceptual path, but **no agent
ever runs automatically** — every run requires an explicit, reviewable action so there's
always an audit trail before anything executes against a finding (an earlier version
defaulted straight to Remediation on click, which read as auto-fixing without review — this
was a deliberate correction). A fresh finding's CTA is **"Select flow…"**, which opens the
same stage modal used everywhere else (agent dropdown + editable context + optional
instructions, `openFreshStageModal()`); the right-click menu offers "Run Triage…" / "Run
Threat Model…" / "Run Remediation…" as equally-weighted shortcuts into that same modal —
none of them run instantly, and none is "the default" over the others. Because a tester can
jump straight to Remediation without Triage or Threat Model ever having run,
`remediation.md` has to be able to stand on its own: if there's no prior verdict in its
context, it does Triage's confirm/severity/framework-mapping call itself before writing fix
guidance (see the "check your context before you start" section at the top of
`agents/remediation.md`). `agents/scan.md` is a fourth agent file but is *not* a per-finding
pipeline agent — `GET /api/agents` filters it out of the Triage/Threat Model/Remediation
list on purpose (see "not yet built" below on where else new agents need wiring).

## Commands

```
npm install
npm start          # runs `node server.js`, serves http://localhost:4500
```

There is no build step, lint script, or test suite — `package.json` has only `start`.
Before invoking, `claude auth status` must succeed (the server spawns the CLI
non-interactively and does not handle auth itself).

To exercise the pipeline manually: open `http://localhost:4500` (lands on Dashboard), enter a
directory path on this machine under "New scan" and click "Start scan" — watch its live card
right there, then check Findings once it completes (or expand the row in Timeline). Click a
finding's card on the Kanban board to open its detail modal, then click "Select flow…" (or
right-click the card / use the ⋮ menu in the modal) to pick an agent — Triage, Threat Model,
or Remediation — review the context/instructions, and explicitly start it; nothing runs
without that step. Once a stage finishes, right-click its card (or use its ⋮ menu) to
continue to the next agent, re-run with new instructions, or branch to a different agent.
There is no automated test for the WebSocket flow — verification is manual, through the
browser.

## Architecture

```
server.js          Express + ws. In-memory findings store (seeded with sample data on
                    boot) and a separate in-memory scans store, behind a small REST API,
                    plus a WebSocket handler that spawns `claude -p` per agent run (or
                    per scan), relays stream-json lines live, and extracts the final JSON
                    block from the accumulated assistant text.
public/index.html   The dashboard: global nav (status summary + Settings entry in the nav
                    footer), the scan kickoff form + live scan card on the Dashboard view
                    itself, a Findings Kanban board (grouped by status or severity) with a
                    detail modal per finding, a per-finding pipeline of stage cards
                    connected left-to-right inside that modal (each showing an Analysis /
                    Conclusion summary, raw stream-json collapsed by default), a right-click
                    context menu, and modals for adding a finding / running a stage with
                    custom instructions.
agents/*.md         Agent system prompts (passed via --append-system-prompt). Plain
                    markdown, no code — this is the only place agent-specific analysis
                    logic lives. New *per-finding* agent = new .md file, no server
                    changes needed beyond it existing on disk (see "not yet built" below
                    on hardcoded assumptions elsewhere). `scan.md` is the one exception —
                    it's invoked through a dedicated code path (`handleScanMessage` in
                    server.js), not the generic per-finding `run` path, because it needs
                    a different tool set (`Glob` in addition to `Read`/`Grep`), a
                    different `cwd` (the scanned directory, not the app's own), and a
                    different output shape (`{"findings": [...]}` array, not a single
                    verdict object).
```

**Findings store**: `findings` (Map, in `server.js`) is session-lifetime only — reset on
restart, seeded from `seedFindings()` with four sample AppSec findings. Each finding owns
a `runs` array; each run record (`{runId, agent, status, verdict, fullText, ...}`) is how
the pipeline persists and how chaining works — when continuing to the next agent, the
client builds the next stage's context by embedding the prior stage's full verdict JSON
alongside the original finding text (see `openStageModal()`'s `'continue'` branch in
`index.html`), so each agent explicitly sees what the previous one concluded rather than
re-deriving it. A finding created by a scan additionally carries `sourceScanId`. REST
surface: `GET /api/findings`, `POST /api/findings`, `GET /api/findings/:id`,
`GET /api/findings/export.csv` (all findings + latest verdict fields, one row each), and
`GET /api/timeline` (flattens every finding's `runs` into one array, newest first — what
the Timeline view fetches on load; live runs after that are patched into the client's copy
directly from WebSocket messages, not re-fetched).

**Scans store**: `scans` (Map, in `server.js`) is the same session-lifetime pattern as
`findings`, separate Map. A scan record is `{id, path, status, findingIds, startedAt,
finishedAt, error}` — it doesn't hold a `runs` chain like a finding does, since a scan is
one invocation, not a pipeline. REST surface: `GET /api/scans`, `GET /api/scans/:id`
(includes the full finding list-items it produced, via `findingIds`).

**Request flow (per-finding agents)**: browser opens a WebSocket → user starts a stage →
client sends `{type: "run", runId, findingId, agent, context, instruction}` → server reads
`agents/<agent>.md`, spawns `claude -p "<instruction>\n\nFinding context:\n<context>"
--append-system-prompt "<agent .md contents>" --output-format stream-json --verbose
--allowedTools "Read,Grep" --permission-mode acceptEdits` (cwd = the app's own directory)
→ each parsed stdout line is relayed immediately as `{type: "event", runId, findingId,
event}` (this is the "live" part) → on process exit, the server regex-searches the
accumulated assistant text for a fenced ` ```json ` block, records the verdict against the
finding's run history, and sends `{type: "done", runId, findingId, code, verdict,
fullText}`.

**Request flow (scans)**: client sends `{type: "scan", runId, path, instruction}` →
server validates `path` exists and is a directory, spawns `claude -p` with
`agents/scan.md` as the system prompt, `--allowedTools "Read,Grep,Glob"` (`Glob` is scan-
only — the per-finding agents don't get it), and **`cwd` set to the target `path`** (the
one place in this app where `claude` runs outside its own directory) → events relay as
`{type: "scan-event", runId, scanId, event}` (deliberately different type names —
`scan-started`/`scan-event`/`scan-stderr`/`scan-error`/`scan-done` — so the client's
generic per-finding message handler and the scan handler never collide on the same
`runId` keying two different lookup Maps) → on close, the server expects
`{"findings": [...]}` (not a single verdict object) from `extractVerdict()`, creates a
new Finding per array entry (skipping malformed ones rather than failing the whole scan),
and sends `{type: "scan-done", runId, scanId, findings: [...]}`.

**Multiple concurrent runs**: a single WebSocket connection tracks runs in a `runId`-keyed
`Map` of child processes (`children` in `server.js`), shared by both per-finding runs and
scans — not a single in-flight run, so multiple stages and/or scans can be running at once
from one browser tab. `{type: "cancel", runId}` kills a specific run (checked against both
`runIndex` and `scanRunIndex`). Closing the tab/connection kills and marks-cancelled every
still-running child tied to it (`ws.on('close')`).

**Why `claude -p` instead of the Messages API directly**: `--output-format
stream-json` already emits structured events (assistant text, tool calls, final
result) with no custom parser needed, and the agents already exist as `.md`
prompt files used manually in a terminal — this automates that same invocation
rather than replacing it.

**The verdict contract**: every agent's `.md` file ends with an instruction to
close its response with exactly one fenced JSON block. The server does not
validate or enforce a schema — `extractVerdict()` in `server.js` just regexes
for the first ` ```json...``` ` block and parses it. The client's `renderVerdict()`
renders any object generically by iterating key/value pairs (badging a fixed set of
known fields: `verdict`, `severity_confirmed`, `confidence`, `priority`), so schema
changes in an agent's `.md` need no frontend change unless new behavior should key off
a new field specifically (e.g. `renderActions()` keys off `next_agent`,
`deriveStatus()` in `server.js` keys off `verdict`/`next_agent`).

**Analysis / Conclusion, not a raw stream**: `handleRawEvent()` in `index.html` (per-finding
stage cards) does not render a blow-by-blow activity feed — tool calls, tool results, and
thinking-token events are captured only into the per-stage "Raw stream-json" `<details>`
toggle (collapsed by default). The only thing surfaced live is the agent's own prose
(assistant `text` content blocks, stripped of the trailing fenced JSON), appended as
paragraphs under an "Analysis" heading via `appendAnalysisParagraph()`; once the run
finishes, `renderVerdict()` renders the parsed JSON verdict under a "Conclusion" heading.
This replaced an earlier design that showed every tool call/result plus a live
"Thinking… (~N tokens)" pill — that read as noise rather than the two things an AppSec
tester actually wants: what was found, and why. Scan cards (`handleScanRawEvent()` in
`index.html`, driven by `agents/scan.md`'s narration contract) use a separate but similarly
curated convention: `agents/scan.md` is instructed to prefix each candidate finding with a
literal `[severity]` tag as it's spotted, which `trackScanCandidates()` parses via
`SEV_TAG_RE` to build a live list of candidates and running severity counts — also with the
raw stream captured only in that card's own collapsed toggle, never rendered inline.

**Taxonomy convention**: severity/confidence/priority definitions live inside
each agent's `.md` file and must stay byte-identical across agents (copy, don't
redefine) — they're meant to match the org's existing `owasp-code-review`
Claude skill so findings read consistently whether a human or an agent
produced them. OWASP/CWE/NIST 800-53 framework mapping is required (not
optional) whenever an agent's verdict is `confirmed` or `needs_review` — this
program runs under FedRAMP Moderate/High and FISMA, and the NIST 800-53
mapping feeds compliance reporting downstream. See `agents/triage.md` for the
current definitions; `threat_model.md` and `remediation.md` reuse them (`remediation.md`
now assigns them itself, same rules, when there's no prior verdict to carry forward — see
"Pipeline shape" above) and only add stage-specific fields
(`preconditions`/`attack_narrative`/`blast_radius` for threat_model;
`root_cause`/`fix_guidance`/`verification_steps`/`effort` for remediation). `scan.md`
findings deliberately do *not* carry `verdict`/`severity_confirmed`/`confidence`/
`priority`/framework-mapping — they're raw, scanner-export-style output; a `severity`
field is the scan's best-effort initial estimate only, and real triage happens downstream.

**Security posture**: this is a local single-user dev tool. No auth on the
WebSocket or REST endpoints; `--permission-mode acceptEdits` and `--allowedTools`
("Read,Grep" for per-finding agents, "Read,Grep,Glob" for scans) are set loosely for a
fast test loop, not for anything beyond localhost use. Both `agent` names and `runId`s
from client messages are validated against `^[a-zA-Z0-9_-]+$` before being used (agent
name is joined into a filesystem path) — don't relax either when adding features. The
Scans feature is a deliberate widening of that posture: it spawns `claude` with `cwd` set
to **any directory path the client sends**, gated only by "does this path exist and is it
a directory" (`fs.statSync` in `handleScanMessage`) — there's no allowlist of scannable
roots. That's consistent with "local single-user tool trusted by its one user," not with
exposing this app beyond localhost; don't add auth-free network exposure without
revisiting this.

**Not yet built**: disk persistence (both the findings store and the scans store are
in-memory and reset on restart — there's no SQLite/JSON-file layer yet), CSV *ingestion*
(export exists — `GET /api/findings/export.csv` — but importing an external scanner's CSV
to seed findings, the original `findings-dashboard.jsx` workflow, does not), surfacing a
finding's `sourceScanId`/source path in the Findings detail view (the data's already on
the finding, just not rendered there yet), and the dashboard merge itself
(`findings-dashboard.jsx`'s Azure DevOps ticket creation currently does a browser-side
`fetch()` that's expected to hit CORS — if that logic moves into this app, it should move
server-side, where Node has no CORS problem).
