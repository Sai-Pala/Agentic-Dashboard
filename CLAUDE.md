# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A local Node app that invokes Claude Code headless (`claude -p`) as a set of specialized
AppSec agents, streams their reasoning live to a browser UI over WebSocket, and parses a
structured JSON verdict out of each run. The UI is a "mission control" style app with a
global left nav (Dashboard / Scans / SCA / Timeline / Findings / Threat Model / Agents), plus
Settings tucked in the nav footer. Four nav items carry a live status badge
(`renderNavBadges()`, called from `upsertTimelineEntry()` and `renderNavStatus()` so it
stays current from any view): **Scans** shows a pulsing yellow dot while any non-SCA scan is
`status: 'running'` (`scansList`, filtered to `scanType !== 'sca'`); **SCA** shows the same
pulsing yellow dot, filtered the other way (`scanType === 'sca'`) — split so a running SCA
scan doesn't make the Scans page look like something's happening there when it isn't, and
vice versa; **Timeline** shows a pulsing yellow dot while any run/scan of *any* kind is
`status: 'running'`, or a solid green dot if nothing's running but a run finished while the
user was on a different view (`timelineUnseenDone`, cleared when they actually visit
Timeline); **Findings** shows a red count pill of findings whose `status !== 'closed'`. When
the sidebar is collapsed, `#global-nav.collapsed .nav-item .nav-badge` forces every badge —
dot or count pill alike — to the same 8×8 corner dot (text hidden via `font-size: 0`, the
count still readable from the badge's `title` tooltip on hover); without this override the
wider count pill overlapped the nav icon instead of sitting in its corner like the plain
status dots do.

- **Dashboard** — a pure status/briefing screen: the Briefing banner, a `.quick-actions` row
  of two prominent cards ("Start a scan" / "View timeline", `#dash-scans-link`/
  `#dash-timeline-link`) linking into those views, stat tiles (in progress, not started, in
  review, remediation ready, total findings, total agent runs), and an Agents panel (the 3
  per-finding pipeline agents only — Scan and App Threat Model are deliberately not listed
  there, see below). It holds no form of its own — `renderDashboard()` only refreshes the
  briefing/stats/agents panel, nothing else. The quick-actions row replaced an earlier
  `.dash-footer` bar that crammed the same two links into a thin text strip alongside a
  "`{n} findings · {m} total runs`" summary — that summary was pure duplication of numbers
  the stat tiles already show directly above it, and the two links read as an afterthought;
  removed the redundant text and gave the links real button-card treatment instead. The
  connection/findings-count/agents-ready/scans-count status lives in the sidebar
  (`#nav-status`, rendered by `renderNavStatus()`) so it's visible from every view, not just
  Dashboard.
- **Scans** — the scan kickoff form and its live cards, on their own top-level page (this
  used to be folded into Dashboard per an earlier explicit request to "combine Scans into
  Dashboard, let me kick off scans from the main screen" — a later request reversed that,
  finding the combined Dashboard confusing, and asked for Scans to be split back out plus for
  the whole-app threat model action to move off the scan form entirely, see below): a
  target-directory input, branch/app fields, a **Scan type** pill row, scope toggle, a row of
  toggleable agent pills ("run after scan") plus an "+ instructions" textarea toggle, and a
  Start button — followed by `#scan-live-container` (2-column grid of live scan cards).
  Starting a scan optimistically pushes into both `scansList` and `timelineEntries` so the
  Dashboard briefing and Timeline update before the server round-trip completes. The "run
  after scan" pill row (`renderScanAgentSelection()`) deliberately excludes `threat_model` —
  its per-finding Triage/Remediation semantics ("run this against every finding this scan
  creates") don't fit Threat Model, which needs an exploit-chain to already exist; whole-app
  threat modeling lives entirely on the Threat Model page instead (see below), fully
  independent of any scan — no foreign key between the two, they just happen to often target
  the same directory.

  The Scan type pill row now only offers **Reasoning Scan** and **Custom** — SAST and DAST used
  to be separate pills/scanTypes, but both were really just this same LLM reading source and
  reasoning about it (no real static-analysis tool parsing an AST, no live traffic hitting a
  running app), so presenting them as distinct scanner categories was misleading. They're
  merged into one `reasoning` scan type whose canned framing (`SCAN_TYPE_FRAMING.reasoning` in
  `server.js`) covers both angles — concrete code-level vulnerabilities and attack-surface/
  entry-point reasoning — in a single pass. SCA is kept as its own genuinely different task
  (checking manifests/lockfiles against known-vulnerable packages, not reasoning about code
  patterns) and moved to its own page entirely rather than staying a pill here — see below.
  The merge goes all the way down to finding classification too: `FINDING_SCAN_TYPES` is now
  just `['reasoning', 'sca']`, and the Findings screen's type tabs became Reasoning/SCA (no
  more separate DAST tab) — see the Findings bullet below.
- **SCA** — Software Composition Analysis gets its own top-level page, structurally identical
  to Scans (target directory, branch/app, scope toggle, run-after-scan pills, Start button,
  live cards) but with no Scan type pill row at all, since the whole point of this page is that
  the type is fixed. It reuses the exact same underlying mechanism as Scans — the same WS
  `'scan'` message, the same `scanRuns` Map, the same `makeScanCard()` — just with a different
  target container (`#sca-live-container`) and `scanType: 'sca'` hardcoded
  (`startScaScan()`/`beginScanRun()` in `index.html`, factored out of the old single `startScan()`
  so both pages share the run-tracking/live-card machinery instead of duplicating it). Its own
  nav badge (`#nav-badge-sca`) mirrors Scans' but filters to `scanType === 'sca'` scans only, so
  the two pages' "something's running" indicators never cross-contaminate.
- **Timeline** — every scan *and* every per-finding agent run, newest first, date-grouped,
  filterable by a `kind` tag (`scan` / `triage` / `threat_model` / `remediation`,
  color-coded via `AGENT_META` in `index.html`). Updates live via `upsertTimelineEntry()` —
  no refetch needed. Scan rows are expandable in place (click toggles a `.timeline-row-body`
  showing the findings that scan produced, reusing `renderScanFindingsBody()`); agent-run
  rows instead navigate to that finding in Findings on click. `GET /api/timeline`
  server-side now merges `findings` runs and `scans` into one array tagged with `kind`
  before sorting by `startedAt` — see `handleScanMessage`'s sibling code in that endpoint.
- **Findings** — a sortable table (`renderFindingsTable()`), not a Kanban board: findings are
  split into type tabs (`findingsTypeFilter`: All / Reasoning / SCA, `#findings-type-tabs`,
  styled as a `.group-toggle` segmented control) because each type's useful columns differ —
  Reasoning shows a merged **Location** column (file path if it's a code-pattern finding,
  endpoint+method if it's an attack-surface one — a reasoning-scan finding can be either, or
  even both, now that there's no separate DAST scanType to gate the field on) plus Rule/CWE;
  SCA shows Package + Fixed-in (`FINDINGS_COLUMNS` in `index.html`). Every type's Runs column shows the run count plus the
  latest run's agent and, if that run produced a verdict, the verdict in parens (e.g. "2 runs
  · Threat Model (needs_review)") — a lightweight way to see a finding's most recent pipeline
  state without opening it. Severity/Title/Status columns are click-to-sort
  (`findingsSort`, toggling asc/desc on the same header). A **Scan** filter
  (`#findings-scan-filter`, `findingsScanFilter`) sits beside the type tabs — populated from
  `scansList` (path + relative time per option, newest first), it restricts the table to one
  scan's findings via `finding.sourceScanId` (`findingsScanScoped()`); the type tabs' counts
  and the empty-state message both react to it too, and a scan that produced no findings
  still on record (or whose findings were all removed) is left out of the option list rather
  than becoming a dead-end filter. Three other places link into this same filtered view via
  `openFindingsFilteredByScan(scanId)`: the Finding Detail page (a "Found by scan of `<path>`"
  line under the badges, if the finding has a `sourceScanId`), a completed scan card's "View in
  Findings →" action (`updateScanCardActions()`, Scans page), and a Timeline scan row's
  expanded body ("View all in Findings →", `renderScanFindingsBody()`) — added because
  discovering the scan filter only via the dropdown wasn't obvious enough on its own.
  `openFindingsFilteredByScan()` just sets `findingsScanFilter` and calls `showView('findings')`.
  This surfaced a real bug in `renderFindingsScanFilter()`: it used to compute
  `findingsScanFilterEl.value || findingsScanFilter` to decide what to preserve across a
  rebuild, but the `<select>`'s DOM value defaults to the truthy string `"all"` until a user
  touches it directly — so that expression always picked `"all"` and silently discarded
  whatever `findingsScanFilter` had just been set to by any of these three programmatic links
  (a plain dropdown selection worked fine, since in that path the native `change` event fires
  after the browser has already updated `.value` to match). Fixed by treating
  `findingsScanFilter` as the single source of truth and the `<select>`'s value as a pure
  render target, never read back as state. Clicking a row navigates to a
  full-page **Finding Detail** view (`#view-finding-detail`, `openFindingDetail()` /
  `renderFindingDetail()`) rather than a modal or panel — earlier rounds tried a right-docked
  panel, then in-Kanban-card expansion, then reverted to a bare Kanban board with no detail
  view at all; a dedicated full page (not an overlay squeezed next to other content) is what
  finally gave the code block and verdict history room to be readable. That page shows: type/
  severity/status badges, a meta grid (File, or Package/Fixed-in, or Endpoint/Method depending
  on `scanType`), the description, a syntax-highlighted code block when `finding.code` is
  present (`highlightCode()` — a hand-rolled regex tokenizer, no external highlighting
  library, consistent with this app's no-external-deps/hand-drawn-icon aesthetic), and an
  **Agent runs** section (`runCardHtml()`) listing every run against this finding with its
  verdict badges/fields rendered generically (same key-badging convention described in "The
  verdict contract" below). A single **"Agent Runs ▾"** button in the page header
  (`renderFindingDetailActions()`) opens the same dropdown menu as right-clicking a table row
  (`openFindingContextMenu()`, positioned under the button via its `getBoundingClientRect()`
  instead of the cursor) — deliberately *not* three separate hardcoded Triage/Threat
  Model/Remediation buttons, since that menu is built by iterating `agentsList` (whatever's
  declared on the Agents screen, built-in or custom), so a new custom agent shows up there
  with no code change. Both paths converge on `openFreshStageModal()`. Note:
  `openFindingContextMenu()`'s button click handler calls `e.stopPropagation()` — without it,
  the click bubbles to the document-level "click outside closes the menu" listener and closes
  the menu in the same tick it opened. An "Export" button (`GET /api/findings/export.csv`)
  downloads all findings + latest verdicts.
- **Threat Model** — a read-only, cross-finding view of every finding with a completed
  Threat Model run whose verdict is `confirmed` or `needs_review` (`latestThreatModelEntries()`
  — findings never threat-modeled just don't appear, no placeholder queue). Entirely derived
  client-side from the same `timelineEntries` cache Timeline already fetches — no dedicated
  endpoint. Rendered as a top-down tree/org-chart built from plain HTML/CSS boxes
  (`buildThreatModelTree()`, no charting library or SVG) instead of a card grid or a radial
  diagram: a root "App" box, one branch per OWASP category (`verdict.owasp`, labeled with its
  finding count, colored by the *worst* severity in that category via `worstSeverity()`), and
  each category's individual findings as leaf boxes stacked below their branch (colored by
  their own `severity_confirmed`). This replaced an earlier hand-drawn SVG hub-and-spoke
  (radial) layout — SVG `<text>` can't wrap without manual `<tspan>` line-breaking, so long
  category labels (e.g. "A01:2021 - Broken Access Control") were getting crowded or truncated
  at the edge; plain HTML/CSS boxes wrap normally, so labels are never cut off no matter how
  long. Clicking a leaf calls `selectThreatModelFinding(findingId)`, which
  renders that finding's **attack-path flow** below the diagram (`renderAttackPathFlow()`):
  four connected boxes — Attacker (generic, not agent data) → Preconditions → Attack Path →
  Blast Radius — using the exact prose those three verdict fields already contain, plus a "View
  finding →" button into the full Finding Detail page. This needed no new agent capability;
  it's purely a different way to look at data `agents/threat_model.md` already produces.
  A finding can carry more than one Threat Model run over its lifetime (re-run after a code
  fix, or re-run after Triage's picture changes) — `allThreatModelEntriesForFinding()` returns
  all of them (newest-first) for a given finding, and whenever there's more than one,
  `renderAttackPathFlow()` shows a **Run** `<select>` above the flow (`#tm-run-select`,
  `renderThreatModelDetail()`) so a specific historical run can be picked instead of always
  showing the latest. Because the diagram itself only maps each finding's *latest* run
  (`latestThreatModelEntries()`, filtered to `confirmed`/`needs_review`), a finding whose most
  recent run is `false_positive` (or whose selected-in-the-dropdown run just isn't the current
  one) won't have a leaf node — in that case the detail panel adds a "Not shown on the map
  above" hint rather than silently looking like it belongs to a node that isn't there.
  A finding's full-page detail view also links here directly: any `threat_model` entry in its
  **Agent runs** list (`runCardHtml()`) gets a "View in Threat Model →" button
  (`openThreatModelForFinding(findingId, runId)`) that navigates to this tab and opens that
  exact run's attack-path flow, regardless of whether it's the finding's current/latest run or
  whether it's even represented on the diagram right now. `showView()` takes an optional
  `{ skipInit: true }` second argument so this navigation can swap the visible view without
  triggering the view's normal auto-load (which would otherwise race with the explicit
  load/select this function already does).

  The Threat Model page opens with its own **"New app threat model"** form (`#atm-path-input`/
  `#atm-branch-input`/`#atm-app-input`/`#atm-instruction-input`/`#atm-start-btn`,
  `startAppThreatModel()`) — target directory, optional branch/app labels, optional focus-area
  instructions, and a Start button, styled like the Scans page's New Scan form but with its
  own pink `.atm-start-btn` accent. This used to be a toggle pill on the scan form itself
  ("Also: Threat-model this app," firing alongside a scan) but was pulled out into its own
  standalone form here — whole-app threat modeling is conceptually unrelated to a findings
  scan (no shared data, just often the same target directory) and putting its kickoff action
  on the screen that actually shows its results reads more clearly than a checkbox buried in
  an unrelated form.

  Below that form, an **App-level Threat Models** section (`renderAppThreatModelSection()`)
  lists every whole-app run (`agents/app_threat_model.md` — a distinct agent from the
  per-finding `threat_model.md`: it takes a directory, not a finding, and produces a single
  holistic architecture report — trust boundaries, data flows, a `top_risks` list, and
  recommendations — rather than a per-finding verdict). These runs are **not** tied to any
  finding or scan (no foreign key to `scans` — `startAppThreatModel()` fires an independent WS
  message straight from this form) and so aren't part of the OWASP tree above; they get
  their own list (`appThreatModelsList`, from `GET /api/app-threat-models`, kept live via
  `upsertAppThreatModel()`/`handleAppThreatModelServerMessage()` — distinct WS message types
  `app-threat-model-started/event/stderr/done/error`, same rationale as `scan-*` types: avoid
  the client's generic per-finding/scan message handlers colliding on the same `runId`-keyed
  lookup). Each row is its own **accordion**, not a click-to-select-into-a-side-panel: clicking
  a row's summary (`.atm-row-summary`) toggles `toggleAppThreatModelRow(runId)`, which sets
  `expandedAtmRunId` (single-expand state — only one run's report is open at a time) and
  re-renders; the full report (summary, trust boundaries, data flows, severity-badged risk
  cards with OWASP/CWE chips, recommendations, via `renderAppThreatModelDetail()`) is embedded
  directly beneath the clicked row (`.atm-row-body`, only present in the HTML when
  `r.runId === expandedAtmRunId`) instead of appearing in a separate panel elsewhere on the
  page — this replaced an earlier design with a standalone `#atm-detail-panel` that a row
  selection populated at the bottom of the list, which read as two disconnected things
  happening in different places for one click. Whenever a run is expanded, a **"Viewing scan:
  ..."** label (`#tm-viewing-label`, `updateTmViewingLabel()`) appears in the page's view header
  in accent color, naming that run's path/app/relative-time, so which report is on screen is
  never ambiguous — it's hidden when nothing is expanded. Server-side,
  `appThreatModels`/`appThreatModelRunIndex` (in `server.js`) mirror the `scans`/`scanRunIndex`
  pattern exactly, including being checked alongside them in `cancel` handling and the
  WebSocket `close` cleanup — a run whose tab/connection closes mid-run lands in `status:
  'cancelled'` server-side and renders as a "Cancelled" row/detail (not "Done" — a first pass
  at this only handled `running`/`error`/else-`done`, which misrendered a cancelled run as
  done since there's no cancel button in this UI to test that path against; fixed by
  explicitly branching on `'cancelled'` in both `renderAppThreatModelSection()` and
  `renderAppThreatModelDetail()`). `app_threat_model` is excluded from `GET /api/agents` (like
  `scan`) since it isn't a per-finding pipeline agent — it doesn't show up in the Findings
  stage modal's agent dropdown or the "run after scan" pill row.

  `renderAppThreatModelDetail()` also draws a diagram, not just prose — `buildAppThreatModelTree()`
  reuses the exact same top-down tree shape and `.tm-tree-*` CSS classes as the per-finding
  tree (`buildThreatModelTree()`), just built from a flat `top_risks` array (grouped by `owasp`)
  instead of per-finding timeline entries, since a whole-app report has no individual findings
  to hang leaf boxes off of. Clicking a leaf (`data-risk-index`) or a risk card below
  cross-highlights both and scrolls the matching risk card into view.

  Running rows also carry live stats — tool/file/token counts, elapsed time, and a
  context-window fill bar — the same way scan cards do (`appThreatModelRuns`, a
  `scanRuns`-style Map of tracking objects, and the same shared `trackRunToolActivity()`/
  `trackRunTokens()`/`updateContextBar()` functions scan cards use). The tricky part: this
  view's `#tm-content` can be rebuilt from scratch at any moment a run is live (any timeline
  update while this view is open re-renders it, per `upsertTimelineEntry`), which would
  normally destroy the live row's DOM and orphan its cached element refs. `appThreatModelRowHtml()`
  works around this by baking the tracking object's *current* counters directly into the
  fresh HTML string (so a rebuild never visually resets progress), and
  `reattachAppThreatModelLiveRefs()` (called at the end of every `renderThreatModelView()`)
  re-queries the fresh DOM and re-points the tracking object's refs at it, so the next
  stream-json event's direct DOM mutation (`handleAppThreatModelRawEvent()` — deliberately
  *not* routed through `upsertAppThreatModel()`, to avoid a full re-render on every single
  event) lands on the currently-attached node. `CONTEXT_WINDOW_TOKENS` (200,000) is a rough
  constant, not a queried value — the app has no way to read the actual configured context
  limit from here, so the fill bar is an early "your scope might be too broad" signal, not a
  precise meter. It's driven by the *latest* turn's `input_tokens` +
  `cache_creation_input_tokens` + `cache_read_input_tokens` (what's actually loaded in context
  right now), not the running `tokenCount` sum shown next to it (a different, cumulative
  "total work done" metric) — summing every turn's input would double-count the growing
  conversation history that gets resent each turn.
- **Agents** — a top-level screen for managing the `.md` files under `agents/` from the
  browser instead of by hand: create/edit/delete via `GET/POST/PUT/DELETE /api/agents(/:name)`
  in `server.js`. Built-in pipeline agents (`triage`/`threat_model`/`remediation`/`scan`/
  `app_threat_model`, `BUILTIN_AGENTS` server-side) can be edited but not deleted (403). New agents are
  immediately usable everywhere `agentsList` is consumed — the Findings stage modal's agent
  dropdown and the Scans page's "Run after scan" pill row are both driven off the same
  dynamic list, no extra wiring needed per agent.
- **Settings** — a nav-footer entry (not a top-level nav item, deliberately tucked away),
  with a Dark/Light theme toggle (`applyTheme()`, persisted to `localStorage` under
  `appsecops-theme`, applied flash-free by an inline `<script>` at the very top of `<head>`
  that reads `localStorage` before any CSS renders), an Environment panel that states
  plainly, in-product, that scans run with this machine's own filesystem permissions and
  are not sandboxed to any directory allowlist, and a red-bordered **Danger zone** panel with
  a single "Clear session" button (`clearSession()`) that, after a `confirm()` prompt, calls
  `POST /api/session/clear` to permanently wipe every finding, scan, and app-level threat
  model on the server — a full reset back to empty, no reseed. The server refuses (`409`)
  if anything across `findings`/`scans`/`appThreatModels` has `status: 'running'`, since it
  can't kill in-progress child processes from a plain REST route (`children` is scoped inside
  `wss.on('connection')`, not reachable from there) — `clearSession()` surfaces that error via
  `alert()`. On success, the client resets every corresponding in-memory cache
  (`findings`/`scansList`/`appThreatModelsList`/`timelineEntries`/`findingCache`/
  `scanDetailCache`), stops and clears any live `scanRuns`/`appThreatModelRuns` tracking
  objects, clears both live-scan containers, and re-renders whichever view is currently open.

**Pipeline shape**: `Scan → Findings → Remediation` is the conceptual path, but **no agent
ever runs automatically** — every run requires an explicit, reviewable action so there's
always an audit trail before anything executes against a finding (an earlier version
defaulted straight to Remediation on click, which read as auto-fixing without review — this
was a deliberate correction). Both the Finding Detail page's "Agent Runs ▾" button and the
right-click context menu on a Findings table row open the same dynamic per-agent menu
(one "Run <Agent>…" item per entry in `agentsList`) as equally-weighted shortcuts into the
same small stage modal (agent dropdown + editable context + optional instructions,
`openFreshStageModal()`) — none of them run instantly, and none is "the default" over the
others. Because a tester can
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

To exercise the pipeline manually: open `http://localhost:4500` (lands on Dashboard), go to
Scans, enter a directory path on this machine under "New scan" and click "Start scan" — watch
its live card right there, then check Findings once it completes (or expand the row in
Timeline). Click a
finding's row in the Findings table (or a Timeline agent-run row) to open its full-page
detail view, then click "Agent Runs ▾" in the page header (or right-click the table row for
the same menu) to pick an agent, review the context/instructions in the small stage modal,
and explicitly start it; nothing runs without
that step. The detail page's Agent runs section updates live once a run finishes (or shows a
"running" placeholder immediately, via an optimistic push in `startStage()`). There is no
automated test for the WebSocket flow — verification is manual, through the browser.

## Architecture

```
server.js          Express + ws. In-memory findings store (seeded with sample data on
                    boot) and a separate in-memory scans store, behind a small REST API,
                    plus a WebSocket handler that spawns `claude -p` per agent run (or
                    per scan), relays stream-json lines live, and extracts the final JSON
                    block from the accumulated assistant text.
public/index.html   The whole app: global nav (status summary + Settings entry in the nav
                    footer) with Dashboard (briefing + stats + agents panel only), Scans
                    (the scan kickoff form — target/branch/app, Reasoning/Custom scan
                    type, full-vs-diff scope — plus its live scan cards), SCA (structurally
                    identical to Scans minus the scan-type row, its own live cards), a
                    Findings table split into Reasoning/SCA type tabs with click-to-sort
                    columns and a per-scan filter, a full-page Finding Detail view per
                    finding (meta grid, syntax-highlighted code block, and an Agent runs
                    history with a single "Agent Runs ▾" dropdown), a Threat Model page
                    (per-finding OWASP top-down tree plus a "New app threat model" form and
                    its own accordion-style App-level Threat Models list), an Agents screen
                    for managing `agents/*.md` from the browser, a right-click context menu
                    on table rows for the same agent actions, and modals for adding a
                    finding / running a stage with custom instructions.
agents/*.md         Agent system prompts (passed via --append-system-prompt). Plain
                    markdown, no code — this is the only place agent-specific analysis
                    logic lives. New *per-finding* agent = new .md file, no server
                    changes needed beyond it existing on disk (see "not yet built" below
                    on hardcoded assumptions elsewhere). `scan.md` and `app_threat_model.md`
                    are the two exceptions — both are invoked through their own dedicated
                    code path (`handleScanMessage` / `handleAppThreatModelMessage` in
                    server.js), not the generic per-finding `run` path, because both need
                    a different tool set (`Glob` in addition to `Read`/`Grep`), a
                    different `cwd` (the target directory, not the app's own), and a
                    different output shape (`scan.md` returns `{"findings": [...]}`;
                    `app_threat_model.md` returns a holistic report object — see the
                    Scans/Threat Model bullets above) rather than a single per-finding
                    verdict object.
```

**Findings store**: `findings` (Map, in `server.js`) is session-lifetime only — reset on
restart, seeded from `seedFindings()` with six sample AppSec findings (five reasoning, one
SCA — enough to populate both Findings type tabs on first run). Every finding has
a `scanType` (`reasoning | sca`, `FINDING_SCAN_TYPES` — narrower than a scan's own
`scanType`, since a `custom`-type scan's findings fall back to `reasoning`) plus a handful of
optional type-specific fields: `code` (reasoning, syntax-highlighted on the detail page),
`packageName`/`packageVersion`/`fixedVersion` (SCA), `endpoint`/`method` (reasoning, for an
attack-surface finding). Each finding
also owns a `runs` array; each run record (`{runId, agent, status, verdict, fullText, ...}`)
is how the pipeline persists and how chaining works — when starting a fresh stage, the
client's `buildBaseContext()` (`index.html`) embeds the finding's own fields *and*, if a run
already exists, the most recent run's full verdict JSON, so each agent explicitly sees what
the previous one concluded rather than re-deriving it. A finding created by a scan
additionally carries `sourceScanId`. REST surface: `GET /api/findings`, `POST /api/findings`,
`GET /api/findings/:id`, `GET /api/findings/export.csv` (all findings + latest verdict
fields, one row each), and `GET /api/timeline` (flattens every finding's `runs` into one
array, newest first — what the Timeline view fetches on load; live runs after that are
patched into the client's copy
directly from WebSocket messages, not re-fetched).

**Scans store**: `scans` (Map, in `server.js`) is the same session-lifetime pattern as
`findings`, separate Map. A scan record is `{id, path, status, findingIds, startedAt,
finishedAt, error}` — it doesn't hold a `runs` chain like a finding does, since a scan is
one invocation, not a pipeline. REST surface: `GET /api/scans`, `GET /api/scans/:id`
(includes the full finding list-items it produced, via `findingIds`).

**App-level threat models store**: `appThreatModels` (Map, in `server.js`) is a third,
independent session-lifetime store, same pattern again. A record is `{id, runId, path, app,
branch, instruction, status, verdict, error, startedAt, finishedAt}` — `verdict` here is the
whole-app report object (`summary`/`trust_boundaries`/`data_flows`/`top_risks`/
`recommendations`), not a per-finding verdict, and there's no `findingIds`/`runs` chain since
these runs never create findings. REST surface: `GET /api/app-threat-models`,
`GET /api/app-threat-models/:id`.

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

**Request flow (app-level threat models)**: client sends `{type: "app_threat_model", runId,
path, app, branch, instruction}` → same directory validation as scans, spawns `claude -p`
with `agents/app_threat_model.md` as the system prompt, `--allowedTools "Read,Grep,Glob"`,
`cwd` set to the target `path` → events relay as `{type: "app-threat-model-event", runId,
id, event}` (again distinct type names —
`app-threat-model-started`/`-event`/`-stderr`/`-error`/`-done` — same collision-avoidance
reasoning as the `scan-*` types) → on close, `extractVerdict()` is expected to return the
holistic report object directly (not wrapped in a `findings` array like `scan.md`, and not a
single finding's verdict like the per-finding agents) and is stored as-is on the record's
`verdict` field, then `{type: "app-threat-model-done", runId, id, code, verdict}` is sent.
No findings are created and no existing finding is touched by this flow.

**Multiple concurrent runs**: a single WebSocket connection tracks runs in a `runId`-keyed
`Map` of child processes (`children` in `server.js`), shared by per-finding runs, scans, and
app-level threat models — not a single in-flight run, so multiple stages/scans/app-level
runs can be running at once from one browser tab. `{type: "cancel", runId}` kills a specific
run (checked against `runIndex`, `scanRunIndex`, and `appThreatModelRunIndex`). Closing the
tab/connection kills and marks-cancelled every still-running child tied to it
(`ws.on('close')`).

**Why `claude -p` instead of the Messages API directly**: `--output-format
stream-json` already emits structured events (assistant text, tool calls, final
result) with no custom parser needed, and the agents already exist as `.md`
prompt files used manually in a terminal — this automates that same invocation
rather than replacing it.

**The verdict contract**: every agent's `.md` file ends with an instruction to
close its response with exactly one fenced JSON block. The server does not
validate or enforce a schema — `extractVerdict()` in `server.js` just regexes
for the first ` ```json...``` ` block and parses it. The client's `runCardHtml()`
(finding detail page's Agent runs section) renders any verdict object generically by
iterating key/value pairs (badging a fixed set of known fields: `verdict`,
`severity_confirmed`, `confidence`, `priority`), so schema changes in an agent's `.md` need
no frontend change unless new behavior should key off a new field specifically (e.g.
`deriveStatus()` in `server.js` keys off `verdict`/`next_agent`).

**No live per-finding streaming view**: per-finding runs (Triage/Threat Model/Remediation)
don't render a live activity feed or even a live "Analysis" prose stream while running —
`handleServerMessage()` in `index.html` ignores `event`/`stderr` WS messages entirely for
these and only acts on `done`/`error`, at which point the Timeline row and (if that finding's
detail page happens to be open) the Agent runs section update via `refreshFindingAfterRun()`
→ `updateFindingListItem()`. `startStage()` does push one optimistic "running" placeholder
into the finding's cached `runs` array so the detail page shows the run as in-progress
immediately rather than staying blank until it finishes, but there's no token-by-token or
tool-by-tool feed — this was a deliberate simplification after an earlier design that showed
every tool call/result plus raw stream-json read as noise rather than the two things an
AppSec tester actually wants: what was found, and why (now surfaced only once, in the
finished verdict). Scan cards on the Scans page are the one place with a live feed, since a
scan can run for minutes over many files: `handleScanRawEvent()` in `index.html` updates a
running tools/tokens/files-read counter and severity chip row per stream-json event, and
`agents/scan.md`'s narration contract has it prefix each candidate finding with a literal
`[severity]` tag as it's spotted, which `trackScanCandidates()` parses via `SEV_TAG_RE` into
a live scrolling list — but even here the raw stream-json itself is never rendered, only
counters and parsed candidates derived from it.

**Taxonomy convention**: severity/confidence/priority definitions live inside
each agent's `.md` file and must stay byte-identical across agents (copy, don't
redefine) — they're meant to match the org's existing `owasp-code-review`
Claude skill so findings read consistently whether a human or an agent
produced them. OWASP/ASVS/CWE/NIST 800-53 framework mapping (`owasp`, `asvs`,
`cwe`, `nist_800_53`) is required (not optional) whenever an agent's verdict
is `confirmed` or `needs_review` — this program runs under FedRAMP
Moderate/High and FISMA, and the mapping feeds compliance reporting downstream (surfaced
today in each finding's detail page and in `GET /api/findings/export.csv`). See
`agents/triage.md` for the current definitions; `threat_model.md` and `remediation.md`
reuse them (`remediation.md`
now assigns them itself, same rules, when there's no prior verdict to carry forward — see
"Pipeline shape" above) and only add stage-specific fields
(`preconditions`/`attack_narrative`/`blast_radius` for threat_model;
`root_cause`/`fix_guidance`/`verification_steps`/`effort` for remediation). `scan.md`
findings deliberately do *not* carry `verdict`/`severity_confirmed`/`confidence`/
`priority`/framework-mapping — they're raw, scanner-export-style output; a `severity`
field is the scan's best-effort initial estimate only, and real triage happens downstream.
`app_threat_model.md` reuses only the `severity` scale and the `owasp`/`cwe` pair (per entry
in its `top_risks` array) — it has no `verdict`/`confidence`/`priority`/`asvs`/
`nist_800_53` fields at all, since it isn't triaging a finding, just flagging structural
risks in a holistic report; framework mapping there is best-effort context, not the
compliance-feed requirement described above.

**Security posture**: this is a local single-user dev tool. No auth on the
WebSocket or REST endpoints; `--permission-mode acceptEdits` and `--allowedTools`
("Read,Grep" for per-finding agents, "Read,Grep,Glob" for scans and app-level threat
models) are set loosely for a fast test loop, not for anything beyond localhost use. Both
`agent` names and `runId`s from client messages are validated against `^[a-zA-Z0-9_-]+$`
before being used (agent name is joined into a filesystem path) — don't relax either when
adding features. The Scans feature (and, the same way, app-level threat models) is a
deliberate widening of that posture: both spawn `claude` with `cwd` set to **any directory
path the client sends**, gated only by "does this path exist and is it a directory"
(`fs.statSync` in `handleScanMessage` / `handleAppThreatModelMessage`) — there's no
allowlist of scannable roots. That's consistent with "local single-user tool trusted by its
one user," not with exposing this app beyond localhost; don't add auth-free network
exposure without revisiting this.

**Not yet built**: disk persistence (both the findings store and the scans store are
in-memory and reset on restart — there's no SQLite/JSON-file layer yet), CSV *ingestion*
(export exists — `GET /api/findings/export.csv` — but importing an external scanner's CSV
to seed findings, the original `findings-dashboard.jsx` workflow, does not), and the
dashboard merge itself (`findings-dashboard.jsx`'s Azure DevOps ticket creation currently
does a browser-side `fetch()` that's expected to hit CORS — if that logic moves into this
app, it should move server-side, where Node has no CORS problem).
