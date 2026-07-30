# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A local Node app that invokes Claude Code headless (`claude -p`) as a set of specialized
AppSec agents, streams their reasoning live to a browser UI over WebSocket, and parses a
structured JSON verdict out of each run. The UI is a "mission control" style app with a
global left nav ordered to mirror the actual finding pipeline — Dashboard / Reasoning Scan /
SCA Scan / Control Scan / Agent Triage / Threat Model / Reports — with Agent Configuration and
Settings both tucked into the nav footer instead of the main list. Agent Configuration used to
be a top-level item, but it's a config/admin screen (editing `agents/*.md` files), not a
workflow step in the Scan → Triage → Threat Model flow the rest of the main nav walks through
in order, so it was moved down next to Settings — the other admin-y nav-footer entry. Reasoning
Scan, SCA Scan, and Control Scan additionally sit grouped under a small non-clickable `SCANS`
section label (`.nav-section-label`) and are visually indented (`.nav-item-indent`, both
collapsing back to a plain centered icon when the sidebar is collapsed) — the flat list
otherwise read as seven equally-weighted items with no hint that these three are all "kick off
a whole-directory run against a target path" actions (two produce findings, one produces a
compliance report — see the Control Scan bullet below for why it's grouped here despite that
difference); the indent groups them without adding a second click target (the label itself
does nothing — clicking any of the three still works exactly as any other nav item). Timeline
is deliberately *not* one of these nav items — see the Timeline bullet below for why and where
it lives instead. Four nav items carry a live status badge (`renderNavBadges()`, called from
`upsertTimelineEntry()`, `upsertControlAssessment()`, and `renderNavStatus()` so it stays
current from any view — `upsertControlAssessment()` needs its own explicit call since Control
Scan runs never flow through `upsertTimelineEntry()` the way scans do):
**Reasoning Scan** shows a pulsing yellow dot while any non-SCA scan is `status: 'running'`
(`scansList`, filtered to `scanType !== 'sca'`); **SCA Scan** shows the same pulsing yellow dot,
filtered the other way (`scanType === 'sca'`) — split so a running SCA scan doesn't make the
Reasoning Scan page look like something's happening there when it isn't, and vice versa;
**Control Scan** shows the same pulsing yellow dot while any `controlAssessmentsList` entry is
`status: 'running'`; **Agent Triage** shows a red count pill of findings whose `status !==
'closed'`. When the
sidebar is collapsed, `#global-nav.collapsed .nav-item .nav-badge` forces every badge — dot
or count pill alike — to the same 8×8 corner dot (text hidden via `font-size: 0`, the count
still readable from the badge's `title` tooltip on hover); without this override the wider
count pill overlapped the nav icon instead of sitting in its corner like the plain status
dots do.

- **Dashboard** — a pure status/briefing screen: the Briefing banner, a `.quick-actions` row
  of two prominent cards ("Start a scan" / "View timeline", `#dash-scans-link`/
  `#dash-timeline-link` — the latter opens the timeline drawer, see the Timeline bullet below,
  not a dedicated view) linking into those destinations, stat tiles (in progress, not started,
  in review, remediation ready, total findings, total agent runs), and an Agents panel (every
  per-finding agent from `agentsList` — built-in or custom — so it grows automatically as
  agents are added in Agent Configuration; the whole-app agents, Scan/App Threat Model/Control
  Scan, are deliberately excluded since `agentsList` itself is already filtered to per-finding
  agents server-side, see below). The panel itself (`#dash-agents-panel`, `.panel-clickable`) is a single
  click target that navigates straight to Agent Configuration — a small "→" fades in on hover
  (`.panel-title-arrow`) as the only visual hint it's clickable, since a whole panel acting as
  one link has no other natural affordance. It holds no form of its own — `renderDashboard()`
  only refreshes the briefing/stats/agents panel, nothing else. The quick-actions row replaced
  an earlier `.dash-footer` bar that crammed the same two links into a thin text strip
  alongside a "`{n} findings · {m} total runs`" summary — that summary was pure duplication of
  numbers the stat tiles already show directly above it, and the two links read as an
  afterthought; removed the redundant text and gave the links real button-card treatment
  instead. The connection/findings-count/agents-ready/scans-count status lives in the sidebar
  (`#nav-status`, rendered by `renderNavStatus()`) so it's visible from every view, not just
  Dashboard.
- **Reasoning Scan** — the scan kickoff form and its live cards, on their own top-level page
  (this used to be folded into Dashboard per an earlier explicit request to "combine Scans
  into Dashboard, let me kick off scans from the main screen" — a later request reversed that,
  finding the combined Dashboard confusing, and asked for Scans to be split back out plus for
  the whole-app threat model action to move off the scan form entirely, see below): a
  target-directory input, branch/app fields, an "+ instructions" textarea toggle, and a Start
  button — followed by `#scan-live-container` (2-column grid of live scan cards). Starting a
  scan optimistically pushes into both `scansList` and `timelineEntries` so the Dashboard
  briefing and timeline drawer update before the server round-trip completes.

  The page used to also carry a **Scan type** pill row (Reasoning Scan vs. Custom) and a
  toggleable "run after scan" agent-pill row — both removed. The scan-type pill was dropped
  because this page is now dedicated to reasoning scans specifically (SCA moved to its own
  page, see below, and nothing in the UI could still produce a `custom`-type scan once the
  pill was gone), so `scanType` is just a hardcoded constant client-side now
  (`const scanType = 'reasoning'`) — the same pattern the SCA page already used for its own
  fixed type. The "run after scan" pill row (`scanSelectedAgents`/`renderScanAgentSelection()`)
  turned out to be dead code on inspection — the selected agents were never actually read
  anywhere or sent to the server, so removing it was a straight cleanup, not a
  functionality cut. The **scope toggle** (Full scan / Diff only, `#scan-scope-toggle`) moved
  from the form body into the page's `view-header`, top-right, alongside the new clock-icon
  timeline button (`.view-header-actions`, see the Timeline bullet below) — freeing the form
  itself down to just the fields that vary per invocation.

  Historically this page also carried a **Scan type** merge story worth keeping straight:
  SAST and DAST used to be separate pills/scanTypes, but both were really just this same LLM
  reading source and reasoning about it (no real static-analysis tool parsing an AST, no live
  traffic hitting a running app), so presenting them as distinct scanner categories was
  misleading — they were merged into one `reasoning` scan type whose canned framing
  (`SCAN_TYPE_FRAMING.reasoning` in `server.js`) covers both angles in a single pass. That
  merge goes all the way down to finding classification: `FINDING_SCAN_TYPES` is
  `['reasoning', 'sca']`, and the Agent Triage screen's type tabs are Reasoning/SCA (no
  separate DAST tab) — see the Agent Triage bullet below.
- **SCA Scan** — Software Composition Analysis gets its own top-level page (renamed from plain
  "SCA" — the nav item is an action/page name, not just the technique's acronym, and "SCA
  Scan" reads more clearly as a peer to "Reasoning Scan"), structurally identical
  to Reasoning Scan (target directory, branch/app, scope toggle now in the header, Start
  button, live cards, a clock-icon timeline button). It reuses the exact same underlying
  mechanism as Reasoning Scan — the same WS `'scan'` message, the same `scanRuns` Map, the
  same `makeScanCard()` — just with a different target container (`#sca-live-container`) and
  `scanType: 'sca'` hardcoded (`startScaScan()`/`beginScanRun()` in `index.html`, factored out
  of the old single `startScan()` so both pages share the run-tracking/live-card machinery
  instead of duplicating it). Its own nav badge (`#nav-badge-sca`) mirrors Reasoning Scan's but
  filters to `scanType === 'sca'` scans only, so the two pages' "something's running"
  indicators never cross-contaminate. This page used to also carry a "Run after scan" pill row
  (`scaAgentsList`/`scaSelectedAgents`/`renderScaAgentSelection()`) — removed, since on
  inspection it turned out to be dead the same way the earlier Reasoning Scan copy was: the
  selected agents were rendered and toggleable but never actually read by `startScaScan()` or
  sent to the server, so there was no real "run after scan" behavior behind the UI. The shared
  `renderAgentPillSelection()` helper it depended on, and the now-unused `.agent-pill`/`.ap-dot`
  CSS, were removed with it.
- **Timeline** — every scan *and* every per-finding agent run, newest first, date-grouped,
  filterable by a `kind` tag (`scan` / `triage` / `threat_model` / `remediation`, color-coded
  via `AGENT_META` in `index.html`). This is **not a top-level nav destination** — it used to
  be, but a dedicated Timeline tab read as one more place to check for "what's happening,"
  competing with the per-page nav badges that already answer that question contextually.
  Instead it's a slide-in drawer (`#timeline-drawer` + `#timeline-drawer-backdrop`,
  `openTimelineDrawer()`/`closeTimelineDrawer()`) opened by a small clock-icon button
  (`.clock-btn`) in the `view-header` of Reasoning Scan, SCA Scan, and Threat Model — each
  button opens the *same* drawer and reuses the *same* list (`#timeline-list` — untouched
  markup/JS, just relocated from a full page into the drawer), but pre-scopes it to that page's
  own activity: Reasoning Scan passes `openTimelineDrawer('scan', 'reasoning')`, SCA Scan passes
  `openTimelineDrawer('scan', 'sca')`, Threat Model passes `openTimelineDrawer('threat_model',
  null)`. The second argument, `timelineScanTypeFilter`, only narrows entries when
  `timelineFilter === 'scan'` (a scan-kind timeline entry now carries `scanType`, added to
  `GET /api/timeline`'s scan-entry shape in `server.js` specifically to make this narrowing
  possible). The filter pills (`#timeline-filters`, `renderTimelineFilters()`) are **All**,
  **Reasoning Scan**, **SCA**, then one per agent kind (`agentsList`) — Reasoning Scan and SCA
  are two distinct pills, not one shared "Scan" pill, specifically so SCA activity has its own
  filter to click instead of being lumped in with reasoning scans (an earlier version had just
  one combined "Scan" pill and no way to isolate SCA runs from the drawer's own filter row).
  Both scan pills set `timelineFilter = 'scan'` and differ only in which `scanType` they set —
  `makePill()`'s active-state check has to account for that (`timelineFilter === 'scan' &&
  timelineScanTypeFilter === scanType`, not a plain key match like the agent-kind pills use).
  Clicking any pill sets both fields explicitly, so a preset from a clock-icon button is fully
  overridden by whichever pill is clicked next — there's no scanType leaking from initial state
  into an unrelated pill selection. This preset-then-override design keeps the drawer
  contextually useful without losing the ability to browse everything from any entry point.
  The Dashboard's "View timeline" quick-action opens the same drawer with no preset
  (`openTimelineDrawer('all')`). The Escape key and clicking the backdrop both close it
  (folded into the same document-level `keydown`/`click` handlers the context menu and modals
  already used, rather than adding a second listener). Scan rows are expandable in place
  (click toggles a `.timeline-row-body` showing the findings that scan produced, reusing
  `renderScanFindingsBody()`); agent-run rows instead navigate to that finding in Agent Triage
  on click. `GET /api/timeline` server-side merges `findings` runs and `scans` into one array
  tagged with `kind` before sorting by `startedAt`. A running-dot per clock button
  (`updateTimelineClockDots()`, replacing the single shared `#nav-badge-timeline` the old nav
  item carried) turns yellow while that page's own scope has something running, or green if
  nothing in scope is running but something finished anywhere since the drawer was last opened
  (`timelineUnseenDone`, still a single global counter — matches the old badge's behavior of
  clearing on any drawer open, regardless of scope).
- **Agent Triage** — a sortable table (`renderFindingsTable()`), not a Kanban board: findings
  are split into type tabs (`findingsTypeFilter`: All / Reasoning / SCA, `#findings-type-tabs`,
  styled as a `.group-toggle` segmented control) because each type's useful columns differ —
  Reasoning shows a merged **Location** column (file path if it's a code-pattern finding,
  endpoint+method if it's an attack-surface one — a reasoning-scan finding can be either, or
  even both, now that there's no separate DAST scanType to gate the field on) plus Rule/CWE;
  SCA shows Package + Fixed-in (`FINDINGS_COLUMNS` in `index.html`). Every type's Runs column shows the run count plus the
  latest run's agent and, if that run produced a verdict, the verdict in parens (e.g. "2 runs
  · Threat Model (needs_review)") — a lightweight way to see a finding's most recent pipeline
  state without opening it. Severity/Title/Status columns are click-to-sort
  (`findingsSort`, toggling asc/desc on the same header). Every row also carries a **checkbox**
  in a leading `.ft-select-col` column (`selectedFindingIds`, a `Set` of finding IDs) plus a
  header "select all visible" checkbox that only ever affects the currently-filtered/sorted
  `rows` array, not the full findings list — checking/unchecking updates a header button,
  "Auto-remediate selected (N)" (`#auto-remediate-btn`, disabled at N=0), which feeds the
  Remediation screen below. Every row also carries a trailing **`.ft-actions-col`** with a
  small three-dot button (reusing the `.console-toggle-btn` icon-button style) that opens the
  exact same per-agent dropdown as right-clicking the row — added because right-click alone
  isn't discoverable, especially without a mouse; the button just calls
  `openFindingContextMenu()` positioned under itself via `getBoundingClientRect()`, same
  pattern as the Finding Detail page's "Agent Runs ▾" button. A **Scan** filter sits beside the type tabs — not a native
  `<select>` but a small custom popover (`.scan-filter-dropdown`, `#findings-scan-filter-btn` +
  `#findings-scan-filter-menu`, `renderFindingsScanFilter()`), each item formatted as e.g.
  "Reasoning scan on `<path>` started 2h ago" / "SCA scan on `<path>` started..."
  (`scanFilterLabel()`) rather than the old dropdown's bare path text — populated from
  `scansList` (newest first), it restricts the table to one scan's findings via
  `finding.sourceScanId` (`findingsScanScoped()`); the type tabs' counts and the empty-state
  message both react to it too, and a scan that produced no findings still on record (or whose
  findings were all removed) is left out of the menu rather than becoming a dead-end filter.
  Three other places link into this same filtered view via `openFindingsFilteredByScan(scanId)`:
  the Finding Detail page (a "Found by scan of `<path>`" line under the badges, if the finding
  has a `sourceScanId`), a completed scan card's "View in Agent Triage →" action
  (`updateScanCardActions()`, Reasoning Scan page), and a timeline drawer scan row's expanded
  body ("View all in Agent Triage →", `renderScanFindingsBody()`) — added because discovering
  the scan filter only via the popover wasn't obvious enough on its own.
  `openFindingsFilteredByScan()` just sets `findingsScanFilter` and calls `showView('findings')`.
  `findingsScanFilter` (not the popover button's DOM text) is the single source of truth for
  which scan is selected, read fresh on every `renderFindingsScanFilter()` call rather than
  scraped back from whatever the button currently displays — a past version of this filter used
  a native `<select>` where reading `.value` back as a fallback silently discarded a
  programmatically-set filter, which is why the state now flows one direction only (JS variable
  → rendered button text, never the reverse). Clicking a row navigates to a
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
  declared on the Agent Configuration screen, built-in or custom), so a new custom agent shows
  up there with no code change. Both paths converge on `openFreshStageModal()`. Note:
  `openFindingContextMenu()`'s button click handler calls `e.stopPropagation()` — without it,
  the click bubbles to the document-level "click outside closes the menu" listener and closes
  the menu in the same tick it opened. An "Export" button (`GET /api/findings/export.csv`)
  downloads all findings + latest verdicts.
- **Remediation** — a second, narrower full-page table reached only via Agent Triage's
  "Auto-remediate selected (N)" button (`autoRemediateSelected()`), not a top-level nav item —
  same reasoning as Finding Detail not being one: it's a destination for one specific action,
  not a place someone browses to on its own. Clicking it clears `selectedFindingIds`, snapshots
  the checked IDs into `remediationBatchIds` (an ordered array — this batch, not "every
  remediation ever run," is deliberately what stays on screen; see below), navigates to
  `#view-remediation`, and then for each ID: ensures the full finding is cached
  (`ensureFindingCached()`), re-renders immediately so the **Issue**/**Code issue** columns
  appear right away (`renderRemediationView()`), and fires a normal `remediation` stage run
  (`startStage(id, 'remediation', buildBaseContext(finding), '')` — the same function every
  other agent run uses, just without the small stage modal in front of it, since "auto" here
  means skip the per-run review step for a batch action). The **Corrected code** column
  (`remediationRowStateHtml()`) shows "Generating…" while that finding's run is `running`, then
  the agent's `corrected_code` verdict field once it lands — a new field added to
  `agents/remediation.md`'s output contract specifically for this screen: the full corrected
  version of the finding's `code` snippet, not just prose fix guidance, so it can render
  side-by-side with the original in a `.code-block` (`highlightCode()`, reused unchanged). It's
  `null` when there's no `code` snippet to correct, or the real fix is architectural (the agent
  is told to say so in `fix_guidance` instead of inventing a misleading single-snippet diff).
  Because this is a real `remediation` run like any other, `deriveStatus()` in `server.js` picks
  it up: a new `remediation_generated` status is derived when the latest run is `agent ===
  'remediation'` with a non-null `corrected_code` and a `confirmed`/`needs_review` verdict
  (checked *before* the existing `remediation_ready` case, but *after* the `false_positive`/
  `duplicate` → `closed` case — a finding the agent itself flagged as not real stays `closed`
  even if it still produced speculative corrected code, since remediation.md's contract has it
  fill in best-effort guidance for a pattern even when this particular instance isn't
  exploitable). The status shows up back on Agent Triage as a new accent-colored "Remediation
  generated" badge (`statusLabel()`/`.badge.remediation_generated`) the moment the run finishes,
  via the same `updateFindingListItem()` hook every other status change already flows through
  (extended with one more branch: re-render the Remediation table too, if it's the open view
  and the finding is part of the current batch). Revisiting this screen only ever shows the
  *current* batch (`remediationBatchIds` is replaced, not appended to, each time the button is
  clicked) — findings remediated in an earlier batch this session aren't still listed after a
  new batch runs; the badge on Agent Triage is the durable record of "this one already has
  corrected code," not this screen.
- **Threat Model** — a read-only, cross-finding view of every finding with a completed
  Threat Model run whose verdict is `confirmed` or `needs_review` (`latestThreatModelEntries()`
  — findings never threat-modeled just don't appear, no placeholder queue). Entirely derived
  client-side from the same `timelineEntries` cache the timeline drawer uses (loaded on
  whichever comes first, `openThreatModelView()` ensures it itself via `loadTimeline()` if
  needed) — no dedicated endpoint. Rendered as a **category × severity heat map**
  (`buildThreatHeatmap()`, plain HTML/CSS `<button>` cells, no charting library or SVG) instead
  of a card grid, a radial hub-and-spoke, or the top-down tree that briefly replaced it: rows
  are OWASP categories (`verdict.owasp`, sorted by finding count descending, row label colored
  by the *worst* severity in that category via `worstOfList()`), columns are the fixed severity
  scale (Critical…Informational, `HEATMAP_SEVERITY_COLS`), and each cell is shaded by how many
  findings land in that category+severity combination (`--heat-intensity`, a per-cell CSS
  custom property scaled `0.28–1.0` against that row's own max count) — this replaced the tree
  (which itself replaced an even earlier radial layout) because a grid answers the actual
  triage question — "which category+severity combination has the most findings" — at a glance,
  where a tree only showed category-level counts and made you read every branch to compare
  severities within it. Clicking a non-empty cell (`.tm-heat-cell.has-findings`) filters
  `entries` in JS by that cell's `data-category`/`data-sev` and calls
  `renderTmCellFindings(cellEntries)`: for the common case of exactly one matching finding it
  jumps straight to that finding's report; for more than one it shows a small row of pill
  buttons (`#tm-cell-findings`, one per finding title) above the report so the user picks which
  one to read — the "report" a cell represents, surfaced without needing a separate list view.
  Either way the report itself is `renderAttackPathFlow()`: four connected boxes — Attacker
  (generic, not agent data) → Preconditions → Attack Path → Blast Radius — using the exact prose
  those three verdict fields already contain, plus a "View finding →" button into the full
  Finding Detail page. This needed no new agent capability; it's purely a different way to look
  at data `agents/threat_model.md` already produces. A finding can carry more than one Threat
  Model run over its lifetime (re-run after a code fix, or re-run after Triage's picture
  changes) — `allThreatModelEntriesForFinding()` returns all of them (newest-first) for a given
  finding, and whenever there's more than one, `renderAttackPathFlow()` shows a **Run**
  `<select>` above the flow (`#tm-run-select`, `renderThreatModelDetail()`) so a specific
  historical run can be picked instead of always showing the latest. Because the heat map
  itself only aggregates each finding's *latest* run (`latestThreatModelEntries()`, filtered to
  `confirmed`/`needs_review`, tracked in `tmMapFindingIds` — a `Set` of the finding IDs
  currently represented on the map, checked instead of re-querying the DOM for a specific
  finding's cell, since a cell aggregates a whole category+severity bucket rather than mapping
  1:1 to one finding), a finding whose most recent run is `false_positive` (or whose
  selected-in-the-dropdown run just isn't the current one) may not be represented in any cell
  right now — in that case the detail panel adds a "Not shown on the map above" hint rather
  than silently implying it belongs to a cell it isn't counted in.
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
  instructions, and a Start button, styled like the Reasoning Scan page's New Scan form but with its
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
  message straight from this form) and so aren't part of the OWASP heat map above; they get
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
  `scan`) since it isn't a per-finding pipeline agent — it doesn't show up in the Agent Triage
  stage modal's agent dropdown or the "run after scan" pill row.

  `renderAppThreatModelDetail()` also draws a diagram, not just prose — it groups `top_risks`
  by `owasp` locally and calls the same shared `buildThreatHeatmap()` the per-finding page uses,
  just with a `getSeverity` callback reading `risk.severity` instead of
  `verdict.severity_confirmed`, since a whole-app report has no per-finding verdict to pull
  from. Risk cards also carry `data-owasp`/`data-severity` attributes now (in addition to their
  existing `data-risk-index`) so a heat-map cell click can cross-highlight every matching card,
  not just one by index: clicking a cell compares its `data-category`/`data-sev` against each
  `.atm-risk-card`'s dataset in JS (not a CSS attribute selector, to avoid escaping arbitrary
  category-name text into a selector string), toggles `.selected` on every match, and scrolls
  the first match into view; clicking a risk card directly still just self-highlights.

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
- **Control Scan** — a top-level page for RMF/ISSO staff (renamed from "Controls Assist" —
  shorter, and reads more like a peer to "Reasoning Scan"/"SCA Scan" in the nav, since it's the
  same kind of whole-directory action just for a different purpose — now grouped with them
  under the `SCANS` nav section label, see the intro above), structurally the same
  form-plus-accordion-list pattern as the Threat Model page's "App-level Threat Models"
  section (own store, own WS message-type family, own live stats) but entirely independent
  of it: it exists to help draft SSP (System Security Plan) content, not to find
  vulnerabilities. `agents/controls_assist.md` reads a whole directory (like
  `app_threat_model.md`) and, instead of a threat narrative, identifies which NIST 800-53
  controls the *application layer* provides evidence for — deliberately not every control in
  the baseline, since most families (PE, PS, CP, MA, MP, and often parts of AT/CA/PL/RA) are
  satisfied by the hosting platform or org process, not app code. Every control in the
  verdict's `controls` array carries `applicability` (`app_addressed | partially_addressed |
  inherited | not_applicable`) and `implementation_status` (`implemented |
  partially_implemented | planned | not_applicable | null`) — this is the mechanism that
  keeps the agent honest about scope rather than claiming coverage it can't back up, plus a
  `narrative`/`evidence`/`gaps` per control. Server-side: `controlAssessments`/
  `controlAssessmentRunIndex` (in `server.js`) mirror `appThreatModels`/
  `appThreatModelRunIndex` exactly — same record shape, same `cancel`/WS-close/session-clear
  wiring — REST at `GET /api/control-assessments(/:id)`, WS messages
  `controls-assist-started/-event/-stderr/-error/-done`. Client-side: `caRowHtml()`/
  `renderControlsAssistDetail()` reuse the exact same `.atm-row`/`.atm-row-summary`/
  `.atm-row-body` CSS scaffold and the same `trackRunToolActivity()`/`trackRunTokens()`/
  `updateContextBar()` helpers app-level threat models use for live tool/file/token/elapsed
  stats — only the detail body differs: controls are grouped by NIST family (plain-card list,
  `.ca-family-group`/`.ca-control-card`) rather than a severity heat map, since applicability/
  implementation-status isn't a severity scale and forcing it through `buildThreatHeatmap()`
  would misrepresent it. A **"Download SSP draft (.md)"** button
  (`buildControlAssessmentMarkdown()` + `downloadTextFile()`, a plain Blob/`URL.createObjectURL`
  download, no server round-trip) turns the report into pasteable Markdown grouped the same
  way, directly serving the "assists with SSP creation" goal rather than leaving the narrative
  stuck on-screen. Like App Threat Model, these runs create no findings and aren't part of
  `GET /api/timeline` (no foreign key to a finding or scan), so there's no clock-icon drawer
  button on this page.
- **Agent Configuration** — a nav-footer entry (moved out of the main nav list, see the intro
  above — it's a config/admin screen, not a workflow step) for managing every file under
  `agents/` from the browser instead of by hand: create/edit/delete via
  `GET/POST/PUT/DELETE /api/agents(/:name)` in `server.js`. Built-in agents
  (`triage`/`threat_model`/`remediation`/`scan`/`app_threat_model`/`controls_assist`,
  `BUILTIN_AGENTS` server-side) can be edited but not deleted (403). This screen fetches
  `GET /api/agents?all=1` into its own `agentConfigList` — deliberately a *different* list
  from `agentsList` (the plain `GET /api/agents`, still filtered by `NON_FINDING_AGENTS =
  ['scan', 'app_threat_model', 'controls_assist']` server-side): `agentsList` feeds the
  per-finding stage modal's agent dropdown and the SCA page's "Run after scan" pill row, where
  a whole-directory agent has no business appearing, while `agentConfigList` is this screen's
  own unfiltered view so all three whole-directory agents are still visible/editable here —
  each gets a second "Whole-app" badge (client-side `NON_FINDING_AGENTS` mirror, next to the
  existing "Core" badge) so it reads clearly as a different kind of agent from the per-finding
  three. New per-finding agents are immediately usable everywhere `agentsList` is consumed, no
  extra wiring needed. The Dashboard's Agents panel (`#dash-agents-panel`) is a shortcut into
  this screen — see the Dashboard bullet above.
- **Reports** — a placeholder top-level screen (`#view-reports`), added ahead of any actual
  reporting feature so the nav slot and page shell exist for whatever gets built there next
  (an exportable compliance/findings report was the motivating idea, per the intro's
  `GET /api/findings/export.csv` and the FedRAMP/FISMA framework-mapping requirement described
  under "Taxonomy convention" below — this screen would be the natural home for a richer,
  formatted version of that same data). Currently just a "Coming soon" message
  (`.placeholder-panel`); no server-side support, no data, no wiring beyond the nav
  item/`showView()` toggle.
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

**Pipeline shape**: `Scan → Agent Triage → Remediation` is the conceptual path, but **no agent
ever runs automatically** — every run requires an explicit, reviewable action so there's
always an audit trail before anything executes against a finding (an earlier version
defaulted straight to Remediation on click, which read as auto-fixing without review — this
was a deliberate correction). Note "Remediation" names two different things in this app: the
`remediation` agent/pipeline stage (run one finding at a time, from the stage modal like any
other agent) and the standalone **Remediation** screen (a batch of those same runs, kicked off
together via Agent Triage's "Auto-remediate selected" button — see the Remediation bullet
above). They share an agent and a verdict shape; the screen is just a different entry point
and a different view of the results, not a separate pipeline. Both the Finding Detail page's
"Agent Runs ▾" button and the right-click context menu on an Agent Triage table row open the
same dynamic per-agent menu
(one "Run <Agent>…" item per entry in `agentsList`) as equally-weighted shortcuts into the
same small stage modal (agent dropdown + editable context + optional instructions,
`openFreshStageModal()`) — none of them run instantly, and none is "the default" over the
others. Because a tester can
jump straight to Remediation without Triage or Threat Model ever having run,
`remediation.md` has to be able to stand on its own: if there's no prior verdict in its
context, it does Triage's confirm/severity/framework-mapping call itself before writing fix
guidance (see the "check your context before you start" section at the top of
`agents/remediation.md`). `agents/scan.md`, `agents/app_threat_model.md`, and
`agents/controls_assist.md` are three further agent files but are *not* per-finding
pipeline agents — `GET /api/agents` (`NON_FINDING_AGENTS` server-side) filters all three out
of the Triage/Threat Model/Remediation list on purpose; `GET /api/agents?all=1` is the
unfiltered variant Agent Configuration uses instead (see its bullet above).

## Commands

```
npm install
npm start          # runs `node server.js`, serves http://localhost:4500
```

There is no build step, lint script, or test suite — `package.json` has only `start`.
Before invoking, `claude auth status` must succeed (the server spawns the CLI
non-interactively and does not handle auth itself).

To exercise the pipeline manually: open `http://localhost:4500` (lands on Dashboard), go to
Reasoning Scan, enter a directory path on this machine under "New scan" and click "Start
scan" — watch its live card right there, then check Agent Triage once it completes (or open
the timeline drawer via the clock icon and expand the row there). Click a finding's row in the
Agent Triage table (or a timeline agent-run row) to open its full-page detail view, then click
"Agent Runs ▾" in the page header (or right-click the table row for the same menu) to pick an
agent, review the context/instructions in the small stage modal, and explicitly start it;
nothing runs without that step. Alternatively, check one or more rows' checkboxes on Agent
Triage and click "Auto-remediate selected" to run Remediation on all of them at once and see
original-vs-corrected code side by side on the Remediation screen. The detail page's Agent
runs section updates live once a run finishes (or shows a "running" placeholder immediately,
via an optimistic push in `startStage()`). There is no automated test for the WebSocket flow —
verification is manual, through the browser.

## Architecture

```
server.js          Express + ws. In-memory findings store (seeded with sample data on
                    boot) and a separate in-memory scans store, behind a small REST API,
                    plus a WebSocket handler that spawns `claude -p` per agent run (or
                    per scan), relays stream-json lines live, and extracts the final JSON
                    block from the accumulated assistant text.
public/index.html   The whole app: global nav (status summary + Settings entry in the nav
                    footer) with Dashboard (briefing + stats + a clickable agents panel),
                    Reasoning Scan (the scan kickoff form — target/branch/app, scope in the
                    header — plus its live scan cards and a timeline-drawer clock button), SCA
                    Scan (structurally identical, its own live cards, its own clock button, plus a
                    still-wired "run after scan" pill row), an Agent Triage table split into
                    Reasoning/SCA type tabs with click-to-sort columns, a per-scan filter
                    popover, and row checkboxes feeding an "Auto-remediate selected" button, a
                    full-page Finding Detail view per finding (meta grid, syntax-highlighted
                    code block, and an Agent runs history with a single "Agent Runs ▾"
                    dropdown), a Remediation screen (original vs. agent-corrected code for a
                    batch of auto-remediated findings), a Threat Model page (per-finding OWASP
                    x severity heat map plus a "New app threat model" form and its own
                    accordion-style App-level Threat Models list, also heat-mapped, plus a
                    clock button), a Control Scan page (its own "New control scan"
                    form plus an accordion list of runs grouping identified NIST 800-53
                    controls by family, for SSP drafting), a nav-footer Agent Configuration
                    screen for managing every `agents/*.md` file from the browser, a Reports
                    placeholder, a slide-in timeline drawer shared by three clock buttons, a
                    right-click context menu on table rows for the same agent actions, and
                    modals for adding a finding / running a stage with custom instructions.
agents/*.md         Agent system prompts (passed via --append-system-prompt). Plain
                    markdown, no code — this is the only place agent-specific analysis
                    logic lives. New *per-finding* agent = new .md file, no server
                    changes needed beyond it existing on disk (see "not yet built" below
                    on hardcoded assumptions elsewhere). `scan.md`, `app_threat_model.md`,
                    and `controls_assist.md` are the three exceptions — each is invoked
                    through its own dedicated code path (`handleScanMessage` /
                    `handleAppThreatModelMessage` / `handleControlsAssistMessage` in
                    server.js), not the generic per-finding `run` path, because all three
                    need a different tool set (`Glob` in addition to `Read`/`Grep`), a
                    different `cwd` (the target directory, not the app's own), and a
                    different output shape (`scan.md` returns `{"findings": [...]}`;
                    `app_threat_model.md` and `controls_assist.md` each return their own
                    holistic report object — see the Reasoning Scan/Threat Model/Control Scan
                    bullets above) rather than a single per-finding verdict object.
```

**Findings store**: `findings` (Map, in `server.js`) is session-lifetime only — reset on
restart, seeded from `seedFindings()` with six sample AppSec findings (five reasoning, one
SCA — enough to populate both Agent Triage type tabs on first run). Every finding has
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
array, newest first — what the timeline drawer fetches the first time it's opened, or the
Threat Model page fetches on load if the drawer hasn't been opened yet; live runs after that
are patched into the client's copy directly from WebSocket messages, not re-fetched).

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

**Control assessments store**: `controlAssessments` (Map, in `server.js`) is a fourth,
independent session-lifetime store, same pattern as `appThreatModels`. A record is `{id,
runId, path, app, branch, instruction, status, verdict, error, startedAt, finishedAt}` —
`verdict` here is the whole-app control-identification report (`system_description`/
`summary`/`controls`/`inherited_note`/`recommendations`), where each entry in `controls` is
`{control_id, control_name, family, applicability, implementation_status, narrative,
evidence, gaps}`. No `findingIds`/`runs` chain, same reason as app-level threat models. REST
surface: `GET /api/control-assessments`, `GET /api/control-assessments/:id`.

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

**Request flow (control assessments)**: client sends `{type: "controls_assist", runId, path,
app, branch, instruction}` → same directory validation as app-level threat models, spawns
`claude -p` with `agents/controls_assist.md` as the system prompt, `--allowedTools
"Read,Grep,Glob"`, `cwd` set to the target `path` → events relay as `{type:
"controls-assist-event", runId, id, event}` (again distinct type names —
`controls-assist-started`/`-event`/`-stderr`/`-error`/`-done` — same collision-avoidance
reasoning as `scan-*`/`app-threat-model-*`) → on close, `extractVerdict()` is expected to
return the control-identification report object directly, stored as-is on the record's
`verdict` field, then `{type: "controls-assist-done", runId, id, code, verdict}` is sent. No
findings are created and no existing finding is touched by this flow either.

**Multiple concurrent runs**: a single WebSocket connection tracks runs in a `runId`-keyed
`Map` of child processes (`children` in `server.js`), shared by per-finding runs, scans,
app-level threat models, and control assessments — not a single in-flight run, so multiple
stages/scans/whole-directory runs can be running at once from one browser tab. `{type:
"cancel", runId}` kills a specific run (checked against `runIndex`, `scanRunIndex`,
`appThreatModelRunIndex`, and `controlAssessmentRunIndex`). Closing the tab/connection kills
and marks-cancelled every still-running child tied to it (`ws.on('close')`).

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

**No live per-finding stats/activity feed, but an opt-in raw console**: per-finding runs
(Triage/Threat Model/Remediation) don't render a live tool/token/file counter or a parsed
activity feed while running — `handleServerMessage()` in `index.html` still only acts on
`done`/`error` for the Timeline row and (if that finding's detail page happens to be open) the
Agent runs section, via `refreshFindingAfterRun()` → `updateFindingListItem()`. `startStage()`
does push one optimistic "running" placeholder into the finding's cached `runs` array so the
detail page shows the run as in-progress immediately rather than staying blank until it
finishes, but there's still no token-by-token or tool-by-tool *stats* feed — showing every
tool call/result plus raw stream-json by default was tried once already and read as noise
rather than the two things an AppSec tester actually wants: what was found, and why (normally
surfaced only once, in the finished verdict). Scan cards on the Reasoning Scan page are the
one place with a live *stats* feed, since a scan can run for minutes over many files:
`handleScanRawEvent()` in `index.html` updates a running tools/tokens/files-read counter and
severity chip row per stream-json event, and `agents/scan.md`'s narration contract has it
prefix each candidate finding with a literal `[severity]` tag as it's spotted, which
`trackScanCandidates()` parses via `SEV_TAG_RE` into a live scrolling list.

What *is* available everywhere, opt-in: a small terminal-icon **console toggle button**
(`consoleToggleButtonHtml()`/`consolePanelHtml()` in `index.html`) next to every live run —
Reasoning/SCA scan cards, App Threat Model rows, Control Scan rows, and Finding Detail's
per-finding run cards. Clicking it reveals a `<pre class="console-panel">` streaming the
model's raw narrated prose (assistant text blocks only, not tool calls/inputs/outputs — the
same noise tradeoff above, just made opt-in instead of removed outright) as it arrives, via
the shared `trackConsoleText()` appending onto each run's `consoleText` buffer and, if the
panel is currently attached to the DOM, directly onto it too. This is deliberately **live-only,
not replayable**: nothing is persisted server-side beyond what already existed (`fullText` is
still discarded after `extractVerdict()` parses it for scan/app-threat-model/control-scan
runs), so a run's console content only exists for as long as its tracking object survives in
the browser tab — reload the page or let the object get GC'd and a finished run's reasoning is
gone, same as the counters next to it. Each of the four surfaces needed its own small amount
of plumbing since each already had a different live-tracking shape: `stageConsoles` (new Map,
`index.html`) is per-finding's *only* live tracking object, since those runs otherwise track
nothing else live; the other three surfaces just gained `consoleText`/`consoleOpen`/
`consoleEl` fields alongside their existing `toolCount`/`tokenCount`/etc. `trackConsoleText()`
is called from each surface's raw-event handler (`handleScanRawEvent`,
`handleAppThreatModelRawEvent`, `handleControlsAssistRawEvent`, and inline in
`handleServerMessage()`'s per-finding `event` branch) right alongside the existing
tool/token/candidate trackers. Because App Threat Model, Control Scan, and Finding Detail all
fully rebuild their row/card HTML on every re-render (unlike scan cards, which are created
once and updated via cached refs), those three surfaces persist `consoleText`/`consoleOpen` on
the run object across rebuilds and reattach `consoleEl` afterward
(`reattachAppThreatModelLiveRefs()`/`reattachControlsAssistLiveRefs()`/`reattachConsoleRefs()`
respectively) — otherwise every stream-json event or accordion toggle would silently wipe an
open panel back to empty. The toggle button always calls `e.stopPropagation()` since it sits
inside a clickable row/summary that would otherwise also fire its own click handler (expanding
an App Threat Model/Control Scan accordion, in particular).

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
`root_cause`/`fix_guidance`/`corrected_code`/`verification_steps`/`effort` for remediation —
`corrected_code` is `null` unless the finding's context included a `code` snippet and the fix
is a meaningful drop-in replacement, and is what the Remediation screen renders side-by-side
with the original; see the Remediation bullet above). `scan.md`
findings deliberately do *not* carry `verdict`/`severity_confirmed`/`confidence`/
`priority`/framework-mapping — they're raw, scanner-export-style output; a `severity`
field is the scan's best-effort initial estimate only, and real triage happens downstream.
`app_threat_model.md` reuses only the `severity` scale and the `owasp`/`cwe` pair (per entry
in its `top_risks` array) — it has no `verdict`/`confidence`/`priority`/`asvs`/
`nist_800_53` fields at all, since it isn't triaging a finding, just flagging structural
risks in a holistic report; framework mapping there is best-effort context, not the
compliance-feed requirement described above. `controls_assist.md` departs from this taxonomy
furthest of all — no `severity`/`confidence`/`priority`/`verdict` fields either, since it
isn't assessing risk at all. Instead each entry in its `controls` array carries its own
two-field scale: `applicability` (`app_addressed | partially_addressed | inherited |
not_applicable`) and `implementation_status` (`implemented | partially_implemented | planned
| not_applicable | null`) — purpose-built to keep the agent from over-claiming coverage for
controls that are normally satisfied by the hosting platform or org process rather than
application code (see the Control Scan bullet above).

**Security posture**: this is a local single-user dev tool. No auth on the
WebSocket or REST endpoints; `--permission-mode acceptEdits` and `--allowedTools`
("Read,Grep" for per-finding agents, "Read,Grep,Glob" for scans, app-level threat models, and
control assessments) are set loosely for a fast test loop, not for anything beyond localhost
use. Both `agent` names and `runId`s from client messages are validated against
`^[a-zA-Z0-9_-]+$` before being used (agent name is joined into a filesystem path) — don't
relax either when adding features. The scan features (Reasoning Scan and SCA Scan) and, the same
way, app-level threat models and control assessments are a deliberate widening of that
posture: all three spawn `claude` with `cwd` set to **any directory path the client sends**,
gated only by "does this path exist and is it a directory" (`fs.statSync` in
`handleScanMessage` / `handleAppThreatModelMessage` / `handleControlsAssistMessage`) — there's
no allowlist of scannable roots. That's consistent with "local single-user tool trusted by its
one user," not with exposing this app beyond localhost; don't add auth-free network
exposure without revisiting this.

**Not yet built**: disk persistence (both the findings store and the scans store are
in-memory and reset on restart — there's no SQLite/JSON-file layer yet), CSV *ingestion*
(export exists — `GET /api/findings/export.csv` — but importing an external scanner's CSV
to seed findings, the original `findings-dashboard.jsx` workflow, does not), the
dashboard merge itself (`findings-dashboard.jsx`'s Azure DevOps ticket creation currently
does a browser-side `fetch()` that's expected to hit CORS — if that logic moves into this
app, it should move server-side, where Node has no CORS problem), and the **Reports** screen
(currently a bare placeholder — no data, no server endpoint, see the Reports bullet above).
The **Remediation** screen also only ever shows the most recently triggered
`remediationBatchIds` batch, not a durable history of every batch run this session — a
finding's `remediation_generated` status on Agent Triage is the only lasting record that it
has corrected code, and there's no way from this screen to re-open an older batch's table.
