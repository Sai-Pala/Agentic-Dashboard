# Phase 4 — splitting `public/index.html`'s `<script>` into ES modules

Status: **plan only.** Nothing in this document has been executed. Phase 4a (the stylesheet
extraction into `public/app.css`) has landed; the `<script>` block is untouched.

Every number below comes from parsing the real file with `@babel/parser`, not from grepping.

---

## 0. Where the file stands after the CSS extraction

| | before | after CSS extraction |
|---|---|---|
| `public/index.html` total lines | 5,111 | **4,319** |
| `<style>` block | 791 lines / 56,212 bytes inline | moved verbatim to `public/app.css`, replaced by one `<link>` |
| main `<script>` block | L1268–L5109 | **L476–L4317** (3,842 lines) |
| markup | ~469 lines | ~469 lines (unchanged) |

Inside that `<script>`:

* **167** top-level `function` declarations
* **27** top-level `let` (no `var` at all — the count in the brief is exactly the `let` count)
* **86** top-level `const`, of which **53 are `document.getElementById` / `querySelector`
  lookups evaluated at load time** and 33 are pure data/`Map`/`Set`
* **35** top-level non-declaration statements — all of them either event wiring or the four
  eager calls listed in §3.4

The script already carries **26 `// ---------- section ----------` banners**. They are a
genuine, author-maintained decomposition and the module layout below follows them rather than
inventing a new one.

---

## 1. The 27 mutable top-level globals

Ownership column = the module in §2 that should own the binding. `W` = functions that assign;
`R` = functions that only read. A global whose `W` set is a single function is trivially
convertible to module-private state behind a setter; a global with a multi-function `W` set is
genuinely shared and needs an explicit owner.

### 1a. Genuinely shared — cross-module, must live in `state.js`

| global | L | init | writers | readers |
|---|---|---|---|---|
| `currentView` | 623 | `'dashboard'` | `showView` | **18 readers**: `connect`, `upsertTimelineEntry`, `loadScans`, `loadAppThreatModels`, `loadControlAssessments`, `upsertControlAssessment`, `upsertAppThreatModel`, `deleteScanRun`, `beginScanRun`, `handleScanServerMessage`, `loadFindings`, `updateFindingListItem`, `startRemediatePreview`, `startRemediateFix`, `startRemediateAll`, `startStage`, `handleServerMessage`, `clearSession` |
| `scansList` | 634 | `[]` | `loadScans`, `deleteScanRun`, `clearSession` | `computeBriefing`, `updateTimelineClockDots`, `renderNavBadges`, `beginScanRun`, `handleScanServerMessage`, `renderFindingsScanFilter`, `findingSourcePath`, `renderFindingDetail`, `openSurfaceView`, `renderSurfaceScanPicker`, `renderSettings` |
| `findings` | 618 | `[]` | `loadFindings`, `clearSession` | `computeBriefing`, `renderDashboard`, `updateTimelineClockDots`, `renderNavBadges`, `findingsScanScoped`, `renderFindingsScanFilter`, `updateFindingListItem` |
| `timelineEntries` | 628 | `[]` | `loadTimeline`, `deleteScanRun`, `clearSession` | `renderDashboard`, `renderTimeline`, `upsertTimelineEntry`, `latestThreatModelEntries`, `allThreatModelEntriesForFinding` |
| `agentsList` | 617 | `[]` | `loadAgents` | `knownAgentsAvailableCount`, `computeBriefing`, `renderDashboard`, `renderTimelineFilters`, `renderFindingDetailActions`, `openFindingContextMenu`, `openFreshStageModal`, `renderSettings` |
| `ws` | 616 | `null` | `connect` | `startAppThreatModel`, `startControlsAssist`, `cancelScanRun`, `beginScanRun`, `startRemediatePreview`, `startRemediateFix`, `startRemediateAll`, `startStage` |
| `currentFindingDetailId` | 622 | `null` | `openFindingDetail` | `updateFindingListItem`, `startRemediatePreview`, `startRemediateFix`, `startRemediateAll`, `renderFindingDetail`, `startStage`, `handleServerMessage` |
| `appThreatModelsList` | 636 | `[]` | `loadAppThreatModels`, `clearSession` | `updateTmViewingLabel`, `renderAppThreatModelSection`, `upsertAppThreatModel` |
| `controlAssessmentsList` | 638 | `[]` | `loadControlAssessments`, `clearSession` | `renderNavBadges`, `renderControlsAssistSection`, `renderControlsAssistView`, `upsertControlAssessment` |
| `timelineLoaded` | 629 | `false` | `loadTimeline`, `clearSession` | `openTimelineDrawer`, `openThreatModelView`, `openThreatModelForFinding` |
| `timelineUnseenDone` | 631 | `0` | `openTimelineDrawer`, `upsertTimelineEntry`, `clearSession` | `updateTimelineClockDots` |
| `timelineDrawerOpen` | 632 | `false` | `openTimelineDrawer`, `closeTimelineDrawer` | `upsertTimelineEntry`, `deleteScanRun`, `clearSession` |
| `expandedAtmRunId` | 1368 | `null` | `toggleAppThreatModelRow`, `clearSession` | `updateTmViewingLabel`, `appThreatModelRowHtml` |
| `expandedCaRunId` | 1540 | `null` | `toggleControlsAssistRow`, `clearSession` | `caRowHtml` |

`clearSession()` alone writes **nine** of these (`findings`, `scansList`,
`appThreatModelsList`, `controlAssessmentsList`, `timelineEntries`, `timelineLoaded`,
`expandedAtmRunId`, `expandedCaRunId`, `timelineUnseenDone`). It is the single hardest
function to place — see §3.3.

### 1b. Single-view state — becomes module-private, no `state.js` entry needed

| global | L | writers | readers | owning module |
|---|---|---|---|---|
| `findingsTypeFilter` | 619 | `renderFindingsTypeTabs` | `renderFindingsTable` | `views/findings.js` |
| `findingsScanFilter` | 620 | `renderFindingsScanFilter`, `openFindingsFilteredByScan` | `findingsScanScoped`, `renderFindingsView`, `renderFindingsTable` | `views/findings.js` |
| `findingsSort` | 621 | `renderFindingsTable` (r/w within itself) | — | `views/findings.js` |
| `timelineFilter` | 630 | `openTimelineDrawer`, `renderTimelineFilters` | `renderTimeline` | `views/timeline.js` |
| `tmMapFindingIds` | 1239 | `renderThreatModelView` | `renderThreatModelDetail` | `views/threat-model.js` |
| `surfaceScanId` | 3572 | `openSurfaceView`, `renderSurfaceScanPicker` | (self-reads only) | `views/surface.js` |
| `surfaceData` | 3573 | `loadSurface` | `renderSurfaceView` | `views/surface.js` |
| `stageModalState` | 4102 | `openFreshStageModal`, `closeStageModal` | `updateStageModalVerifyHint` | `ui/menus-modals.js` |
| `scansLoaded` | 635 | `loadScans` | **nobody** | `views/scans.js` |
| `appThreatModelsLoaded` | 637 | `loadAppThreatModels` | **nobody** | `views/app-threat-model.js` |
| `controlAssessmentsLoaded` | 639 | `loadControlAssessments` | **nobody** | `views/controls-assist.js` |

> **Observation, not a fix (CLEANUP-ONLY rule):** `scansLoaded`, `appThreatModelsLoaded` and
> `controlAssessmentsLoaded` are each assigned `true` exactly once (L1828 / L1836 / L1843) and
> read by nothing. `timelineLoaded` — the fourth member of the same family — *is* read
> (`openTimelineDrawer`, `openThreatModelView`, `openThreatModelForFinding` all guard on it).
> The three write-only ones look like an incomplete lazy-load guard, i.e. `loadScans()` /
> `loadAppThreatModels()` / `loadControlAssessments()` re-fetch on every view switch where the
> timeline does not. Do not fix this during the module split — it is a behaviour change and
> would invalidate the "nothing changed" claim the split needs.

### 1c. Written only from top-level event wiring — needs a real owner

| global | L | assigned at | read by |
|---|---|---|---|
| `scanScope` | 587 | L710, inside the arrow passed to `wireScopeToggle('#scan-scope-toggle', …)` | `startScan` |
| `scanBudgetEnabled` | 592 | L714, inside the `#scan-budget-toggle` click listener | `startScan` |

These are the only two globals with **no named-function writer at all**. They cannot move to
`views/scans.js` unless the wiring at L710–L718 moves with them; leaving the wiring in
`main.js` while the `let` lives in `views/scans.js` would require exporting a setter. The
cheaper option is to move the wiring into an exported `wireScanForm()` in `views/scans.js`,
called from `main.js`.

### 1d. The 33 non-DOM `const`s (also need a home, but are immutable so trivially safe)

`ICONS`, `KNOWN_AGENTS`, `AGENT_META`, `SCAN_TYPE_META`, `scanType`, `findingCache`, `stages`,
`stageConsoles`, `scanRuns`, `scanDetailCache`, `NAV_COLLAPSE_KEY`, `HEATMAP_SEVERITY_COLS`,
`appThreatModelRuns`, `controlAssistRuns`, `APPLICABILITY_LABELS`,
`IMPLEMENTATION_STATUS_LABELS`, `SEV_VAR`, `SEV_ORDER`, `SEV_TAG_RE`, `SEV_ORDER_MAP`,
`STATUS_ORDER_MAP`, `FINDINGS_TYPE_LABEL`, `FINDINGS_COLUMNS`, `precheckRunIds`,
`VERDICT_BADGE_FIELDS`, `VERDICT_SKIP_FIELDS`, `HL_KEYWORDS`, `HL_TOKEN_RE`, `AUTHZ_WORDS`,
`AUTHN_WORDS`, `FIX_FLOW_AGENTS`, `SCA_EXCLUDED_AGENTS`, `THEME_KEY`.

Note the `const` bindings that are **mutable containers** — `findingCache`, `stages`,
`stageConsoles`, `scanRuns`, `scanDetailCache`, `appThreatModelRuns`, `controlAssistRuns`,
`precheckRunIds` — are shared mutable state in every sense that matters even though the binding
is `const`. `clearSession()` mutates `scanRuns` and `appThreatModelRuns`; the WS handlers mutate
`stages` / `stageConsoles`; `precheckRunIds` is written by the three `startRemediate*` functions
and read by `handleServerMessage`. Treat these exactly like §1a globals: they belong in
`state.js`, not in whichever view happens to declare them today.

---

## 2. Proposed module layout

Line ranges are where the code sits **today** in the post-CSS-extraction `index.html`.
Function-body line totals are measured, and exclude the 35 top-level statements.

| module | fns | ~lines | functions | owns |
|---|---|---|---|---|
| `ui/icons.js` | 1 | 3 | `icon` | `ICONS` |
| `data/meta.js` | 2 | 6 | `agentMeta`, `knownAgentsAvailableCount` | `KNOWN_AGENTS`, `AGENT_META`, `SCAN_TYPE_META`, `SEV_VAR`, `SEV_ORDER`, `SEV_ORDER_MAP`, `STATUS_ORDER_MAP`, `FINDINGS_TYPE_LABEL`, `APPLICABILITY_LABELS`, `IMPLEMENTATION_STATUS_LABELS`, `HEATMAP_SEVERITY_COLS`, `VERDICT_BADGE_FIELDS`, `VERDICT_SKIP_FIELDS`, `FIX_FLOW_AGENTS`, `SCA_EXCLUDED_AGENTS` |
| `dom.js` | 0 | 0 | — | all **53** element-ref `const`s (L554–L614, L795–L796, L3187, L4233–L4234) |
| `state.js` | 0 | 0 | — | the 14 shared `let`s from §1a + the 8 mutable `const` containers from §1d |
| `util/format.js` | 12 | 65 | `uid`, `truncate`, `escapeHtml`, `formatRelativeTime`, `dateGroupLabel`, `formatElapsed`, `formatTokenCount`, `statusLabel`, `severityLabel`, `verdictFieldLabel`, `formatInlineText`, `downloadTextFile` | — |
| `api.js` | 1 | 10 | `loadAgents` (+ the raw `fetch` calls the loaders use) | — |
| `ws.js` | 2 | 17 | `connect`, `setStatus` | writes `ws` |
| `run-tracking.js` | 7 | 54 | `trackRunToolActivity`, `trackRunTokens`, `trackConsoleText`, `consoleToggleButtonHtml`, `consolePanelHtml`, `wireConsoleToggles`, `reattachConsoleRefs` | — |
| `nav.js` | 6 | 85 | `showView`, `applyNavCollapsed`, `renderNavStatus`, `renderNavBadges`, `updateTimelineClockDots`, `wireScopeToggle` | writes `currentView` |
| `ui/heatmap.js` | 2 | 40 | `buildThreatHeatmap`, `worstOfList` | — |
| `ui/highlight.js` | 2 | 27 | `highlightCode`, `diffLineHtml` | `HL_KEYWORDS`, `HL_TOKEN_RE` |
| `views/dashboard.js` | 4 | 72 | `renderDashboardHeader`, `statTile`, `computeBriefing`, `renderDashboard` | — |
| `views/timeline.js` | 8 | 161 | `loadTimeline`, `openTimelineDrawer`, `closeTimelineDrawer`, `renderTimelineFilters`, `timelineStatusBadge`, `timelineSummary`, `renderTimeline`, `upsertTimelineEntry` | `timelineFilter` |
| `views/threat-model.js` | 9 | 168 | `openThreatModelView`, `latestThreatModelEntries`, `allThreatModelEntriesForFinding`, `renderThreatModelView`, `renderTmCellFindings`, `selectThreatModelFinding`, `renderThreatModelDetail`, `openThreatModelForFinding`, `renderAttackPathFlow` | `tmMapFindingIds` |
| `views/app-threat-model.js` | 13 | 208 | `updateAppThreatModelElapsed`, `stopAppThreatModelElapsedTimer`, `handleAppThreatModelRawEvent`, `toggleAppThreatModelRow`, `updateTmViewingLabel`, `appThreatModelRowHtml`, `reattachAppThreatModelLiveRefs`, `renderAppThreatModelSection`, `renderAppThreatModelDetail`, `loadAppThreatModels`, `upsertAppThreatModel`, `startAppThreatModel`, `handleAppThreatModelServerMessage` | `expandedAtmRunId`, `appThreatModelsLoaded` |
| `views/controls-assist.js` | 14 | 247 | `updateControlsAssistElapsed`, `stopControlsAssistElapsedTimer`, `handleControlsAssistRawEvent`, `toggleControlsAssistRow`, `caRowHtml`, `reattachControlsAssistLiveRefs`, `renderControlsAssistSection`, `renderControlsAssistDetail`, `buildControlAssessmentMarkdown`, `renderControlsAssistView`, `loadControlAssessments`, `upsertControlAssessment`, `startControlsAssist`, `handleControlsAssistServerMessage` | `expandedCaRunId`, `controlAssessmentsLoaded` |
| `views/scans.js` | 22 | 468 | `loadScans`, `renderScanFindingsBody`, `makeScanCard`, `updateScanCardActions`, `cancelScanRun`, `deleteScanRun`, `renderScanCardResults`, `updateScanElapsed`, `stopScanElapsedTimer`, `renderScanSevChips`, `trackScanCandidates`, `updateDetBar`, `updateScaBar`, `reasoningCostSuffix`, `updateReasoningBar`, `updateReasoningModuleProgress`, `markReasoningBarDone`, `handleScanRawEvent`, `beginScanRun`, `startScan`, `handleScanServerMessage`, `scanFilterLabel` | `scanScope`, `scanBudgetEnabled`, `scansLoaded`, `SEV_TAG_RE` |
| `views/findings.js` | 13 | 225 | `loadFindings`, `findingsSortValue`, `findingsScanScoped`, `renderFindingsView`, `renderFindingsScanFilter`, `renderFindingsTypeTabs`, `findingsCellHtml`, `renderFindingsTable`, `updateFindingListItem`, `ensureFindingCached`, `findingSourcePath`, `findingSourceTagHtml`, `openFindingsFilteredByScan` | `findingsTypeFilter`, `findingsScanFilter`, `findingsSort`, `FINDINGS_COLUMNS` |
| `loop/loop-state.js` | 6 | 177 | `findingStageRuns`, `findingLoopState`, `findingLoopNextAction`, `loopTrackHtml`, `findingLoopCellHtml`, `fdLoopBoxesHtml` | — (pure) |
| `loop/loop-actions.js` | 9 | 123 | `confirmApplyWrite`, `onLoopAdvanceClick`, `confirmRunAll`, `onLoopRunAllClick`, `onViewDiffClick`, `startRemediatePreview`, `startRemediateFix`, `startRemediateAll`, `buildBaseContext` | `precheckRunIds` |
| `views/finding-detail.js` | 8 | 269 | `openFindingDetail`, `renderFindingDetail`, `verdictArrayHtml`, `correctedCodeHtml`, `editPlanHtml`, `runCardHtml`, `renderFindingDetailActions`, `findingFlowHtml` | writes `currentFindingDetailId` |
| `views/surface.js` | 8 | 186 | `openSurfaceView`, `loadSurface`, `renderSurfaceScanPicker`, `guardNameSegments`, `guardKindOf`, `surfaceGuardBadge`, `surfaceRouteRowsHtml`, `renderSurfaceView` | `surfaceScanId`, `surfaceData`, `AUTHZ_WORDS`, `AUTHN_WORDS` |
| `ws-handlers.js` | 4 | 125 | `startStage`, `handleServerMessage`, `refreshFindingAfterRun`, `setStageStatus` | `stages` |
| `ui/menus-modals.js` | 9 | 90 | `openFindingContextMenu`, `positionAndShowMenu`, `closeContextMenu`, `updateStageModalVerifyHint`, `openFreshStageModal`, `closeStageModal`, `updateFindingModalTypeFields`, `openFindingModal`, `closeFindingModal` | `stageModalState` |
| `settings.js` | 4 | 56 | `applyTheme`, `renderThemeToggle`, `renderSettings`, `clearSession` | `THEME_KEY` |
| `main.js` | 1 | 10 | `init` + all 35 top-level statements | — |

`views/scans.js` at 468 lines is the largest and is a candidate for a further split
(`scan-card.js` for `makeScanCard`/`updateScanCardActions`/`updateDetBar`/`updateScaBar`/
`updateReasoningBar`/`updateReasoningModuleProgress`/`markReasoningBarDone`/`renderScanSevChips`/
`trackScanCandidates`, vs. `scan-run.js` for `beginScanRun`/`startScan`/`handleScanServerMessage`).
Do that *after* the first split lands, not during it.

---

## 3. The hard cases

### 3.1 Circular imports — 15 mutual module pairs, and they are unavoidable

Even after hoisting every shared helper into `util/format.js`, `run-tracking.js`,
`ui/heatmap.js` and `ui/icons.js`, the measured cross-module edge count is 98 and there are
**15 mutually-dependent module pairs**:

```
nav.js                    <-> views/findings.js         (showView / renderFindingsView, renderNavStatus)
nav.js                    <-> views/threat-model.js     (openThreatModelView / showView)
nav.js                    <-> views/controls-assist.js  (renderControlsAssistView / renderNavBadges)
nav.js                    <-> settings.js               (renderSettings / renderNavStatus)
views/threat-model.js     <-> views/timeline.js         (loadTimeline / renderThreatModelView)
views/app-threat-model.js <-> views/threat-model.js     (4 edges each way)
views/scans.js            <-> ws-handlers.js            (setStageStatus / handleScanServerMessage)
views/scans.js            <-> views/timeline.js         (renderTimeline, upsertTimelineEntry / renderScanFindingsBody)
views/findings.js         <-> views/scans.js            (scanFilterLabel / openFindingsFilteredByScan, loadFindings)
loop/loop-state.js        <-> views/findings.js         (findingsCellHtml, findingSourcePath / findingLoopCellHtml)
loop/loop-actions.js      <-> views/findings.js         (ensureFindingCached, findingSourcePath / onViewDiffClick)
loop/loop-actions.js      <-> views/finding-detail.js   (openFindingDetail, renderFindingDetail / onLoopAdvanceClick, onLoopRunAllClick)
views/finding-detail.js   <-> views/findings.js         (findingSourceTagHtml, openFindingsFilteredByScan / openFindingDetail, renderFindingDetail)
views/finding-detail.js   <-> views/threat-model.js     (openThreatModelForFinding / openFindingDetail)
ui/menus-modals.js        <-> views/findings.js         (ensureFindingCached, findingSourcePath / openFindingContextMenu)
```

**These are fine, and that is the key architectural finding of this analysis.** ES module
cycles only break when a cyclically-imported binding is *used during module evaluation* (the
TDZ error). Every one of the 98 cross-module edges above is a call **inside a function body**,
resolved at click/message time, long after every module has finished evaluating. Function
declarations are hoisted and ESM bindings are live, so `views/findings.js` calling
`openFindingDetail` from `views/finding-detail.js` while the latter imports
`renderFindingsView` back is legal and works.

The rule that must be written into the module headers and held to: **no module may call an
imported function at its own top level.** Today that is already almost true — see §3.4.

Do **not** attempt to break these cycles with an event-bus indirection in the same change that
moves the code. Motion and redesign in one diff is what makes a 3,842-line split unreviewable.

### 3.2 Functions used by many views (fan-in ≥ 5)

Measured fan-in (distinct calling functions):

| fn | fan-in | proposed home |
|---|---|---|
| `escapeHtml` | 31 | `util/format.js` — **but it is not pure**: it builds a detached `<div>` and reads `.innerHTML` |
| `icon` | 10 | `ui/icons.js` |
| `renderDashboard` | 9 | `views/dashboard.js` |
| `truncate` | 9 | `util/format.js` |
| `agentMeta` | 9 | `data/meta.js` |
| `formatRelativeTime` | 8 | `util/format.js` |
| `renderFindingDetail` | 8 | `views/finding-detail.js` |
| `uid` | 7 | `util/format.js` |
| `renderThreatModelView` | 7 | `views/threat-model.js` |
| `upsertTimelineEntry` | 7 | `views/timeline.js` |
| `renderNavStatus` | 6 | `nav.js` |
| `renderTimeline` | 6 | `views/timeline.js` |
| `openFindingDetail` | 6 | `views/finding-detail.js` |
| `renderFindingsView` / `renderControlsAssistView` / `formatElapsed` / `findingSourcePath` | 5 each | as tabled in §2 |

`escapeHtml` at fan-in 31 is the single most-shared function and the one most likely to be
imported by nearly every module. It touches `document`, so `util/format.js` will not be a
DOM-free module. If a DOM-free `util/` is wanted, put `escapeHtml` in a separate
`util/html.js` and keep `util/format.js` importable from Node with no DOM — that materially
helps §4.

Two functions show a fan-in of 0 in the call graph but are **not** dead: `runCardHtml` and
`diffLineHtml` are passed by reference (`.map(runCardHtml)`) rather than called by name, which
an identifier-callee analysis does not see. Verify by reference, not by call, before concluding
anything is unused.

### 3.3 `clearSession()` — the worst placement problem

`clearSession()` (L4266–L4300, `settings.js` by topic) writes **nine** of the 14 shared globals
and additionally mutates `scanRuns` and `appThreatModelRuns`, clears both live-scan DOM
containers, and re-renders whichever view is open. Under §1a's rule ("a global's owner is the
module that writes it") it would drag `findings`, `scansList`, `appThreatModelsList`,
`controlAssessmentsList`, `timelineEntries`, `timelineLoaded`, `timelineUnseenDone`,
`expandedAtmRunId` and `expandedCaRunId` into `settings.js`.

The resolution: `state.js` exports a `resetAll()` that performs every assignment, and
`clearSession()` in `settings.js` calls it after the `POST /api/session/clear` succeeds. Keep
the DOM clearing and the re-render in `settings.js`. This is the one place where a small
behaviour-preserving *shape* change is unavoidable, so do it in its own step (§5 step 6).

### 3.4 DOM read at load time

**53 top-level `const`s are `document.getElementById(...)` / `querySelectorAll(...)` results
evaluated during script execution** (L554–L614 form/table/modal refs, L795–L796 nav refs,
L3187 `fdBodyEl`, L4233–L4234 theme refs). They work today only because the `<script>` sits at
L476 — after all the markup and immediately before `</body>` (L4318).

`<script type="module">` is **deferred by default**, executing after the document is parsed.
So this gets *safer*, not more fragile: the refs resolve regardless of where the `<script>` tag
is placed. This is one of the few things the migration makes strictly better. The corollary is
that `dom.js` must be imported (directly or transitively) by everything that uses a ref, and
its top-level lookups will run at module-evaluation time — which is fine, because the DOM is
already parsed. Do not make `dom.js` lazy; that would be a behaviour change.

### 3.5 The event wiring — 35 top-level statements

All 35 are listed with line numbers in the appendix. They break into:

* **31 `addEventListener` / `querySelectorAll(...).forEach(...)` registrations** — scattered
  through the file next to the code they wire (L710, L712, L744, L770, L788, L791, L792, L802,
  L808, L932, L954–L957, L2407, L3541, L4090, L4093, L4117, L4135–L4138, L4172, L4176,
  L4182–L4187, L4226, L4250, L4302).
* **1 `try { applyNavCollapsed(localStorage…) } catch {}`** at L807.
* **2 eager render calls**: `renderThemeToggle()` at L4254 and `init()` at L4316.

Four of these are the *only* top-level calls into named functions —
`wireScopeToggle(...)` (L710), `applyNavCollapsed(...)` (L807), `renderThemeToggle()` (L4254),
`init()` (L4316). They are exactly what §3.1 says must not exist inside a cyclic module. All
four must end up in `main.js` (or in exported `wireX()` functions that `main.js` calls), which
also fixes §1c's orphaned `scanScope` / `scanBudgetEnabled` writers.

Two document-level delegated handlers deserve care because they are shared by unrelated
features: L4090 (`click` — closes the context menu) and L4093 (`keydown` — Escape closes the
context menu, the stage modal, the finding modal **and** the timeline drawer). The Escape
handler spans `ui/menus-modals.js` and `views/timeline.js`. Keep it whole in `main.js`
importing both, rather than splitting it into two listeners — two listeners is a behaviour
change (ordering, and both would fire).

---

## 4. What happens to `test/helpers/extract-client-fns.js`

`test/client-logic.test.js` lifts **21 named top-level declarations** out of the `<script>`
through the harness and evaluates them in a bare `node:vm` context:

```
guardKindOf, guardNameSegments, AUTHZ_WORDS, AUTHN_WORDS,
findingStageRuns, findingLoopState, findingLoopNextAction,
findingsSortValue, scanFilterLabel, formatRelativeTime, verdictFieldLabel,
truncate, statusLabel, severityLabel, formatElapsed, formatTokenCount,
worstOfList, agentMeta, SEV_ORDER_MAP, STATUS_ORDER_MAP, AGENT_META
```

Mapped onto §2, those 21 land in **six** modules:

| module | declarations the test needs |
|---|---|
| `views/surface.js` | `guardKindOf`, `guardNameSegments`, `AUTHZ_WORDS`, `AUTHN_WORDS` |
| `loop/loop-state.js` | `findingStageRuns`, `findingLoopState`, `findingLoopNextAction` |
| `views/findings.js` | `findingsSortValue` |
| `views/scans.js` | `scanFilterLabel` |
| `util/format.js` | `formatRelativeTime`, `verdictFieldLabel`, `truncate`, `statusLabel`, `severityLabel`, `formatElapsed`, `formatTokenCount` |
| `ui/heatmap.js` | `worstOfList` |
| `data/meta.js` | `agentMeta`, `SEV_ORDER_MAP`, `STATUS_ORDER_MAP`, `AGENT_META` |

**The ordering constraint this creates:** the harness's `extract()` throws by design if a name
is no longer a *top-level declaration of the largest `<script>` block in index.html*. So the
moment any one of those 21 names leaves the inline script, `client-logic.test.js` goes red —
even if the function is byte-identical in its new module. The harness cannot be deleted before
the split and cannot survive the first step of it. Therefore:

* **Move the 21 tested declarations in as few steps as possible, and convert the test in the
  same commit as each move.** Every step must swap the moved names out of `TARGETS` and into
  real `import`s in the same diff — never leave the suite red between commits.
* The clean sequencing is: extract `util/format.js`, `data/meta.js`, `ui/heatmap.js`,
  `views/surface.js`'s guard trio and `loop/loop-state.js` **first** (steps 2–5 in §5). Those
  five modules cover 19 of the 21. `findingsSortValue` and `scanFilterLabel` are the only two
  that force touching a large view module, and both are small, pure and have no imports — they
  can be hoisted into `util/format.js`/`data/meta.js`-adjacent modules early rather than
  waiting for `views/findings.js` and `views/scans.js` to be split.
* Node's test runner (`node --test`, CommonJS test files) can `import()` an ES module —
  `client-logic.test.js` becomes `const C = await import('../public/js/util/format.js')` (or
  the file becomes `.mjs`). Prefer top-level `await import()` inside the test rather than
  renaming the file, so the other six test files keep their existing CommonJS shape.
* Three things in `client-logic.test.js` exist **only** because of the `vm` and get deleted
  with the harness: the `plain()` and `isTypeError()` cross-realm shims, and the
  `extract(['guardKindOf', 'aFunctionThatDoesNotExist'])` throw-test at L126 (it tests the
  harness, not the app). The ~380 behavioural assertions survive untouched — which is the
  entire point of having written them first.
* `readMainScript()` / `listTopLevelNames()` are exported by the harness but only
  `readMainScript` is used outside `extract()`. Grep before deleting: nothing else in
  `test/` should reference it, but confirm rather than assume.
* **`extract-client-fns.js` must be deleted in the same commit as the last of the 21 names to
  move**, not left as a dead file. A harness that throws loudly is only useful while it is
  being obeyed.

Note also: `escapeHtml`, `diffLineHtml`, `highlightCode`, `loopTrackHtml`,
`findingLoopCellHtml` and `fdLoopBoxesHtml` are documented as deliberately *not* covered
because they need a DOM. Once the split lands, `loopTrackHtml`/`findingLoopCellHtml`/
`fdLoopBoxesHtml` sit in `loop/loop-state.js` and are string-builders that only reach the DOM
via `escapeHtml`/`icon` — importable and testable if those two are injected or stubbed. That is
new coverage, not a migration requirement; note it and move on.

---

## 5. Recommended sequence

Every step ends with `npm test` green (385/385 today) and the app loading in a browser. The
riskiest work is last. Steps 1–5 do not touch a single view module.

**Step 0 (done).** CSS → `public/app.css`. Verified: `GET /` 200 with the `<link>` and no
`<style>`, `GET /app.css` 200 `text/css`, 56,212 bytes matching disk; `npm test` 385/385.

**Step 1 — flip the script to a module with no code motion at all.**
Move the entire `<script>` body verbatim into `public/js/app.js`; replace the inline block with
`<script type="module" src="/js/app.js"></script>`. Nothing is split, nothing is renamed, no
`import`/`export` is added yet.
*Why first:* it proves the two properties everything else depends on — that `express.static`
serves the file with a JS MIME type, and that module-deferred execution does not break the 53
load-time DOM refs (§3.4) — while the diff is still a pure move that `git diff -M` shows as a
rename. Modules are strict-mode, and that was checked ahead of time rather than assumed: the
current script body **already parses cleanly with `sourceType: 'module'`, already compiles
under `"use strict"`, and contains no assignment to an undeclared identifier**. So step 1 is
expected to be a genuine no-op behaviourally — but re-run those three checks after the move,
because they are cheap and they are the only thing standing between "pure move" and a
silent sloppy-mode regression.
*Test impact:* `extract-client-fns.js` reads `public/index.html` and picks the largest
`<script>` block — after this step there is no application `<script>` block left in the HTML,
only the 9-line theme bootstrap, so `extract()` will lift the wrong thing and the suite goes
red. **Step 1 must therefore also repoint `readMainScript()` at `public/js/app.js`** (read the
whole file instead of regexing a `<script>` out of it). That is a ~6-line change to the harness
and the only harness edit needed before its eventual deletion. Steps 2+ then work unchanged.

**Step 2 — `util/format.js` + `util/html.js` + `ui/icons.js`.**
The 12 formatting helpers, `escapeHtml` (into `util/html.js`, DOM-touching, kept separate so
`util/format.js` stays Node-importable), and `icon`/`ICONS`. Zero incoming dependencies, so
these are leaves; `app.js` imports them. Convert `client-logic.test.js` in the same commit for
the 7 names this covers (`formatRelativeTime`, `verdictFieldLabel`, `truncate`, `statusLabel`,
`severityLabel`, `formatElapsed`, `formatTokenCount`).

**Step 3 — `data/meta.js` + `ui/heatmap.js`.**
`agentMeta`/`knownAgentsAvailableCount` + the 15 metadata tables; `worstOfList`/
`buildThreatHeatmap`/`HEATMAP_SEVERITY_COLS`. Covers 5 more tested names (`agentMeta`,
`AGENT_META`, `SEV_ORDER_MAP`, `STATUS_ORDER_MAP`, `worstOfList`).

**Step 4 — `loop/loop-state.js`.**
The six loop functions. `findingStageRuns`/`findingLoopState`/`findingLoopNextAction` are pure
and already characterization-tested; `loopTrackHtml`/`findingLoopCellHtml`/`fdLoopBoxesHtml`
come along because they are the same state machine's renderers and depend on it directly.
Creates the first real cycle (`loop/loop-state.js ↔ views/findings.js`) — a deliberate, small,
first exercise of §3.1's "cycles are fine as long as nothing calls across at eval time" rule.

**Step 5 — `views/surface.js` guard trio + `state.js` + `dom.js`.**
`guardKindOf`/`guardNameSegments`/`AUTHZ_WORDS`/`AUTHN_WORDS` finish the tested set (with
`findingsSortValue` and `scanFilterLabel`, which move here too as pure leaf helpers). In the
same step, create `state.js` (the 14 §1a `let`s + the 8 mutable containers) and `dom.js` (the
53 element refs) as pure declaration modules that everything else will import. **Delete
`test/helpers/extract-client-fns.js` at the end of this step** and strip the `plain()` /
`isTypeError()` / harness-throw shims from `client-logic.test.js`.

**Step 6 — `state.js` gets `resetAll()`; `settings.js` splits out.**
The §3.3 fix. Small, isolated, and it is the only step that changes a function's *shape*, so it
gets its own commit and its own manual smoke test of Settings → Clear session.

**Step 7 onward — one view module per commit, smallest first.**
`views/dashboard.js` (72 lines) → `views/timeline.js` (161) → `views/threat-model.js` (168) →
`ui/menus-modals.js` (90) → `views/surface.js` remainder (186) → `views/app-threat-model.js`
(208) → `views/findings.js` (225) → `views/controls-assist.js` (247) → `views/finding-detail.js`
(269) → `loop/loop-actions.js` (123) → `ws.js`/`ws-handlers.js`/`run-tracking.js` →
**`views/scans.js` (468) last**, because it is the largest, has the most cross-edges, and owns
the two orphaned globals from §1c.

**Step N (last) — `main.js`.**
Collect all 35 top-level statements. This is deliberately last: until every module exists, the
wiring cannot be centralised, and centralising it is what finally satisfies §3.1's "no
top-level calls across a cycle" invariant.

### Verification per step

`npm test` is necessary but **not sufficient** — it covers 21 declarations out of 167
functions, and none of the DOM, WebSocket, or rendering paths. After each step also:
`PORT=<free> node server.js` (allow ~45 s to bind — module load alone is ~45 s on this
machine), load the page, and confirm zero console errors plus that the nav switches all seven
views. There is no automated browser test in this repo and this plan does not propose adding
one; a console-error check on every view is the cheapest real signal available.

---

## Appendix — the 35 top-level statements

```
L710  wireScopeToggle('#scan-scope-toggle', …, (s) => { scanScope = s; })   ← writes scanScope
L712  document.querySelectorAll('#scan-budget-toggle .group-toggle-btn').forEach(…)  ← writes scanBudgetEnabled (L714)
L744  atmStartBtn.addEventListener('click', startAppThreatModel)
L770  caStartBtn.addEventListener('click', startControlsAssist)
L788  document.querySelectorAll('.nav-item[data-view]').forEach(… showView …)
L791  #dash-timeline-link  -> openTimelineDrawer('all')
L792  #dash-scans-link     -> showView('scans')
L802  navCollapseBtn click -> applyNavCollapsed + localStorage
L807  try { applyNavCollapsed(localStorage.getItem(NAV_COLLAPSE_KEY) === '1') } catch {}   ← EAGER CALL
L808  document.querySelectorAll('.nav-item[data-view]').forEach(btn => btn.title = …)
L932  #timeline-refresh        -> loadTimeline
L954  #timeline-drawer-close   -> closeTimelineDrawer
L955  #timeline-drawer-backdrop-> closeTimelineDrawer
L956  #scans-clock-btn         -> openTimelineDrawer('scan')
L957  #tm-clock-btn            -> openTimelineDrawer('threat_model')
L2407 scanStartBtn             -> startScan
L3541 #fd-back-btn             -> showView('findings')
L4090 document click   -> closeContextMenu (delegated)
L4093 document keydown -> Escape: closeContextMenu + closeStageModal + closeFindingModal + closeTimelineDrawer  ← spans two modules
L4117 stageModalAgent change -> updateStageModalVerifyHint
L4135 #stage-modal-cancel     -> closeStageModal
L4136 stageModalOverlay click -> closeStageModal
L4138 #stage-modal-start      -> (inline, reads stageModalState)
L4172 findingsScanFilterBtn click
L4176 document click -> close the scan-filter popover (delegated)
L4182 addFindingBtn           -> openFindingModal
L4183 #finding-modal-cancel   -> closeFindingModal
L4184 findingModalOverlay     -> closeFindingModal
L4185 findingModalScanType change -> updateFindingModalTypeFields
L4187 #finding-modal-save     -> (inline async POST /api/findings)
L4226 exportCsvBtn            -> window.open('/api/findings/export.csv')
L4250 navThemeBtn             -> applyTheme
L4254 renderThemeToggle()                                                     ← EAGER CALL
L4302 #clear-session-btn      -> clearSession
L4316 init()                                                                  ← EAGER CALL
```
