# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A local Node app combining a deterministic security scanner with a set of specialized AppSec
agents that invoke Claude Code headless (`claude -p`), streaming their reasoning live to a
browser UI over WebSocket and parsing a structured JSON verdict out of each run. Finding
*detection* is a mix: SCA Scan is purely deterministic (`sast-engine/`'s dependency-audit
wrapper, no LLM at all); Reasoning Scan is a **hybrid** — `sast-engine/` (vendored from the
open-source `ship-safe` project) runs 29 regex/heuristic pattern agents plus a code-context
`VerifierAgent` in parallel with a real `claude -p` reasoning pass (`agents/scan.md`) over the
same directory, and the two result sets are merged/deduped — the deterministic half covers
known vulnerability categories fast and consistently, the reasoning half covers business-logic/
authorization/attack-surface reasoning no fixed rule set can do. Finding *analysis* (Threat
Model, Remediation, Verify) still uses `claude -p` against each finding, unchanged. Triage sits
in between: it's not a live agent anymore (its old `.md` file is gone), but every finding still
gets a triage verdict synthesized at creation time — from the deterministic engine's
verification pass, from the reasoning pass's own assessment (it triages what it finds in the
same call), or a neutral placeholder for a manually added finding. The UI is a "mission control" style app with a
global left nav ordered to mirror the actual finding pipeline — Dashboard / Reasoning Scan /
SCA Scan / Control Scan / Agent Triage / Threat Model / Reports — with Agent Configuration and
Settings both tucked into the nav footer instead of the main list. Agent Configuration used to
be a top-level item, but it's a config/admin screen (editing `agents/*.md` files), not a
workflow step in the Scan → Agent Triage → Threat Model flow the rest of the main nav walks
through in order, so it was moved down next to Settings — the other admin-y nav-footer entry. Reasoning
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
- **Reasoning Scan** — the scan kickoff form and its live cards, on their own top-level page: a
  target-directory input, branch/app fields, and a Start button — followed by
  `#scan-live-container` (2-column grid of live scan cards). Starting a scan optimistically
  pushes into both `scansList` and `timelineEntries` so the Dashboard briefing and timeline
  drawer update before the server round-trip completes.

  **This scan is a hybrid — a deterministic pattern engine and a real LLM reasoning pass run
  in parallel over the same directory, and their results are merged.** This replaced two
  earlier designs in sequence: originally this page spawned `claude -p` against
  `agents/scan.md` and let it freely reason over the whole directory with no fixed rule set
  behind it (inconsistent results, easy to miss known patterns); that was then replaced with a
  purely deterministic engine, which fixed the consistency problem but meant Reasoning Scan
  could no longer catch anything a fixed rule set can't — business-logic flaws, authorization/
  access-control gaps that only make sense in context, multi-file reasoning. Current design
  keeps both:
  - **Deterministic half**: `sast-engine/` (adapted, MIT-licensed, from the open-source
    `ship-safe` project, fully self-contained in this repo — see `sast-engine/LICENSE`): 29
    regex/heuristic pattern agents (SQLi, SSRF, auth bypass, hardcoded secrets, supply-chain,
    IaC misconfig, LLM/agentic-security patterns, and more — see `sast-engine/agents/index.js`
    for the full list) run in parallel over the repo, followed by a deterministic second-pass
    `VerifierAgent` that confirms or downgrades each finding by reading its surrounding code —
    no LLM call anywhere in this half (`runDeterministicPatternScan()` in `server.js`).
  - **Reasoning half**: real `claude -p` calls against `agents/scan.md` (`runLLMReasoningScan()`
    in `server.js`), run *concurrently* with the deterministic half, not before or after it.
    `scan.md`'s framing explicitly tells it a fixed-pattern engine is covering known categories
    in parallel, so it should lean into what that engine structurally can't do — business logic,
    authorization reasoning, attack-surface analysis — though it's free to report anything real
    regardless of category. **This is no longer a single unscoped call over the whole
    directory** — that scaled both token spend and hallucination surface directly with repo
    size, with nothing bounding how far the model could roam on a large codebase. Instead:
    - A **"full" scope** scan partitions the target directory into modules
      (`partitionReasoningModules()`) sized by *actual file count*, not just directory
      boundaries — an earlier version grouped purely by top-level subdirectory, which gave zero
      real scoping benefit to the extremely common case of one big top-level `src/` and nothing
      else at the root (that one "module" was still the whole codebase in one call). Now:
      `fast-glob` enumerates every real file under the target (respecting sast-engine's own
      `SKIP_DIRS`/`SKIP_EXTENSIONS`/`SKIP_FILENAMES`/`.gitignore` rules — the same "real code"
      definition the deterministic engine uses), and `splitFileGroup()` recursively re-groups any
      bucket over `REASONING_MODULE_MAX_FILES` (30) by the *next* path segment — e.g. a repo
      whose only top-level entry is `src/` groups everything under that one segment at depth 0
      (no separation), so it tries depth 1 next and splits by `src`'s own subdirectories instead;
      any of those still too big splits one level deeper again, up to
      `REASONING_MODULE_SPLIT_MAX_DEPTH` (3). A group that can't be subdivided further even at
      max depth (a single flat directory with hundreds of files and no nesting left to split on)
      is accepted as-is — still bounded by `--max-budget-usd` regardless of size. The resulting
      groups are then bin-packed smallest-first into buckets capped at
      `REASONING_MODULE_MAX_FILES` each (by actual size, not an arbitrary directory index the way
      an earlier version's round-robin merge worked), so a repo with many small directories
      doesn't spawn one process per directory; never exceeds `REASONING_MODULE_MAX` (24) total
      buckets — anything beyond that keeps merging into whichever bucket is currently smallest. A
      small repo (or one without much real code) naturally collapses into a single module here —
      there's no special-cased "skip partitioning" path, it falls out of the algorithm. A
      module's `paths` is the literal list of relative file paths it covers (not a directory
      reference) — the same explicit-file-list style the diff-scope flow already used, so the
      model gets an exact manifest instead of needing its own `Glob` call to discover what's in
      scope.
    - Each module gets its **own scoped `claude -p` call** — the same "limit your review to only
      these files" prompt-level restriction the diff-scope flow already used (not a hard
      filesystem sandbox; `cwd`/`--allowedTools` are unchanged, the model is instructed and
      trusted to stay in scope, same trust model as everywhere else in this app) — capped at
      `REASONING_MODULE_BUDGET_USD` ($0.50) via the CLI's own `--max-budget-usd` flag, so one
      module chasing a dead end can't blow an unbounded amount of spend. At most
      `REASONING_MODULE_CONCURRENCY` (3) run at once, via a small concurrency-limited queue
      inside `runLLMReasoningScan()` — keeps process count sane on a dev machine and avoids
      hammering rate limits on a repo with many top-level directories.
    - **The cap itself is a per-scan toggle, not a hardcoded always-on constraint.** The
      Reasoning Scan form has a **"Budget cap" On/Off** pill toggle (`#scan-budget-toggle`,
      mirroring the Scope toggle's `.group-toggle` styling) next to Branch/App, defaulting to
      On — the safe default, since every reasoning call being bounded is the whole point of this
      design. Turning it off is an explicit opt-in (with an inline hint explaining the tradeoff:
      "each module/cross-cutting call can run unbounded on spend until it finishes on its own")
      for when a scan is getting cut short by the cap and the user wants it to finish regardless
      of cost. The toggle's state (`scanBudgetEnabled`) rides along on the `scan` WS message as
      `budgetEnabled`; `handleScanMessage()` reads it (`msg.budgetEnabled !== false`, so an old
      client that never sends the field still defaults to the safe On behavior) and stores it on
      the scan record. `runOneModule()` in `runLLMReasoningScan()` only pushes
      `--max-budget-usd` onto the spawned `claude` args when `scan.budgetEnabled` is true — with
      it off, the flag is omitted entirely rather than passed as some enormous number, so the
      budget-exhaustion detection path (see below) simply never triggers, no special-casing
      needed. Verified empirically: an uncapped scan against this app's own `agents/` directory
      ran for several minutes and reached **$2.29** in real cost — far past what either budget
      constant would ever allow — and still completed normally rather than hanging, confirming
      omitting the flag doesn't change anything about how or whether the model decides to stop.
      Persisted on the scan record (`toScanListItem()`'s `budgetEnabled` field, always `true` for
      an SCA scan, which has no reasoning half) and surfaced on the scan card as a small amber
      "No budget cap" chip (`makeScanCard()`) whenever a reasoning scan ran with it off, so a
      finished scan's card doesn't quietly hide that its cost was uncapped.
    - A **cross-cutting pass** runs once more per "full" scope scan, appended to the module list
      as `{ label: '(cross-cutting review)', paths: null, crosscut: true }` — the one call in the
      whole design that sees the *entire* tree, unscoped, since every module call above is told
      to stay inside its own file list and therefore can't notice a protection defined in one
      module (auth middleware, a validator) never actually being applied in another. Its user
      prompt is framed differently from a module call's ("check whether protections defined in
      one place are actually applied everywhere they should be... do NOT re-review file internals
      in depth, separate calls already do that") but shares the exact same `agents/scan.md`
      system prompt and output contract, so no new taxonomy was needed. Capped at
      `REASONING_CROSSCUT_BUDGET_USD` ($0.75, slightly higher than a module's since it has to
      sample across the whole tree rather than deep-dive one area). **Verified empirically, not
      just assumed** — a controlled side-by-side test (a route wired to a decoy `logRequest`
      middleware instead of the real `requireAdminAuth`, both defined in a separate module) found
      that a module-scoped call *does* still usually catch this class of gap on its own, via
      naming heuristics and shape ("this looks like it should have an auth check and doesn't"),
      but self-reports lower confidence (`medium`) and explicitly hedges ("I could not read
      middleware/auth.js to confirm — the naming makes it unlikely \[to be a real check\]"). The
      cross-cutting pass, with full-tree access, confirmed the same finding at `confidence: high`
      by grepping the whole repo for the real middleware's call sites (finding zero) — real proof
      instead of a name-based guess — and reported one clean finding instead of the module call's
      five, since it explicitly declines to re-review file internals the module calls already
      cover. So: the cross-cutting pass's measured value is **confidence and precision**, not
      rescuing a total miss — the original "per-module scoping might create a total blind spot"
      concern was real in principle but less severe in practice than assumed. Treat that as the
      current evidence, not a permanent guarantee — it was one test case, not a general proof.
    - A **"diff" scope** scan skips partitioning entirely and stays exactly one call over the
      changed-file list (`modules = [{label:'diff', paths: diffFiles}]`) — the git diff is
      already a tight, pre-bounded scope, so there's nothing to gain from splitting it further,
      and it gets no cross-cutting pass either (same reasoning: already narrow).
    - Each module's (and the cross-cutting pass's) child process is registered under its own
      synthetic `` `${scan.runId}::mod${i}` `` key in `children` (tracked on
      `scan.moduleRunIds`) rather than the scan's own runId, so the WS `cancel` handler (and the
      `ws.on('close')` cleanup) can kill every in-flight call for a cancelled scan, not just one
      process.
    - **Budget exhaustion is detected and reported distinctly, not silently swallowed as a clean
      "nothing found."** Empirically confirmed (a real `claude -p` run against a deliberately
      tiny `--max-budget-usd`): the CLI exits non-zero with a final `stream-json` `result` event
      carrying `subtype: 'error_max_budget_usd'`, `is_error: true`, `terminal_reason:
      'budget_exhausted'`, and — critically — a real `total_cost_usd` field with actual dollar
      spend for that call (not an estimate). `runOneModule()` captures that `result` event
      (`resultEvent`) and, on a non-zero exit, checks its `subtype` to produce a specific message
      ("hit its $0.50 budget cap before finishing... coverage may be incomplete") instead of the
      generic "claude exited with code 1" — any findings the model did manage to report before
      the cutoff are still kept, not discarded just because the process technically errored.
    - **Real dollar spend is aggregated and surfaced, not estimated from token/tool-call
      counts.** Each call's `total_cost_usd` sums into `totalCostUsd`, sent live via
      `scan-progress`'s new `costUsd` field (index.html's `updateReasoningModuleProgress()`
      appends it to the Reasoning bar's stat text, e.g. "3/5 modules done · $1.23") and persisted
      on the scan record as `scan.reasoningCostUsd` (`toScanListItem()`), so it's visible via
      `GET /api/scans/:id` after the fact too, not just live in the browser tab that started it.
    - **A dedicated `scan-warning` message type exists for this app's own non-fatal notes** —
      distinct from `scan-stderr` (raw CLI stderr chatter, still silently discarded client-side,
      unchanged). Before this, the "one engine/module failed but the scan still recovered"
      summary was itself sent as `scan-stderr` and therefore silently dropped by the client too —
      caught during the budget-exhaustion verification above, when a real induced failure
      produced no visible signal anywhere in the UI despite the server correctly detecting and
      describing it. `scan-warning` renders as a small amber `.scan-warning-msg` banner on the
      scan card (`handleScanServerMessage()`'s `scan-warning` branch) — appended, not replaced, so
      multiple notes across different modules all stay visible; never touches `run.status` or
      the elapsed timer, since the scan is still running or already succeeded. Used for: one
      engine erroring while the other still produced results, and the "N/M reasoning calls had
      issues" partial-failure summary (which now includes budget-exhaustion messages).
    - This design (bounded-context scoping instead of full-repo roam, a hard per-call dollar cap,
      concurrency-limited execution, a cross-cutting pass for wiring gaps, and honest
      budget/cost/failure reporting) is phase 1 of a larger reasoning-engine hardening effort
      discussed with the user — see that conversation for the fuller design (bounded-context
      triage of deterministic findings via grep-based blast radius, self-consistency voting
      across repeated runs, stricter citation enforcement, real per-endpoint route enumeration, a
      rule-mining feedback loop into sast-engine) — phases not yet implemented.
  - **Merge**: `runHybridReasoningScan()` awaits both (`Promise.all`), then deduplicates — a
    reasoning-pass finding whose file+line sits within 2 lines of a deterministic finding in the
    same file is dropped as a near-duplicate (`parseFileLine()` + a small proximity check);
    anything without a resolvable line (most business-logic/attack-surface findings) always
    survives, since there's nothing to compare it against. If one half errors out, the scan
    still succeeds on the other half's results alone (a `scan-stderr` note flags the failure).

  Both halves stream live: the deterministic half's `onAgentDone` callback (a hook added on top
  of ship-safe's own orchestrator, which only reported progress via terminal spinners) relays
  each completed agent's findings as a synthetic `scan-event` carrying one `[severity] message`
  line per finding; the reasoning half streams its own *real* narration the normal way a
  `claude -p` stage always has — now interleaved *across every concurrently-running module*, not
  just one call, since the client can't tell (or need to tell) which module produced a given
  narration line any more than it could tell deterministic from reasoning narration before. Both
  event streams share the same `scan-event` type and arrive interleaved in whatever order each
  engine produces them — the client's existing `trackScanCandidates()`/`SEV_TAG_RE` parser
  doesn't care which one produced a line, so **no front-end changes** were needed to support the
  hybrid design. Tool-call/token counters on the card only reflect the reasoning half's real
  activity (the deterministic half has none to report) and now accumulate across every module's
  events, not one. The "Reasoning" progress bar (`updateReasoningModuleProgress()` in
  `index.html`) shows real `X/N modules done` progress on a "Full" scope scan with more than one
  module — driven by its own `scan-progress {engine:'reasoning'}` message, sent once per
  completed module, mirroring the deterministic bar's `{engine:'deterministic'}` message exactly.
  A "diff" scope scan (or a full scan whose directory only yielded one module) reports `total <=
  1`, so there's nothing module-like to show — the bar falls back to the indeterminate
  tool-call-count estimate it always used (`updateReasoningBar()`). If some but not all modules
  error out, the scan still succeeds on the surviving modules' findings alone (a `scan-stderr`
  note reports how many of N failed, e.g. "2/4 reasoning modules failed: ..."); if *every* module
  in the reasoning half fails, that's treated the same as the whole engine erroring for the
  purposes of the det/llm dual-failure handling described below. Diff-only scope restricts both halves to the same changed-file list — `options.onlyFiles`
  on `orchestrator.runAll()` for the deterministic half (a small addition on top of ship-safe's
  own orchestrator, since most of the 29 agents read `context.files` directly rather than
  opting into `context.changedFiles` individually), and the changed-file list appended to
  `scan.md`'s prompt for the reasoning half.

  **Every finding this scan produces is already triaged, and each half assigns it differently.**
  Deterministic findings: `findingFromSastEngine()` in `server.js` synthesizes a `triage` run
  straight from the `VerifierAgent`'s `verified`/`verifierNote`/`confidence` output (`verdict:
  'confirmed'` when verified, `'needs_review'` otherwise — only critical/high findings actually
  get checked by `VerifierAgent`, so anything below that floor lands as `needs_review` too, not
  because it's suspect but because it was never independently re-checked); `cwe`/`owasp` come
  straight from the pattern that matched, `asvs`/`nist_800_53` are always `null` (sast-engine has
  no mapping for either). Reasoning-pass findings: `findingFromLLMScan()` instead takes the
  *real* triage verdict `scan.md` assigned itself in the same pass (`verdict`,
  `severity_confirmed`, `confidence`, `priority`, and — unlike the deterministic half — genuine
  `owasp`/`asvs`/`cwe`/`nist_800_53` mapping, since the model doing the reasoning is also the one
  filling in the mapping; see "Taxonomy convention" below for what this does and doesn't close
  of the framework-mapping gap). Both kinds of synthetic run carry a `source` field
  (`'sast-engine-verifier'` vs. `'reasoning-scan'`) so Finding Detail can distinguish them.
  `agents/triage.md` stays deleted — Triage is still not a live agent stage anywhere in this
  app; see the Agent Triage bullet's "Pipeline shape" discussion below for what that changes
  about the Remediation Loop.
- **SCA Scan** — Software Composition Analysis gets its own top-level page (structurally
  similar to Reasoning Scan: target directory, branch/app, Start button, live cards, a
  clock-icon timeline button — but **no scope toggle**, since a dependency audit always reads
  the whole manifest/lockfile; there's no per-file "diff only" concept for it). Also
  deterministic now: `runDeterministicScaScan()` in `server.js` calls sast-engine's
  `runDepsAudit(targetPath)` (adapted from the open-source ship-safe project's deps command,
  trimmed to the programmatic path only) — which shells out to whichever package manager's own audit tool is
  present (`npm audit --json`, `yarn audit --json`, `pnpm audit --json`, `pip-audit`,
  `bundle-audit`, auto-detected from lockfiles) and normalizes the result into findings. No
  agent-progress loop needed here (one call, already fast) — if a finding is produced, its
  narration line is sent the same synthetic-assistant-event way Reasoning Scan's are. SCA
  findings still carry no synthetic triage run and never enter the Remediation Loop (see the
  Agent Triage bullet below) — nothing about that changed.
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
  even both, now that there's no separate DAST scanType to gate the field on) plus Rule/CWE,
  then **Remediation Loop**; SCA shows Package + Fixed-in, then a plain **Status** column
  instead (`FINDINGS_COLUMNS` in `index.html` — the `sca` config uses `key: 'status'`, not
  `'loop'`; see below for why). Severity/Title/Remediation Loop/Status columns are click-to-sort
  (`findingsSort`, toggling asc/desc on the same header, both `'status'` and `'loop'` keys
  sorting by the same `STATUS_ORDER_MAP`). Every row carries a trailing **`.ft-actions-col`**
  (`.ft-actions-cell`, a small flex row) holding, for a reasoning finding, the Remediation
  Loop's own advance/run-all buttons (`findingLoopActionsHtml()` — see below) rendered here
  rather than inside the narrow loop cell itself, followed by a small three-dot button (reusing
  the `.console-toggle-btn` icon-button style) that opens the exact same per-agent dropdown as
  right-clicking the row — added because right-click alone isn't discoverable, especially
  without a mouse; the button just calls `openFindingContextMenu()` positioned under itself via
  `getBoundingClientRect()`, same pattern as the Finding Detail page's "Agent Runs ▾" button.
  There's no row-selection checkbox column, and no per-row "quick remediate" wrench either — an
  earlier design had a wrench icon here running the advisory, read-only Remediation agent with
  one click; removed because a completed quick-remediate run never actually moved the
  Remediation Loop forward (it never wrote anything), which read as "this button does nothing"
  even though it had produced real advisory guidance visible on Finding Detail — confusing
  enough in practice that it was simpler to cut than to explain. Before that wrench, an even
  earlier design had these same checkboxes plus a page-header "Auto-remediate selected (N)" bulk
  button running the same read-only call across every checked row — also removed, for being a
  redundant second path once the wrench existed. Both of those advisory-preview entry points are
  gone now; the only way to run Remediation from this table is the loop's own advance/run-all
  buttons, and both of those always write (see "Progressing the loop" below).

  **The Remediation Loop column** (`findingLoopCellHtml()`, reasoning findings only — see
  below for SCA) is the main way this table communicates progress through the full pipeline —
  Found → Triaged → Fixed → Verified, matching "Pipeline shape" below exactly. **Triaged is
  always already "done" the moment a finding exists** — Triage is no longer a live agent stage
  at all (`agents/triage.md` was deleted; see the Reasoning Scan bullet above and "Pipeline
  shape" below): every finding gets a synthetic `triage` run pushed at creation time, either
  from sast-engine's `VerifierAgent` output (scan-sourced) or a neutral placeholder (manually
  added via "+ Add", or this app's own seed data). A small **status track** (`loopTrackHtml()`:
  three tiny circular `.loop-seg` dots for Triaged / Fixed / Verified — 7px, the same small-dot
  convention the sidebar's `.nav-badge` uses, not a wide bar — each gray/pending, amber/running
  with a pulse, green/done, or red/attention) sits above a one-line status label —
  `findingLoopCellHtml()` is a pure status readout now, no buttons live inside this column. The
  column header reads just **"Loop"**, not "Remediation Loop" — table cells clip overflowing
  text at the cell boundary in this app's browser rendering regardless of `overflow` CSS (a
  quirk of `<th>`/`<td>` layout, not something `overflow:visible` can override), so the fuller
  label didn't fit once the column was narrowed and just silently truncated to "REMEDIATION" —
  shortening the label was simpler than widening the column back out. The column's `<th>`/`<td>`
  carry `data-col="loop"` specifically so CSS can cap its rendered width (`width`/`max-width:
  104px`) — `table.findings-table` otherwise uses the browser's default auto layout (no
  `table-layout:fixed`), which would hand this column any left-over horizontal space in the row
  even though three tiny dots and a short label never need it. "Found" isn't a fourth dot here —
  a finding is always already "found" the moment it exists, so a node for it never carried real
  information; an earlier 4-dot-track design included it anyway (see the redesign history below)
  before being condensed to just the three stages that can actually change state. The
  advance/run-all controls instead render in the row's own actions column
  (`findingLoopActionsHtml()`, see the actions-column paragraph above) — "on the side" of the
  row, next to the "…" menu button, rather than crammed into this narrow column: a circular
  **advance button** (24px, sized up from an earlier 20px pass that read as too small to
  comfortably click — a single chevron `›` icon, `.loop-advance-btn`, using the new `chevronRight`
  glyph rather than the older `arrowRight` icon, which included a horizontal shaft that made it
  harder to tell apart from the run-all button at a glance) that runs exactly the *next* stage
  and stops — not a wide label-changing button — plus a second, accent-bordered **"run all
  stages" button** (same 24px sizing, a skip-forward `⏭` icon via the new `skipForward` glyph —
  a triangle-plus-bar shape, deliberately *not* the old double-chevron `fastForward` icon, which
  read as just a slightly-longer version of the advance button's arrow rather than a visually
  distinct action — `.loop-run-all-btn`) that chains the two remaining real stages (Remediation
  apply → Verify) under one confirmation, for
  when stepping through individually isn't needed (see "Progressing the loop" below for both).
  `findingLoopActionsHtml()` shares the exact same state-derivation (`findingLoopState()`) as the
  status column, so the two always agree — it just returns `''` while any stage is `running` or
  once `verified === 'done'` (nothing left to advance to). State is derived by
  `findingLoopState()` from `findingStageRuns()`, which needs each stage's own latest run
  independently (not just the single overall latest) — a list-item finding (from `GET
  /api/findings`) carries that precomputed server-side as `.stageRuns` (`toListItem()` in
  `server.js`, via `latestRunByAgent()` scanning `finding.runs` for the last run of each agent
  type), while a full cached finding (from `GET /api/findings/:id`, e.g. Finding Detail's context
  menu) only has the raw `.runs` array — `findingStageRuns()` derives the same shape from that
  when `.stageRuns` isn't present. Found is always "done" — the finding exists; Triaged/Fixed/
  Verified only ever move because of their own `triage`/`remediation`/`verify` run specifically,
  so Threat Model (a separate, optional deep-dive — see the context-menu bullet below) never
  touches this column. Crucially, "Fixed" requires the latest `remediation` run's verdict to
  carry a real `applied_diff`, not just a completed run with `corrected_code` filled in — even a
  write-capable run whose proposed `edit_plan` failed validation or was left `null` because the
  model wasn't confident enough to propose one (per `agents/remediation.md`'s apply-mode
  guidance not to guess at an edit) —
  showing "Fixed" and offering "Verify the fix" when nothing was actually written would be
  actively misleading, not just imprecise. `findingLoopNextAction()` reduces that state to the
  one thing the advance button would do next — `'triage'` | `'remediate'` | `'verify'` | `null`
  (busy, or nothing left); triage issues (never run, or errored) would come first if they ever
  occurred — nothing else should happen before a finding's been triaged — but in practice this
  branch is now unreachable, since every finding already carries a triage run from creation time
  (see above); it's kept only as a defensive fallback. A `verified === 'attention'` state maps
  back to `'remediate'`, not another `'verify'`, since Verify already said the fix didn't hold
  and the actionable next step is another fix attempt, not re-checking the same unfixed state.
  The status label + advance button read: triaged, not yet fixed → accent "Triaged" + advance
  (tooltip "Apply a fix (writes to your code)", disabled without a path); any stage `running` →
  a plain "Fixing…"/"Verifying…" hint, no button; Remediation failed → red "Fix failed" + advance (tooltip "Retry
  the fix"); Verify came back `still_vulnerable`/`partially_fixed`/`inconclusive` → red "Not
  fixed yet" + advance (tooltip "Retry the fix"); Verify came back `verified_fixed` → green
  "Verified fixed" + a small `.loop-view-diff` link (`onViewDiffClick()`, just calls
  `openFindingDetail()` — see below for why there's no popup to open) instead of a button —
  nothing left to advance to. Only Remediation/Verify-bound advance-button states are disabled
  (`opacity:.3`) when `findingSourcePath()` can't resolve a directory for the finding (no
  `sourceScanId` — manually-added findings have nowhere to write to); the "run all stages"
  button is *always* gated on a known path, since Remediation is unconditionally part of that
  chain. Both buttons disable themselves client-side the instant they're clicked
  (`e.currentTarget.disabled = true` in the row-wiring handlers) so a fast double-click can't
  fire two real runs/pipelines against the same directory at once — the next table render (on
  that run's `done`/`error`) replaces the row's DOM anyway, so nothing needs to re-enable it. A
  `status === 'closed'` finding (false positive/duplicate) shows neither track nor buttons — the
  loop doesn't apply to something dismissed as not real. This column has gone through several
  redesigns: a plain status *badge* plus a pencil icon requiring horizontal scroll to see, gated
  by a page-level **Read-only** checkbox that silently changed what the same pencil did; a
  one-click-does-everything "Fix & Verify" button with a 3-segment flat-bar stepper; a
  dot-track-plus-single-advance-button version scoped to just Found → Fixed → Verified (Triage
  excluded, reachable only from the row menu); a version that folded Triage into a 4-dot track
  and reintroduced a "run everything" shortcut as its own dedicated button rather than a
  row-menu item — a "Push loop ahead" menu item briefly existed for the same purpose and was
  removed for reading as a near-duplicate of the bulk "Auto-remediate selected" button that
  existed at the time (single-finding + real writes vs. bulk + advisory-only); and now this one,
  which condenses that 4-dot track into three tiny dots (dropping the redundant "Found" node,
  which never carried information since a finding is always already found) and relocates the
  advance/run-all buttons out of the loop cell entirely, into the row's actions column — an
  intermediate pass first replaced the 4 dots with 3 wide flex-stretched rectangle bars before a
  follow-up shrank them back down to tiny dots (the bars read as too heavy for a status readout,
  and stretched to fill whatever width the column's auto-layout happened to grant it — see
  above for why that width is now explicitly capped) — done at the same time the
  wrench/quick-remediate button and the checkbox-driven bulk
  button before it were both removed outright (see the actions-column paragraph above), leaving
  the loop cell a pure status readout and every row-level action in one place on the side.

  **SCA findings don't get a Remediation Loop at all** — `findingLoopCellHtml()` special-cases
  `f.scanType === 'sca'` to just render the plain `'status'` cell (a taxonomy badge) instead,
  since an SCA finding's fix is "bump the dependency to the `Fixed in` version already shown in
  its own column," not a code edit this app's agents reason about; implying an editable loop
  there would be misleading. This branch is only reachable from the **All** type tab, which
  shares the `'loop'` column key across both finding types — the dedicated **SCA** tab instead
  uses `{ key: 'status', label: 'Status' }` directly in its own `FINDINGS_COLUMNS` entry, so its
  header never says "Remediation Loop" in the first place. The exclusion goes further than just
  the column: the actions-column's Remediation Loop advance/run-all buttons
  (`findingLoopActionsHtml()`) aren't rendered for SCA rows either (an SCA finding has no loop
  state to have buttons for), and `openFindingContextMenu()` filters `SCA_EXCLUDED_AGENTS = [...
  FIX_FLOW_AGENTS, 'threat_model']` out of an SCA finding's menu entirely — none of the four
  per-finding code-analysis agents have anything meaningful to say about a dependency version
  bump, so rather than leave them in as options that would just produce confused or irrelevant
  output, an SCA row's "…" menu (or Finding Detail's "Agent Runs ▾") shows only whatever custom
  agents exist beyond the four built-ins, or — in the common case where there are none — a
  single disabled "No agent actions apply — update the package instead" item.
  `renderFindingDetailActions()` mirrors this when deciding whether to disable its own "Agent
  Runs ▾" button.

  **Progressing the loop** — two entry points, run exactly what you asked for and nothing more,
  always confirm before writing. Neither one ever runs Triage live anymore — a finding's triage
  run already exists from the moment it was created (see the Reasoning Scan bullet above), so
  the loop's real work starts at Remediation:
  - **`onLoopAdvanceClick()`** (the loop cell's advance button) — looks up
    `findingLoopNextAction()`; if it's `'verify'`, fires an ordinary read-only
    `startStage(id, 'verify', ...)` (no confirmation needed — nothing is written); if it's
    `'remediate'`, confirms once via `confirmApplyWrite()` (a native `confirm()` naming the
    exact target directory and the clean-git-tree requirement — the friction point instead of a
    hidden mode toggle) and then calls `startRemediateApply()`, which sends `{type:
    'remediate_apply', runId, findingId, context, instruction, path}` — a single Remediation run
    that does *not* auto-chain into Verify. (The `'triage'` case is still handled defensively —
    see the Remediation Loop column bullet above — but shouldn't be reachable in practice.)
    Advancing the loop this way is always a deliberate click per stage.
  - **`onLoopRunAllClick()`** (the loop cell's fast-forward "run all stages" button) — always
    restarts the remaining pipeline fresh (Remediation apply → Verify) rather than trying to
    resume from wherever the finding currently stands; simpler to reason about, and matches "run
    all stages" literally (there's no live Triage stage left to include). Confirms once via
    `confirmRunAll()` (same git-clean-tree framing) and then calls `startRemediateAll()`, which
    sends `{type: 'remediate_all', remediationRunId, verifyRunId, findingId, context,
    instruction, path}` — two client-generated runIds for what the server turns into two real,
    sequential agent runs. Only the first (Remediation) gets an optimistic "running" placeholder
    at click time — Verify's placeholder arrives via the server's own `started` message once
    that stage actually begins, since the chain doesn't yet know whether it'll even run
    (Remediation erroring, or its plan failing to apply, stops the chain early — see below).

  Server-side, `checkCleanGitTarget()` (the **clean git working tree** gate — `git status
  --porcelain`, refusing an uncommitted or non-git directory outright, so anything either flow
  does is trivially revertible entirely outside this app — see "Security posture" below),
  `spawnAgentStage()` (the spawn/relay/close logic, kept as its own function purely to keep the
  handlers below readable), and `applyRemediationPlan()` (validates and applies a Remediation
  verdict's `edit_plan` — see below) back two handlers in `server.js`:
  `handleRemediateApplyMessage()` runs one Remediation stage — **read-only**
  (`--allowedTools 'Read,Grep,Glob'`, no `Edit`/`Write` — see "Security posture" for why that
  changed), asking it to propose an `edit_plan` in its verdict instead of editing directly — then
  calls `applyRemediationPlan(targetPath, verdict)`, which validates every proposed edit against
  the real file (`sast-engine/remediation-apply.js`'s `validatePlan()` — the `find` string must
  match exactly once, whitespace-tolerant fallback if not; protected paths like `.env`/
  lockfiles/`node_modules` are refused outright) and only then writes it (`applyPlan()`),
  captures `git diff` right after and attaches it to the run's verdict as `applied_diff` (real
  evidence of what actually changed, independent of what the agent claims), and stops. If the
  model proposed no `edit_plan` at all (a legitimate "this needs a human, not a guess" outcome
  per `agents/remediation.md`'s guidance), nothing is written and the run stays a normal
  "done" analysis-only result; if it proposed one that fails validation, the run is marked
  `error` instead (surfaces as "Fix failed" in the loop, see above) so a bad plan doesn't sit
  looking identical to "no fix needed yet." `handleRemediateAllMessage()` checks the git-clean
  gate once up front, runs Remediation the same read-only/edit_plan way, applies it the same
  way, and — only if the apply step didn't error — runs Verify the normal read-only way with
  the Remediation verdict folded into its prompt. Both handlers push onto `finding.runs` and
  relay via the *exact same* `started`/`event`/`done` message shapes the generic per-finding
  `run` path already uses — the client needed no new message-type handling for run lifecycles
  at all. There's no popup for the diff — `runCardHtml()` on the Finding Detail
  page already renders any remediation run's `applied_diff` as its own colored diff block
  (`diffLineHtml()`, hand-rolled `+`/`-`/`@@` line coloring, no external diff library) right
  alongside that run's other verdict fields, so "see what changed" is just "look at the finding,"
  not a separate screen — an earlier design auto-popped a modal titled "Fix applied" instead,
  removed for reading as messy/redundant with content the detail page already showed (and for a
  real accuracy bug: it auto-opened before a chained Verify run had even started, so its wording
  risked implying a confirmation that hadn't happened yet). `applyWriteRunIds` tracks which
  runIds belong to a git-gated flow so a precheck failure (not a git repo, dirty tree) — which
  never gets a run pushed server-side, so it can't rely on the normal error-badge-on-a-run
  treatment — can be surfaced via the client's `error` handler calling `alert()` on those runIds
  directly (for the chained flow, the precheck error is tagged with the first stage's runId,
  since that's the only one with a client-side placeholder before the server responds). Verify's
  `still_vulnerable`/`partially_fixed` verdict sends the finding back to `in_review` exactly like
  a normal (non-write) Verify run would, and a Triage verdict of `confirmed`/`needs_review`
  behaves like any other Triage run — no separate status logic was needed, `deriveStatus()`'s
  existing branches (see the Verify bullet above) already cover both paths since they only look
  at the finding's latest run, not how that run was triggered. A **Scan** filter sits beside the
  type tabs — not a native
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
  up there with no code change. It's no longer a flat list of everything, though — Triage,
  Remediation, and Verify (`FIX_FLOW_AGENTS`) are filtered out entirely, since the Remediation
  Loop column's advance/run-all buttons (see the Agent Triage bullet's "Progressing the loop"
  paragraph above) are now their dedicated controls; running any of the three with custom
  instructions via the stage modal is no longer possible from this menu (a deliberate
  trade-off — the dedicated buttons are faster for the common case, at the cost of that
  flexibility). What's left is just Threat Model — a separate, optional deep-dive that
  deliberately doesn't sit on the fix-flow path — plus whatever custom agents exist beyond the
  four built-ins; SCA findings lose Threat Model from this list too (`SCA_EXCLUDED_AGENTS`, see
  below). Both paths converge on `openFreshStageModal()`. Note:
  `openFindingContextMenu()`'s button click handler calls `e.stopPropagation()` — without it,
  the click bubbles to the document-level "click outside closes the menu" listener and closes
  the menu in the same tick it opened. An "Export" button (`GET /api/findings/export.csv`)
  downloads all findings + latest verdicts.
- **`remediation_generated` status** — `deriveStatus()` in `server.js` derives an accent-colored
  "Remediation generated" badge (`statusLabel()`/`.badge.remediation_generated`) once a finding's
  latest run is `agent === 'remediation'` with a non-null `corrected_code` (a field on
  `agents/remediation.md`'s output contract: the full corrected version of the finding's `code`
  snippet, not just prose fix guidance — `null` when there's no `code` snippet to correct, or
  the fix is architectural) and a `confirmed`/`needs_review` verdict (checked *before* the
  existing `remediation_ready` case, but *after* the `false_positive`/`duplicate` → `closed`
  case), via the same `updateFindingListItem()` hook every other status change flows through.
  This status predates the Remediation Loop's write-capable design and originally covered the
  advisory-only "quick remediate" wrench button and, before that, a bulk "Auto-remediate
  selected" checkbox flow — both since removed (see the actions-column paragraph above) for
  reading as dead-weight next to the loop's own advance button, since neither ever moved the
  loop itself to "Fixed." The status is still reachable today, though, without either of those:
  a write-capable Remediation run whose model filled in `corrected_code` as guidance but declined
  to propose an `edit_plan` (a legitimate "this needs a human, not a guess" outcome, see
  `agents/remediation.md`) lands here too — `corrected_code` present, `applied_diff` absent, so
  the Remediation Loop column correctly still reads "Triaged," not "Fixed," while the finding's
  overall status still surfaces that useful guidance exists. Click into the finding for the full
  guidance (root cause, fix guidance, `corrected_code`) via Finding Detail's normal Agent runs
  section, same as any other verdict — there's no dedicated results screen for this.
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
  (`triage`/`threat_model`/`remediation`/`verify`/`scan`/`app_threat_model`/`controls_assist`,
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

**Pipeline shape**: `Scan → Agent Triage → Remediation → Verify` is the conceptual path, but
**no agent ever runs automatically** — every run requires an explicit, reviewable action so
there's always an audit trail before anything executes against a finding (an earlier version
defaulted straight to Remediation on click, which read as auto-fixing without review — this
was a deliberate correction). The Remediation Loop column's advance/run-all buttons (rendered in
the row's actions column, see the Agent Triage bullet above) are the exception to "always opens
a stage modal first" — each still requires an explicit click per finding/step, just skips the
modal, because reviewing context ahead of a routine next-step click would slow down the exact
workflow they exist to speed up (a native `confirm()` naming the target directory is still the
gate before either one writes). The Finding Detail page's "Agent Runs ▾" button and the
right-click context menu (or its visible three-dot equivalent) on an Agent Triage table row open
the same dynamic per-agent menu (one "Run <Agent>…" item per entry in `agentsList`, minus the
fix-flow agents now that the Loop column covers them — see the Finding Detail bullet above) as
shortcuts into the same small stage modal (agent dropdown + editable context + optional
instructions, `openFreshStageModal()`) — none of them run instantly. Triage itself is no longer
in that menu at all (or any menu) — it's not a live agent stage anymore (see the Reasoning Scan
bullet above), so every finding already carries a triage verdict from creation time and
`remediation.md` still has to be able to stand on its own for the rare case where that's
somehow missing: if there's no prior verdict in its context, it does that confirm/severity/
framework-mapping assessment itself before writing fix guidance (see the "check your context
before you start" section at the top of `agents/remediation.md`).

**Verify** (`agents/verify.md`) is the newest stage, closing a gap the pipeline used to have no
answer for: nothing previously confirmed a fix actually worked, only that Remediation had
*proposed* one. It's a genuinely different kind of stage from Threat Model/Remediation —
those two reason primarily over the finding's already-captured `code` snippet and whatever
`Read`/`Grep` happens to turn up in this app's own directory (the fixed `cwd` every per-finding
run gets by default); Verify's whole point is to re-check the *current* state of the finding's
real target codebase, which requires it to be spawned with a different `cwd`. The client resolves
that path from the finding's `sourceScanId` (via `findingSourcePath()` in `index.html`, walking
`sourceScanId` → the matching `scansList` entry's `path`) and sends it as an optional `path`
field on the WS `run` message; `server.js`'s per-finding run handler validates it's still a real
directory and, only then, spawns with `cwd: path` and `--allowedTools 'Read,Grep,Glob'` instead
of the usual `cwd: process.cwd()` / `Read,Grep` — Glob is added because Verify may need to
relocate a file, not just re-read one at a known path. Findings with no `sourceScanId`
(manually added via "+ Add") fall back to the old default `cwd`, which for Verify's purposes is
effectively "no live access" — `verify.md` is written to recognize that (sanity-check whether
what it actually read plausibly matches the finding at all) and return `inconclusive` rather
than reasoning over an unrelated repository. The stage modal surfaces this transparently: a
hint line under the agent dropdown (`updateStageModalVerifyHint()`, only shown when `verify` is
selected) states either "Will re-check the live code at: <path>" or "No known source directory
for this finding — review will be based on the saved snippet only," resolved fresh whenever the
agent dropdown changes. Verify's own verdict vocabulary (`verified_fixed | still_vulnerable |
partially_fixed | inconclusive`) doesn't reuse Triage's `verdict` values on purpose — it isn't
re-litigating whether the finding is real, only whether it's still open. `deriveStatus()` in
`server.js` derives a new `verified_fixed` status when the latest run is `agent === 'verify'`
with `verdict === 'verified_fixed'`; the other three verdict values all fall through to the
existing generic `in_review` default, which is the right outcome for "still needs work" and
"couldn't confirm either way" alike — `still_vulnerable`/`partially_fixed` send the finding back
into the queue, `inconclusive` just doesn't advance it. `agents/scan.md`,
`agents/app_threat_model.md`, and `agents/controls_assist.md` are three further agent files but
are *not* per-finding pipeline agents — `GET /api/agents` (`NON_FINDING_AGENTS` server-side)
filters all three out of the Threat Model/Remediation/Verify list on purpose;
`GET /api/agents?all=1` is the unfiltered variant Agent Configuration uses instead (see its
bullet above). (`agents/triage.md` used to be a fourth agent file in this category — deleted
when Triage moved to a synthetic verdict assigned at finding-creation time instead of a live
agent stage; see the Reasoning Scan bullet above.)

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
nothing runs without that step. Alternatively, click a reasoning finding's small `→` advance
button (in its actions column, next to the "…" menu) to run just the next real step — a
write-capable fix, then a Verify check once that's done, one click each — needs a finding that
came from a scan, the button is disabled otherwise. Watch the row itself update —
no separate screen. The detail page's
Agent runs section updates live once a run
finishes (or shows a "running" placeholder immediately, via an optimistic push in
`startStage()`). There is no automated test for the WebSocket flow — verification is manual,
through the browser.

## Architecture

```
server.js          Express + ws. In-memory findings store (seeded with sample data on
                    boot) and a separate in-memory scans store, behind a small REST API,
                    plus a WebSocket handler that spawns `claude -p` per per-finding agent
                    run (Threat Model, Remediation, Verify), relays stream-json lines live,
                    and extracts the final JSON block from the accumulated assistant text.
                    SCA Scan calls into sast-engine/ directly (see below), no `claude -p`
                    involved. Reasoning Scan is a hybrid — it calls into sast-engine/ *and*
                    spawns a real `claude -p` against agents/scan.md concurrently, then
                    merges/dedupes both result sets (runHybridReasoningScan()); both sides
                    relay scan-events in the same shape (one real, one synthetic to match
                    it) so the client needed no changes to keep showing live progress from
                    either.
sast-engine/        Deterministic security-scanning engine, adapted (MIT license, see
                    `sast-engine/LICENSE`) from the open-source `ship-safe` project and now
                    fully self-contained in this repo, trimmed to just what this app uses:
                    `agents/` (29 regex/heuristic pattern agents plus ReconAgent and
                    VerifierAgent, orchestrated by `orchestrator.js`), `commands/deps.js`
                    (wraps the project's own package-manager audit tool for SCA Scan), and
                    `remediation-apply.js` (validates and applies a Remediation verdict's
                    proposed `edit_plan` against the real file — the only place any agent's
                    output can reach disk in this app). Its own `package.json` sets `"type":
                    "module"` so it can stay real ESM without converting server.js's
                    CommonJS; server.js loads it via dynamic `import()` (`loadSastEngine()`).
public/index.html   The whole app: global nav (status summary + Settings entry in the nav
                    footer) with Dashboard (briefing + stats + a clickable agents panel),
                    Reasoning Scan (the scan kickoff form — target/branch/app, scope in the
                    header — plus its live scan cards and a timeline-drawer clock button), SCA
                    Scan (target/branch/app, no scope toggle, its own live cards, its own clock
                    button), an Agent Triage table split into Reasoning/SCA type tabs with
                    click-to-sort columns, a per-scan filter popover, a per-row action menu, a
                    Remediation Loop column (reasoning findings only, always starting at
                    "Triaged" since Triage is no longer a live stage, rendered as a 3-segment
                    status track with its one-step-at-a-time advance button plus a "run all
                    remaining stages" fast-forward button living in the row's own actions
                    column instead), a full-page Finding
                    Detail view per finding (meta grid, syntax-highlighted code block, and an
                    Agent runs history with a single "Agent Runs ▾" dropdown), a Threat Model
                    page (per-finding OWASP
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
                    logic lives (`scan.md`, `threat_model.md`, `remediation.md`,
                    `verify.md`, `app_threat_model.md`, `controls_assist.md` — `triage.md`
                    was deleted when Triage moved to a synthetic verdict assigned at
                    finding-creation time; `scan.md` itself was deleted and then revived
                    once Reasoning Scan became a hybrid of sast-engine + a real reasoning
                    pass — see the Reasoning Scan bullet above). New
                    *per-finding* agent = new .md file, no server changes needed beyond it
                    existing on disk (see "not yet built" below on hardcoded assumptions
                    elsewhere) — unless it needs live-codebase access like Verify does, in
                    which case the client just needs to send a `path` on its `run` message
                    (see the Verify bullet under "Pipeline shape"); that plumbing is
                    generic, not specific to `verify.md`.
                    `app_threat_model.md`, `controls_assist.md`, and `scan.md` are three
                    exceptions — each is invoked through its own dedicated code path
                    (`handleAppThreatModelMessage` / `handleControlsAssistMessage` /
                    `handleScanMessage` in server.js), not the generic per-finding `run`
                    path, because all three need a different tool set (`Glob` in addition to
                    `Read`/`Grep`), a different `cwd` (the target directory, not the app's
                    own), and a different output shape (`app_threat_model.md`/
                    `controls_assist.md` each return their own holistic report object;
                    `scan.md` returns a `{"findings": [...]}` array, one of two sources
                    `handleScanMessage` merges into Reasoning Scan's results — see the
                    Reasoning Scan bullet above) rather than a single per-finding verdict
                    object.
```

**Findings store**: `findings` (Map, in `server.js`) is session-lifetime only — reset on
restart, seeded from `seedFindings()` with six sample AppSec findings (five reasoning, one
SCA — enough to populate both Agent Triage type tabs on first run). Every finding has
a `scanType` (`reasoning | sca`, `FINDING_SCAN_TYPES`) plus a handful of
optional type-specific fields: `code` (reasoning, syntax-highlighted on the detail page),
`packageName`/`packageVersion`/`fixedVersion` (SCA), `endpoint`/`method` (reasoning, for an
attack-surface finding). Every reasoning finding — seeded, scan-sourced, or manually added via
`POST /api/findings` — gets a synthetic `triage` run (`placeholderTriageRun()`, or
`findingFromSastEngine()`'s real sast-engine-derived version for scan-sourced ones) pushed
onto its `runs` array at creation time, since Triage is no longer a live agent stage anywhere
in this app (see the Reasoning Scan bullet above) — without this, the Remediation Loop's first
stage would be permanently stuck pointing at a stage that can no longer run. Each finding
also owns that `runs` array; each run record (`{runId, agent, status, verdict, fullText, ...}`)
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
client sends `{type: "run", runId, findingId, agent, context, instruction}`, optionally with a
`path` field (see the Verify bullet above — only `startStage()` populates this, and only for
`agent === 'verify'`) → server reads `agents/<agent>.md`, spawns `claude -p
"<instruction>\n\nFinding context:\n<context>" --append-system-prompt "<agent .md contents>"
--output-format stream-json --verbose --allowedTools "Read,Grep" --permission-mode
acceptEdits` with `cwd = the app's own directory` — *unless* a valid `path` was given, in which
case `cwd` becomes that directory and `--allowedTools` becomes `"Read,Grep,Glob"` instead → each
parsed stdout line is relayed immediately as `{type: "event", runId, findingId, event}` (this is
the "live" part) → on process exit, the server regex-searches the accumulated assistant text for
a fenced ` ```json ` block, records the verdict against the finding's run history, and sends
`{type: "done", runId, findingId, code, verdict, fullText}`.

**Request flow (scans)**: client sends `{type: "scan", runId, path, scanType, scope,
baseBranch, branch, app}` → server validates `path` exists and is a directory (and, for
`scope: "diff"`, that `baseBranch` diffs cleanly via `git diff --name-only`) → dispatches to
`runHybridReasoningScan()` or `runDeterministicScaScan()` (`server.js`) depending on `scanType`.
SCA: `runDepsAudit(path)` shells out to whichever package manager's own audit tool is present —
**no `claude -p` involved**. Reasoning: `runHybridReasoningScan()` kicks off two things
concurrently (`Promise.all`) and waits for both — `runDeterministicPatternScan()`
(`buildOrchestratorAsync(path)` + `orchestrator.runAll(path, { onlyFiles, onAgentDone })`, no
`claude -p`, relays each completed pattern-agent's findings via `onAgentDone` as a synthetic
`{type: "scan-event", ...}` shaped like an assistant-text stream-json block) and
`runLLMReasoningScan()` (real `claude -p` calls against `agents/scan.md`, `cwd` set to the
target path, `--allowedTools "Read,Grep,Glob"` — one call per module on a "full" scope scan,
one call total on a "diff" scope scan, see the Reasoning Scan bullet above for the module
partitioning/budget-cap/concurrency details — relaying each module's actual stream-json events
the same way any other per-finding stage does). Both send the same `{type: "scan-event", runId,
scanId, event}` shape regardless of which one (or which module) produced it, so the client's
live-card parser needs no changes — see the Reasoning Scan bullet above. Once both resolve, the server dedupes (drops a
reasoning-pass finding whose file+line is within 2 lines of a deterministic one in the same
file) and builds a Finding per surviving result (`findingFromSastEngine()` for the deterministic
half, `findingFromLLMScan()` for the reasoning half — each attaches its own kind of synthetic
`triage` run, see "Findings store" above) and sends `{type: "scan-done", runId, scanId,
findings: [...]}`. `scan-started`/`scan-event`/`scan-stderr`/`scan-error`/`scan-done` remain
deliberately distinct type names from the generic per-finding message types, same
collision-avoidance reasoning as before (`scanRunIndex` is still a separate `runId`-keyed
lookup from `runIndex`/`children`). The reasoning half's `claude` child process *is* registered
in `children` (keyed by the scan's own `runId`, same as any other per-run agent) so `cancel` can
kill it mid-run — the deterministic half never spawns a child, so `scanRunIndex` alone is enough to
track an in-flight deterministic scan and let `cancel` mark it `status: 'cancelled'` so its
`onAgentDone` callback stops relaying events and its completion handler skips creating
findings. This suppresses all visible effects but doesn't abort the underlying
`orchestrator.runAll()` promise early — the 29 agents keep running to completion in the
background either way (they're regex passes over files, not long-running child processes, so
in practice this finishes quickly regardless).

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
`Map` of child processes (`children` in `server.js`), shared by per-finding runs, app-level
threat models, control assessments, and — for a Reasoning Scan — the reasoning half's `claude`
process(es) (the deterministic half never spawns a child, see "Request flow (scans)" above, but a
scan's `runId` is still tracked independently in `scanRunIndex` regardless of whether a child
exists under it) — not a single in-flight run, so multiple stages/scans/whole-directory runs
can be running at once from one browser tab. A "full" scope reasoning scan is the one exception
to "one runId, one child": every module call plus the cross-cutting pass (see the Reasoning Scan
bullet above) is registered under its own synthetic `` `${scan.runId}::mod${i}` `` key instead,
tracked on the scan's own `moduleRunIds` array, since a single scan can have several of these
processes in flight concurrently. `{type: "cancel", runId}` kills a specific run's child process if it has one, marks
it `status: 'cancelled'` either way (checked against `runIndex`, `scanRunIndex`,
`appThreatModelRunIndex`, and `controlAssessmentRunIndex`), and — specifically for a scan —
additionally walks `scanIndexed.moduleRunIds` to kill every one of that scan's in-flight module
children too, since none of them are reachable via the scan's own `runId` lookup. Closing the
tab/connection kills every still-running child tied to it regardless of key naming
(`ws.on('close')` iterates `children` directly and kills unconditionally) and separately marks
every still-`running` entry in `scanRunIndex` as `cancelled` up front, so a modular scan's status
bookkeeping doesn't depend on its module keys happening to match a real runId.

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
(Threat Model/Remediation) don't render a live tool/token/file counter or a parsed
activity feed while running — `handleServerMessage()` in `index.html` still only acts on
`done`/`error` for the Timeline row and (if that finding's detail page happens to be open) the
Agent runs section, via `refreshFindingAfterRun()` → `updateFindingListItem()`. `startStage()`
does push one optimistic "running" placeholder into the finding's cached `runs` array so the
detail page shows the run as in-progress immediately rather than staying blank until it
finishes, but there's still no token-by-token or tool-by-tool *stats* feed — showing every
tool call/result plus raw stream-json by default was tried once already and read as noise
rather than the two things an AppSec tester actually wants: what was found, and why (normally
surfaced only once, in the finished verdict). Scan cards on the Reasoning Scan/SCA Scan pages
have the same *shape* of live feed (severity chip row + scrolling live-findings list via
`trackScanCandidates()`/`SEV_TAG_RE`), fed from different sources depending on the scan.
SCA Scan and Reasoning Scan's deterministic half have no LLM narrating `[severity] ...` lines
(that was `agents/scan.md`'s whole job, back when a scan was purely a `claude -p` call) — for
these, `server.js`'s `runDeterministicPatternScan()`/`runDeterministicScaScan()` synthesize an
assistant-text-shaped `scan-event` per completed agent/audit result, carrying that same
`[severity] message` line format, purely so `trackScanCandidates()` keeps working unmodified.
Reasoning Scan's *reasoning* half (`runLLMReasoningScan()`) is real `claude -p` calls again —
`agents/scan.md` still exists and still narrates real `[severity]` lines as it reasons, exactly
as it always did, just now once per module on a "full" scope scan instead of once for the whole
directory (see the Reasoning Scan bullet above); those events interleave with the deterministic
half's synthetic ones — and with each other, across every concurrently-running module — in
whatever order each side produces them, and the client can't tell (or need to tell) the
difference. Tool/token counters on a Reasoning Scan card during a live run reflect only the
reasoning half's real activity (the deterministic half has none to report); an SCA Scan card's
counters stay at zero throughout, since nothing behind it is an LLM call.

What *is* available everywhere, opt-in: a small terminal-icon **console toggle button**
(`consoleToggleButtonHtml()`/`consolePanelHtml()` in `index.html`) next to every live run —
Reasoning/SCA scan cards, App Threat Model rows, Control Scan rows, and Finding Detail's
per-finding run cards. Clicking it reveals a `<pre class="console-panel">` streaming the
model's raw narrated prose (assistant text blocks only, not tool calls/inputs/outputs — the
same noise tradeoff above, just made opt-in instead of removed outright) as it arrives, via
the shared `trackConsoleText()` appending onto each run's `consoleText` buffer and, if the
panel is currently attached to the DOM, directly onto it too. On an SCA Scan card, or the
deterministic-only findings within a Reasoning Scan card, this shows the same synthesized
`[severity] message` lines already visible in the live-findings list above it (there's no
separate LLM prose to distinguish it from) — a little redundant there, but harmless; on a
Reasoning Scan card it also carries the reasoning half's real narrated prose, same as any other
`claude -p` stage. This is deliberately **live-only,
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
produced them. `agents/remediation.md` is now the canonical source for these definitions
(it used to point to `agents/triage.md`, which is deleted — Triage is no longer a live agent
at all, see the Reasoning Scan bullet above); `threat_model.md` and `verify.md` both point to
`remediation.md` instead. OWASP/ASVS/CWE/NIST 800-53 framework mapping (`owasp`, `asvs`,
`cwe`, `nist_800_53`) is required (not optional) whenever an agent's verdict
is `confirmed` or `needs_review` — this program runs under FedRAMP
Moderate/High and FISMA, and the mapping feeds compliance reporting downstream (surfaced
today in each finding's detail page and in `GET /api/findings/export.csv`). `threat_model.md`
reuses the taxonomy as-is; `remediation.md` (the canonical definition) assigns it itself when
there's no prior verdict to carry forward — see "Pipeline shape" above — and both only add
stage-specific fields on top
(`preconditions`/`attack_narrative`/`blast_radius` for threat_model;
`root_cause`/`fix_guidance`/`corrected_code`/`edit_plan`/`verification_steps`/`effort` for
remediation — `corrected_code` is `null` unless the finding's context included a `code`
snippet and the fix is a meaningful drop-in replacement; `edit_plan` is `null` unless
remediation is running in apply mode and confident in an exact edit, see "Progressing the
loop" above; see the `remediation_generated` status bullet above for `corrected_code`).

**A known gap, partially closed by the reasoning-pass half**: sast-engine's *deterministic*
findings (`findingFromSastEngine()` in `server.js`) carry `owasp`/`cwe` directly from whichever
pattern matched, but **`asvs` and `nist_800_53` are always `null`** for these — sast-engine has
no ASVS or NIST 800-53 mapping data at all, and that used to be Triage's job specifically.
Reasoning Scan's *other* half doesn't have this gap: `agents/scan.md`'s findings
(`findingFromLLMScan()`) come with real `asvs`/`nist_800_53` mapping already, since the same LLM
pass that found the issue also assigns its full taxonomy in one call (see the Reasoning Scan
bullet above). So in practice: a finding from the deterministic half sits with incomplete
framework mapping until a later Remediation/Threat-Model pass fills it in (`remediation.md` will
still try, per "check your context before you start" — see below); a finding from the reasoning
half already has it. This is a known, accepted asymmetry rather than something hidden — not yet
resolved with, say, a static ASVS/CWE→NIST-control lookup table for the deterministic half,
which would be the natural next step if closing that specific gap (as opposed to relying on the
reasoning half to cover it) becomes worth doing.

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
application code (see the Control Scan bullet above). `verify.md` also breaks from the
Triage-derived taxonomy on purpose: its `verdict` field uses its own vocabulary
(`verified_fixed | still_vulnerable | partially_fixed | inconclusive`), not
`confirmed`/`needs_review`/`false_positive`/`duplicate`, because it isn't re-litigating whether
the finding is real — that was already decided upstream — only whether it's still open. It
keeps `confidence` (reusing Triage's scale, see the Verify bullet above) but has no
`priority`/framework-mapping fields at all, since it's not re-triaging.

**Security posture**: this is a local single-user dev tool. No auth on the
WebSocket or REST endpoints; `--permission-mode acceptEdits` and `--allowedTools`
("Read,Grep" for per-finding agents by default, "Read,Grep,Glob" for app-level threat models,
control assessments, Remediation's apply mode, and — only when a `path` was resolved — Verify
runs too) are set loosely for a fast test loop, not for anything beyond localhost use. Both
`agent` names and `runId`s from client messages are validated against `^[a-zA-Z0-9_-]+$` before
being used (agent name is joined into a filesystem path) — don't relax either when adding
features. App-level threat models and control assessments are a deliberate widening of that
posture: both spawn `claude` with `cwd` set to **any directory path the client sends**, gated
only by "does this path exist and is it a directory" (`fs.statSync` in
`handleAppThreatModelMessage` / `handleControlsAssistMessage`) — there's no allowlist of
scannable roots. Reasoning Scan and SCA Scan widen the same posture without spawning `claude`
at all now: `orchestrator.runAll()` reads arbitrary files under the client-supplied path
directly via Node's own `fs`, and `runDepsAudit()` shells out to whatever package-manager audit
command it auto-detects (`npm audit`, `pip-audit`, etc.) with that path as `cwd` — same trust
boundary, different mechanism. The generic per-finding `run` handler accepts the same kind of
client-supplied `path` for the same reason (see the Verify bullet above) — the client only ever
populates it from a finding's own recorded scan path, never from arbitrary user input, but the
server applies the identical "exists and is a directory" check and nothing more, so the trust
boundary is the same one the scan-family handlers already accept. That's consistent with "local
single-user tool trusted by its one user," not with exposing this app beyond localhost; don't
add auth-free network exposure without revisiting this.

**No agent in this app gets `Edit`/`Write` tools anymore** — this changed from the app's
earlier design, where the write-capable Remediation stage was explicitly the one exception.
Remediation's apply mode (`remediate_apply`, fired one step at a time by the loop cell's advance
button, or chained via `remediate_all`) now runs fully read-only (`Read,Grep,Glob`) and instead
proposes an `edit_plan` in its verdict — a structured list of exact `find`/`replace` strings
(see `agents/remediation.md`'s output contract). `applyRemediationPlan()` in `server.js` is what
actually reaches disk: it calls `sast-engine/remediation-apply.js`'s `validatePlan()` (the
`find` string must match the real file exactly once — or via a whitespace-tolerant fallback —
and the path must not be a protected one like `.env`/lockfiles/`node_modules`) before
`applyPlan()` writes anything, so a proposed edit that doesn't cleanly match the live file (it
drifted, or the model hallucinated it) is rejected rather than corrupting the file or falling
back to a fuzzier match. This is a strictly higher-trust posture than giving the model direct
tool access: the model can *describe* a change but never *execute* one against the filesystem
itself. The one remaining guardrail carried over from before: `checkCleanGitTarget()` refuses to
run unless `git status --porcelain` against the target directory comes back both git-tracked
and clean, so every edit that does land is trivially inspectable (`git diff`, surfaced back to
the user automatically) and revertible (`git checkout`) entirely outside this app — that check
happens once, before the stage starts, and doesn't prevent a validated multi-file plan from
touching more of the tree than the one file the finding named, the same way nothing stops
Remediation from proposing an incorrect fix. Treat this as the highest-trust action in the app:
same "local single-user tool" posture as the rest of it, just with real consequences if the
target directory isn't what the user thinks it is.

**Not yet built**: disk persistence (both the findings store and the scans store are
in-memory and reset on restart — there's no SQLite/JSON-file layer yet), CSV *ingestion*
(export exists — `GET /api/findings/export.csv` — but importing an external scanner's CSV
to seed findings, the original `findings-dashboard.jsx` workflow, does not), the
dashboard merge itself (`findings-dashboard.jsx`'s Azure DevOps ticket creation currently
does a browser-side `fetch()` that's expected to hit CORS — if that logic moves into this
app, it should move server-side, where Node has no CORS problem), and the **Reports** screen
(currently a bare placeholder — no data, no server endpoint, see the Reports bullet above).

**Reasoning-engine hardening, phase 1 of several**: module-scoped scanning, size-aware
splitting/merging, a cross-cutting pass for wiring gaps, and honest budget/cost/failure
reporting (see the Reasoning Scan bullet above) are the first phase of a larger design discussed
with the user for reducing hallucination and token-cost risk on large codebases — all shipped
and empirically verified, including catching and fixing two real bugs the first pass introduced
(a splitting algorithm that silently failed to split a repo with only one top-level directory,
and a partial-failure summary that was itself being silently discarded by the same client-side
code path that discards raw CLI stderr chatter). Not yet built: bounded-context triage of
deterministic findings (re-verify a sast-engine finding VerifierAgent couldn't confirm, using a
grep-based blast radius of the finding's function + likely callers rather than a real call-graph
index — this app has no symbol/AST infrastructure at all); self-consistency voting (run a
discovery-mode task 2-3 times, surface only findings that repeat, as a cheap hallucination
filter before acting on a finding); stricter citation enforcement (reject/downgrade a finding
that doesn't cite a real, verifiable file:line — today `extractVerdict()` just parses whatever
JSON comes back with no validation against the actual file); real per-endpoint route enumeration
for a finer-grained discovery scope than the current file-count-based module split (`ReconAgent`'s
existing `apiRoutes` is only a file-level heuristic, not real endpoint+method extraction); a
token-spend budget/kill-switch surfaced per finding rather than only as a per-call CLI-level cap;
and a "promote to pattern" UI action for feeding a repeated reasoning-mode finding back into
sast-engine as a new deterministic rule.
