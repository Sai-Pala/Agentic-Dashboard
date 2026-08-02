# The client

`public/` is served as-is. No bundler, no build step — the client is native ES modules loaded via
a single `<script type="module" src="/js/app.js">`. Keep it that way.

```
public/
  index.html          markup only (386 lines)
  app.css             all styles (693 lines)
  js/
    package.json      {"type":"module"} — lets Node import these files in tests
    app.js            views, wiring, WebSocket handling, and the mutable state
    data/meta.js      AGENT_META, severity/status order maps, label tables
    ui/icons.js       hand-drawn inline SVG — no icon library
    ui/highlight.js   hand-rolled regex tokenizer — no highlighting library
    util/format.js    pure formatters (Node-importable, no DOM)
    util/html.js      escapeHtml / formatInlineText (DOM-touching)
    views/surface-guards.js   guard classification for the Attack Surface page
```

The no-external-dependency aesthetic is deliberate and consistent: hand-drawn icons, a
hand-rolled syntax highlighter, and hand-rolled `+`/`-`/`@@` diff colouring rather than a diff
library.

`util/format.js` is kept free of DOM access specifically so the test suite can import it
directly. Anything DOM-touching goes in `util/html.js` instead.

## Views

Global left nav, ordered to mirror the finding pipeline, with the theme toggle and Settings in
the nav footer rather than the main list.

| View | What it is |
|---|---|
| **Dashboard** | briefing banner, two quick-action cards, stat tiles, and a plain (non-clickable) agents panel listing every per-finding agent |
| **Hybrid Scan** | the scan kickoff form plus live scan cards |
| **Agent Triage** | a sortable findings table, split into All / Hybrid / SCA type tabs |
| **Finding Detail** | full-page per-finding view — not a modal or side panel |
| **Attack Surface** | a read-only render of one scan's enumerated manifest |
| **Reports** | placeholder — no data, no endpoint |
| **Settings** | environment disclosure + a "Clear session" danger zone |

**Timeline is deliberately not a nav item.** A dedicated tab read as one more place to check for
"what's happening", competing with the nav badges that already answer that contextually. It's a
slide-in drawer opened by a clock button in the Hybrid Scan header and by the Dashboard's "View
timeline" quick action, each pre-scoping the shared list to its own activity. Escape and a
backdrop click both close it, folded into the existing document-level handlers rather than adding
new listeners.

Finding Detail is a **full page** because earlier attempts at a right-docked panel and at
in-card expansion both failed the same way: the code block and verdict history need room to be
readable.

## Nav badges

`renderNavBadges()` drives two: **Hybrid Scan** shows a pulsing dot while any scan is running;
**Agent Triage** shows a red count pill of findings whose `status !== 'closed'`.

When the sidebar is collapsed, both collapse to the same 8×8 corner dot (`font-size: 0`, count
still readable from the `title` tooltip). Without that override the wider count pill overlaps the
nav icon instead of sitting in its corner.

## The Remediation Loop

The Agent Triage table's Loop column is a **pure read-only status readout** — four tiny dots
(Triaged / Remediated / Fixed / Verified) above a one-line label. No buttons. Advancing happens
entirely on Finding Detail.

State is derived by `findingLoopState()` from `findingStageRuns()`, which needs **each stage's
own latest run independently**, not just the single overall latest. A list-item finding carries
that precomputed server-side as `.stageRuns`; a full cached finding only has the raw `.runs`
array, so `findingStageRuns()` derives the same shape when `.stageRuns` is absent.

Three state distinctions are load-bearing:

- **"Remediated" is done the moment a `remediation` run completes**, whether or not it proposed
  an `edit_plan`. A proposal that declines to guess is still a completed proposal.
- **"Fixed" requires the latest `fix` run's verdict to carry a real `applied_diff`.** A completed
  `fix` run without one (a stale plan that no longer matches the file) reads as `attention`, not
  `done`. Showing "Fixed" and offering "Verify the fix" when nothing was written would be
  actively misleading.
- **`fixed === 'unavailable'`** is a distinct fourth state: Remediate finished and proposed
  nothing to apply. `findingLoopNextAction()` resolves it to `null` — there is nothing left to
  automate once Remediate has explicitly declined.

`findingLoopNextAction()` reduces the whole state to one next action. `verified === 'attention'`
maps back to `'remediate'`, not another `'verify'` — Verify already said the fix didn't hold, so
the actionable step is a fresh proposal. `fixed === 'attention'` maps back to `'remediate'` too,
since retrying the same stale apply would just fail again.

A `closed` finding shows neither track nor boxes — the loop doesn't apply to something dismissed
as not real. SCA findings get a plain status badge instead, since their fix is a version bump.

### Column width

The header reads **"Loop"**, not "Remediation Loop". Table cells clip overflowing text at the
cell boundary regardless of `overflow` CSS, so the fuller label silently truncated to
"REMEDIATION". The `<th>`/`<td>` carry `data-col="loop"` so CSS can cap the rendered width —
`table.findings-table` uses the browser's default auto layout, which would otherwise hand this
column any leftover row width even though four dots and a short label never need it.

## Progressing the loop

One entry point: Finding Detail's four boxes plus a "Run all stages" button. Only one box is ever
clickable — the pipeline is strictly linear, so `findingLoopNextAction()` always resolves to a
single next stage regardless of which box is clicked, and there is no independent per-stage click
logic to keep in sync.

Each box carries a fixed one-line caption ("Proposes a fix to review" / "Writes the fix to your
code") because icon + one-word status didn't make it obvious what clicking would do.

Confirmation is scoped to the stage that actually writes:

| Action | Confirms? | Why |
|---|---|---|
| Remediate | **no** | read-only, nothing to gate |
| Fix | yes | names the exact target directory and the clean-tree requirement |
| Verify | no | read-only |
| Run all stages | yes | Fix is unconditionally in the chain |

Both buttons disable themselves client-side the instant they're clicked, so a fast double-click
can't fire two real runs against the same directory. The next render replaces the node anyway, so
nothing needs to re-enable them.

The boxes are disabled when `findingSourcePath()` can't resolve a directory (a manually-added
finding has nowhere to write to). "Run all stages" is *always* gated on a known path.

There is **no diff popup**. `runCardHtml()` already renders any `fix` run's `applied_diff` as a
coloured diff block alongside its other verdict fields, so "see what changed" is just "look at
the finding". An earlier auto-popping modal was removed for redundancy and for a real accuracy
bug: it opened before a chained Verify had started, so its wording implied a confirmation that
hadn't happened yet.

## The header layout override

`#view-finding-detail .view-header { flex-direction: column; }` overrides the base row layout
every other page uses. On a title that wraps to two lines, four boxes squeezed into the leftover
row width read as cramped; giving the actions their own full-width row fixes it regardless of
title length.

## Live run tracking

Scan cards are created once by `startScan()` and updated through cached element refs. They are
**never rebuilt from `scansList`**, so a page reload loses them entirely — which is why the
timeline drawer's expanded scan row refetches `GET /api/scans/:id` and is the durable view of a
scan's agent-gating counts.

Finding Detail fully rebuilds its run cards on every render, so anything live there must survive
the rebuild. The pattern: persist the state on the tracking object, bake current counter values
directly into the fresh HTML string so a rebuild never visually resets progress, then re-query
and re-point the element refs afterward (`reattachConsoleRefs()`). Without that, every
stream-json event would wipe an open console panel back to empty.

**This reattach dance is a workaround for state having no owner, not a pattern to copy.** See
"Known weaknesses" below.

## The opt-in console

Every live run has a small terminal-icon toggle revealing a `<pre>` that streams the model's raw
narrated prose — assistant text blocks only, not tool calls or results. Showing everything by
default was tried and read as noise rather than the two things an AppSec tester wants: what was
found, and why.

It is deliberately **live-only, not replayable**: nothing extra is persisted server-side, so a
run's console exists only as long as its tracking object survives in the tab.

The toggle always calls `e.stopPropagation()`, since it sits inside a clickable row that would
otherwise fire its own handler.

## One-directional filter state

`findingsScanFilter` (a JS variable) is the single source of truth for the per-scan filter, read
fresh on every render rather than scraped back from the button's DOM text. An earlier version
used a native `<select>` and read `.value` back as a fallback, which silently discarded a
programmatically-set filter. **State flows JS → DOM, never the reverse.**

## Attack Surface: route-driven, not mount-driven

This distinction is load-bearing. The original version derived everything from mounts, which
broke on an app that registers routes directly on `app` with no `express.Router()` — a completely
ordinary Express style, and what this repo itself does. With no mounts, the unguarded count was
`0` and rendered green for an app whose 19 endpoints were *all* unauthenticated, while the same
scan flagged seven `Route Without Auth Check` findings. Routes were also only emitted nested
inside a mount row, so the tile said "19 Endpoints" and the page listed none.

**A security view stating the reassuring opposite of the truth is worse than one that says
nothing.** So:

- `ownerOf(r)` resolves a route's mount by filename substring — a display heuristic, not the
  engine's own resolution, so a route can be misattributed when two router filenames share a
  fragment.
- `routeKind(r)` classifies by the **effective** chain (owning mount's middleware + its own), so
  a bare route behind an authenticated mount counts as authenticated rather than unguarded.
- The risk tiles count **routes**, not mounts, so they read `0`/green only when that's actually
  true of the endpoints.
- Routes with no owning mount render in their own "Directly registered routes" panel — nothing is
  counted in a tile but missing from the page.

`guardKindOf()` classifies three ways: `none` (no middleware → red), `authn` (middleware present
but none matching a privilege vocabulary → amber "authenticated, not authorized"), `authz`
(green). That middle case is what the page exists to make visible. Unrecognised guard names
resolve to `none` — the safe direction.

This is a **deliberately separate, simpler implementation** from the engine's own predicate. It's
a display-time classification over an already-computed manifest, not a detection rule, so the two
are not kept in sync and this page can label a mount `authn` without a corresponding finding.

## Known weaknesses

Two, both known and both worth fixing before adding features here:

1. **`app.js` is still ~2,700 lines** and holds every view. The remaining split is blocked on
   the item below, since view modules would need to write shared state.
2. **20 module-level `let` bindings are the app's entire state model**, mutated in place from
   anywhere. **ES modules forbid assigning to an imported binding**, so these cannot simply be
   moved into a `state.js` and imported — they need a mutable container or setters. This is also
   the root cause of the three `reattach*` workarounds: state has no owner, so re-rendering
   destroys the DOM those bindings implicitly point at.
