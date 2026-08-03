/**
 * Shape definitions for the records that move through the app.
 *
 * Documentation only — this module exports nothing and is never required at runtime. It exists
 * because the central records are plain object literals with no schema anywhere, and reading a
 * chain like `f.stageRuns.triage.verdict.source` gives no way to know whether any link in it is
 * optional. Editors surface these via JSDoc `@typedef`, so `@param {Finding}` is enough to get
 * completion and a red squiggle on a typo.
 *
 * Nothing enforces these. Keep them in sync with the code that actually builds the records:
 *   Finding          src/store/findings/factories.js  (baseFinding + the three factories)
 *   Disposition      src/store/findings/factories.js  (buildDisposition)
 *   FindingListItem  src/store/findings/list-item.js  (toListItem)
 *   Run              src/services/claude.js           (runRecord in spawnAgentStage)
 *   Scan             src/store/scans.js               (toScanListItem) + the scan-only fields
 *                                                     written by services/scanner.js
 *
 * `null` and `undefined` are meaningfully different here and the annotations say which: a field
 * typed `string|null` is always present and may be empty; an optional field is marked `[name]`
 * and may be absent entirely.
 */

/**
 * One agent invocation against one finding. Appended to `finding.runs`, never replaced — the
 * array IS the pipeline history, and chaining works by reading the most recent entry.
 *
 * @typedef {object} Run
 * @property {string} runId      client-generated, validated against RUN_ID_RE before any use
 * @property {string} agent      'triage' | 'remediation' | 'fix' | 'verify' | a prompts/*.md name
 * @property {'running'|'done'|'error'|'cancelled'} status
 * @property {object|null} verdict   parsed JSON from the agent; null while running or on error
 * @property {string} [fullText]     raw transcript; cleared on the wire to keep frames small
 * @property {string} [instruction]  the human's free-text instruction, if any
 * @property {string} [context]      the prompt the agent actually received
 * @property {number} startedAt      epoch ms
 * @property {number|null} finishedAt
 */

/**
 * What the app did to a finding after the engine emitted it. Null whenever nothing happened,
 * which is the common case — so every consumer must guard before reading into it.
 *
 * @typedef {object} Disposition
 * @property {string} [severityFrom]       severity as the engine matched it
 * @property {string} [severityTo]         severity after adjudication
 * @property {'up'|'down'} [severityDirection]
 * @property {string} [severityChangedBy]  which pass rewrote it
 * @property {boolean} [severityApplied]   whether the ROW shows the new severity. True for the
 *                                         adjudicator; false for the reasoning pass's
 *                                         `severity_confirmed`, which sits in the verdict beside
 *                                         a `severity` that still disagrees with it
 * @property {'false_positive'|'duplicate'} [closedAs]
 * @property {string} [closedBy]
 * @property {boolean} [corroborated]      both engines independently flagged this location
 * @property {number} [collapsed]          sibling hits of the same rule folded into this row
 */

/**
 * A security finding. Created by one of three factories and then owned by the findings Map for
 * the lifetime of the process.
 *
 * Engine-specific fields are always present and default to null rather than being omitted, so
 * consumers can read `finding.packageName` on a reasoning finding without a guard.
 *
 * @typedef {object} Finding
 * @property {string} id
 * @property {string} title
 * @property {string} description
 * @property {'critical'|'high'|'medium'|'low'|'informational'} severity
 * @property {'new'|'in_review'|'closed'} status  derived from runs — see store/findings/status.js
 * @property {'reasoning'|'sca'} scanType
 * @property {string|null} rule      rule id or CWE; null for a manually added finding
 * @property {string|null} file      repo-relative, forward-slash, optionally `path:line`
 * @property {string|null} code      captured snippet
 * @property {object|null} flow      taint path: `{sourceLine, sinkLine, lines: [{n, text}]}`
 * @property {string|null} endpoint
 * @property {string|null} method
 * @property {string|null} packageName     SCA only
 * @property {string|null} packageVersion  SCA only
 * @property {string|null} fixedVersion    SCA only
 * @property {Disposition|null} disposition
 * @property {string} [sourceScanId] the scan that produced it; DANGLING if that scan was deleted,
 *                                   which costs the finding its Fix and live-Verify ability
 * @property {Run[]} runs            oldest first; the last entry is what the next stage chains from
 * @property {number} createdAt      epoch ms
 */

/**
 * The lighter shape every list view receives. Not a Finding: `runs` is replaced by counts and by
 * `stageRuns`, the per-stage lookup the client reads instead of walking the history itself.
 *
 * @typedef {object} FindingListItem
 * @property {number} runCount
 * @property {{agent: string, status: string, verdict: object|null}|null} latestRun
 * @property {{triage: Run|null, remediation: Run|null, fix: Run|null, verify: Run|null}} stageRuns
 * @property {Disposition|null} disposition
 */

/**
 * One scan invocation. Not a pipeline, so unlike a Finding it has no `runs` chain.
 *
 * Everything up to `agentsSkipped` is on the wire shape (`toScanListItem`). Everything after it
 * lives only on the in-memory record: too large for a list fetched by nearly every view, or
 * internal bookkeeping. `surface` has its own endpoint, GET /api/scans/:id/surface.
 *
 * @typedef {object} Scan
 * @property {string} id
 * @property {string} runId
 * @property {string} path            the target directory as the client sent it
 * @property {string} instruction
 * @property {string|null} branch
 * @property {string|null} app
 * @property {'reasoning'} scanType   scan RECORDS are all hybrid; findings are a separate axis
 * @property {'full'|'diff'} scope
 * @property {string|null} baseBranch
 * @property {number|null} diffFileCount
 * @property {'running'|'done'|'error'|'cancelled'} status
 * @property {string|null} error
 * @property {string[]} findingIds
 * @property {number} startedAt
 * @property {number|null} finishedAt
 * @property {boolean} budgetEnabled
 * @property {number} [reasoningCostUsd]
 * `agentsRun`, `agentsSkipped` and `agentsFailed` are DORMANT alongside the three at the bottom:
 * all six are written only by engines/deterministic.js, so no scan the app currently produces
 * carries them. The first two are still on the wire shape, where they read as a scan that ran
 * zero agents rather than as a scan from an engine that has none.
 * @property {number} [agentsRun]      pattern agents this target warranted
 * @property {string[]} agentsSkipped  names gated out by shouldRun(recon) — part of what the
 *                                     scan did NOT cover, so it is persisted, not just relayed
 * @property {string[]} [agentsFailed]  "Name (reason)" per agent that errored or timed out
 *
 * @property {object} [coverage]        what the scan read and what it dropped, and why —
 *                                      `{root, considered, scanned, dropped, prunedDirs,
 *                                        prunedDirCount, ignoreFiles}`, or `{error}`
 * @property {object} [dispositions]    tally of every decision the merge made on the user's
 *                                      behalf — collapsed, merged, closed, re-severitied
 * @property {object} [reviewCoverage]  what the reasoning pass reviewed and what it skipped —
 *                                      `{totalRoutes, reviewedRoutes, skippedRoutes, shards,
 *                                        adjudicated, adjudicable, shardFiles, unreviewedFiles}`
 * @property {object} [surface]         full attack-surface manifest; large, own endpoint
 * @property {string[]} [moduleRunIds]  synthetic child keys, so cancel can kill every in-flight
 *                                      reasoning call and not just one
 *
 * The three below are written only by the DORMANT engines/deterministic.js — absent on every
 * scan the app currently produces. See that file before relying on them.
 * @property {object[]} [agentRoster]
 * @property {object} [engineRecon]
 * @property {object} [suppression]
 */

/**
 * What an agent returns. Only `verdict` is contractually required; the rest vary by agent and
 * are documented in docs/agents.md.
 *
 * @typedef {object} Verdict
 * @property {string} verdict            the agent's conclusion, e.g. 'confirmed' | 'false_positive'
 * @property {string} [reasoning]
 * @property {string} [source]           which engine produced the original finding
 * @property {object} [edit_plan]        Remediate only — what Fix will apply, `{files: [...]}`
 * @property {string} [fix_guidance]
 * @property {string} [corrected_code]
 */

module.exports = {};
