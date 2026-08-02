/**
 * Shape definitions for the records that move through the app.
 * ============================================================
 *
 * Documentation only — this module exports nothing and is never required at runtime. It exists
 * because the two central records are plain object literals with no schema anywhere, and reading
 * a chain like `f.stageRuns.triage.verdict.source` gives no way to know whether any link in it is
 * optional. Editors surface these via JSDoc `@typedef`, so `@param {Finding}` on a function is
 * enough to get completion and a red squiggle on a typo.
 *
 * Keep in sync with the code that actually builds these:
 *   Finding  ->  src/store/findings/factories.js  (baseFinding + the three factories)
 *   Run      ->  src/services/claude.js           (runRecord in spawnAgentStage)
 *   Scan     ->  src/store/scans.js               (toScanListItem is the authoritative shape)
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
 * @property {string} [sourceScanId] the scan that produced it; DANGLING if that scan was deleted,
 *                                   which costs the finding its Fix and live-Verify ability
 * @property {Run[]} runs            oldest first; the last entry is what the next stage chains from
 * @property {number} createdAt      epoch ms
 */

/**
 * One scan invocation. Not a pipeline, so unlike a Finding it has no `runs` chain.
 *
 * Two fields are deliberately kept OFF the list-item shape and live only on the in-memory record:
 * `moduleRunIds` (cancel bookkeeping) and `surface` (the full attack-surface manifest, large,
 * fetched on demand via GET /api/scans/:id/surface).
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
 * @property {number} [agentsRun]      pattern agents this target warranted
 * @property {string[]} agentsSkipped  names gated out by shouldRun(recon) — part of what the
 *                                     scan did NOT cover, so it is persisted, not just relayed
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
