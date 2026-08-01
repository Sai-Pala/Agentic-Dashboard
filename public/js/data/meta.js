/**
 * Static metadata tables
 * ======================
 *
 * The vocabularies the UI renders against: agent identities and their icons/blurbs, severity
 * and status orderings, column configurations, and the field lists that decide how a verdict
 * object is displayed. All frozen data plus one lookup helper — no DOM, no app state, no
 * imports, so this is a leaf every view can depend on without creating a cycle.
 *
 * Moved verbatim out of the single inline <script> during the Phase 4 split.
 */

// 'triage' deliberately excluded — agents/triage.md no longer exists (Triage is a synthetic
// verdict now, not a live agent stage, see CLAUDE.md), so GET /api/agents can never return it;
// including it here permanently capped knownAgentsAvailableCount() at 3/4 on a healthy install.
export const KNOWN_AGENTS = ['threat_model', 'remediation', 'verify'];

// Kind is differentiated by icon + label text only, not hue — color in this app is reserved
// for real signal (severity, running/done/error state), not decorative category-tagging.
export const AGENT_META = {
  scan: { label: 'Scan', icon: 'radar', color: 'var(--text-dim)', role: 'Reads a directory and creates findings' },
  triage: { label: 'Triage', icon: 'search', color: 'var(--text-dim)', role: 'First pass: real finding or noise, how urgent' },
  threat_model: { label: 'Threat Model', icon: 'target', color: 'var(--text-dim)', role: 'Exploit path, preconditions, blast radius' },
  remediation: { label: 'Remediate', icon: 'wrench', color: 'var(--text-dim)', role: 'Proposes a fix for review — writes nothing' },
  fix: { label: 'Fix', icon: 'edit', color: 'var(--text-dim)', role: 'Writes the proposed fix directly to your code' },
  verify: { label: 'Verify', icon: 'checkCircle', color: 'var(--text-dim)', role: 'Re-checks the live code to confirm a fix actually landed' },
  app_threat_model: { label: 'App Threat Model', icon: 'shield', color: 'var(--text-dim)', role: 'Whole-app architecture-level threat model' },
  controls_assist: { label: 'Control Scan', icon: 'clipboard', color: 'var(--text-dim)', role: 'Whole-app NIST 800-53 control identification for SSP drafting' },
};

export function agentMeta(name) {
  return AGENT_META[name] || { label: name, icon: 'gear', color: 'var(--muted)', role: '' };
}

// 'reasoning' replaced the old separate 'sast'/'dast' entries — both were just this same LLM
// reading source and reasoning about it, so calling them distinct scanner categories was
// misleading. SCA stays distinct on a per-FINDING basis — Agent Triage's type tabs/columns and
// this chip still tell a dependency finding apart from a code finding — even though there's no
// longer a separate SCA Scan page to kick one off from; a dependency audit now always runs
// alongside pattern-matching and reasoning as part of a single Hybrid Scan (see the Reasoning
// Scan bullet in CLAUDE.md), so every scan RECORD's own scanType is always 'reasoning' now —
// only individual findings still carry 'sca'.
export const SCAN_TYPE_META = {
  reasoning: { label: 'Hybrid Scan', icon: 'search', color: 'var(--text-dim)', caption: 'LLM reasoning pass over source — vulnerability patterns and attack surface, no live target is hit' },
  sca: { label: 'SCA', icon: 'package', color: 'var(--text-dim)', caption: 'Dependency manifests & lockfiles for known-vulnerable packages' },
};

export const SEV_VAR = { critical: 'var(--crit)', high: 'var(--err)', medium: 'var(--warn)', low: 'var(--ok)', informational: 'var(--muted)' };

export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

export const SEV_ORDER_MAP = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

export const STATUS_ORDER_MAP = { new: 0, in_review: 1, remediation_ready: 2, remediation_generated: 3, closed: 4, verified_fixed: 5 };

export const FINDINGS_TYPE_LABEL = { all: 'All', reasoning: 'Hybrid', sca: 'SCA' };

export const APPLICABILITY_LABELS = {
  app_addressed: 'App addressed', partially_addressed: 'Partially addressed',
  inherited: 'Inherited', not_applicable: 'Not applicable',
};

export const IMPLEMENTATION_STATUS_LABELS = {
  implemented: 'Implemented', partially_implemented: 'Partially implemented',
  planned: 'Planned', not_applicable: 'Not applicable',
};

export const HEATMAP_SEVERITY_COLS = ['critical', 'high', 'medium', 'low', 'informational'];

export const VERDICT_BADGE_FIELDS = ['verdict', 'severity_confirmed', 'confidence', 'priority'];

// corrected_code and edit_plan get their own dedicated renderers (a syntax-highlighted code
// block, and a diff-style preview respectively — see runCardHtml()) instead of the generic
// key/value grid every other field falls into, since dumping a multi-line code string or a
// nested {summary,risk,files:[...]} object through String() there produced unreadable output
// (a wrapped code paragraph with no monospacing, and literally "[object Object]").
export const VERDICT_SKIP_FIELDS = new Set([...VERDICT_BADGE_FIELDS, 'reasoning', 'next_agent', 'applied_diff', 'corrected_code', 'edit_plan']);

// Triage/Remediation/Verify each have their own dedicated control now — the Remediation Loop
// column's step arrow and "run all stages" button (see findingLoopCellHtml()) — so this menu no
// longer lists them; it's just Threat Model (a separate, optional deep-dive that deliberately
// doesn't sit on that path — see CLAUDE.md's Pipeline shape) plus whatever custom agents exist.
export const FIX_FLOW_AGENTS = ['triage', 'remediation', 'fix', 'verify'];

// SCA findings additionally lose Threat Model too — none of the four per-finding code-analysis
// agents apply to a dependency version bump (already named in the Package/Fixed-in columns), so
// nothing in FIX_FLOW_AGENTS or Threat Model is offered, leaving only custom agents (if any).
export const SCA_EXCLUDED_AGENTS = [...FIX_FLOW_AGENTS, 'threat_model'];
