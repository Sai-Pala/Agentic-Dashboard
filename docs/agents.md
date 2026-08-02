# Agents

`prompts/*.md` are system prompts, passed to `claude -p` via `--append-system-prompt`. Plain
markdown, no code. **This is the only place agent-specific analysis logic lives.**

| File | Role | Invoked by |
|---|---|---|
| `scan.md` | the reasoning review pass over the enumerated attack surface | `handleScanMessage` |
| `adjudicate.md` | reviews the deterministic engine's findings, removes false positives | `handleScanMessage` |
| `remediation.md` | proposes a fix for one finding | the generic per-finding `run` path |
| `verify.md` | re-checks whether a fix held | the generic per-finding `run` path |

`scan.md` and `adjudicate.md` are in `NON_FINDING_AGENTS` — they operate on a whole scan, not one
finding, so they are filtered out of `GET /api/agents` and never appear as a stage a user can
start. `GET /api/agents?all=1` is the unfiltered variant.

Two synthetic agents have **no `.md` file** but do appear as `agent` values on `finding.runs`:
`triage` (synthesized at finding creation) and `fix` (deterministic apply, no LLM call). See the
pipeline table in CLAUDE.md.

Adding a new per-finding agent is just adding the `.md` file — no server change needed. The one
exception is an agent that needs live-codebase access, which requires the client to send a `path`
on its `run` message; that plumbing is generic, not specific to `verify.md`.

## Invocation

The generic per-finding path spawns:

```
claude -p "<instruction>\n\nFinding context:\n<context>"
  --append-system-prompt "<agent .md contents>"
  --output-format stream-json --verbose
  --allowedTools "Read,Grep"
  --permission-mode acceptEdits
```

with `cwd` = the app's own directory — **unless** a valid `path` was supplied, in which case
`cwd` becomes that directory and `--allowedTools` becomes `Read,Grep,Glob`.

`scan.md` and `adjudicate.md` go through their own path instead, because they need a different
tool set, a different `cwd` (the target directory), and a different output shape (`scan.md`
returns `{"findings": [...]}`, not a single verdict object).

Each parsed stdout line is relayed immediately as `{type: "event", runId, findingId, event}` —
this is the "live" part. On exit the server extracts the verdict and sends `done`.

### Why `claude -p` and not the Messages API

`--output-format stream-json` already emits structured events (assistant text, tool calls, final
result) with no custom parser needed, and the agents already existed as `.md` prompt files used
manually in a terminal. This automates that same invocation rather than replacing it.

## Verify is different on purpose

Remediation reasons over the finding's already-captured `code` snippet. **Verify's whole point is
to re-check the *current* state of the real target codebase**, which requires a different `cwd`.

The client resolves that from the finding's `sourceScanId` (`findingSourcePath()`) and sends it
as an optional `path`. `Glob` is added because Verify may need to *relocate* a file, not just
re-read one at a known path.

A finding with no `sourceScanId` (manually added, or whose scan was deleted) falls back to the
app's own directory, which for Verify's purposes is effectively no live access. `verify.md` is
written to recognise that — sanity-check whether what it read plausibly matches the finding at
all, and return `inconclusive` rather than reasoning over an unrelated repository.

## The verdict contract

Every agent's `.md` ends with an instruction to close its response with **exactly one fenced JSON
block**. The server does not validate or enforce a schema — `extractVerdict()` regexes for the
first ` ```json ` block (case-insensitively) and parses it.

The client renders any verdict object **generically**, iterating key/value pairs and badging a
fixed set of known fields (`verdict`, `severity_confirmed`, `confidence`, `priority`). So a
schema change in an agent's `.md` needs no frontend change unless new behaviour should key off a
new field specifically — `deriveStatus()` keys off `verdict`/`next_agent`.

Generic fields render as a single-column row stack, not a multi-column grid. This contract has to
render arbitrary future fields and cannot assume they are short: `fix_guidance` and
`attack_narrative` are paragraphs, and a 200px auto-fill column mangled them.

## Taxonomy

Severity / confidence / priority definitions live **inside each agent's `.md` and must stay
byte-identical across agents** — copy, do not redefine. They match the org's existing
`owasp-code-review` Claude skill so findings read consistently whether a human or an agent
produced them.

`prompts/remediation.md` is the canonical source. `verify.md` points to it.

**Framework mapping (`owasp`, `asvs`, `cwe`, `nist_800_53`) is required, not optional**, whenever
a verdict is `confirmed` or `needs_review` — this program runs under FedRAMP Moderate/High and
FISMA, and the mapping feeds compliance reporting downstream (surfaced in each finding's detail
page and in `GET /api/findings/export.csv`).

Stage-specific fields on top of the shared taxonomy:

- `remediation.md` — `root_cause`, `fix_guidance`, `corrected_code`, `edit_plan`,
  `verification_steps`, `effort`
- `verify.md` — no `priority` or framework fields at all; it is not re-triaging

`verify.md` breaks from the shared vocabulary deliberately: its `verdict` is `verified_fixed |
still_vulnerable | partially_fixed | inconclusive`, because it is not re-litigating whether the
finding is real — that was decided upstream — only whether it is still open. It keeps
`confidence` on the shared scale.

## Known gap: incomplete mapping on deterministic findings

Deterministic findings carry `owasp`/`cwe` directly from the matched pattern, but **`asvs` is
always `null` and `nist_800_53` is always `[]`** — sast-engine has no ASVS or NIST mapping data,
and filling it in used to be Triage's job specifically.

Reasoning-pass findings do not have this gap: the same LLM pass that found the issue assigns the
full taxonomy in one call.

So a deterministic finding sits with incomplete mapping until a later Remediation pass fills it
in; a reasoning finding already has it. This is a known, accepted asymmetry. The natural fix, if
it becomes worth closing, is a static ASVS/CWE→NIST lookup table for the deterministic half.

## The two write-adjacent contracts

`remediation.md` produces two optional fields that drive real behaviour:

- **`corrected_code`** — the full corrected version of the finding's `code` snippet, not just
  prose. `null` when there's no snippet to correct or the fix is architectural. Its presence
  (with a `confirmed`/`needs_review` verdict) is what derives the `remediation_generated` status.
- **`edit_plan`** — a structured list of exact `find`/`replace` strings. `null` unless the model
  is confident in an exact edit. Declining to guess is a legitimate outcome, explicitly
  sanctioned by the prompt; the loop renders it as "No fix proposed" rather than an error.

`edit_plan` is what the deterministic Fix stage applies. Before writing,
`sast-engine/remediation-apply.js` validates it: the `find` string must match the real file
**exactly once** (with a whitespace-tolerant fallback), and protected paths (`.env`, lockfiles,
`node_modules`) are refused outright. A plan that no longer cleanly matches the live file — it
drifted since Remediate ran, or the model hallucinated it — is **rejected rather than applied
fuzzily**, and the run is marked `error` so it doesn't sit looking identical to "no fix needed
yet".

## Remediate must stand on its own

Triage is not a live agent, so in the normal case `remediation.md` receives a finding that
already carries a triage verdict. But it still has to handle the case where one is missing — see
the "check your context before you start" section at the top of that file. If there is no prior
verdict in its context, it does the confirm/severity/framework-mapping assessment itself before
writing fix guidance.
