# Engine Rework

Where the scan engine actually stands, measured rather than assumed, and what to do about it.

Written after the first end-to-end evaluation against an external codebase with a published
answer key. Every number here was produced by a real run; nothing is estimated. Where something
is a judgement rather than a measurement, it says so.

---

## 1. Why this document exists

The engine had never been scored. It produced findings, the findings looked plausible, and there
was no way to tell whether it was finding *most* of what was there or a convenient third of it.
"Some findings" and "good findings" are different things, and only a benchmark separates them.

Two earlier attempts to evaluate it failed for the same reason, and the failure is worth recording
so it is not repeated:

- **OWASP VulnerableApp** — a Java DAST benchmark carrying its answer key in-source as 157
  `@AttackVector` annotations. A static analyser cannot be fairly measured against a target whose
  vulnerable lines are labelled, and worse, an LLM reading those files is handed the answers.
- **A JVM route extractor was built off that invalid measurement** before the contamination was
  noticed. The work was stashed, not merged. The lesson: *validate the benchmark before building
  anything on its output.*

---

## 2. The measurement

### 2.1 Target

**DVNA** (Damn Vulnerable NodeJS Application, appsecco) — Express + Sequelize + EJS, 12 source
files, 19 vulnerabilities documented in `docs/solution/*.md`.

Chosen over the alternatives after a contamination check on all three:

| Candidate | Source files | Answer key | Verdict |
|---|---|---|---|
| OWASP Juice Shop | 392 | `// vuln-code-snippet vuln-line <challenge>` **on the vulnerable line** | Rejected — same trap as VulnerableApp |
| OWASP NodeGoat | 30 | `app/views/tutorial/*.html`, generic prose, no file pointers | Usable |
| **DVNA** | **12** | `docs/solution/*.md`, names exact files | **Chosen** |

DVNA won because its answer key is *separable* — it lives in a directory you delete before
scanning and keep for scoring afterwards. Juice Shop's markers cannot be separated from the code
they annotate.

### 2.2 Isolation performed

- `docs/` and `README.md` moved out of the tree before scanning
- `.sast-engineignore` added for `public/assets/` (minified vendor bundles),
  `views/vulnerabilities/` (37 OWASP write-ups), `views/learn.ejs`
- Shallow clone, so no fix commits in history
- Prior scan state cleared via `POST /api/session/clear`

Isolation was **verified from the coverage manifest**, not assumed: 37 write-ups and `learn.ejs`
appear in the dropped list. An earlier run had read all 37 — which is how we know the check was
worth doing.

> The coverage manifest is what made this checkable. Before it existed, files being read left no
> trace anywhere in the app.

### 2.3 Result

40 findings · $1.34 · 210s · 40 of 116 files read.

Scored by hand against the 19 documented vulnerabilities. A regex-based scorer was written first
and **discarded** — it reported 68% by matching shared words ("mathjs RCE" scored a hit off "No
Lock File Found" because both contain *dependency*). Manual adjudication of 40 findings is
tractable and honest; automated matching against a small key is neither.

**Detection: 9 / 19 (47%).**

| Class | Rate | What it means |
|---|---|---|
| `pattern` — a fixed rule should find these | **3 / 10** | The deterministic engine's own territory |
| `reasoning` — needs intent or policy comparison | **5 / 6** | Only the LLM half can reach these |
| `absence` — the flaw is *missing* code | **1 / 2** | Predicted ~0; the CSRF catch was a surprise |
| `config` | partial | Helmet finding is adjacent, not the same claim |

13 findings mapped to nothing in the docs. Those are **not** false positives — DVNA documents a
teaching subset, not a complete inventory. Judging them needs reading, which is separate work.

---

## 3. What the evidence actually shows

### 3.1 The pattern engine is misrouted, not under-ruled

Three of the ten `pattern` misses were XSS. Chasing why produced the single most important finding
in this document:

`sast-engine/rules/web/injection-tester.js:174` already contains a correct rule:

```js
{ title: 'XSS via innerHTML Assignment', regex: /\.innerHTML\s*=\s*(?!['"]<)/g, ... }
```

Run verbatim against the target's `.ejs` files, it fires three times, on exactly the documented
DOM XSS:

```
views/app/adminusers.ejs:40   c_id.innerHTML = users[i].id;
views/app/adminusers.ejs:41   c_name.innerHTML = users[i].name;
views/app/adminusers.ejs:42   c_email.innerHTML = users[i].email;
```

It never fires, because the extension list at `injection-tester.js:536` reads
`.js .jsx .ts .tsx .py .rb .php .go .java` — and not `.ejs`.

Corroborated structurally across the whole rule set:

```
rule ids                              491
with a CWE tag                         94
rules filtering on .ejs / .hbs / .pug    0
```

**Zero rules target any template language, in any framework.** This is not "we missed three XSS
in one app" — it is a whole vulnerability class with no coverage anywhere, and the rules to cover
it partly already exist. The 3/10 understates the rule *content*; much of the gap is routing.

### 3.2 SCA fails silently, violating a stated invariant

The dependency audit returned zero findings. Run directly:

```
pm detected : npm
error       : Audit failed: ENOLOCK: This command requires an existing lockfile
vulns found : 0
```

The error *was* reported — as a `scan-warning` over WebSocket, to the live panel, which is
discarded on reload. Nothing persists. Opening that scan afterwards, SCA's silence is
indistinguishable from "no vulnerable dependencies."

This breaks CLAUDE.md invariant #7: *a tool that shows "no findings" when it could not look is the
one failure mode a security tool cannot afford.* The invariant is implemented in the transport and
lost in the record. `mathjs 3.10.1`, pinned and known-vulnerable, went unreported.

### 3.3 Adjudication is subsidizing the pattern engine's imprecision

`CMD_INJECTION_EXEC_TEMPLATE` matches *any* template literal inside `exec()`. It has no way to know
whether the interpolated value is user-controlled — that is the actual vulnerability condition, and
a line-oriented regex cannot express it.

So the LLM is being paid, every scan, to close false positives that a taint-aware substrate would
never have produced. Fixing the substrate improves precision **and** lowers cost. Nothing else on
the roadmap does both.

---

## 4. The spec-synthesis experiment

Before committing to a plan, one hypothesis was tested: *can an LLM given only a codebase map emit
detection specs that catch what the fixed rules missed?*

Pre-registered before running — hypothesis, scoring table, success thresholds, and disqualification
criteria written down first, in `PRE-REGISTRATION.md`.

**Setup.** Anonymised map (languages, frameworks, template engine, dependency list, file paths).
No app name, description, or repo URL. No file access, no tools, one call. The dependency list was
kept deliberately: a real pipeline sees it, and reasoning from "`node-serialize` is installed" to
"add an `unserialize` sink" is the mechanism working, not a leak.

**Result: $0.34, one turn, 24 specs.** Did not name the application, so not disqualified.

| Miss | Outcome | Evidence |
|---|---|---|
| node-serialize RCE | **catch** | `(?:^\|\.)unserialize$` → `appHandler.js:218`, the exact line |
| Hardcoded session secret | **catch** | `SESSION_HARDCODED_SECRET` → `server.js` |
| mathjs known-vuln | **catch** | `math(?:js)?\.(?:eval\|compile\|parse)` → `appHandler.js:197` |
| Template XSS ×3 | **partial, 2 of 3** | `<%- output.searchTerm %>`, `<%- output.products[i].* %>` |
| Stack-trace disclosure | miss | no spec emitted |

Threshold for "build it" was ≥3. Verified by **executing** the regexes against the source, not by
reading them. Redundancy with the existing 491 rules was low (~4 of 24).

**The result validates the idea and simultaneously argues against doing it next.** The LLM wrote a
fresh EJS rule because it had no way to know a working one already existed. Ship this layer first
and the routing bug is papered over permanently — and the same misrouting is presumably hiding
rules from `.vue`, `.svelte`, and `.hbs` too.

---

## 5. Prior art

Three positions the LLM can occupy. All three have been built and published.

### Position 1 — LLM downstream (deterministic detects, LLM triages and fixes)

What actually shipped commercially. **GitHub Copilot Autofix**: CodeQL detects, LLM writes the fix
— they deliberately did not let the LLM detect. **Semgrep Assistant**: Semgrep detects, LLM
triages. **Checkmarx** now ships a security-tuned LLM in its engine.

Strongest measured number in the literature: **SAST-Genius** reports ~2.5× detection rate and a
**91% false-positive reduction (225 → 20)** over Semgrep alone — from the triage layer, not from
better detection.

*We already have this. It scored 5/6.*

### Position 2 — LLM upstream (LLM synthesizes the checkers)

**KNighter** (arXiv 2503.09002). LLM synthesizes static-analysis checkers, validates them before
deployment, hands them to existing infrastructure to run. Found previously-unknown bugs in real
code.

**The critical design difference:** KNighter synthesizes from *historical bug reports and patches*,
not from a codebase map. It starts from one confirmed real bug and generalizes to "find every other
instance of this class." That is a far stronger signal than guessing from a dependency list.

Pre-LLM ancestry, ~15 years of it: **Merlin** (Microsoft Research — probabilistic inference of taint
specs from dataflow), **SUSI** (ML classifying Android APIs as sources/sinks), **Seldon**.

KNighter's reported failure modes are ours: semantic bugs needing deep comprehension, anything
cross-file or interprocedural, and FP rates that become prohibitive.

### Position 3 — LLM as the agent

Google **Big Sleep** (ex-Naptime) — model with a debugger and code browser, found a real SQLite bug.
**Vulnhuntr** — builds call chains and feeds slices rather than whole files.

**DARPA AIxCC** (2023–2025) is the largest body of work here: **ATLANTIS** (Team Atlanta) won,
**Buttercup** (Trail of Bits) second, all finalists open-sourced.

The SoK paper's warning is the relevant part: the **most agentic** architecture took the **largest
accuracy penalty**, and the team coordinating 53 components "over-engineered at the expense of
reliability." More agents did not mean better.

### The substrate nobody skips

Every serious system sits on a dataflow substrate with declarative source/sink/sanitizer specs.
CodeQL compiles to a queryable database with taint as a first-class concept. Semgrep uses AST
patterns with metavariables and deliberately moved past regex. Joern uses code property graphs.
Buttercup uses tree-sitter plus code queries.

`sast-engine/rules/core/taint-ast.js` already has the right shape — `AST_SINKS` is declarative
data, not code. It is simply underpowered (intra-procedural), and the 491 rules are regex-first
rather than spec-first.

---

## 6. Recommendation

**Position 1, which we already have, plus substrate work. Defer Position 2. Skip Position 3.**

Do not add a new LLM stage. Move detection off regex onto the taint engine that already exists, and
leave the LLM where it is already winning.

| Layer | Target state | Today |
|---|---|---|
| Substrate | Dataflow with declarative source/sink/sanitizer specs | Partial — `taint-ast.js`, intra-procedural |
| Detection | Specs over that substrate | 491 regex rules |
| Upstream LLM | Synthesize specs, seeded by confirmed bugs | Validated, not built |
| Downstream LLM | Triage and fix | **Working — best-performing component** |

---

## 7. Plan

### Phase 0 — File-type routing · hours

Add template and component extensions (`.ejs`, `.hbs`, `.pug`, `.vue`, `.svelte`) to the file
filters of the agents whose rules apply to them.

- **Acceptance:** the existing `innerHTML` rule fires on `views/app/adminusers.ejs:40-42`.
  DVNA detection moves from 9/19 to at least 11/19 with **no new rules written**.
- **Guard:** measure the false-positive delta on this repo's own self-scan before and after. A
  template file is mostly markup; some rules will misfire on it and must stay gated.
- **Risk:** low. Additive, one line per rule file, reversible.

### Phase 1 — Coverage matrix · days

Extract `(rule id, category, file-type filter, CWE)` from all 491 rules. Grid it as vulnerability
class × file type × language. Read the empty cells.

- **Acceptance:** a committed matrix, plus a ranked list of gaps that is *not* derived from any
  single target codebase.
- **Why it matters:** this is a gap *finder*. A corpus you author can only test for gaps you
  already thought of. The matrix finds them by construction, complete rather than sampled, and it
  cannot overfit because it never looks at a target.
- **Side benefit:** 397 of 491 rules carry no CWE tag. That is what blocks the ASVS/NIST mapping
  listed as unbuilt in `docs/agents.md`.

### Phase 2 — Paired corpus · days

Fixtures for the gaps Phase 1 found. **Every vulnerable case needs a safe twin that must not fire.**

- **Acceptance:** precision and recall reported per rule, not just a total.
- **Why the twin is non-negotiable:** with vulnerable-only fixtures you measure recall alone, and
  *every* change looks like an improvement because more firing always scores better. The safe twin
  is the only thing that distinguishes "the rule got smarter" from "the rule got louder."
- **Placement:** not `test/fixtures/` — that is a frozen golden master whose own header says adding
  a line fails `engine-golden.test.js`, and that property is worth keeping. New directory, with its
  own `.sast-engineignore` entry for the same reason the rule corpus has one.

### Phase 3 — Regex → taint specs · weeks

Migrate the ~20 highest-volume rules to `AST_SINKS`-style specs so they only fire when untrusted
input actually reaches the sink. Not all 491 — the ones producing the most findings and the most
false positives.

- **Acceptance:** precision up on the Phase 2 corpus, recall not down, adjudication cost per scan
  down.
- **Note:** this is where the adjudication subsidy (§3.3) is repaid.

### Phase 4 — Spec synthesis · later

KNighter-style, seeded by **adjudicated true positives** rather than a stack description. A finding
the adjudicator confirmed becomes a spec that finds every sibling instance. That loop compounds;
guessing from `package.json` does not. The input already exists.

- **Prerequisite:** Phase 3. Synthesizing specs for a substrate that cannot consume them well is
  premature.
- **Required if built:** cache generated specs by content hash (determinism), surface them in
  Insights (known coverage), and withhold the rule rationale from the adjudicator (independence).

### Separately, not in sequence — persist engine failure

Put SCA's error on the scan record and give it an Insights row: *"Dependency audit could not run —
no lockfile. A9-class issues were NOT checked."* Persist `scan-warning` messages generally.

Independent of everything above, needs no corpus, cannot overfit, and fixes a case where the tool
under-reports risk. **Do this whenever; it is the only item here that is a correctness bug rather
than an improvement.**

---

## 8. What not to do

- **Do not write rules to fix DVNA's specific misses.** Five rules tonight would take the score to
  ~14/19 and measure nothing but how well the rules were fitted to one 12-file app. This is the
  mistake the stashed JVM work already made once.
- **Do not loosen the secrets or stack-trace rules.** Both fired correctly. `secret: 'keyboard cat'`
  is *weak configuration*, a different class from *credential leakage*; the 110 secret patterns are
  vendor-shaped and correctly ignore low-entropy English. The stack-trace rule requires `err.stack`
  reaching a response, and DVNA uses `req.flash('danger', err)`. Widening either trades two misses
  for dozens of false positives.
- **Do not build agentic detection.** AIxCC's evidence is against it and it does not fit a local
  single-user tool's cost model.
- **Do not delete rule files.** Standing constraint, and the rules are better than the score
  suggested.

---

## 9. Constraints that hold throughout

From `CLAUDE.md`, plus constraints set during this work:

1. Rule files are the core of the engine and are treated with extreme caution. Changes are
   additive, reviewed line by line, and reversible.
2. A scan engine that fails is reported, not counted as clean.
3. Nothing reaches disk from inside a `claude` invocation.
4. The tests are characterization tests. A failure means behaviour changed — acceptable only when
   that was the point of the edit.
5. Client-side stays native ES modules. No bundler.

---

## Appendix A — Reproducing the benchmark

```bash
git clone --depth 1 https://github.com/appsecco/dvna.git
cd dvna
cp -r docs ../dvna-ANSWERS && rm -rf docs README.md
printf 'public/assets/\nviews/vulnerabilities/\nviews/learn.ejs\n' > .sast-engineignore
```

Then clear prior state (`POST /api/session/clear`), scan, and **verify isolation from the Insights
coverage panel before trusting any score** — the write-ups must appear in the dropped list.

Score by hand against `../dvna-ANSWERS/solution/*.md`. A hit requires the right file **and** the
right vulnerability class; nine of the nineteen flaws live in `core/appHandler.js`, so file-only
matching puts the score above 50% on noise alone.

## Appendix B — Baseline to beat

| Metric | Value | Date |
|---|---|---|
| DVNA detection, strict | 9 / 19 (47%) | 2026-08-02 |
| `pattern` class | 3 / 10 | |
| `reasoning` class | 5 / 6 | |
| Findings | 40 | |
| Cost | $1.34 | |
| Wall clock | 210s | |
| Files read | 40 of 116 | |

Any change to the engine should be reported against this row.
