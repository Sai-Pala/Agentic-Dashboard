# How the Scan Engine Works (Plain-Language Guide)

When you click "Start scan" on the Hybrid Scan page, three separate checks kick off at the
same time against the directory you gave it. This document walks through what each one does
and how their results come back together into the findings you see in Agent Triage —
described in plain terms, without assuming you know the codebase.

---

## The three checks, in one sentence each

1. **Pattern matching** — a fast, rule-based scanner that reads every file and looks for code
   that matches ~29 known-bad patterns (hardcoded secrets, SQL built by string concatenation,
   missing auth checks, and so on). No AI involved — just very well-informed find-and-check.
2. **Reasoning** — the actual AI (Claude) reads through the code and looks for the kind of
   problems a fixed list of patterns can't catch: business-logic mistakes, missing
   authorization that only makes sense once you understand what the code is trying to do,
   suspicious combinations of things that are individually fine.
3. **Dependency audit** — a check of your `package.json`/lockfile (or your language's
   equivalent) against known-vulnerable package versions, the same way `npm audit` works.

All three start together, run independently, and the app waits for all three to finish before
showing you the combined results. None of them wait on each other.

---

## Check 1: Pattern matching, in plain terms

Think of this as 29 specialists, each an expert in one narrow thing — one only looks for
hardcoded API keys, another only looks for SQL injection, another only checks for exposed
admin routes, and so on. Before they start, the app quickly looks at your codebase and figures
out which specialists are even relevant — there's no point running the "mobile app" specialist
on a plain web backend, so that one just sits out. Everyone else runs at the same time (a
handful at once, not all 29 simultaneously, to keep things fast without overwhelming the
machine), each reading through the same list of files.

Once a specialist finds something, there's a second step: a **verifier** takes a second, closer
look at the most serious findings (critical and high severity only) and asks a few sanity-check
questions — is this value actually hardcoded, or does it come from user input? Is there
sanitization happening just above this line that would neutralize it? Is this code even
reachable, or is it sitting after a `return` statement that means it never runs? Based on the
answers, the finding either gets confirmed as real or gets flagged as "needs another look" —
this is what feeds directly into the finding's status the moment the scan finishes, so nothing
sits in an ambiguous "no one checked this yet" state.

This whole check involves zero AI calls — it's fast, consistent, and repeatable, which is
exactly what you want for the categories of bugs that have a well-known shape.

## Check 2: Reasoning (the AI pass), in plain terms

This is where an actual language model reads the code and thinks about it, which is slower and
costs real money per call — so the app is careful about how much it lets any single call bite
off.

**For a small project**, the whole thing might fit in one pass. **For a large one**, the
directory gets broken up into bite-sized groups of files first — roughly 30 files per group,
grouped by folder where that makes sense, and automatically re-split or merged as needed so no
group is absurdly huge or absurdly tiny. Each group then gets its own, separate conversation
with the AI, and the AI is explicitly told "only look at these specific files — nothing else."
Several of these run at once (three at a time), so a big codebase doesn't take forever, but
also doesn't spawn dozens of AI calls simultaneously.

There's one more pass on top of the per-group ones: a **cross-cutting review** that looks at
the *entire* codebase at once, but only to check one specific kind of thing — are the
protections that are defined somewhere (an authentication check, a validation function)
actually *used* everywhere they should be? A group-scoped pass can't see this, because by
definition it only sees a slice of the code — it might notice a route that looks like it should
require login and flag it as suspicious, but it can't prove the real login check isn't hiding
in a file it wasn't shown. The cross-cutting pass *can* prove that, because it can search the
whole repository. In testing, this genuinely made a real difference: a route wired up to a
decoy function instead of the real authentication check was flagged by the group-scoped pass
as "looks suspicious, not sure," and confirmed with much higher confidence by the cross-cutting
pass, which could actually verify the real check was never called anywhere.

Every one of these AI calls is also told, up front, what the pattern-matching check (Check 1)
already covers — so it doesn't waste its time re-finding the same hardcoded-secret patterns a
plain regex already caught for free, and instead focuses on the harder, contextual stuff only
it can do.

**Cost control**: each of these AI calls has a dollar cap by default (fifty cents per group,
seventy-five cents for the cross-cutting pass) so one call that goes down a rabbit hole can't
run away with your budget. If a call hits its cap before finishing, the app tells you that
plainly instead of just quietly showing zero results — you'll see a note that says coverage
might be incomplete for that part of the scan. There's also a toggle to turn the cap off
entirely, for when you'd rather let a scan run to completion regardless of cost.

## Check 3: Dependency audit, in plain terms

This one just runs whatever your package manager's own audit tool is — `npm audit`,
`pip-audit`, or similar, auto-detected from what lockfile is present — and reports back any
dependency with a known public vulnerability, along with the version that fixes it. It's the
fastest of the three checks by a wide margin, since it's a single command rather than reading
through your whole codebase.

---

## Putting it back together

Once all three checks finish, the app combines their results into one list of findings:

- Anything the **dependency audit** found becomes its own findings — these are always distinct,
  since a vulnerable package version has nothing in common with a specific line of code.
- Anything **pattern matching** found becomes a finding, already carrying the verifier's
  confirm/needs-a-closer-look verdict from earlier.
- Anything the **reasoning pass** found also becomes a finding — but first, the app checks
  whether it's pointing at essentially the same spot in the same file as something pattern
  matching already reported. If so, it's dropped as a duplicate rather than shown twice. Most
  of what the reasoning pass finds doesn't have this problem in the first place, since
  business-logic and authorization issues usually don't map to one specific line the same way
  a hardcoded secret does.

Every finding that comes out of this process already has an initial verdict attached — you
don't have to manually kick off a separate "triage" step before you can start working a
finding. From there, the normal workflow takes over: you review it, and if it's real, you can
have the fix agent draft and apply a change, then have the verify agent confirm the fix
actually landed.

## What happens when something goes wrong

If one of the three checks fails outright — say, the dependency audit errors because there's
no recognizable lockfile — the scan doesn't stop. It finishes with whatever the other two
checks found, and shows a small warning noting that one part didn't complete. Only if *all
three* checks fail does the whole scan report as failed. The same idea applies inside the
reasoning pass itself: if some of the file-group calls fail but others succeed, you still get
the findings from the ones that worked, plus a note about how many didn't.

If you close the scan (or navigate away) while it's running, everything still in flight — every
AI call, still-running pattern check — gets stopped cleanly rather than left running in the
background.
