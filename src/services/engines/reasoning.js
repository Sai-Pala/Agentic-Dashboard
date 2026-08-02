/**
 * The reasoning half of a hybrid scan: two concurrent `claude -p` passes, both taking the
 * deterministic half's output as their input.
 *
 *   ADJUDICATE — the pattern findings with their code, asking which are real. Only runs when
 *                the deterministic half found something. Scales with finding count.
 *   REVIEW     — the enumerated attack surface plus what the deterministic half already
 *                reported, asking the authorization and business-logic questions no fixed rule
 *                set can express. Always runs; an empty deterministic result is not evidence
 *                the code is clean. Scales with endpoint count, sharded (see plan.js).
 *
 * Neither scales with repo size, so a large codebase costs roughly what a small one does.
 */

const fs = require('fs');

const {
  agentFilePath,
  ADJUDICATE_MAX_FINDINGS,
  ADJUDICATE_MAX_PER_RULE,
  REASONING_ADJUDICATE_BUDGET_USD,
  REASONING_REVIEW_BUDGET_USD,
  REASONING_TOTAL_USD,
  REVIEW_MAX_SHARDS,
  REVIEW_MAX_SHARDS_UNCAPPED,
  REVIEW_SHARD_CONCURRENCY,
} = require('../../config');
const { severityRank } = require('../taxonomy');
const { runReasoningCall } = require('../claude');
const { loadSastEngine } = require('../sast-engine');
const { buildCoverageSummary, renderAdjudicationWorklist, planReviewShards, selectForAdjudication } = require('./plan');
const { toRepoRelative } = require('../paths');

/**
 * Announce what the review pass will NOT look at, before it starts.
 *
 * Kept separate from the orchestration because it is the one part with no state of its own — it
 * reads the plan and emits. It is also the part that must never be quietly dropped: a scan that
 * reviewed a fraction of the surface and says nothing reads identically to one that reviewed all
 * of it, and "found nothing" where "could not look" is the truth is the failure mode a security
 * tool cannot afford.
 */
function reportCoverageGaps(scan, surface, shards, send) {
  if (!surface) {
    send({
      type: 'scan-warning', runId: scan.runId, scanId: scan.id,
      message: 'Attack-surface enumeration produced nothing — the review pass will run without a route worklist, which weakens coverage of authorization and business-logic issues.',
    });
  }
  if (surface && shards.totalRoutes === 0) {
    // Zero routes is ambiguous, and the two readings are not equally likely. A library or worker
    // genuinely has no HTTP surface; so does a web application written in a language the
    // enumerator cannot parse — it understands Express-shaped JavaScript and nothing else, so a
    // Spring or Django app reads as zero. Both fall through to one unscoped call over the whole
    // tree, which on a large repo reads a handful of files and reports success.
    //
    // The route-coverage warning below cannot catch this: with no routes, skippedRoutes is 0 too,
    // so the worst-coverage case was the one that stayed silent.
    send({
      type: 'scan-warning', runId: scan.runId, scanId: scan.id,
      message: 'No HTTP routes were enumerated, so the review pass ran unscoped over the whole '
        + 'tree instead of endpoint by endpoint — authorization and business-logic coverage is '
        + 'substantially weaker than a normal scan. If this application does serve HTTP, its '
        + 'framework is one the attack-surface enumerator does not recognise, and this is '
        + 'incomplete coverage rather than a clean result.',
    });
  }
  if (shards.skippedRoutes > 0) {
    // Report the ceiling that actually applied, and only suggest the cap toggle when it is on.
    // This message exists to state how much was NOT reviewed; naming the wrong limit, or
    // advising a change already in effect, undermines the one job it has.
    const appliedMaxShards = scan.budgetEnabled ? REVIEW_MAX_SHARDS : REVIEW_MAX_SHARDS_UNCAPPED;
    const remedy = scan.budgetEnabled
      ? 'Turn off the budget cap, or scan a narrower directory, for full coverage.'
      : 'The budget cap is already off — scan a narrower directory for full coverage.';
    send({
      type: 'scan-warning', runId: scan.runId, scanId: scan.id,
      message: `${shards.totalRoutes} routes exceeded what ${appliedMaxShards} review shards can cover — the ${shards.reviewedRoutes} highest-risk were reviewed (unguarded mounts and authenticated-but-not-authorized surfaces first); ${shards.skippedRoutes} were NOT reviewed for authorization or business-logic issues. ${remedy}`,
    });
  }
}

/**
 * @returns {{findings, adjudications: Map<number, object>, error, costUsd}} `findings` is raw
 * review-pass output; `adjudications` maps deterministic-finding index -> verdict.
 */
async function runLLMReasoningScan(scan, targetPath, diffFiles, detFindings, surface, { children, send }) {
  let engine;
  try {
    engine = await loadSastEngine();
  } catch (err) {
    return { findings: [], adjudications: new Map(), error: `Failed to load scan engine: ${err.message}`, costUsd: 0 };
  }

  const readAgent = (name) => {
    const p = agentFilePath(name);
    if (!fs.existsSync(p)) throw new Error(`prompts/${name}.md is not available.`);
    return fs.readFileSync(p, 'utf8');
  };

  let reviewPrompt;
  try {
    reviewPrompt = readAgent('scan') + '\n\n' + buildCoverageSummary(engine, {
      skipped: scan.agentsSkipped,
      failed: scan.agentsFailed,
    });
  } catch (err) {
    return { findings: [], adjudications: new Map(), error: err.message, costUsd: 0 };
  }

  scan.moduleRunIds = [];

  const adjudicable = [...detFindings.entries()]
    .sort(([, a], [, b]) => severityRank(a.severity) - severityRank(b.severity));
  const adjudicating = selectForAdjudication(adjudicable, ADJUDICATE_MAX_FINDINGS, ADJUDICATE_MAX_PER_RULE);
  const overflow = adjudicable.length - adjudicating.length;

  let adjudicatePrompt = null;
  if (adjudicating.length) {
    try {
      adjudicatePrompt = readAgent('adjudicate');
    } catch (err) {
      send({
        type: 'scan-warning', runId: scan.runId, scanId: scan.id,
        message: `${err.message} Deterministic findings will keep their pattern-engine verdicts without independent review.`,
      });
    }
  }

  // Planned before `total` so the progress bar's denominator is right from the first message.
  const shards = planReviewShards(surface, detFindings, targetPath, {
    maxShards: scan.budgetEnabled ? REVIEW_MAX_SHARDS : REVIEW_MAX_SHARDS_UNCAPPED,
  });

  const total = (adjudicatePrompt ? 1 : 0) + shards.list.length;
  let done = 0;
  let totalCostUsd = 0;
  const errors = [];
  const progress = () => {
    if (scan.status !== 'cancelled') {
      send({ type: 'scan-progress', runId: scan.runId, scanId: scan.id, engine: 'reasoning', done, total, costUsd: totalCostUsd });
    }
  };
  progress();

  const adjudications = new Map();

  const adjudicatePass = async () => {
    if (!adjudicatePrompt) return;
    if (overflow > 0) {
      send({
        type: 'scan-warning', runId: scan.runId, scanId: scan.id,
        message: `${adjudicable.length} deterministic findings exceeded the ${ADJUDICATE_MAX_FINDINGS}-finding adjudication limit — the ${ADJUDICATE_MAX_FINDINGS} most severe were independently reviewed; the remaining ${overflow} keep their pattern-engine verdict and are marked "needs review".`,
      });
    }

    const worklist = renderAdjudicationWorklist(adjudicating.map(([, f]) => f), targetPath);
    const userPrompt = [
      `A deterministic pattern-matching engine reported ${adjudicating.length} finding${adjudicating.length === 1 ? '' : 's'} in this codebase. Decide which are real.`,
      'Read the actual files before deciding — the snippets below are a few lines of context, and what makes a finding real or not is often outside them.',
      `Target directory: ${targetPath}`,
      `Findings to adjudicate:\n\n${worklist}`,
    ].join('\n\n');

    const res = await runReasoningCall({
      scan, targetPath, children, send, index: 0, label: 'Adjudication pass',
      systemPrompt: adjudicatePrompt, userPrompt, budgetUsd: REASONING_ADJUDICATE_BUDGET_USD,
    });
    totalCostUsd += res.costUsd;
    done++;
    progress();
    if (res.error) errors.push(res.error);

    const verdicts = res.parsed && Array.isArray(res.parsed.verdicts) ? res.parsed.verdicts : [];
    for (const v of verdicts) {
      // `id` indexes the sorted slice handed to the model, not detFindings — map it back through
      // `adjudicating` so a verdict can never land on the wrong finding.
      const entry = adjudicating[Number(v.id)];
      if (!entry) continue;
      adjudications.set(entry[0], v);
    }
  };

  // Persisted so the Attack Surface page can state review depth after the fact — the live
  // panel is thrown away on reload, and "how much of the surface was actually reviewed" is
  // exactly the number that must survive.
  const reviewedFiles = new Set(shards.list.flatMap((s) => s.files || []));
  const routeFiles = new Set(
    (surface && Array.isArray(surface.routes) ? surface.routes : []).map((r) => r.file).filter(Boolean),
  );

  scan.reviewCoverage = {
    totalRoutes: shards.totalRoutes,
    reviewedRoutes: shards.reviewedRoutes,
    skippedRoutes: shards.skippedRoutes,
    shards: shards.list.length,
    adjudicated: adjudicating.length,
    adjudicable: adjudicable.length,
    // Which files the review actually opened, and which route-bearing files it never reached.
    // The counts above say how much was left out; only these say WHAT was left out, which is the
    // half you need to judge whether the shard budget landed on the right code.
    shardFiles: shards.list.map((s, i) => ({ index: i + 1, files: s.files || null, routeCount: s.routeCount })),
    unreviewedFiles: [...routeFiles].filter((f) => !reviewedFiles.has(f)).sort(),
  };

  reportCoverageGaps(scan, surface, shards, send);

  const runReviewShard = async (shard, index) => {
    // Checked at dispatch rather than up front so shards already in flight always finish —
    // killing a call mid-analysis wastes what it already spent.
    if (scan.budgetEnabled && totalCostUsd >= REASONING_TOTAL_USD) {
      return { findings: [], skipped: true };
    }

    const parts = [
      'Review this application for security vulnerabilities that a pattern-matching engine cannot find: '
      + 'authorization and access-control gaps, business-logic flaws, and controls that are defined in one '
      + 'place but never actually applied where they are needed. Reason about externally-reachable endpoints '
      + 'the way an attacker interacting with the running application would. No live instance is being hit — '
      + 'this is inferred from static code, so frame findings accordingly.',
    ];

    if (diffFiles) {
      parts.push(`Limit your review to only the following changed files versus the base branch — do not scan anything else in the repository:\n${diffFiles.map((p) => `- ${p}`).join('\n')}`);
    } else if (shard.files && shards.list.length > 1) {
      // Focus, NOT a sandbox. Answering "could this data belong to someone else" almost always
      // means following the call into a file outside the list; forbidding that would defeat the
      // questions the pass is being asked.
      parts.push(
        'You are reviewing one slice of a larger application. These files hold the routes you '
        + 'are responsible for:\n'
        + shard.files.map((p) => `- ${p}`).join('\n')
        + '\n\nReport findings for these routes only — other slices are being reviewed separately, '
        + 'so do not report issues whose root cause lives in a file outside this list. You may and '
        + 'should read anything in the repository to understand what these routes do.',
      );
    }
    parts.push(`Target directory: ${targetPath}`);

    // The enumerated surface is what bounds this call: the model answers questions about a
    // known set of endpoints instead of deciding for itself what to read. A malformed worklist
    // degrades to the unscoped behaviour and must never cost us the shard.
    if (surface) {
      try {
        const worklist = engine.renderWorklist(surface, shard.files || diffFiles || null);
        if (worklist.trim()) parts.push(worklist);
      } catch { /* non-fatal */ }
    }

    // Naming what the deterministic half already found is the other half of making this a
    // hybrid: without it the model spends its budget rediscovering the same hardcoded secret.
    // Locations only — the point is avoidance, not review, which was the adjudication pass's job.
    const shardFileSet = shard.files ? new Set(shard.files) : null;
    const relevantDet = detFindings.filter((f) => {
      if (!shardFileSet) return true;
      if (!f.file) return false;
      return shardFileSet.has(toRepoRelative(targetPath, f.file));
    });
    if (relevantDet.length) {
      const already = relevantDet.slice(0, 60).map((f) => {
        const rel = toRepoRelative(targetPath, f.file) || '(no file)';
        return `- ${f.title || f.rule} @ ${f.line ? `${rel}:${f.line}` : rel}`;
      }).join('\n');
      parts.push(
        'Already reported by the deterministic engine — do NOT report these again, and do not spend '
        + `effort re-deriving them. Report only what is missing from this list:\n${already}`
        + (relevantDet.length > 60 ? `\n(+${relevantDet.length - 60} more of the same kinds)` : ''),
      );
    }

    const res = await runReasoningCall({
      scan, targetPath, children, send,
      // index 0 is the adjudication pass; review shards follow it.
      index: index + 1,
      label: shards.list.length > 1 ? `Review shard ${index + 1}/${shards.list.length}` : 'Review pass',
      systemPrompt: reviewPrompt, userPrompt: parts.join('\n\n'), budgetUsd: REASONING_REVIEW_BUDGET_USD,
    });
    totalCostUsd += res.costUsd;
    done++;
    progress();
    if (res.error) errors.push(res.error);
    return {
      findings: res.parsed && Array.isArray(res.parsed.findings) ? res.parsed.findings : [],
      skipped: false,
    };
  };

  const reviewPass = async () => {
    const out = [];
    let skippedForBudget = 0;
    let next = 0;
    const worker = async () => {
      while (next < shards.list.length && scan.status !== 'cancelled') {
        const i = next++;
        const r = await runReviewShard(shards.list[i], i);
        if (r.skipped) { skippedForBudget++; done++; progress(); continue; }
        out.push(...r.findings);
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(REVIEW_SHARD_CONCURRENCY, shards.list.length) }, worker),
    );
    if (skippedForBudget) {
      send({
        type: 'scan-warning', runId: scan.runId, scanId: scan.id,
        message: `This scan reached its $${REASONING_TOTAL_USD} reasoning budget — ${skippedForBudget} of ${shards.list.length} shards were skipped and their routes were NOT reviewed. Turn off the budget cap for full coverage.`,
      });
    }
    return out;
  };

  // Concurrent: the two passes share no data with each other, and both their inputs already
  // exist by the time this runs, so sequencing them adds the shorter one's whole wall clock to
  // every scan for nothing.
  const [, reviewFindings] = await Promise.all([adjudicatePass(), reviewPass()]);

  if (scan.status === 'cancelled') {
    return { findings: [], adjudications, error: null, costUsd: totalCostUsd };
  }

  // Every pass failing is an engine failure; some passing is a degraded scan that still produced
  // real results. scan-warning rather than scan-stderr, which the client discards.
  if (errors.length === total) {
    return { findings: [], adjudications, error: errors.join(' | '), costUsd: totalCostUsd };
  }
  if (errors.length) {
    send({ type: 'scan-warning', runId: scan.runId, scanId: scan.id, message: `${errors.length}/${total} reasoning passes had issues: ${errors.join(' | ')}` });
  }
  return { findings: reviewFindings, adjudications, error: null, costUsd: totalCostUsd };
}

module.exports = { runLLMReasoningScan };
