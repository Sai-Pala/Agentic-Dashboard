/**
 * What the deterministic engine decided, and what it decided it on.
 * =================================================================
 *
 * `orchestrator.runAll()` returns five things. Until now the app kept two of them — `findings`
 * and `surface` — and dropped `recon`, `agentResults` and `suppression` on the floor. Those three
 * are the entire record of *how* a scan reached its answer:
 *
 *   `recon`        the facts every gating decision was made on. The engine's own comment calls
 *                  part of it "signals that exist purely so agents can gate themselves via
 *                  shouldRun()", which makes it the closest thing to a reason a skipped agent has.
 *   `agentResults` per agent: did it complete, how much did it find, how much did it suppress.
 *   `suppression`  the roll-up of findings an agent deliberately withheld.
 *
 * WHAT THIS MODULE WILL NOT CLAIM. `shouldRun()` returns a bare boolean — no reason string. So
 * "MobileScanner did not run" can be stated as fact, but "because there is no mobile framework"
 * cannot: it would be an inference about code this module does not read. The roster therefore
 * reports the decision and publishes the recon evidence beside it, and leaves the inference to
 * the person reading it. Getting a real per-agent reason means changing `shouldRun()` inside the
 * vendored engine, which is a separate decision.
 */

/** Recon fields that are lists of detected things — rendered as chips, empty ones dropped. */
const RECON_LISTS = [
  ['frameworks', 'Frameworks'],
  ['languages', 'Languages'],
  ['databases', 'Databases'],
  ['cloudProviders', 'Cloud providers'],
  ['packageManagers', 'Package managers'],
  ['authPatterns', 'Auth patterns'],
  ['frontendExposure', 'Frontend exposure'],
  ['cicd', 'CI/CD'],
  ['aiFrameworks', 'AI frameworks'],
  ['vectorStores', 'Vector stores'],
  ['mcpConfigs', 'MCP configs'],
  ['agentConfigs', 'Agent configs'],
  ['modelFiles', 'Model files'],
  ['envFiles', 'Env files'],
];

/** Recon booleans. Present-but-false still matters — it is why an agent stayed silent. */
const RECON_FLAGS = [
  ['hasDockerfile', 'Dockerfile'],
  ['hasTerraform', 'Terraform'],
  ['hasKubernetes', 'Kubernetes'],
];

/**
 * A Set, an array of strings, or an array of records — recon uses all three, and `cicd` entries
 * are `{platform, file}` while `frameworks` entries are bare strings. Anything object-shaped is
 * reduced to its most name-like field; without this the chips read "[object Object]".
 */
function toList(value) {
  if (value instanceof Set) return [...value].map(String);
  if (!Array.isArray(value)) return [];
  return value.map((v) => {
    if (typeof v === 'string') return v;
    if (v && typeof v === 'object') return String(v.platform || v.name || v.type || v.file || JSON.stringify(v));
    return String(v);
  });
}

/**
 * Flatten recon into something JSON-serialisable and renderable.
 *
 * Deliberately lossy: `apiRoutes` and `configFiles` can each run to thousands of entries and are
 * already shown by Attack Surface, so only their counts survive here.
 */
function summarizeRecon(recon) {
  if (!recon || typeof recon !== 'object') return null;

  const signals = [];
  for (const [key, label] of RECON_LISTS) {
    const values = [...new Set(toList(recon[key]))];
    if (values.length) signals.push({ label, values });
  }

  const flags = RECON_FLAGS.map(([key, label]) => ({ label, present: Boolean(recon[key]) }));

  return {
    signals,
    flags,
    routeCount: toList(recon.apiRoutes).length || (Array.isArray(recon.apiRoutes) ? recon.apiRoutes.length : 0),
    configFileCount: Array.isArray(recon.configFiles) ? recon.configFiles.length : 0,
  };
}

/**
 * Every agent the engine has, with what happened to it.
 *
 * Built from the orchestrator's own agent list rather than from the results, so an agent that was
 * gated out still appears. A roster showing only agents that ran makes relevance gating invisible
 * — "17 agents ran" reads as though 17 is all there is, when 15 more were judged inapplicable and
 * are contributing nothing.
 *
 * @param {Array<{name:string,category:string,description:string}>} allAgents  orchestrator.agents
 * @param {Array<object>} agentResults  runAll()'s per-agent results
 * @param {string[]} skippedNames  names reported by onScopeReady
 * @returns {Array<{name,category,description,status,findingCount,suppressedCount,error}>}
 */
function buildAgentRoster(allAgents, agentResults, skippedNames) {
  const skipped = new Set(skippedNames || []);
  const byName = new Map((agentResults || []).map((r) => [r.agent, r]));

  const roster = (allAgents || []).map((a) => {
    const result = byName.get(a.name);
    let status = 'skipped';
    if (result) status = result.success === false ? 'failed' : 'ran';
    else if (!skipped.has(a.name)) status = 'unknown'; // neither gated out nor reported back

    return {
      name: a.name,
      category: a.category || 'uncategorised',
      description: a.description || '',
      status,
      findingCount: result ? result.findingCount || 0 : 0,
      suppressedCount: result ? result.suppressedCount || 0 : 0,
      error: result && result.error ? String(result.error) : null,
    };
  });

  // Worst first: an agent that crashed is a coverage hole, an agent that was never asked to run
  // is a scoping decision, and an agent that ran cleanly needs no attention.
  const rank = { failed: 0, unknown: 1, ran: 2, skipped: 3 };
  roster.sort((a, b) => (rank[a.status] - rank[b.status])
    || (b.findingCount - a.findingCount)
    || a.name.localeCompare(b.name));
  return roster;
}

module.exports = { summarizeRecon, buildAgentRoster };
