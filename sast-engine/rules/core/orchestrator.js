/**
 * Agent Orchestrator
 * ==================
 *
 * Coordinates all security agents, deduplicates findings,
 * and produces a unified report.
 *
 * Features:
 * - Per-agent timeouts (default 30s, configurable via --timeout)
 * - Parallel execution with configurable concurrency (default 6)
 *
 * Adapted from the open-source ship-safe project (MIT license, see LICENSE)
 * into this app's own sast-engine/. One deliberate change from upstream:
 * runAll() accepts options.onAgentDone(agentResult,
 * findings), invoked right after each agent settles, so a caller (server.js)
 * can stream live progress over a WebSocket. Upstream only reports progress
 * via `ora` terminal spinners, which don't reach a browser client.
 *
 * USAGE:
 *   const orchestrator = new Orchestrator();
 *   orchestrator.register(new InjectionTester());
 *   const results = await orchestrator.runAll(rootPath, options);
 */

import path from 'path';
import { ReconAgent } from './recon-agent.js';
import { VerifierAgent } from './verifier-agent.js';
import { enumerateSurface } from '../../enumerate.js';

// =============================================================================
// CONSTANTS
// =============================================================================

const DEFAULT_TIMEOUT = 30_000; // 30s per agent
const DEFAULT_CONCURRENCY = 6;

// =============================================================================
// ORCHESTRATOR
// =============================================================================

export class Orchestrator {
  constructor() {
    /** @type {import('./base-agent.js').BaseAgent[]} */
    this.agents = [];
    this.reconAgent = new ReconAgent();
    this.verifierAgent = new VerifierAgent();
  }

  /**
   * Register an agent for execution.
   */
  register(agent) {
    this.agents.push(agent);
    return this;
  }

  /**
   * Register multiple agents at once.
   */
  registerAll(agents) {
    for (const agent of agents) {
      this.register(agent);
    }
    return this;
  }

  /**
   * Run a single agent with a timeout.
   */
  async runAgent(agent, context, timeout) {
    return Promise.race([
      agent.analyze(context),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error(`timed out after ${timeout / 1000}s`)), timeout);
      }),
    ]);
  }

  /**
   * Run all registered agents against the codebase.
   *
   * @param {string} rootPath — Absolute path to the project root
   * @param {object} options  — { agents[], categories[], timeout, concurrency, onAgentDone }
   * @returns {Promise<object>} — { recon, findings[], agentResults[], suppression }
   */
  async runAll(rootPath, options = {}) {
    const absolutePath = path.resolve(rootPath);
    const timeout = options.timeout || DEFAULT_TIMEOUT;
    const concurrency = options.concurrency || DEFAULT_CONCURRENCY;
    const onAgentDone = typeof options.onAgentDone === 'function' ? options.onAgentDone : null;

    // ── 1. Recon — map the attack surface ─────────────────────────────────────
    const recon = await this.reconAgent.analyze({ rootPath: absolutePath, options });

    // ── 2. Discover files once (shared across agents) ─────────────────────────
    let files = await this.reconAgent.discoverFiles(absolutePath);

    // Optional diff-only scope: restrict every agent's view of the repo to a
    // specific file list (absolute or relative to rootPath) up front, rather
    // than relying on each agent to opt into context.changedFiles individually
    // (most of the 29 built-in agents read context.files directly and would
    // otherwise ignore scoping entirely).
    if (Array.isArray(options.onlyFiles) && options.onlyFiles.length > 0) {
      const onlySet = new Set(options.onlyFiles.map((f) => path.resolve(absolutePath, f)));
      files = files.filter((f) => onlySet.has(path.resolve(f)));
    }

    // ── 3. Filter agents if specific ones requested ───────────────────────────
    let agentsToRun = this.agents;
    if (options.agents && options.agents.length > 0) {
      const requested = options.agents.map(a => a.toLowerCase());
      agentsToRun = this.agents.filter(a => {
        const name = a.name.toLowerCase();
        const cat = a.category.toLowerCase();
        return requested.some(r => name === r || name.includes(r) || cat === r);
      });
    }
    if (options.categories && options.categories.length > 0) {
      const requested = new Set(options.categories.map(c => c.toLowerCase()));
      agentsToRun = agentsToRun.filter(a => requested.has(a.category.toLowerCase()));
    }

    // ── 4. Build shared context ─────────────────────────────────────────────
    // sharedFindings allows cross-agent awareness: later agents can see
    // what earlier agents found (e.g., secrets agent finds a key,
    // supply-chain agent can check if it's committed to a public repo).
    const sharedFindings = [];
    // Structural map of the app — routes with their middleware chains, sinks,
    // and every security-relevant function with its real call count. Computed
    // once here and shared, because more than one consumer needs it: agents that
    // reason about whole-app wiring, and (via the caller) the reasoning pass,
    // which is handed it as an enumerated worklist. Accepted from options when
    // the caller already built it, so it is never computed twice per scan.
    const surface = options.surface || enumerateSurface(absolutePath, { files });
    const context = { rootPath: absolutePath, files, recon, options, sharedFindings, surface };
    if (options.changedFiles) {
      context.changedFiles = options.changedFiles;
    }

    // ── 5. Run agents in parallel (chunked by concurrency) ──────────────────
    const agentResults = [];
    let allFindings = [];

    // Filter agents by framework relevance (shouldRun check)
    const relevantAgents = agentsToRun.filter(a => {
      if (typeof a.shouldRun === 'function') {
        return a.shouldRun(recon);
      }
      return true;
    });
    const skippedAgents = agentsToRun.length - relevantAgents.length;

    // Framework-relevance filtering above means the agent count a caller guessed before
    // calling runAll() (e.g. this.agents.length) is very often wrong — most repos skip several
    // shouldRun-gated agents (mobile-scanner, supabase-rls-agent, etc.), so a caller driving a
    // live progress bar off its own upfront guess will under-report a total that never reaches
    // 100%. Report the real, post-filter count as soon as it's known so the caller can correct
    // its total before the per-agent loop (and its onAgentDone calls) even starts.
    // Also reports which agents were filtered out and are therefore contributing nothing to
    // this scan. A caller showing only the surviving count ("17/17 agents") makes relevance
    // gating invisible — it reads as though 17 is all there is, when 15 more were deliberately
    // judged inapplicable. Which ones were skipped is the interesting half of that decision.
    if (typeof options.onScopeReady === 'function') {
      const relevant = new Set(relevantAgents.map((a) => a.name));
      options.onScopeReady(
        relevantAgents.length,
        this.agents.filter((a) => !relevant.has(a.name)).map((a) => a.name),
      );
    }

    for (let i = 0; i < relevantAgents.length; i += concurrency) {
      const chunk = relevantAgents.slice(i, i + concurrency);
      const settled = await Promise.allSettled(
        chunk.map(agent => this.runAgent(agent, context, timeout))
      );

      for (let j = 0; j < chunk.length; j++) {
        const agent = chunk[j];
        const result = settled[j];

        if (result.status === 'fulfilled') {
          const findings = result.value;
          const agentResult = {
            agent: agent.name,
            category: agent.category,
            findingCount: findings.length,
            // How much this agent was asked not to report. A scan that silenced
            // findings must not read like a scan that had none.
            suppressedCount: agent.suppressedCount || 0,
            floorSuppressionAttempts: agent.floorSuppressionAttempts || 0,
            success: true,
          };
          agentResults.push(agentResult);
          allFindings = allFindings.concat(findings);
          // Share findings with subsequent agents
          sharedFindings.push(...findings);
          if (onAgentDone) onAgentDone(agentResult, findings);
        } else {
          const agentResult = {
            agent: agent.name,
            category: agent.category,
            findingCount: 0,
            success: false,
            error: result.reason.message,
          };
          agentResults.push(agentResult);
          if (onAgentDone) onAgentDone(agentResult, []);
        }
      }
    }

    // ── 6. Deduplicate ────────────────────────────────────────────────────────
    allFindings = this.deduplicate(allFindings);

    // ── 7. Second-pass verification (confirms or downgrades findings) ───────
    if (!options.skipVerifier) {
      allFindings = this.verifierAgent.verify(allFindings, options);
    }

    // ── 8. Context-aware confidence tuning ──────────────────────────────────
    allFindings = this.tuneConfidence(allFindings);

    // ── 9. Sort by severity ──────────────────────────────────────────────────
    const sevOrder = { critical: 0, high: 1, medium: 2, moderate: 2, low: 3 };
    allFindings.sort((a, b) =>
      (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)
    );

    // Roll the suppression tally up to the scan level so callers (CLI output,
    // JSON, CI gates) can show it without walking agentResults.
    const suppression = {
      suppressed: agentResults.reduce((n, a) => n + (a.suppressedCount || 0), 0),
      floorAttempts: agentResults.reduce((n, a) => n + (a.floorSuppressionAttempts || 0), 0),
    };

    return { recon, surface, findings: allFindings, agentResults, suppression, skippedAgents, totalAgents: relevantAgents.length };
  }

  /**
   * Downgrade confidence for findings in test files, comments, docs, or examples.
   * Reduces false-positive noise since ScoringEngine applies confidence multipliers.
   */
  tuneConfidence(findings) {
    const TEST_PATH = /(?:__tests__|\.test\.|\.spec\.|\/test\/|\/tests\/|\/fixtures?\/)/i;
    const DOC_EXT = new Set(['.md', '.txt', '.rst', '.adoc', '.rdoc']);
    const EXAMPLE_PATH = /(?:\/examples?\/|\/samples?\/|\/demos?\/|\/fixtures?\/|\/mocks?\/)/i;
    const COMMENT_LINE = /^\s*(?:\/\/|#|\/?\*|<!--)/;

    for (const f of findings) {
      const ext = (f.file || '').match(/\.[^.]+$/)?.[0]?.toLowerCase() || '';

      // Findings in documentation files
      if (DOC_EXT.has(ext)) {
        f.confidence = 'low';
        continue;
      }

      // Findings in test files
      if (TEST_PATH.test(f.file || '')) {
        f.confidence = 'low';
        continue;
      }

      // Findings in example/sample/demo paths: high → medium
      if (EXAMPLE_PATH.test(f.file || '') && f.confidence === 'high') {
        f.confidence = 'medium';
        continue;
      }

      // Findings on comment lines
      if (f.matched && COMMENT_LINE.test(f.matched)) {
        f.confidence = 'low';
      }
    }

    return findings;
  }

  /**
   * Remove duplicate findings (same file + line + rule).
   */
  deduplicate(findings) {
    const seen = new Set();
    return findings.filter(f => {
      const key = `${f.file}:${f.line}:${f.rule}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}

export default Orchestrator;
