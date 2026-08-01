/**
 * Agent Registry
 * ===============
 *
 * Central export of all agents and supporting classes.
 *
 * Adapted from the open-source ship-safe project (MIT license, see LICENSE)
 * into this app's own sast-engine/, trimmed to only the 29 built-in
 * deterministic pattern agents + the orchestrator. Dropped from upstream:
 * DeepAnalyzer, GPTRedAgent, ScoringEngine, HTMLReporter, SBOM/ABOM/AIBOM
 * generators, PolicyEngine — none of those are part of this app's Scan/SCA
 * replacement (see CLAUDE.md's Reasoning Scan / SCA Scan bullets).
 */

import { Orchestrator as OrchestratorClass } from './orchestrator.js';
import { InjectionTester } from './injection-tester.js';
import { AuthBypassAgent } from './auth-bypass-agent.js';
import { SSRFProber } from './ssrf-prober.js';
import { SupplyChainAudit } from './supply-chain-agent.js';
import { ConfigAuditor } from './config-auditor.js';
import { LLMRedTeam } from './llm-redteam.js';
import { MobileScanner } from './mobile-scanner.js';
import { GitHistoryScanner } from './git-history-scanner.js';
import { CICDScanner } from './cicd-scanner.js';
import { APIFuzzer } from './api-fuzzer.js';
import { SupabaseRLSAgent } from './supabase-rls-agent.js';
import { MCPSecurityAgent } from './mcp-security-agent.js';
import { AgenticSecurityAgent } from './agentic-security-agent.js';
import { RAGSecurityAgent } from './rag-security-agent.js';
import { PIIComplianceAgent } from './pii-compliance-agent.js';
import { VibeCodingAgent } from './vibe-coding-agent.js';
import { ExceptionHandlerAgent } from './exception-handler-agent.js';
import { AgentConfigScanner } from './agent-config-scanner.js';
import { MemoryPoisoningAgent } from './memory-poisoning-agent.js';
import { ManagedAgentScanner } from './managed-agent-scanner.js';
import { HermesSecurityAgent } from './hermes-security-agent.js';
import { AgentAttestationAgent } from './agent-attestation-agent.js';
import { AgenticSupplyChainAgent } from './agentic-supply-chain-agent.js';
import { RobloxSecurityAgent } from './roblox-security-agent.js';
import { ModelScanAgent } from './model-scan-agent.js';
import { TrustBoundaryAgent } from './trust-boundary-agent.js';
import { SlopSquatAgent } from './slopsquat-agent.js';
import { ClickFixAgent } from './clickfix-agent.js';
import { InstallGuardAgent } from './install-guard-agent.js';
import { SecretsAgent } from './secrets-agent.js';
import { TaintFlowAgent } from './taint-flow-agent.js';
import { UnusedGuardAgent } from './unused-guard-agent.js';
import { loadPlugins } from '../utils/plugin-loader.js';

const BUILT_IN_AGENTS = () => [
  new InjectionTester(),
  new AuthBypassAgent(),
  new SSRFProber(),
  new SupplyChainAudit(),
  new ConfigAuditor(),
  new LLMRedTeam(),
  new MobileScanner(),
  new GitHistoryScanner(),
  new CICDScanner(),
  new APIFuzzer(),
  new SupabaseRLSAgent(),
  new MCPSecurityAgent(),
  new AgenticSecurityAgent(),
  new RAGSecurityAgent(),
  new PIIComplianceAgent(),
  new VibeCodingAgent(),
  new ExceptionHandlerAgent(),
  new AgentConfigScanner(),
  new MemoryPoisoningAgent(),
  new ManagedAgentScanner(),
  new HermesSecurityAgent(),
  new AgentAttestationAgent(),
  new AgenticSupplyChainAgent(),
  new RobloxSecurityAgent(),
  new ModelScanAgent(),
  new TrustBoundaryAgent(),
  new SlopSquatAgent(),
  new ClickFixAgent(),
  new InstallGuardAgent(),
  new SecretsAgent(),
  new TaintFlowAgent(),
  new UnusedGuardAgent(),
];

export const BUILT_IN_AGENT_COUNT = BUILT_IN_AGENTS().length;

/**
 * Lists each built-in agent's own declared name/description/category — the exact strings
 * passed to super() in each agent file's constructor, not a separately maintained summary.
 * Used to tell the LLM reasoning pass (agents/scan.md) what the deterministic half already
 * covers, without duplicating per-rule regex/description/fix detail into its prompt: a plugin
 * or a new built-in agent shows up here automatically, with no second file to keep in sync.
 */
export function listBuiltInAgents() {
  return BUILT_IN_AGENTS().map((a) => ({ name: a.name, description: a.description, category: a.category }));
}

/**
 * Async build — loads built-in agents + any plugins from .sast-engine/agents/.
 *
 * @param {string} rootPath — project root (for plugin discovery)
 * @param {object} options  — { verbose, quiet }
 */
export async function buildOrchestratorAsync(rootPath, options = {}) {
  const orchestrator = new OrchestratorClass();
  orchestrator.registerAll(BUILT_IN_AGENTS());

  if (rootPath) {
    const plugins = await loadPlugins(rootPath, options);
    if (plugins.length > 0) {
      orchestrator.registerAll(plugins);
    }
  }

  return orchestrator;
}
