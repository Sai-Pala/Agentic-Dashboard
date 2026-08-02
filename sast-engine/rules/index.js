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

import { Orchestrator as OrchestratorClass } from './core/orchestrator.js';
import { InjectionTester } from './web/injection-tester.js';
import { AuthBypassAgent } from './web/auth-bypass-agent.js';
import { SSRFProber } from './web/ssrf-prober.js';
import { SupplyChainAudit } from './supply-chain/supply-chain-agent.js';
import { ConfigAuditor } from './compliance/config-auditor.js';
import { LLMRedTeam } from './ai/llm-redteam.js';
import { MobileScanner } from './platform/mobile-scanner.js';
import { GitHistoryScanner } from './secrets/git-history-scanner.js';
import { CICDScanner } from './supply-chain/cicd-scanner.js';
import { APIFuzzer } from './web/api-fuzzer.js';
import { SupabaseRLSAgent } from './web/supabase-rls-agent.js';
import { MCPSecurityAgent } from './ai/mcp-security-agent.js';
import { AgenticSecurityAgent } from './ai/agentic-security-agent.js';
import { RAGSecurityAgent } from './ai/rag-security-agent.js';
import { PIIComplianceAgent } from './compliance/pii-compliance-agent.js';
import { VibeCodingAgent } from './ai/vibe-coding-agent.js';
import { ExceptionHandlerAgent } from './web/exception-handler-agent.js';
import { AgentConfigScanner } from './ai/agent-config-scanner.js';
import { MemoryPoisoningAgent } from './ai/memory-poisoning-agent.js';
import { ManagedAgentScanner } from './ai/managed-agent-scanner.js';
import { HermesSecurityAgent } from './ai/hermes-security-agent.js';
import { AgentAttestationAgent } from './ai/agent-attestation-agent.js';
import { AgenticSupplyChainAgent } from './ai/agentic-supply-chain-agent.js';
import { RobloxSecurityAgent } from './platform/roblox-security-agent.js';
import { ModelScanAgent } from './supply-chain/model-scan-agent.js';
import { TrustBoundaryAgent } from './web/trust-boundary-agent.js';
import { SlopSquatAgent } from './supply-chain/slopsquat-agent.js';
import { ClickFixAgent } from './compliance/clickfix-agent.js';
import { InstallGuardAgent } from './supply-chain/install-guard-agent.js';
import { SecretsAgent } from './secrets/secrets-agent.js';
import { TaintFlowAgent } from './web/taint-flow-agent.js';
import { UnusedGuardAgent } from './web/unused-guard-agent.js';
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
