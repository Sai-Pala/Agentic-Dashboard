/**
 * Lazy loader for the vendored deterministic engine (sast-engine/).
 * It is real ESM, so it is pulled in via dynamic import() from this CommonJS tree and cached —
 * none of those modules hold per-call state.
 */

let enginePromise = null;

function loadSastEngine() {
  if (!enginePromise) {
    enginePromise = Promise.all([
      import('../../sast-engine/rules/index.js'),
      import('../../sast-engine/commands/deps.js'),
      import('../../sast-engine/remediation-apply.js'),
      import('../../sast-engine/utils/patterns.js'),
      import('../../sast-engine/enumerate.js'),
      import('../../sast-engine/rules/core/base-agent.js'),
    ]).then(([agentsIndex, deps, remediationApply, patterns, enumerate, baseAgent]) => ({
      buildOrchestratorAsync: agentsIndex.buildOrchestratorAsync,
      listBuiltInAgents: agentsIndex.listBuiltInAgents,
      enumerateSurface: enumerate.enumerateSurface,
      renderWorklist: enumerate.renderWorklist,
      runDepsAudit: deps.runDepsAudit,
      validatePlan: remediationApply.validatePlan,
      applyPlan: remediationApply.applyPlan,
      SKIP_DIRS: patterns.SKIP_DIRS,
      SKIP_EXTENSIONS: patterns.SKIP_EXTENSIONS,
      SKIP_FILENAMES: patterns.SKIP_FILENAMES,
      MAX_FILE_SIZE: patterns.MAX_FILE_SIZE,
      loadGitignorePatterns: patterns.loadGitignorePatterns,
      // The agents' own file discovery. Coverage reporting calls this rather than
      // reimplementing the skip rules, so "what was scanned" cannot drift from what was.
      discoverFiles: (rootPath) => new baseAgent.BaseAgent('coverage', 'file discovery', 'meta')
        .discoverFiles(rootPath),
    }));
  }
  return enginePromise;
}

module.exports = { loadSastEngine };
