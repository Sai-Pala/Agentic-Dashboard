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
    ]).then(([agentsIndex, deps, remediationApply, patterns, enumerate]) => ({
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
    }));
  }
  return enginePromise;
}

module.exports = { loadSastEngine };
