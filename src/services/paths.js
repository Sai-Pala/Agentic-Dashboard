/**
 * Turning an absolute path from the engine into the repo-relative, forward-slash form that
 * findings, prompts and worklists all use.
 *
 * Small, but it was written out longhand in seven places, and the `.split(path.sep).join('/')`
 * half is easy to drop on a machine where it happens to be a no-op — which is every machine the
 * app is developed on, and not the one a Windows user runs it on.
 */

const path = require('path');

/**
 * Absolute path -> `src/routes/scans.js`, or null when there is no file.
 * Callers choose their own placeholder for the null case; they do not agree on one.
 */
function toRepoRelative(root, absPath) {
  if (!absPath) return null;
  return path.relative(root, absPath).split(path.sep).join('/');
}

module.exports = { toRepoRelative };
