/**
 * What a scan actually looked at.
 *
 * The engine drops files through six independent mechanisms — a 40-entry skip-directory list,
 * 45 skipped extensions, 14 skipped filenames, `.gitignore`, `.sast-engineignore`, and a 1 MB
 * size cap. None of them announce themselves, so without this a user has no way to learn that
 * half of the repository they aimed at was never read.
 *
 * That matters most for `.gitignore`, which is honoured. A vendored SDK, a generated-but-
 * committed client, or a `build/` directory holding real source is skipped silently and the scan
 * reports clean. It is the exact failure the engine's own invariant forbids everywhere else:
 * "no findings" must never be shown where "could not look" is the truth.
 *
 * HOW THE NUMBERS ARE PRODUCED, and why it is done this way:
 *
 *   `scanned`  comes from the engine itself, via the same discoverFiles() the agents use. It is
 *              ground truth, not a reimplementation, so it cannot drift from what was really read.
 *   `considered` comes from a walk here, applying only the skip-directory rule.
 *   The difference is attributed to a reason where this module can determine one locally
 *              (extension, filename, minified, size). Whatever remains is attributed to the
 *              ignore files, because reproducing glob semantics accurately enough to attribute
 *              per-pattern would be a second implementation of the thing most likely to drift.
 *
 * The residual bucket is therefore honest rather than precise: it says "these were excluded by
 * an ignore rule" and names the ignore files in play, without claiming which pattern matched.
 */

const fs = require('fs');
const path = require('path');

/**
 * How many paths to keep per exclusion reason.
 *
 * This IS meant to be a file listing. It was capped at 5 once, which turned the most important
 * bucket — source removed by an ignore rule — into "46 files and 44 more", naming neither the
 * 44 nor the pattern that took them. You cannot check whether an exclusion was correct against a
 * number. The cap that remains is a memory bound, not an editorial one: it sits far above what
 * any real repository produces, and when it does bite, `truncated` says so rather than implying
 * the list is complete.
 */
const MAX_LISTED_FILES = 2000;

/**
 * Walk the tree, skipping the engine's skip-directories without descending into them.
 * Returns every remaining file plus a tally of which directories were pruned.
 */
function walkConsidered(root, skipDirs) {
  const files = [];
  const prunedDirs = new Map(); // dir name -> how many times it was pruned

  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (skipDirs.has(e.name)) {
          prunedDirs.set(e.name, (prunedDirs.get(e.name) || 0) + 1);
          continue;
        }
        walk(full);
      } else if (e.isFile()) {
        files.push(full);
      }
    }
  };
  walk(root);
  return { files, prunedDirs };
}

/** The first rule that excludes this file, or null when nothing local explains it. */
function localExclusionReason(file, engine) {
  const ext = path.extname(file).toLowerCase();
  const base = path.basename(file);

  if (engine.SKIP_EXTENSIONS.has(ext)) return 'extension';
  if (engine.SKIP_FILENAMES.has(base)) return 'filename';
  if (base.endsWith('.min.js') || base.endsWith('.min.css')) return 'minified';
  try {
    if (fs.statSync(file).size > engine.MAX_FILE_SIZE) return 'tooLarge';
  } catch {
    return 'unreadable';
  }
  return null;
}

/** Does this ignore file exist, and how many patterns does it carry? */
function ignoreFileInfo(root, name) {
  const p = path.join(root, name);
  try {
    if (!fs.existsSync(p)) return { present: false, patterns: 0 };
    const patterns = fs.readFileSync(p, 'utf8')
      .split('\n').map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#')).length;
    return { present: true, patterns };
  } catch {
    return { present: false, patterns: 0 };
  }
}

/**
 * Build the manifest.
 *
 * @param {object} engine     loaded sast-engine (for its own skip rules and discoverFiles)
 * @param {string} targetPath
 * @param {string[]} scannedFiles  the files the engine actually discovered — ground truth
 * @returns {object} coverage manifest, safe to store on the scan record
 */
function buildCoverageManifest(engine, targetPath, scannedFiles) {
  const { files: considered, prunedDirs } = walkConsidered(targetPath, engine.SKIP_DIRS);
  const scannedSet = new Set(scannedFiles.map((f) => path.resolve(f)));

  const dropped = {};
  const addDrop = (reason, file) => {
    const bucket = dropped[reason] || (dropped[reason] = { count: 0, files: [], truncated: false });
    bucket.count++;
    if (bucket.files.length < MAX_LISTED_FILES) {
      bucket.files.push(path.relative(targetPath, file).split(path.sep).join('/'));
    } else {
      bucket.truncated = true;
    }
  };

  for (const file of considered) {
    if (scannedSet.has(path.resolve(file))) continue;
    // `ignored` is the residual: excluded, but by a glob rather than by anything decidable here.
    addDrop(localExclusionReason(file, engine) || 'ignored', file);
  }

  const prunedList = [...prunedDirs.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  return {
    root: targetPath,
    // Files present under the target once skip-directories are pruned. Directories like
    // node_modules are counted as pruned rather than enumerated — walking them would dominate
    // the scan's own cost to report a number nobody acts on.
    considered: considered.length,
    scanned: scannedSet.size,
    dropped,
    prunedDirs: prunedList,
    prunedDirCount: prunedList.reduce((n, d) => n + d.count, 0),
    ignoreFiles: {
      gitignore: ignoreFileInfo(targetPath, '.gitignore'),
      sastEngineIgnore: ignoreFileInfo(targetPath, '.sast-engineignore'),
    },
  };
}

module.exports = { buildCoverageManifest };
