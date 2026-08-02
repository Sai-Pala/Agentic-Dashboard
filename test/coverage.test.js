'use strict';

/**
 * The scan coverage manifest.
 *
 * This is the answer to "what did the scan actually look at", and it exists because the engine
 * drops files through six independent mechanisms and reported none of them. The most important
 * assertion here is not a count — it is that a file removed by an ignore rule is REPORTED as
 * removed. A scanner that silently skips source and then says "no findings" is indistinguishable
 * from one that looked and found nothing.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildCoverageManifest } = require('../src/services/coverage');

/** The engine's own rules, in the shape buildCoverageManifest consumes. */
const fakeEngine = {
  SKIP_DIRS: new Set(['node_modules', 'dist']),
  SKIP_EXTENSIONS: new Set(['.png', '.lock']),
  SKIP_FILENAMES: new Set(['package-lock.json']),
  MAX_FILE_SIZE: 1024,
};

let root;

before(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'coverage-test-'));
  const write = (rel, content) => {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  };
  write('src/app.js', 'const a = 1;');
  write('src/util.js', 'const b = 2;');
  write('src/secret-vendor/sdk.js', 'const c = 3;');   // stands in for gitignored source
  write('logo.png', 'binary');
  write('package-lock.json', '{}');
  write('big.js', 'x'.repeat(2048));                    // over the 1 KB cap
  write('bundle.min.js', 'var a=1');
  write('node_modules/dep/index.js', 'module.exports={}');
  write('dist/out.js', 'built');
  fs.writeFileSync(path.join(root, '.gitignore'), 'src/secret-vendor/\n# a comment\n*.log\n');
});

after(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('scan coverage manifest', () => {
  /** What the engine "found" — everything except the gitignored dir and the local exclusions. */
  const scanned = () => [path.join(root, 'src/app.js'), path.join(root, 'src/util.js')];

  test('counts what was considered and what was actually read', () => {
    const m = buildCoverageManifest(fakeEngine, root, scanned());
    assert.equal(m.scanned, 2);
    assert.ok(m.considered > m.scanned, 'considered must exceed scanned when files were dropped');
  });

  test('skip-directories are pruned and named, not enumerated', () => {
    const m = buildCoverageManifest(fakeEngine, root, scanned());
    const names = m.prunedDirs.map((d) => d.name).sort();
    assert.deepEqual(names, ['dist', 'node_modules']);
    assert.equal(m.prunedDirCount, 2);
    // Nothing inside them should have been counted as considered-then-dropped.
    const allFiles = Object.values(m.dropped).flatMap((d) => d.files);
    assert.ok(!allFiles.some((e) => e.startsWith('node_modules/')), 'pruned dirs must not be walked');
  });

  test('each local exclusion rule is attributed to its own reason', () => {
    const m = buildCoverageManifest(fakeEngine, root, scanned());
    assert.equal(m.dropped.extension.count, 1, 'logo.png');
    assert.equal(m.dropped.filename.count, 1, 'package-lock.json');
    assert.equal(m.dropped.tooLarge.count, 1, 'big.js');
    assert.equal(m.dropped.minified.count, 1, 'bundle.min.js');
  });

  test('a file the engine did not read for no local reason is reported as ignore-excluded', () => {
    // THE point of this module. src/secret-vendor/sdk.js is real source with a scannable
    // extension, under the size cap, not a skipped filename — the only reason it went unread is
    // a .gitignore pattern. Before this manifest existed it vanished with no trace, and the scan
    // reported clean over code it never opened.
    const m = buildCoverageManifest(fakeEngine, root, scanned());
    assert.ok(m.dropped.ignored, 'an ignore-excluded bucket must exist');
    assert.ok(
      m.dropped.ignored.files.some((e) => e.includes('secret-vendor')),
      'the gitignored source file must be named as excluded',
    );
  });

  test('ignore files in play are reported with their pattern counts', () => {
    const m = buildCoverageManifest(fakeEngine, root, scanned());
    assert.equal(m.ignoreFiles.gitignore.present, true);
    assert.equal(m.ignoreFiles.gitignore.patterns, 2, 'comments and blanks are not patterns');
    assert.equal(m.ignoreFiles.sastEngineIgnore.present, false);
  });

  test('every dropped file is named, not sampled', () => {
    // The manifest IS a file listing. It was a 5-item sample once, which reduced the bucket that
    // matters most to "46 files and 44 more" — you cannot check an exclusion you cannot see. The
    // cap that remains is a memory bound; when it bites, `truncated` says so.
    const m = buildCoverageManifest(fakeEngine, root, scanned());
    for (const [reason, d] of Object.entries(m.dropped)) {
      assert.equal(d.files.length, d.count, `${reason} listed ${d.files.length} of ${d.count}`);
      assert.equal(d.truncated, false, `${reason} should not be truncated at this size`);
    }
  });

  test('when everything was read, nothing is reported as dropped', () => {
    const everything = buildCoverageManifest(fakeEngine, root, scanned());
    const all = [];
    (function walk(d) {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) { if (!fakeEngine.SKIP_DIRS.has(e.name)) walk(p); } else all.push(p);
      }
    })(root);
    const m = buildCoverageManifest(fakeEngine, root, all);
    assert.equal(m.scanned, everything.considered);
    assert.deepEqual(m.dropped, {}, 'no drop buckets when the engine read everything');
  });
});
