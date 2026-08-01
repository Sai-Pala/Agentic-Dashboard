/**
 * Characterization tests for sast-engine/remediation-apply.js
 * ==========================================================
 *
 * This is the guard on the ONLY code path in this app that writes to a user's real files.
 * The Fix stage makes no LLM call at all — it takes whatever `edit_plan` the Remediate stage
 * proposed and hands it to validatePlan()/applyPlan(). So everything standing between a
 * hallucinated or stale edit and the user's disk is in this one module, which is why it gets
 * its own test file rather than being folded into the engine golden master.
 *
 * These are CHARACTERIZATION tests: they record what the code does TODAY, not what it should
 * do. A failure means behaviour changed — that may be a fix or a regression, and you have to
 * look to know which.
 *
 * TWO TESTS DELIBERATELY ASSERT BUGGY BEHAVIOUR. They are tagged KNOWN-BUG below and were
 * found by this app scanning itself. They exist so the bug cannot change silently; when the
 * bug is fixed, these assertions MUST be inverted, and the fix should be considered incomplete
 * until they are. Do not "repair" them to make a fix pass.
 *
 * Test runner: node:test. Run `npm test`, or `node --test test/remediation-apply.test.js`.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// sast-engine/ is ESM ("type":"module" in its own package.json) while test/ is CommonJS,
// so the module is pulled in with a dynamic import, the same way server.js does it.
let mod;
before(async () => {
  mod = await import('../sast-engine/remediation-apply.js');
});

// Each test gets a throwaway tree so nothing here can touch the repo.
let tmpRoot;
let siblingDir;
before(() => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'remediation-apply-'));
  tmpRoot = path.join(base, 'app');
  // A sibling whose name EXTENDS the root's name. This is the shape that defeats a prefix
  // comparison: "/…/app-secrets".startsWith("/…/app") is true.
  siblingDir = path.join(base, 'app-secrets');
  fs.mkdirSync(tmpRoot, { recursive: true });
  fs.mkdirSync(siblingDir, { recursive: true });
  fs.writeFileSync(path.join(tmpRoot, 'target.js'), 'const a = 1;\nconst b = 2;\nconst a2 = 1;\n');
  fs.writeFileSync(path.join(tmpRoot, 'unique.js'), 'function only() {\n  return 42;\n}\n');
  fs.writeFileSync(path.join(siblingDir, 'creds.js'), 'module.exports = { key: "real" };\n');
});
after(() => {
  try { fs.rmSync(path.dirname(tmpRoot), { recursive: true, force: true }); } catch { /* best effort */ }
});

const plan = (files) => ({ summary: 's', risk: 'low', files });

describe('locateFindString', () => {
  test('an exact single occurrence is unique', () => {
    const r = mod.locateFindString('alpha\nbeta\ngamma', 'beta');
    assert.equal(r.kind, 'unique');
    assert.equal(r.count, 1);
  });

  test('an exact repeated occurrence is ambiguous, never silently first-wins', () => {
    const r = mod.locateFindString('x\nx\n', 'x');
    assert.equal(r.kind, 'ambiguous');
    assert.ok(r.count > 1);
  });

  test('a needle that is absent is missing', () => {
    assert.equal(mod.locateFindString('alpha', 'nope').kind, 'missing');
  });

  test('whitespace-tolerant fallback matches when indentation differs', () => {
    // Exact match misses because of the leading spaces; the normalized pass should still
    // find it uniquely. This is what lets a model-proposed snippet with slightly different
    // indentation still apply rather than being rejected outright.
    const hay = 'function f() {\n      return 1;\n}\n';
    const r = mod.locateFindString(hay, 'function f() {\n  return 1;\n}');
    assert.equal(r.kind, 'unique');
    assert.equal(r.matched.includes('return 1;'), true);
  });

  test('an empty needle is missing rather than matching everything', () => {
    assert.equal(mod.locateFindString('anything', '').kind, 'missing');
  });
});

describe('countOccurrences', () => {
  test('counts non-overlapping occurrences', () => {
    assert.equal(mod.countOccurrences('aaaa', 'aa'), 2);
  });
  test('an empty needle counts zero rather than looping forever', () => {
    assert.equal(mod.countOccurrences('aaaa', ''), 0);
  });
});

describe('validatePlan — structural rejections', () => {
  test('a plan with no files is rejected', () => {
    assert.equal(mod.validatePlan(tmpRoot, plan([])).ok, false);
    assert.equal(mod.validatePlan(tmpRoot, null).ok, false);
    assert.equal(mod.validatePlan(tmpRoot, {}).ok, false);
  });

  test('a file entry with no path is rejected', () => {
    assert.equal(mod.validatePlan(tmpRoot, plan([{ edits: [] }])).ok, false);
  });

  test('a file that does not exist is rejected for a normal edit', () => {
    const r = mod.validatePlan(tmpRoot, plan([{ path: 'nope.js', edits: [{ find: 'x', replace: 'y' }] }]));
    assert.equal(r.ok, false);
    assert.match(r.reason, /not found/i);
  });
});

describe('validatePlan — protected paths', () => {
  // Each of these must be refused regardless of what the plan claims it is doing.
  for (const p of [
    '.env',
    'secrets.pem',
    'id.key',
    'package-lock.json',
    'yarn.lock',
    'node_modules/left-pad/index.js',
    'dist/bundle.js',
    'build/out.js',
    'vendor/jquery.min.js',
  ]) {
    test(`refuses to edit ${p}`, () => {
      const r = mod.validatePlan(tmpRoot, plan([{ path: p, edits: [{ find: 'a', replace: 'b' }] }]));
      assert.equal(r.ok, false, `${p} should be refused`);
      assert.match(r.reason, /protected path/i);
    });
  }

  test('.env.example is exempt — it is a safe companion file, not a secret store', () => {
    // .env.example matches the NEVER_EDIT .env pattern, so this only passes because
    // SAFE_NEW_FILES is checked first. If that ordering is ever inverted, this fails.
    const r = mod.validatePlan(tmpRoot, plan([{ path: '.env.example', create: true, content: 'API_KEY=' }]));
    assert.equal(r.ok, true);
  });
});

describe('validatePlan — find-string resolution', () => {
  test('a find string matching exactly once is accepted and resolved', () => {
    const files = [{ path: 'unique.js', edits: [{ find: 'return 42;', replace: 'return 43;' }] }];
    const r = mod.validatePlan(tmpRoot, plan(files));
    assert.equal(r.ok, true);
    // validatePlan mutates the edit with the actually-matched text for applyEdit() to use.
    assert.equal(files[0].edits[0]._resolvedFind, 'return 42;');
  });

  test('an ambiguous find string is rejected rather than applied to the first hit', () => {
    // 'const a = 1;' appears twice in target.js. Guessing which one the model meant is
    // exactly the silent-corruption failure this validation exists to prevent.
    const r = mod.validatePlan(tmpRoot, plan([
      { path: 'target.js', edits: [{ find: 'const a', replace: 'const z' }] },
    ]));
    assert.equal(r.ok, false);
  });

  test('a find string absent from the live file is rejected (the stale-plan case)', () => {
    const r = mod.validatePlan(tmpRoot, plan([
      { path: 'unique.js', edits: [{ find: 'this text is not in the file', replace: 'x' }] },
    ]));
    assert.equal(r.ok, false);
  });
});

describe('validatePlan — path containment', () => {
  test('an obvious traversal out of the target directory is rejected', () => {
    const r = mod.validatePlan(tmpRoot, plan([
      { path: '../../etc/passwd', edits: [{ find: 'a', replace: 'b' }] },
    ]));
    assert.equal(r.ok, false);
  });

  test('a sibling directory sharing the root name prefix is rejected', () => {
    // REGRESSION GUARD (was KNOWN-BUG, fixed): containment used a bare
    // `abs.startsWith(path.resolve(root))` — a string prefix with no path-boundary awareness.
    // With root "/…/app", "../app-secrets/creds.js" resolves to "/…/app-secrets/creds.js",
    // which startsWith "/…/app" and passed, so the write landed outside the directory the user
    // confirmed in the Fix dialog. Now compared against `resolvedRoot + path.sep`.
    const r = mod.validatePlan(tmpRoot, plan([
      { path: '../app-secrets/creds.js', edits: [{ find: 'real', replace: 'pwned' }] },
    ]));
    assert.equal(r.ok, false);
    assert.match(r.reason, /escapes target directory/i);
  });

  test('the target directory itself is still reachable', () => {
    // The separator fix must not reject a path that resolves to root-relative content.
    const r = mod.validatePlan(tmpRoot, plan([
      { path: './unique.js', edits: [{ find: 'return 42;', replace: 'return 43;' }] },
    ]));
    assert.equal(r.ok, true);
  });
});

describe('validatePlan — create/append handling', () => {
  test('creating a genuinely new file at an unsafe path is rejected', () => {
    const r = mod.validatePlan(tmpRoot, plan([{ path: 'brand-new.js', create: true, content: 'x' }]));
    assert.equal(r.ok, false);
    assert.match(r.reason, /cannot create new file/i);
  });

  test('create without string content is rejected', () => {
    const r = mod.validatePlan(tmpRoot, plan([{ path: '.env.example', create: true }]));
    assert.equal(r.ok, false);
  });

  test('append must be a string', () => {
    const r = mod.validatePlan(tmpRoot, plan([{ path: '.gitignore', append: 123 }]));
    assert.equal(r.ok, false);
  });

  test('create:true against an EXISTING file is refused rather than overwriting it', () => {
    // REGRESSION GUARD (was KNOWN-BUG, fixed): the create/append branch ends in `continue`,
    // skipping find-string validation, and its only existence guard was `!exists && !isSafeNew`
    // — which does not fire when the file exists. So `create: true` accepted a plan with no
    // find string at all and applyPlan() would overwrite the whole file. One boolean bypassed
    // the entire "never write something that does not match the live file" guarantee.
    const r = mod.validatePlan(tmpRoot, plan([
      { path: 'target.js', create: true, content: 'ENTIRE FILE REPLACED' },
    ]));
    assert.equal(r.ok, false);
    assert.match(r.reason, /refusing to overwrite/i);
  });

  test('create:true on a safe companion file that already exists is still allowed', () => {
    // .gitignore is in SAFE_NEW_FILES, so regenerating it stays permitted — the overwrite
    // refusal must not become a blanket ban on the companion files the plan is meant to write.
    fs.writeFileSync(path.join(tmpRoot, '.gitignore'), 'node_modules\n');
    const r = mod.validatePlan(tmpRoot, plan([
      { path: '.gitignore', create: true, content: 'node_modules\ndist\n' },
    ]));
    assert.equal(r.ok, true);
  });
});
