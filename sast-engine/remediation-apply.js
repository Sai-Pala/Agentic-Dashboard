/**
 * Remediation apply/validate — deterministic edit-plan mechanics
 * ================================================================
 *
 * Adapted from the open-source ship-safe project's agent-fix command (MIT
 * license, see LICENSE), stripped down to the plan-validation/apply mechanics
 * only — no LLM provider, no interactive prompts, no extra logging.
 * This app's Remediation agent still uses an LLM (via `claude -p`) to
 * draft the edit plan; what moves here is the part that used to be "trust the model's own
 * Edit/Write tool calls" — every proposed edit is now validated against the real file (exact
 * or whitespace-tolerant unique match) before anything is written, and disk writes only ever
 * happen through applyEdit() below, never through a tool call the model controls directly.
 *
 * Plan shape (produced by agents/remediation.md's `edit_plan` field):
 *   { summary, risk, files: [
 *       { path, edits: [{ find, replace, reason }] }              — standard edit
 *     | { path, create: true, content }                            — new file (safe paths only)
 *     | { path, append: "text" }                                   — append (safe paths only)
 *   ]}
 */

import fs from 'fs';
import path from 'path';

const NEVER_EDIT = [
  /(^|\/)\.env(\.|$)/i,
  /\.pem$|\.key$|\.p12$|\.pfx$/i,
  /package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$/i,
  /(^|\/)node_modules\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /\.min\.(js|css)$/,
];
// Files the plan IS allowed to create or append to freely (companions to a fix).
const SAFE_NEW_FILES = [
  /(^|\/)\.env\.example$/i,
  /(^|\/)\.env\.sample$/i,
  /(^|\/)\.gitignore$/i,
];

/**
 * Try exact match first, then whitespace-normalized match if exact misses.
 * Returns { kind: 'unique'|'ambiguous'|'missing', matched, count }
 */
export function locateFindString(haystack, needle) {
  const exact = countOccurrences(haystack, needle);
  if (exact === 1) return { kind: 'unique', matched: needle, count: 1 };
  if (exact > 1) return { kind: 'ambiguous', matched: needle, count: exact };

  const norm = (s) => s.replace(/[ \t]+/g, ' ').replace(/\s*\n\s*/g, '\n').trim();
  const needleNorm = norm(needle);
  if (!needleNorm) return { kind: 'missing', matched: null, count: 0 };

  const lines = haystack.split('\n');
  const needleLines = needleNorm.split('\n').length;
  let foundIdx = -1;
  let foundCount = 0;
  for (let i = 0; i + needleLines <= lines.length; i++) {
    const window = lines.slice(i, i + needleLines).join('\n');
    if (norm(window) === needleNorm) {
      foundIdx = i;
      foundCount++;
      if (foundCount > 1) break;
    }
  }
  if (foundCount === 1) {
    const matched = lines.slice(foundIdx, foundIdx + needleLines).join('\n');
    return { kind: 'unique', matched, count: 1 };
  }
  if (foundCount > 1) return { kind: 'ambiguous', matched: null, count: foundCount };
  return { kind: 'missing', matched: null, count: 0 };
}

export function countOccurrences(haystack, needle) {
  if (!needle) return 0;
  let count = 0, idx = 0;
  while ((idx = haystack.indexOf(needle, idx)) !== -1) { count++; idx += needle.length; }
  return count;
}

/**
 * Validate a plan against the real files on disk before anything is written. Returns
 * { ok: true } or { ok: false, reason }. Mutates each edit with `_resolvedFind` (the actual
 * matched text) for use by applyEdit() below.
 */
export function validatePlan(root, plan) {
  if (!plan || !Array.isArray(plan.files) || plan.files.length === 0) {
    return { ok: false, reason: 'plan has no file changes' };
  }

  for (const f of plan.files) {
    if (!f.path) return { ok: false, reason: 'file entry missing path' };

    const rel = String(f.path).replace(/\\/g, '/');
    const isSafeNew = SAFE_NEW_FILES.some((p) => p.test(rel));

    if (!isSafeNew && NEVER_EDIT.some((p) => p.test(rel))) {
      return { ok: false, reason: `protected path: ${f.path}` };
    }

    // Containment must compare against root + separator. A bare `abs.startsWith(root)` is a
    // string-prefix test with no path-boundary awareness, so with root "/home/u/app" the path
    // "../app-secrets/creds.js" resolves to "/home/u/app-secrets/creds.js", which starts with
    // "/home/u/app" and passed. The write then landed outside the directory the user confirmed
    // in the Fix dialog — the single thing that gate exists to guarantee.
    const resolvedRoot = path.resolve(root);
    const abs = path.resolve(resolvedRoot, f.path);
    if (abs !== resolvedRoot && !abs.startsWith(resolvedRoot + path.sep)) {
      return { ok: false, reason: `path escapes target directory: ${f.path}` };
    }
    const exists = fs.existsSync(abs);

    if (f.create || f.append !== undefined) {
      if (!exists && !isSafeNew) {
        return { ok: false, reason: `cannot create new file at ${f.path}` };
      }
      // `create: true` against a file that already exists is a whole-file overwrite, and this
      // branch ends in `continue` — skipping the find-string validation below entirely. So a
      // plan could replace any existing file wholesale, with no find string and therefore no
      // check that the model was even looking at the current contents, by setting one boolean.
      // That defeats the entire purpose of this function: never write something that does not
      // match the live file. Overwriting an existing path is only allowed for the explicitly
      // safe companion files (.env.example, .gitignore) that SAFE_NEW_FILES already names.
      if (f.create && exists && !isSafeNew) {
        return {
          ok: false,
          reason: `refusing to overwrite existing file ${f.path} — use edits with a find string, not create`,
        };
      }
      if (f.create && typeof f.content !== 'string') {
        return { ok: false, reason: 'create entry missing content' };
      }
      if (f.append !== undefined && typeof f.append !== 'string') {
        return { ok: false, reason: 'append must be a string' };
      }
      continue;
    }

    if (!exists) return { ok: false, reason: `file not found: ${f.path}` };
    if (!Array.isArray(f.edits) || f.edits.length === 0) {
      return { ok: false, reason: `no edits for ${f.path}` };
    }

    const content = fs.readFileSync(abs, 'utf8');
    for (const e of f.edits) {
      if (typeof e.find !== 'string' || typeof e.replace !== 'string') {
        return { ok: false, reason: 'edit missing find/replace' };
      }
      if (e.find === e.replace) {
        return { ok: false, reason: 'edit is a no-op' };
      }
      const match = locateFindString(content, e.find);
      if (match.kind === 'missing') {
        return { ok: false, reason: `find string not present in ${f.path}` };
      }
      if (match.kind === 'ambiguous') {
        return { ok: false, reason: `find string is ambiguous (${match.count} matches) in ${f.path}` };
      }
      e._resolvedFind = match.matched;
    }
  }
  return { ok: true };
}

/**
 * Apply an already-validated plan to disk. Call validatePlan() first — this trusts
 * `_resolvedFind` was set by it and does not re-check protected paths itself.
 */
export function applyPlan(root, plan) {
  for (const fileChange of plan.files) {
    const abs = path.resolve(root, fileChange.path);

    if (fileChange.create) {
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, fileChange.content, 'utf8');
      continue;
    }

    if (fileChange.append !== undefined) {
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      const existing = fs.existsSync(abs) ? fs.readFileSync(abs, 'utf8') : '';
      if (existing.includes(fileChange.append.trim())) continue; // already present
      const sep = existing && !existing.endsWith('\n') ? '\n' : '';
      fs.writeFileSync(abs, existing + sep + fileChange.append, 'utf8');
      continue;
    }

    let content = fs.readFileSync(abs, 'utf8');
    for (const e of fileChange.edits) {
      const find = e._resolvedFind || e.find;
      if (!content.includes(find)) {
        throw new Error(`find string drifted in ${fileChange.path} (file changed since validation)`);
      }
      content = content.replace(find, e.replace);
    }
    fs.writeFileSync(abs, content, 'utf8');
  }
}
