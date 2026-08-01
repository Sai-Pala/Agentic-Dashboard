/**
 * Attack-surface enumeration
 * ==========================
 *
 * Deterministically extracts *what exists* in a codebase — every HTTP route and
 * its middleware chain, every dangerous sink, and every security-relevant
 * function together with its real call count. It reports no vulnerabilities and
 * makes no LLM call. Its output is a manifest.
 *
 * Why this exists: the reasoning pass was being handed a directory and asked to
 * "review it for vulnerabilities", so it read like a sharp engineer skimming —
 * it reported what was *interesting* rather than what was *exhaustive*. Business
 * logic and authorization flaws do not announce themselves in a skim; they are
 * found by asking the same few questions about every endpoint ("who can reach
 * this, what does it trust, what does it change, is authorization enforced").
 * Handing the model an enumerated worklist converts free reading into a fixed
 * set of forced answers, which is what that class of bug actually requires.
 *
 * The same manifest also feeds a deterministic check no LLM is needed for: a
 * security function that is defined and exported but never called anywhere.
 *
 * Extraction runs off a real parse tree (`ast-extract.js`), falling back to the
 * regex path in this file per-file when a file cannot be parsed — so an exotic
 * dialect or a syntax error degrades that one file instead of blanking it.
 *
 * The regex path is kept deliberately rather than deleted: it is the fallback,
 * and it is the reference implementation the AST path was diffed against before
 * becoming the default (`options.forceRegex` still selects it, which is how that
 * comparison is reproduced).
 *
 * Scope limits, stated plainly: this is structural extraction, not semantic
 * analysis. It understands the conventional Express/Koa/Fastify shapes and will
 * miss routes built dynamically — a loop over a config array, a decorator, a
 * generated router — because those have no static route string to read.
 */

import fs from 'fs';
import path from 'path';
import { parseFile, extractFromAst } from './ast-extract.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

/** `router.get('/path', mwA, mwB, handler)` — the conventional route shape. */
const ROUTE_RE =
  /\b(?<obj>app|router|server|api|r)\s*\.\s*(?<method>get|post|put|patch|delete|options|head|all)\s*\(\s*(?<quote>['"`])(?<routePath>[^'"`]*)\k<quote>\s*(?<rest>[^)]*)/;

/** `app.use('/api/admin', requireUser, adminRouter)` — mounts and global middleware. */
const MOUNT_RE =
  /\b(?<obj>app|router|server)\s*\.\s*use\s*\(\s*(?:(?<quote>['"`])(?<prefix>[^'"`]*)\k<quote>\s*,)?\s*(?<rest>[^)]*)/;

/** Function definitions, in the three forms that actually appear. */
const FUNC_DEFS = [
  /^\s*(?:export\s+)?(?:async\s+)?function\s+(?<name>[A-Za-z_$][\w$]*)\s*\(/,
  /^\s*(?:export\s+)?(?:const|let|var)\s+(?<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>/,
  /^\s*(?:export\s+)?(?:const|let|var)\s+(?<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b/,
];

/**
 * Names that suggest a function's job is to enforce or establish safety. Used
 * only to decide what is worth reporting as "defined but never called" — a
 * naming heuristic, so it is deliberately generous and the finding it feeds is
 * medium severity rather than high.
 */
const SECURITY_NAME_RE =
  /^(?:require|ensure|check|verify|validate|assert|authorize|authenticate|guard|protect|restrict|sanitiz|escape|safe|is|has|can|must)[A-Z_]|(?:auth|admin|permission|role|token|csrf|xsrf|sanitiz|escape|validat|verify|guard|acl|rbac|owner|tenant)/i;

/** Operations where untrusted data causes real damage. */
const SINK_KINDS = [
  { kind: 'sql', re: /\b(?:query|execute|raw|\$queryRaw|\$executeRaw)\s*\(/ },
  { kind: 'command', re: /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/ },
  { kind: 'filesystem', re: /\bfs\s*\.\s*\w+|\b(?:readFile|writeFile|unlink|createReadStream|createWriteStream|sendFile)\w*\s*\(/ },
  { kind: 'code-eval', re: /\beval\s*\(|new\s+Function\s*\(|vm\s*\.\s*run/ },
  { kind: 'outbound-http', re: /\b(?:axios|fetch|got|request|superagent)\b\s*\.?\s*\w*\s*\(/ },
  { kind: 'response', re: /\bres(?:ponse)?\s*\.\s*(?:send|json|write|end|render|redirect|sendFile)\s*\(/ },
  { kind: 'crypto', re: /\bcrypto\s*\.\s*create(?:Cipheriv|Hash|Hmac)|jwt\s*\.\s*(?:sign|verify|decode)\s*\(/ },
];

/** Lines that reference a name without using it: imports and re-exports. */
const IMPORT_LINE_RE = /^\s*(?:import\b|(?:const|let|var)\s*\{?[^=]*=\s*require\s*\()/;
const EXPORT_LINE_RE = /^\s*(?:module\.exports|exports\.|export\s*\{)/;
/** Opens a multi-line `module.exports = {` / `export {` block. */
const EXPORT_BLOCK_OPEN_RE = /^\s*(?:module\.exports\s*=\s*\{|export\s*\{)\s*$|^\s*module\.exports\s*=\s*\{[^}]*$/;

/**
 * Find the line range of a function body, by brace matching from its definition.
 *
 * Needed so a function's own recursive calls are not counted as uses of it. A
 * recursive merge helper that nothing else ever calls is unused from the outside
 * — which is exactly the finding — but counting its self-call hides that.
 */
function bodyRange(lines, startIdx) {
  let depth = 0;
  let seenOpen = false;
  for (let i = startIdx; i < lines.length && i < startIdx + 400; i++) {
    for (const ch of lines[i]) {
      if (ch === '{') { depth++; seenOpen = true; }
      else if (ch === '}') depth--;
    }
    if (seenOpen && depth <= 0) return [startIdx, i];
  }
  return [startIdx, startIdx];
}

function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '/' && line[i + 1] === '/') return line.slice(0, i);
  }
  return line;
}

/**
 * Strip `/* … *\/` blocks across the whole file before scanning.
 *
 * Not cosmetic: security tooling and framework code are full of documentation
 * examples like `app.get('/admin', requireAuth, handler)` inside doc comments,
 * and enumerating those as real routes puts endpoints in the manifest that do
 * not exist — the worst possible input to a pass whose job is to reason about
 * the real attack surface.
 */
function blankBlockComments(content) {
  let out = '';
  let i = 0;
  let quote = null;
  while (i < content.length) {
    const ch = content[i];
    if (quote) {
      if (ch === '\\') { out += content.slice(i, i + 2); i += 2; continue; }
      if (ch === quote) quote = null;
      out += ch; i++; continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; out += ch; i++; continue; }
    if (ch === '/' && content[i + 1] === '/') {
      while (i < content.length && content[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    if (ch === '/' && content[i + 1] === '*') {
      // Preserve newlines so every reported line number stays correct.
      while (i < content.length && !(content[i] === '*' && content[i + 1] === '/')) {
        out += content[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += '  '; i += 2;
      continue;
    }
    out += ch; i++;
  }
  return out;
}

/**
 * Pull identifier arguments out of a route/use call's argument tail. An inline
 * handler (`(req, res) => {`) is not a middleware name, and neither is a call
 * expression like `express.json()`; both are skipped so what remains is the
 * chain of named middleware guarding the route.
 */
function middlewareNames(rest) {
  if (!rest) return [];
  const out = [];
  let depth = 0;
  // Only identifiers at the call's own argument level are middleware. Anything
  // inside nested parentheses is an argument to something else — without this,
  // `app.use(express.static(path.join(__dirname, 'public')))` reports __dirname
  // as a guard.
  for (const m of rest.matchAll(/[()]|[A-Za-z_$][\w$.]*/g)) {
    const tok = m[0];
    if (tok === '(') { depth++; continue; }
    if (tok === ')') { depth--; continue; }
    if (depth !== 0) continue;
    const after = rest.slice(m.index + tok.length).match(/^\s*\(/);
    if (after) continue;                        // a call, e.g. express.json()
    if (/^(?:req|res|next|async|function|await|new)$/.test(tok)) continue;
    out.push(tok);
  }
  return out;
}

function isInlineHandler(rest) {
  return /\(\s*(?:req|request)\s*,\s*(?:res|response)/.test(rest || '') || /=>\s*\{?\s*$/.test(rest || '');
}

/**
 * Walk a directory, honouring the same skip rules the scanning agents use.
 * Accepts an explicit file list instead when the caller already has one.
 */
function discover(rootPath, skipDirs) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name.startsWith('.')) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (skipDirs.has(e.name)) continue;
        walk(full);
      } else if (CODE_EXTENSIONS.has(path.extname(e.name).toLowerCase())) {
        out.push(full);
      }
    }
  };
  walk(rootPath);
  return out;
}

/**
 * Build the manifest.
 *
 * @param {string} rootPath
 * @param {{ files?: string[], skipDirs?: Set<string>, maxFiles?: number }} [options]
 */
export function enumerateSurface(rootPath, options = {}) {
  const skipDirs = options.skipDirs || new Set(['node_modules', 'dist', 'build', 'coverage', 'vendor', '.git']);
  // Filter by extension even when the caller supplies the list. discover()
  // already does this, but the orchestrator passes its own file set — which
  // includes package.json, .md, .yml and so on — and every one of those counts
  // as a parse failure, inflating the fallback rate and wasting a parse attempt
  // on a file that was never JavaScript.
  const files = (options.files || discover(rootPath, skipDirs))
    .filter((f) => CODE_EXTENSIONS.has(path.extname(f).toLowerCase()))
    .slice(0, options.maxFiles || 5000);

  const routes = [];
  const mounts = [];
  const sinks = [];
  const definitions = [];          // every function definition seen
  const referenceCounts = new Map(); // name -> count of real (non-import, non-export, non-definition) references

  const rel = (f) => path.relative(rootPath, f).split(path.sep).join('/');

  let parsedFiles = 0;
  let fallbackFiles = 0;

  for (const file of files) {
    let content;
    try { content = fs.readFileSync(file, 'utf8'); } catch { continue; }
    if (content.length > 1_000_000) continue;
    const relPath = rel(file);

    // Preferred path: a real parse tree. Falls back per file, not per run — one
    // unparseable file degrades to regex rather than disappearing from the map.
    if (!options.forceRegex) {
      const ast = parseFile(content, file);
      if (ast) {
        parsedFiles++;
        const got = extractFromAst(ast, relPath);
        const srcLines = content.split(/\r?\n/);
        const codeAt = (n) => (n && srcLines[n - 1] ? srcLines[n - 1].trim().slice(0, 200) : '');
        for (const r of got.routes) routes.push({ ...r, code: codeAt(r.line) });
        for (const m of got.mounts) mounts.push({ ...m, code: codeAt(m.line) });
        for (const s of got.sinks) sinks.push({ ...s, code: codeAt(s.line) });
        definitions.push(...got.definitions);
        for (const ref of got.references) {
          const list = referenceCounts.get(ref.name) || [];
          list.push({ file: ref.file, line: ref.line });
          referenceCounts.set(ref.name, list);
        }
        continue;
      }
      fallbackFiles++;
    }

    const lines = blankBlockComments(content).split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];
      const line = stripComment(raw);
      if (!line.trim()) continue;

      const routeMatch = line.match(ROUTE_RE);
      if (routeMatch) {
        const { method, routePath, rest } = routeMatch.groups;
        routes.push({
          method: method.toUpperCase(),
          path: routePath,
          file: relPath,
          line: i + 1,
          middleware: middlewareNames(rest),
          inlineHandler: isInlineHandler(rest),
          code: line.trim().slice(0, 200),
        });
      } else {
        const mountMatch = line.match(MOUNT_RE);
        if (mountMatch) {
          const { prefix, rest } = mountMatch.groups;
          const names = middlewareNames(rest);
          if (names.length || prefix) {
            // In a prefixed use(), the LAST identifier is the router being
            // mounted and everything before it guards that whole subtree. With
            // a single name there is no guard at all — `app.use('/api/x', x)`
            // mounts x unprotected, which is the case worth surfacing, so it
            // must not be misread as "guarded by x".
            const hasPrefix = Boolean(prefix);
            mounts.push({
              prefix: prefix || null,
              file: relPath,
              line: i + 1,
              middleware: hasPrefix ? names.slice(0, -1) : names,
              mounted: hasPrefix && names.length ? names[names.length - 1] : null,
              code: line.trim().slice(0, 200),
            });
          }
        }
      }

      for (const s of SINK_KINDS) {
        if (s.re.test(line)) {
          sinks.push({ kind: s.kind, file: relPath, line: i + 1, code: line.trim().slice(0, 160) });
          break;
        }
      }

      for (const re of FUNC_DEFS) {
        const m = line.match(re);
        if (m) {
          const [bodyStart, bodyEnd] = bodyRange(lines, i);
          definitions.push({
            name: m.groups.name,
            file: relPath,
            line: i + 1,
            exported: /^\s*export\b/.test(line),
            bodyStart: bodyStart + 1,
            bodyEnd: bodyEnd + 1,
          });
          break;
        }
      }
    }

    // Second pass for references, recorded with their location so a definition
    // can later discount its own body (recursion) and its own definition line.
    let inExportBlock = false;
    for (let i = 0; i < lines.length; i++) {
      const line = stripComment(lines[i]);
      if (!line.trim()) continue;

      // A multi-line `module.exports = { a, b, c }` lists names without using
      // them. Excluding only its first line — as an earlier version did — made
      // every exported function look called, which silently defeated the whole
      // unused-function check.
      if (inExportBlock) {
        if (line.includes('}')) inExportBlock = false;
        continue;
      }
      if (EXPORT_BLOCK_OPEN_RE.test(line)) { inExportBlock = !line.includes('}'); continue; }
      if (IMPORT_LINE_RE.test(line) || EXPORT_LINE_RE.test(line)) continue;

      for (const m of line.matchAll(/\b([A-Za-z_$][\w$]*)\b/g)) {
        const name = m[1];
        const list = referenceCounts.get(name) || [];
        list.push({ file: relPath, line: i + 1 });
        referenceCounts.set(name, list);
      }
    }
  }

  // Turn raw references into real uses: drop the definition line itself, and
  // drop anything inside the function's own body, which is recursion rather
  // than a caller. What survives is split by file so "used only where it is
  // defined" stays distinguishable from "used across the app".
  const securityFunctions = [];
  for (const def of definitions) {
    if (!SECURITY_NAME_RE.test(def.name)) continue;
    const refs = referenceCounts.get(def.name) || [];
    const uses = refs.filter((r) => {
      if (r.file === def.file && r.line === def.line) return false;             // the definition
      if (r.file === def.file && r.line >= def.bodyStart && r.line <= def.bodyEnd) return false; // recursion
      return true;
    });
    const external = uses.filter((r) => r.file !== def.file);
    securityFunctions.push({
      ...def,
      callCount: uses.length,
      externalCallCount: external.length,
      callSites: uses.slice(0, 10),
    });
  }

  // Resolve each route's full path through the mount that carries its router,
  // best-effort: only when a single prefixed mount exists for the route's file.
  const mountByFile = new Map();
  for (const m of mounts) {
    if (!m.prefix || !m.mounted) continue;
    const list = mountByFile.get(m.mounted) || [];
    list.push(m);
    mountByFile.set(m.mounted, list);
  }

  return {
    root: rootPath,
    fileCount: files.length,
    parsedFiles,
    fallbackFiles,
    routes,
    mounts,
    sinks,
    securityFunctions,
    counts: {
      routes: routes.length,
      mounts: mounts.length,
      sinks: sinks.length,
      securityFunctions: securityFunctions.length,
      unusedSecurityFunctions: securityFunctions.filter((f) => f.callCount === 0).length,
    },
  };
}

// Hard caps on each worklist section. The routes a call is asked about are
// already bounded by the caller's sharding, but the whole-app context sections
// (mounts, unused controls) and the sink list are not — and on a large
// application either can run to thousands of entries. An unbounded worklist
// spends the call's entire budget on its own instructions before the model
// reads a single line of code. Overflow is always stated, never silently cut:
// "+N more" is the difference between a bounded review and a misleading one.
const WORKLIST_MAX_ROUTES = 60;
const WORKLIST_MAX_MOUNTS = 60;
const WORKLIST_MAX_UNUSED = 40;
const WORKLIST_MAX_SINKS_PER_KIND = 30;

/**
 * Render the manifest as the worklist text handed to a reasoning call.
 *
 * Scoped to `onlyFiles` when given, so a shard-scoped call sees only its own
 * routes but still gets the whole-app middleware/mount picture — without that
 * context it cannot tell whether a route's guard is applied somewhere else.
 */
export function renderWorklist(manifest, onlyFiles = null) {
  const inScope = onlyFiles ? new Set(onlyFiles.map((f) => f.split(path.sep).join('/'))) : null;
  const keep = (item) => !inScope || inScope.has(item.file);

  const routes = manifest.routes.filter(keep);
  const sinks = manifest.sinks.filter(keep);
  const lines = [];

  lines.push('## Enumerated attack surface');
  lines.push('');
  lines.push('This was extracted mechanically from the code. It is what EXISTS, not what is');
  lines.push('wrong. Work through it item by item — do not skim for whatever looks most');
  lines.push('interesting, because the flaws that matter here do not look interesting.');
  lines.push('');

  // Emits at most `max` rendered items and, when there were more, a line saying
  // exactly how many were left out.
  const pushCapped = (items, max, render, moreLabel) => {
    for (const item of items.slice(0, max)) lines.push(render(item));
    if (items.length > max) {
      lines.push(`- (+${items.length - max} more ${moreLabel} not listed here — not reviewed by this call)`);
    }
  };

  if (routes.length) {
    lines.push(`### Routes in your scope (${Math.min(routes.length, WORKLIST_MAX_ROUTES)}`
      + `${routes.length > WORKLIST_MAX_ROUTES ? ` of ${routes.length}` : ''})`);
    lines.push('');
    lines.push('For EACH route, answer all four before moving on:');
    lines.push('  1. Who can reach it? (unauthenticated / any logged-in user / admin only)');
    lines.push('  2. What request data does it trust without validating?');
    lines.push('  3. What does it read or change, and could that belong to someone else?');
    lines.push('  4. Is the authorization check the right one, or only authentication?');
    lines.push('');
    pushCapped(routes, WORKLIST_MAX_ROUTES, (r) => {
      const mw = r.middleware.length ? r.middleware.join(' -> ') : 'NONE';
      return `- ${r.method} ${r.path}  (${r.file}:${r.line})   middleware: ${mw}`;
    }, 'routes');
    lines.push('');
  }

  if (manifest.mounts.length) {
    lines.push('### Mounts and global middleware (whole app, for context)');
    lines.push('');
    pushCapped(manifest.mounts, WORKLIST_MAX_MOUNTS, (m) => {
      const mw = m.middleware.length ? m.middleware.join(' -> ') : 'none';
      const target = m.mounted ? ` -> ${m.mounted}` : '';
      return `- ${m.prefix || '(global)'}${target}   guards: ${mw}   (${m.file}:${m.line})`;
    }, 'mounts');
    lines.push('');
  }

  const unused = manifest.securityFunctions.filter((f) => f.callCount === 0);
  if (unused.length) {
    lines.push('### Security functions defined but never called (whole app)');
    lines.push('');
    lines.push('Each of these was written to enforce something and is currently enforcing');
    lines.push('nothing. Confirm whether the protection it provides is missing at the places');
    lines.push('that should have it.');
    lines.push('');
    pushCapped(unused, WORKLIST_MAX_UNUSED, (f) => `- ${f.name}()  (${f.file}:${f.line})`, 'unused controls');
    lines.push('');
  }

  if (sinks.length) {
    const byKind = {};
    for (const s of sinks) (byKind[s.kind] = byKind[s.kind] || []).push(s);
    lines.push(`### Sinks in your scope (${sinks.length})`);
    lines.push('');
    lines.push('Trace what reaches each one. A sink fed only by constants is fine; say so and');
    lines.push('move on.');
    lines.push('');
    for (const [kind, items] of Object.entries(byKind)) {
      const shown = items.slice(0, WORKLIST_MAX_SINKS_PER_KIND).map((s) => `${s.file}:${s.line}`).join(', ');
      const extra = items.length > WORKLIST_MAX_SINKS_PER_KIND
        ? ` (+${items.length - WORKLIST_MAX_SINKS_PER_KIND} more)`
        : '';
      lines.push(`- ${kind}: ${shown}${extra}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
