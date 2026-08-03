/**
 * UnusedGuardAgent
 * ================
 *
 * Reports security functions that are defined, exported, and never called, and
 * routers mounted with no guard in front of them.
 *
 * This is a whole-app structural check, not a pattern match — it cannot be
 * expressed as a regex over one line, because the evidence is an *absence*
 * spread across the tree. It reads the manifest built by enumerate.js rather
 * than scanning files itself.
 *
 * Why this class is worth its own agent: a codebase that contains
 * `requireAdmin` and never applies it is not missing a security control by
 * oversight of design — someone wrote the control, believed it was in force, and
 * it is not. That is a different and more dangerous situation than never having
 * written one, because a reviewer reading auth.js sees a hardened system. It is
 * also invisible to every line-local rule: nothing about the definition looks
 * wrong, and nothing about the unguarded route mentions the guard.
 *
 * Confidence is deliberately capped at medium. Reference counting here is
 * textual, so a function invoked dynamically (a name looked up in a map, wired
 * by a framework decorator, or called from a template) reads as unused when it
 * is not. Reporting it as a certainty would be overclaiming.
 */

import { BaseAgent, createFinding } from '../core/base-agent.js';

/**
 * Names that indicate a function whose absence has security consequences.
 * Narrower than enumerate.js's heuristic: that one is broad because it feeds a
 * prompt, where a false entry costs a sentence. This one produces findings, so
 * it only fires on names that clearly describe enforcement.
 */
const ENFORCEMENT_NAME_RE =
  /^(?:require|ensure|assert|authorize|authenticate|guard|protect|restrict|verify|validate|check)[A-Z_]|(?:^|[^a-z])(?:auth|admin|permission|role|csrf|xsrf|acl|rbac|owner|tenant)/i;

/** Functions whose job is to produce a safe value rather than to gate access. */
const SAFETY_NAME_RE = /^(?:safe|sanitiz|escape|encrypt|hash|redact|mask)/i;

/** A mount path or router name that implies elevated capability. */
const PRIVILEGED_SURFACE_RE = /admin|internal|manage|ops|privileged|superuser|root|staff|backoffice/i;

/**
 * Middleware that checks *what you are allowed to do*, as opposed to merely
 * *that you are someone*.
 *
 * Two regexes rather than one: the vocabulary check must be case-insensitive
 * (`requireAdmin` capitalizes the word), while the camelCase predicate check
 * depends on case to mean anything at all. Folding them into a single /i regex
 * silently breaks the first — which is exactly the bug this comment exists to
 * stop someone reintroducing.
 */
const PRIVILEGE_WORD_RE = /admin|role|permission|privileg|acl|rbac|scope|claim|staff|superuser|owner|tenant/i;
const PRIVILEGE_PREDICATE_RE = /\b(?:can|is|has|may)[A-Z]/;
const isPrivilegeCheck = (name) => PRIVILEGE_WORD_RE.test(name) || PRIVILEGE_PREDICATE_RE.test(name);

export class UnusedGuardAgent extends BaseAgent {
  constructor() {
    super('UnusedGuardAgent', 'Find security controls that are defined but never applied', 'access-control');
  }

  shouldRun() {
    return true;
  }

  async analyze(context) {
    const surface = context.surface;
    if (!surface) return []; // orchestrator always provides this; standalone callers may not
    const findings = [];

    for (const fn of surface.securityFunctions) {
      if (fn.callCount > 0) continue;
      const enforcing = ENFORCEMENT_NAME_RE.test(fn.name);
      const safety = SAFETY_NAME_RE.test(fn.name);
      if (!enforcing && !safety) continue;

      findings.push(createFinding({
        file: this._absolute(context.rootPath, fn.file),
        line: fn.line,
        column: 1,
        severity: enforcing ? 'high' : 'medium',
        category: 'access-control',
        rule: enforcing ? 'SECURITY_CONTROL_NEVER_APPLIED' : 'SAFE_HELPER_NEVER_USED',
        title: enforcing
          ? `Security control \`${fn.name}\` is defined but never applied`
          : `Safe helper \`${fn.name}\` is defined but never used`,
        description: enforcing
          ? `\`${fn.name}\` is defined at ${fn.file}:${fn.line} and has no call sites anywhere in the codebase. The protection it implements is currently enforced nowhere, so any route or operation meant to be covered by it is unprotected — while the code reads as though the control exists.`
          : `\`${fn.name}\` is defined at ${fn.file}:${fn.line} and has no call sites anywhere in the codebase. If a less safe alternative is being used in its place, every caller of that alternative carries the risk this helper was written to remove.`,
        matched: `${fn.name}(...)`,
        confidence: 'medium',
        cwe: enforcing ? 'CWE-862' : 'CWE-1173',
        owasp: 'A01:2021',
        fix: enforcing
          ? `Apply \`${fn.name}\` to the routes it was written to protect, or delete it so the codebase does not imply a control that is not in force.`
          : `Use \`${fn.name}\` at the call sites currently using the unsafe alternative, or delete it.`,
      }));
    }

    // Authentication mistaken for authorization. A privileged surface guarded
    // only by "is this someone" lets every logged-in customer reach it, and it
    // reads as protected in review — which is why it survives. Reported at the
    // mount rather than at the unused control, because the mount is where the
    // missing middleware has to be added.
    const privilegeControls = surface.securityFunctions
      .filter((f) => isPrivilegeCheck(f.name) && ENFORCEMENT_NAME_RE.test(f.name));

    for (const mount of surface.mounts) {
      if (!mount.prefix || !mount.mounted) continue;
      if (!PRIVILEGED_SURFACE_RE.test(`${mount.prefix} ${mount.mounted}`)) continue;
      if (mount.middleware.some((mw) => isPrivilegeCheck(mw))) continue;
      if (!mount.middleware.length) continue; // no guard at all — covered by the rule below
      if (!privilegeControls.length) continue; // app has no privilege concept to apply

      const names = privilegeControls.map((f) => `${f.name} (${f.file}:${f.line})`).join(', ');
      findings.push(createFinding({
        file: this._absolute(context.rootPath, mount.file),
        line: mount.line,
        column: 1,
        severity: 'high',
        category: 'access-control',
        rule: 'PRIVILEGED_SURFACE_AUTHENTICATED_NOT_AUTHORIZED',
        title: `${mount.prefix} is gated by authentication only, never authorization`,
        description: `\`${mount.prefix}\` mounts \`${mount.mounted}\` behind ${mount.middleware.join(' -> ')}, which establishes *who* the caller is but never checks *what they are allowed to do*. Any authenticated user — including an ordinary customer — can reach every route inside it. This codebase already defines a privilege check that is not applied here: ${names}.`,
        matched: mount.code,
        confidence: 'high',
        cwe: 'CWE-285',
        owasp: 'A01:2021',
        fix: `Add the privilege check to this mount, e.g. app.use('${mount.prefix}', ${mount.middleware.join(', ')}, ${privilegeControls[0].name}, ${mount.mounted}).`,
      }));
    }

    for (const mount of surface.mounts) {
      if (!mount.prefix || !mount.mounted) continue;
      if (mount.middleware.length > 0) continue;
      // A router mounted with no guard is only interesting when the app has
      // guards elsewhere — otherwise this is simply an app without auth, which
      // other rules already cover and which would fire on every public route.
      const appHasGuards = surface.mounts.some((m) => m.middleware.length > 0)
        || surface.routes.some((r) => r.middleware.length > 0);
      if (!appHasGuards) continue;
      if (!/admin|internal|manage|ops|config|debug|private/i.test(mount.prefix + ' ' + mount.mounted)) continue;

      findings.push(createFinding({
        file: this._absolute(context.rootPath, mount.file),
        line: mount.line,
        column: 1,
        severity: 'high',
        category: 'access-control',
        rule: 'PRIVILEGED_ROUTER_MOUNTED_UNGUARDED',
        title: `Privileged router mounted at ${mount.prefix} with no middleware`,
        description: `\`${mount.prefix}\` mounts \`${mount.mounted}\` with no middleware in front of it, while other mounts in this app do carry guards. Every route inside that router is reachable by anyone who can reach the app.`,
        matched: mount.code,
        confidence: 'medium',
        cwe: 'CWE-862',
        owasp: 'A01:2021',
        fix: `Add the appropriate authentication and authorization middleware to the \`${mount.prefix}\` mount.`,
      }));
    }

    return findings;
  }

  /** Manifest paths are root-relative; findings carry absolute paths. */
  _absolute(rootPath, relPath) {
    return `${rootPath.replace(/[\\/]+$/, '')}/${relPath}`;
  }
}
