/**
 * Dependency Audit
 * ================
 *
 * Audit project dependencies for known CVEs using the package manager's
 * built-in audit tool (npm, yarn, pnpm, pip-audit, bundler-audit).
 *
 * Adapted from the open-source ship-safe project's deps command (MIT
 * license, see LICENSE), trimmed to the programmatic path only
 * (runDepsAudit) — this app's SCA Scan calls this directly rather than
 * shelling out to an external CLI. Dropped: the CLI-printing/`--fix` exec
 * path (this app never auto-runs the package manager's own fix command).
 *
 * SUPPORTED PACKAGE MANAGERS:
 *   npm     →  npm audit --json
 *   yarn    →  yarn audit --json (NDJSON format)
 *   pnpm    →  pnpm audit --json
 *   pip     →  pip-audit --format json  (requires: pip install pip-audit)
 *   bundler →  bundle-audit check       (requires: gem install bundler-audit)
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

// =============================================================================
// PACKAGE MANAGER DETECTION
// =============================================================================

function detectPackageManager(rootPath) {
  // Node.js — detect specific lock file first for accuracy
  if (fs.existsSync(path.join(rootPath, 'pnpm-lock.yaml'))) {
    return {
      name: 'pnpm',
      manifest: 'package.json',
      auditCommand: 'pnpm audit --json',
      fixCommand: 'pnpm audit --fix',
      type: 'npm-v2'
    };
  }

  if (fs.existsSync(path.join(rootPath, 'yarn.lock'))) {
    return {
      name: 'yarn',
      manifest: 'package.json',
      auditCommand: 'yarn audit --json',
      fixCommand: 'yarn upgrade',
      type: 'yarn'
    };
  }

  if (fs.existsSync(path.join(rootPath, 'package.json'))) {
    return {
      name: 'npm',
      manifest: 'package.json',
      auditCommand: 'npm audit --json',
      fixCommand: 'npm audit fix',
      type: 'npm-v2'
    };
  }

  // Python
  if (fs.existsSync(path.join(rootPath, 'requirements.txt'))) {
    return {
      name: 'pip-audit',
      manifest: 'requirements.txt',
      auditCommand: 'pip-audit --format json -r requirements.txt',
      fixCommand: 'pip-audit --fix -r requirements.txt',
      type: 'pip',
      installHint: 'pip install pip-audit'
    };
  }

  // Ruby
  if (fs.existsSync(path.join(rootPath, 'Gemfile.lock'))) {
    return {
      name: 'bundler-audit',
      manifest: 'Gemfile.lock',
      auditCommand: 'bundle-audit check',
      fixCommand: 'bundle update',
      type: 'bundler',
      installHint: 'gem install bundler-audit'
    };
  }

  return null;
}

// =============================================================================
// RUNNING THE AUDIT
// =============================================================================

/**
 * Run the package manager audit and return normalized vulnerability list.
 * Catches exit code 1 (vulnerabilities found) which is NOT a real error.
 */
function runAudit(pm, cwd) {
  let stdout;
  try {
    stdout = execSync(pm.auditCommand, { cwd, stdio: ['pipe', 'pipe', 'pipe'] }).toString();
  } catch (err) {
    // npm/yarn/pnpm exit with code 1 when vulns found — that's expected
    if (err.stdout) {
      stdout = err.stdout.toString();
    } else {
      throw err;
    }
  }

  switch (pm.type) {
    case 'npm-v2': return parseNpmAudit(stdout);
    case 'yarn':   return parseYarnAudit(stdout);
    case 'pip':    return parsePipAudit(stdout);
    case 'bundler': return parseBundlerAudit(stdout);
    default: return [];
  }
}

// =============================================================================
// AUDIT PARSERS
// =============================================================================

/**
 * Parse npm audit v7+ JSON (auditReportVersion: 2).
 * Also works for pnpm which uses the same format.
 */
function parseNpmAudit(jsonStr) {
  let data;
  try {
    data = JSON.parse(jsonStr);
  } catch {
    return [];
  }

  const vulns = [];

  if (data.auditReportVersion === 2) {
    // npm v7+ format
    for (const [name, vuln] of Object.entries(data.vulnerabilities || {})) {
      // Find the advisory details (via array may contain objects or strings)
      const advisory = Array.isArray(vuln.via)
        ? vuln.via.find(v => typeof v === 'object')
        : null;

      vulns.push({
        name,
        range: vuln.range || 'unknown',
        severity: vuln.severity || 'unknown',
        title: advisory?.title || name,
        cve: advisory?.cves?.[0] || null,
        url: advisory?.url || null,
        fix: vuln.fixAvailable
          ? (typeof vuln.fixAvailable === 'object'
            ? `npm install ${vuln.fixAvailable.name}@${vuln.fixAvailable.version}`
            : 'npm audit fix')
          : null,
        isDirect: vuln.isDirect ?? false
      });
    }
  } else {
    // npm v6 format (legacy)
    for (const [, adv] of Object.entries(data.advisories || {})) {
      vulns.push({
        name: adv.module_name,
        range: adv.vulnerable_versions,
        severity: adv.severity,
        title: adv.title,
        cve: adv.cves?.[0] || null,
        url: adv.url || null,
        fix: adv.patched_versions !== '<0.0.0'
          ? `npm install ${adv.module_name}@"${adv.patched_versions}"`
          : null,
        isDirect: true
      });
    }
  }

  // Deduplicate by package name (transitive deps appear multiple times)
  const seen = new Set();
  return vulns.filter(v => {
    const key = `${v.name}:${v.severity}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Parse yarn audit output (NDJSON — one JSON object per line).
 */
function parseYarnAudit(ndjsonStr) {
  const vulns = [];
  const seen = new Set();

  for (const line of ndjsonStr.split('\n')) {
    if (!line.trim()) continue;
    let obj;
    try { obj = JSON.parse(line); } catch { continue; }

    if (obj.type !== 'auditAdvisory') continue;
    const adv = obj.data?.advisory;
    if (!adv) continue;

    const key = `${adv.module_name}:${adv.severity}`;
    if (seen.has(key)) continue;
    seen.add(key);

    vulns.push({
      name: adv.module_name,
      range: adv.vulnerable_versions,
      severity: adv.severity,
      title: adv.title,
      cve: adv.cves?.[0] || null,
      url: adv.url || null,
      fix: adv.patched_versions !== '<0.0.0'
        ? `yarn upgrade ${adv.module_name}`
        : null,
      isDirect: true
    });
  }

  return vulns;
}

/**
 * Parse pip-audit JSON output.
 * Format: [{ name, version, vulns: [{ id, fix_versions, description }] }]
 */
function parsePipAudit(jsonStr) {
  let data;
  try {
    data = JSON.parse(jsonStr);
  } catch {
    return [];
  }

  const vulns = [];
  for (const pkg of (Array.isArray(data) ? data : [])) {
    for (const vuln of (pkg.vulns || [])) {
      const fixVersion = vuln.fix_versions?.[0];
      vulns.push({
        name: pkg.name,
        range: `==${pkg.version}`,
        severity: 'high', // pip-audit doesn't reliably report CVSS severity
        title: (vuln.description || vuln.id).slice(0, 100),
        cve: vuln.id.startsWith('CVE-') ? vuln.id : null,
        url: `https://osv.dev/vulnerability/${vuln.id}`,
        fix: fixVersion ? `pip install "${pkg.name}>=${fixVersion}"` : null,
        isDirect: true
      });
    }
  }

  return vulns;
}

/**
 * Parse bundler-audit text output (plain text format).
 */
function parseBundlerAudit(text) {
  const vulns = [];
  const blocks = text.split(/\n(?=Name:)/);

  for (const block of blocks) {
    const name = block.match(/^Name:\s*(.+)/m)?.[1]?.trim();
    const version = block.match(/Version:\s*(.+)/m)?.[1]?.trim();
    const cve = block.match(/CVE:\s*(.+)/m)?.[1]?.trim();
    const title = block.match(/Title:\s*(.+)/m)?.[1]?.trim();
    const solution = block.match(/Solution:\s*(.+)/m)?.[1]?.trim();

    if (name) {
      vulns.push({
        name,
        range: version ? `==${version}` : 'unknown',
        severity: 'high',
        title: title || cve || name,
        cve: cve || null,
        url: cve ? `https://www.cve.org/CVERecord?id=${cve}` : null,
        fix: solution ? `bundle update ${name}` : null,
        isDirect: true
      });
    }
  }

  return vulns;
}

// =============================================================================
// PUBLIC ENTRY POINT
// =============================================================================

/**
 * Run the dependency audit for a given path and return normalized vulns.
 * Returns { pm, vulns } — pm is null (vulns []) when no supported manifest is
 * found, or when the package manager's audit tool isn't installed/errors.
 */
export async function runDepsAudit(rootPath) {
  const pm = detectPackageManager(rootPath);
  if (!pm) return { pm: null, vulns: [], error: null };

  try {
    const vulns = runAudit(pm, rootPath);
    return { pm, vulns, error: null };
  } catch (err) {
    if (err.code === 'ENOENT' || /not found|not recognized|command not found/i.test(err.message)) {
      return { pm, vulns: [], error: `${pm.name} is not installed or not in PATH.${pm.installHint ? ` Install: ${pm.installHint}` : ''}` };
    }
    return { pm, vulns: [], error: `Audit failed: ${err.message}` };
  }
}
