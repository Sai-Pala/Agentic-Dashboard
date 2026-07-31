/**
 * AgenticSupplyChainAgent
 * ========================
 *
 * Detects supply chain attack vectors specific to AI integrations —
 * the class of vulnerability exploited in the Vercel April 2026 incident.
 *
 * Four detection tracks:
 *   1. Over-privileged AI actions in CI (GitHub Actions)
 *   2. Excessive OAuth scopes in AI platform integrations
 *   3. Webhook receivers that trust AI platform payloads without HMAC
 *   4. Agent tools forwarding credentials cross-boundary (MCP / Hermes)
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// ── Track 1: AI actions in CI with overly broad scopes ───────────────────────
// Match action names that are AI-related — these get elevated scrutiny because
// a compromised AI CI action has access to secrets + can exfiltrate model outputs.
const AI_ACTION_NAME_RE = /uses\s*:\s*([\w.-]+\/[\w.-]*(?:ai|llm|copilot|claude|openai|anthropic|gpt|gemini|cursor|codeium|tabnine|hermes|codex|devin|agent|autopilot)[\w.-]*)@([\w./-]+)/gi;

// Broad write/admin scopes in the same workflow as an AI action
const BROAD_SCOPE_PATTERNS = [
  {
    rule: 'AI_CI_WRITE_ALL',
    title: 'AI CI Action: Workflow Has write-all Permissions',
    regex: /permissions\s*:\s*write-all/g,
    severity: 'critical',
    cwe: 'CWE-250',
    owasp: 'ASI-02',
    description: 'This workflow uses an AI action and has write-all permissions. A compromised AI action (e.g. via a malicious model response or prompt injection) can exfiltrate all repository secrets and push malicious code. This is the permission level abused in the Vercel April 2026 AI pipeline compromise.',
    fix: 'Scope permissions to the minimum needed. If the AI action only reads code, use: permissions: { contents: read }',
  },
  {
    rule: 'AI_CI_ADMIN_SCOPE',
    title: 'AI CI Action: Administration Write Permission',
    regex: /administration\s*:\s*write/g,
    severity: 'critical',
    cwe: 'CWE-250',
    owasp: 'ASI-02',
    description: 'Administration write scope in a workflow that may include AI actions grants branch protection bypass. An AI agent with prompt injection can use this to push directly to protected branches.',
    fix: 'Remove administration: write unless absolutely necessary. AI actions do not require administration scope.',
  },
  {
    rule: 'AI_CI_SECRETS_WRITE',
    title: 'AI CI Action: Secrets Write Permission',
    regex: /secrets\s*:\s*write/g,
    severity: 'critical',
    cwe: 'CWE-250',
    owasp: 'ASI-02',
    description: 'Secrets write permission in a CI workflow. If an AI action is present, a prompt injection attack could cause the agent to overwrite repository secrets.',
    fix: 'Remove secrets: write. AI actions should only read secrets via environment variables.',
  },
  {
    rule: 'AI_CI_PACKAGES_WRITE',
    title: 'AI CI Action: Packages Write Permission',
    regex: /packages\s*:\s*write/g,
    severity: 'high',
    cwe: 'CWE-829',
    owasp: 'ASI-02',
    confidence: 'medium',
    description: 'Packages write permission in a workflow with AI actions. A supply chain attack via prompt injection could cause the AI agent to publish malicious packages to the GitHub Container Registry.',
    fix: 'Separate package publishing into a dedicated workflow without AI actions. Use packages: read in AI workflows.',
  },
  {
    rule: 'AI_CI_UNPINNED_AI_ACTION',
    title: 'AI CI Action: Unpinned AI Action (mutable tag)',
    // Matches AI action uses: lines NOT pinned to a 40-char SHA
    regex: /uses\s*:\s*[\w.-]*(?:ai|llm|copilot|claude|openai|anthropic|gpt|gemini|cursor|codeium|tabnine|hermes|codex|devin|agent|autopilot)[\w.-]*\/[\w.-]+@(?![\da-f]{40}\b)[\w./-]+/gi,
    severity: 'critical',
    cwe: 'CWE-829',
    owasp: 'CICD-SEC-8',
    description: 'An AI-related GitHub Action is not pinned to a full commit SHA. AI actions are high-value supply chain targets: a compromised action version can exfiltrate all secrets passed to it and inject malicious code into AI-generated PRs. This is the exact vector used against Vercel in April 2026.',
    fix: 'Pin to the full 40-character commit SHA: uses: ai-vendor/action@a1b2c3d4e5f6... # v1.2.3',
  },
];

// ── Track 2: Excessive OAuth scopes in AI platform integrations ──────────────

// Vercel integration config — checks for AI integrations with broad scopes
const VERCEL_AI_INTEGRATIONS = new Set([
  'vercel-ai', 'v0', 'cursor', 'codeium', 'copilot', 'openai',
  'anthropic', 'gemini', 'devin', 'sweep', 'cody', 'tabnine',
]);

// GitHub App manifest: dangerous scopes that AI apps rarely need
const DANGEROUS_GITHUB_APP_SCOPES = new Set([
  'administration', 'organization_administration', 'secrets',
  'organization_secrets', 'actions', 'organization_hooks',
  'members', 'organization_plan',
]);

// Netlify plugin scopes
const NETLIFY_AI_PLUGINS = new Set([
  '@netlify/plugin-ai', 'netlify-plugin-openai', 'netlify-plugin-anthropic',
  'netlify-plugin-langchain', 'netlify-plugin-vector-db',
]);

// ── Track 3: Webhook receivers that skip HMAC ────────────────────────────────
// We look for route handlers that parse AI platform webhook payloads
// without verifying a signature.

const WEBHOOK_PATTERNS = [
  {
    rule: 'WEBHOOK_NO_HMAC_OPENAI',
    title: 'Webhook: OpenAI Payload Without Signature Verification',
    regex: /(?:openai|stripe|linear|vercel)[._-]?(?:webhook|event|payload|hook)/gi,
    severity: 'high',
    cwe: 'CWE-345',
    owasp: 'ASI-06',
    description: 'Route appears to handle AI platform webhook events. If the Stripe-Signature / OpenAI-Signature header is not verified via HMAC-SHA256, an attacker can forge arbitrary events to trigger AI agent actions (e.g., invoice.paid spoofing to grant premium access, or forging model completion events to inject malicious output).',
    fix: 'Verify the webhook signature before processing: compare the HMAC-SHA256 of the raw body against the signature header using a constant-time comparison.',
  },
  {
    rule: 'WEBHOOK_RAW_BODY_NOT_USED',
    title: 'Webhook: Parsed JSON Body Used for HMAC Input',
    // Catches cases where body is JSON.parsed BEFORE signature check
    regex: /(?:req|request|event)\.(?:body|json\(\))\s*(?:;|\n|\.)/g,
    severity: 'medium',
    cwe: 'CWE-345',
    owasp: 'ASI-06',
    confidence: 'low',
    description: 'HMAC webhook verification requires the raw request body bytes — JSON.parse then re-stringify changes whitespace and property order, invalidating the signature check. Always read the raw buffer before any JSON parsing.',
    fix: 'Use express.raw({ type: "application/json" }) or Buffer from readable stream before calling JSON.parse.',
  },
];

// HMAC verification markers — if any of these appear near a webhook route, we
// suppress the Track 3 findings for that file (not a simple regex thing — handled
// in the custom analyze logic below).
const HMAC_MARKERS = [
  /createHmac/,
  /timingSafeEqual/,
  /stripe\.webhooks\.constructEvent/,
  /verifySignature/,
  /webhook[Ss]ecret/,
  /x-hub-signature/i,
  /svix-signature/i,
  /openai-beta-assistant/i,
];

// ── Track 4: Cross-boundary token forwarding in agent tool configs ────────────

const TOKEN_FORWARD_PATTERNS = [
  {
    rule: 'MCP_TOKEN_FORWARD_ENV',
    title: 'MCP: Agent Tool Forwards Auth Token to Third-Party URL',
    // env vars that look like bearer tokens / API keys passed to remote tool servers
    regex: /(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|VERCEL_TOKEN|LINEAR_API_KEY|SLACK_BOT_TOKEN|GH_PAT|CI_TOKEN)\s*[:=]\s*(?:\$\{[^}]+\}|["'][^"']{10,}["'])/g,
    severity: 'high',
    cwe: 'CWE-200',
    owasp: 'ASI-09',
    description: 'A high-value credential is set in an MCP server or agent tool configuration. If the tool server URL points to a third-party host, this credential will be transmitted to that host on every tool call — the data exfiltration vector exploited in the April 2026 Vercel incident where compromised AI integrations forwarded Vercel deployment tokens.',
    fix: 'Never pass production credentials to third-party MCP servers. Use scoped, read-only tokens. Prefer official first-party integrations.',
  },
  {
    rule: 'MCP_THIRD_PARTY_SERVER_WITH_AUTH',
    title: 'MCP: Third-Party Server URL With Auth Headers',
    regex: /(?:url|baseUrl|endpoint|server)\s*[:=]\s*["']https?:\/\/(?!localhost|127\.|0\.0\.0\.0|::1)([^"'/]+)[^"']*["'][^}]{0,200}(?:Authorization|Bearer|api[_-]?key|token)/gs,
    severity: 'critical',
    cwe: 'CWE-200',
    owasp: 'ASI-09',
    description: 'An MCP server configuration sends auth headers to a non-localhost URL. The remote MCP server receives every tool call result, including file contents and environment variable values. A compromised or malicious MCP server at this URL is a silent data exfiltration channel.',
    fix: 'Audit this MCP server. Prefer self-hosted or officially verified servers. If third-party is required, use a dedicated secrets-free agent profile.',
  },
  {
    rule: 'HERMES_TOOL_EXFIL',
    title: 'Hermes: Tool Config Forwards Credentials to Remote URL',
    regex: /(?:tools?|plugin)\s*[:=]\s*\{[^}]{0,400}(?:url|endpoint)\s*[:=]\s*["']https?:\/\/(?!localhost|127\.|0\.0\.0\.0)[^"']+["'][^}]{0,200}(?:auth|token|key|secret|bearer)/gis,
    severity: 'critical',
    cwe: 'CWE-200',
    owasp: 'ASI-09',
    description: 'A Hermes agent tool configuration passes authentication material to a remote endpoint. Hermes tools execute with the full ambient credentials of the agent — a malicious tool server receives them all.',
    fix: 'Audit all Hermes tool endpoints. Use allowlist-based URL validation and never inject high-privilege tokens into tool configs.',
  },
  {
    rule: 'AGENT_OAUTH_SCOPE_CREEP',
    title: 'Agent Config: Dangerously Broad OAuth Scopes',
    regex: /scopes?\s*[:=]\s*(?:\[|["'])(?:[^"'\]]*,\s*){3,}[^"'\]]*/g,
    severity: 'high',
    cwe: 'CWE-272',
    owasp: 'ASI-02',
    confidence: 'medium',
    description: 'Agent OAuth configuration requests 4 or more scopes. AI agents should follow least-privilege: request only the scopes needed for the specific task. Broad scope sets increase the blast radius of a prompt injection attack.',
    fix: 'Reduce to the minimum required scopes. Create separate agent profiles for different task types.',
  },
];

export class AgenticSupplyChainAgent extends BaseAgent {
  constructor() {
    super(
      'AgenticSupplyChainAgent',
      'Detect AI integration supply chain attack vectors (over-privileged CI actions, OAuth scope abuse, unsigned webhooks, cross-boundary token forwarding)',
      'supply-chain'
    );
  }

  async analyze(context) {
    const { rootPath, files } = context;
    const findings = [];

    // ── Track 1: Over-privileged AI actions in CI ─────────────────────────────
    const ciFiles = files.filter(f => {
      const rel = path.relative(rootPath, f).replace(/\\/g, '/');
      return rel.startsWith('.github/workflows/') && /\.ya?ml$/.test(f);
    });

    for (const file of ciFiles) {
      const content = this.readFile(file);
      if (!content) continue;

      // Check if this workflow uses any AI actions
      const hasAiAction = AI_ACTION_NAME_RE.test(content);
      AI_ACTION_NAME_RE.lastIndex = 0;

      if (hasAiAction) {
        // Flag broad scope patterns in this workflow
        findings.push(...this.scanFileWithPatterns(file, BROAD_SCOPE_PATTERNS));

        // Flag AI actions not pinned to a commit SHA
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          AI_ACTION_NAME_RE.lastIndex = 0;
          let m;
          while ((m = AI_ACTION_NAME_RE.exec(lines[i])) !== null) {
            const ref = m[2];
            // Warn if ref is NOT a 40-char hex SHA
            if (!/^[0-9a-f]{40}$/i.test(ref)) {
              findings.push(createFinding({
                file,
                line: i + 1,
                column: m.index + 1,
                severity: 'critical',
                category: this.category,
                rule: 'AI_CI_UNPINNED_AI_ACTION',
                title: `AI CI Action Not Pinned to SHA: ${m[1]}@${ref}`,
                description: `The AI action "${m[1]}" is referenced by a mutable tag ("${ref}") rather than a commit SHA. A supply chain attack via tag hijacking (as seen in April 2026) can replace this action with a credential stealer. All secrets passed to this action would be silently exfiltrated.`,
                matched: m[0],
                cwe: 'CWE-829',
                owasp: 'CICD-SEC-8',
                fix: `Pin to the full 40-character commit SHA: uses: ${m[1]}@<sha> # ${ref}`,
              }));
            }
          }
          AI_ACTION_NAME_RE.lastIndex = 0;
        }
      }
    }

    // ── Track 2: Excessive OAuth scopes in AI platform integrations ───────────

    // vercel.json / .vercel/project.json
    for (const vercelConfig of ['vercel.json', '.vercel/project.json']) {
      const p = path.join(rootPath, vercelConfig);
      if (!fs.existsSync(p)) continue;
      try {
        const cfg = JSON.parse(fs.readFileSync(p, 'utf-8'));
        this._auditVercelIntegrations(p, cfg, findings);
      } catch { /* skip parse errors */ }
    }

    // GitHub App manifests (app.yml, .github/app.yml, github-app.yml)
    for (const appManifest of [
      'app.yml', 'app.yaml',
      '.github/app.yml', '.github/app.yaml',
      'github-app.yml', 'github-app.yaml',
    ]) {
      const p = path.join(rootPath, appManifest);
      if (!fs.existsSync(p)) continue;
      this._auditGitHubAppManifest(p, findings);
    }

    // netlify.toml
    const netlifyPath = path.join(rootPath, 'netlify.toml');
    if (fs.existsSync(netlifyPath)) {
      this._auditNetlify(netlifyPath, findings);
    }

    // ── Track 3: Webhook receivers without HMAC ───────────────────────────────
    const webhookFiles = files.filter(f => {
      const rel = path.relative(rootPath, f).replace(/\\/g, '/');
      return (
        /webhook/i.test(rel) &&
        !f.includes('node_modules') &&
        /\.(js|ts|mjs|cjs)$/.test(f)
      );
    });

    for (const file of webhookFiles) {
      const content = this.readFile(file);
      if (!content) continue;

      const hasHmac = HMAC_MARKERS.some(re => re.test(content));
      if (!hasHmac) {
        // Only fire if the file actually looks like it handles AI/payment webhook events
        const looksLikeWebhook = /(?:openai|anthropic|vercel|stripe|linear|github|slack).*(?:event|payload|hook)/i.test(content);
        if (looksLikeWebhook) {
          findings.push(createFinding({
            file,
            line: 1,
            severity: 'high',
            category: this.category,
            rule: 'WEBHOOK_NO_HMAC_VERIFICATION',
            title: 'AI Platform Webhook: No HMAC Signature Verification',
            description: 'This webhook handler processes AI or payment platform events but no HMAC verification was detected. An attacker can POST forged events to trigger AI agent actions, grant access, or inject malicious payloads — without a valid signature. This was a secondary exploit path in the April 2026 Vercel incident.',
            matched: path.basename(file),
            cwe: 'CWE-345',
            owasp: 'ASI-06',
            fix: 'Verify the platform-specific signature header (e.g. Stripe-Signature, X-Hub-Signature-256) using HMAC-SHA256 with a constant-time comparison before processing any event.',
          }));
        }
      }
    }

    // Also scan for raw-body anti-pattern in verified webhook files
    for (const file of webhookFiles) {
      findings.push(...this.scanFileWithPatterns(file, [WEBHOOK_PATTERNS[1]]));
    }

    // ── Track 4: Cross-boundary token forwarding ──────────────────────────────
    const agentConfigFiles = files.filter(f => {
      const rel = path.relative(rootPath, f).replace(/\\/g, '/');
      const base = path.basename(f);
      return (
        !f.includes('node_modules') &&
        (
          /mcp[._-]?(?:server|config|settings)/i.test(base) ||
          /\.hermes(?:rc|\.json|\.yaml|\.yml)$/.test(base) ||
          /hermes[._-]?config/i.test(base) ||
          /agent[._-]?config/i.test(base) ||
          /claude[._-]?(?:md|settings|config)/i.test(base) ||
          base === '.mcp.json' ||
          base === 'mcp.json' ||
          rel.includes('.claude/') ||
          rel.includes('.hermes/')
        )
      );
    });

    for (const file of agentConfigFiles) {
      findings.push(...this.scanFileWithPatterns(file, TOKEN_FORWARD_PATTERNS));
    }

    // Also scan workflow files for token forwarding to external MCP servers
    for (const file of ciFiles) {
      findings.push(...this.scanFileWithPatterns(file, [TOKEN_FORWARD_PATTERNS[0]]));
    }

    return findings;
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  _auditVercelIntegrations(filePath, cfg, findings) {
    // Vercel integrations can specify required scopes — check for overly broad ones
    const integrations = cfg.integrations || cfg.extensions || [];
    if (!Array.isArray(integrations)) return;

    for (const integration of integrations) {
      const name = (integration.name || integration.slug || '').toLowerCase();
      const isAi = VERCEL_AI_INTEGRATIONS.has(name) ||
        /ai|llm|copilot|claude|gpt|agent|cursor/.test(name);
      if (!isAi) continue;

      const scopes = integration.scopes || integration.permissions || [];
      const broadScopes = (Array.isArray(scopes) ? scopes : Object.keys(scopes))
        .filter(s => /write|admin|delete|deploy|secret/.test(String(s).toLowerCase()));

      if (broadScopes.length > 0) {
        findings.push(createFinding({
          file: filePath,
          line: 0,
          severity: 'high',
          category: this.category,
          rule: 'VERCEL_AI_INTEGRATION_BROAD_SCOPE',
          title: `Vercel AI Integration Overly Broad Scopes: ${name}`,
          description: `The Vercel AI integration "${name}" requests write/admin scopes: ${broadScopes.join(', ')}. If this integration is compromised (e.g. via a trojanized update — the vector in the April 2026 Vercel incident), it can modify deployments, exfiltrate secrets, or inject malicious environment variables.`,
          matched: broadScopes.join(', '),
          cwe: 'CWE-272',
          owasp: 'ASI-02',
          fix: `Review whether "${name}" actually needs ${broadScopes.join(', ')} scope. Request read-only scopes where possible.`,
        }));
      }
    }
  }

  _auditGitHubAppManifest(filePath, findings) {
    const content = this.readFile(filePath);
    if (!content) return;

    // Check for dangerous permission combinations
    for (const scope of DANGEROUS_GITHUB_APP_SCOPES) {
      const re = new RegExp(`${scope}\\s*:\\s*write`, 'gi');
      if (re.test(content)) {
        findings.push(createFinding({
          file: filePath,
          line: 0,
          severity: 'high',
          category: this.category,
          rule: 'GITHUB_APP_DANGEROUS_SCOPE',
          title: `GitHub App Manifest: Dangerous Scope "${scope}: write"`,
          description: `The GitHub App manifest requests "${scope}: write". If this app integrates AI functionality, a supply chain compromise of the app (malicious version update, OAuth token theft) grants an attacker ${scope} write access across all installed repositories.`,
          matched: `${scope}: write`,
          cwe: 'CWE-272',
          owasp: 'ASI-02',
          fix: `Only request write access to scopes your app directly needs. Consider splitting AI-only functionality into a separate app with minimal permissions.`,
        }));
      }
    }

    // Check if the app manifest includes a webhook URL without TLS
    const webhookMatch = content.match(/webhook_url\s*:\s*["']?(http:\/\/[^"'\s]+)/i);
    if (webhookMatch) {
      findings.push(createFinding({
        file: filePath,
        line: 0,
        severity: 'high',
        category: this.category,
        rule: 'GITHUB_APP_INSECURE_WEBHOOK',
        title: 'GitHub App Manifest: Webhook URL Without TLS',
        description: `The GitHub App webhook_url uses plain HTTP: "${webhookMatch[1]}". All event payloads (including code review comments and CI results) are transmitted unencrypted, and the HMAC signature over HTTP provides no protection against MITM injection.`,
        matched: webhookMatch[1],
        cwe: 'CWE-319',
        owasp: 'A02:2021',
        fix: 'Use an https:// webhook URL. GitHub will not deliver events to HTTP URLs in production.',
      }));
    }
  }

  _auditNetlify(filePath, findings) {
    const content = this.readFile(filePath);
    if (!content) return;

    // Look for AI plugins in netlify.toml [[plugins]] sections
    const pluginMatches = content.matchAll(/\[\[plugins\]\][^[]*package\s*=\s*["']([^"']+)["']/gs);
    for (const m of pluginMatches) {
      const pkg = m[1];
      if (!NETLIFY_AI_PLUGINS.has(pkg) && !/ai|llm|openai|anthropic|langchain|vector/.test(pkg)) continue;

      // Check if the plugin section has env vars containing secrets
      const pluginSection = m[0];
      if (/(?:api[_-]?key|token|secret)\s*=\s*["']?\$\{?(?:process\.env|env)\./i.test(pluginSection)) {
        findings.push(createFinding({
          file: filePath,
          line: 0,
          severity: 'high',
          category: this.category,
          rule: 'NETLIFY_AI_PLUGIN_SECRET_EXPOSURE',
          title: `Netlify AI Plugin Exposes Secrets in Build Config: ${pkg}`,
          description: `The Netlify AI plugin "${pkg}" receives secrets via the build configuration. Netlify plugins run in the build environment with access to all env vars. A compromised plugin version can exfiltrate every secret in your Netlify site.`,
          matched: pkg,
          cwe: 'CWE-312',
          owasp: 'ASI-09',
          fix: 'Pin the plugin to a specific version and verify it on npm before updating. Only pass the minimum required secrets.',
        }));
      }
    }
  }
}

export default AgenticSupplyChainAgent;
