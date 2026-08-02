/**
 * Agent-run cards on Finding Detail
 * =================================
 *
 * Renders any verdict object generically by iterating its key/value pairs, so an agent's .md
 * can add fields without a frontend change. Three fields get dedicated renderers instead of the
 * generic grid: corrected_code (a code block), edit_plan (a diff preview) and applied_diff.
 */

import { state } from '../../state.js';
import { escapeHtml, formatInlineText } from '../../lib/html.js';
import { icon } from '../../lib/icons.js';
import { highlightCode, diffLineHtml } from '../../lib/highlight.js';
import { formatRelativeTime, verdictFieldLabel } from '../../lib/format.js';
import { agentMeta, VERDICT_BADGE_FIELDS, VERDICT_SKIP_FIELDS } from '../../lib/meta.js';
import { consoleToggleButtonHtml, consolePanelHtml } from '../../components/console.js';

/**
 * `evidence` is file/pattern references, so it renders as a monospace block; other long arrays
 * become a real list. Short arrays stay an inline comma list, which reads better at that size.
 */
function verdictArrayHtml(items, key) {
  const strs = items.map((v) => String(v));
  if (key === 'evidence') {
    return `<pre class="code-block fd-verdict-codeblock">${strs.map((s) => escapeHtml(s)).join('\n')}</pre>`;
  }
  const needsList = strs.length > 3 || strs.some((s) => s.length > 30);
  if (!needsList) return formatInlineText(strs.join(', '));
  return `<ul class="fd-verdict-list">${strs.map((s) => `<li>${formatInlineText(s)}</li>`).join('')}</ul>`;
}

function correctedCodeHtml(code) {
  if (!code) return '';
  return `<div class="fd-section-title" style="margin-top:10px;">Proposed fix</div><pre class="code-block"><code>${highlightCode(code)}</code></pre>`;
}

/**
 * `edit_plan` is { summary, risk, files: [{ path, edits: [{find, replace}] }] }, drawn as a
 * diff preview so "what will Fix write" reads the same way as "what did Fix write".
 */
function editPlanHtml(plan) {
  if (!plan || typeof plan !== 'object') return '';
  const files = Array.isArray(plan.files) ? plan.files : [];
  if (!files.length) return '';
  const summaryHtml = plan.summary
    ? `<div class="fd-verdict-reasoning" style="margin-top:10px;">${formatInlineText(plan.summary)}${plan.risk ? ` <span class="badge ${escapeHtml(String(plan.risk))}">${escapeHtml(String(plan.risk))} risk</span>` : ''}</div>`
    : '';
  const fileBlocks = files.map((f) => {
    const lines = [];
    if (Array.isArray(f.edits)) {
      for (const e of f.edits) {
        String(e.find || '').split('\n').forEach((l) => lines.push('-' + l));
        String(e.replace || '').split('\n').forEach((l) => lines.push('+' + l));
      }
    } else if (f.create) {
      String(f.content || '').split('\n').forEach((l) => lines.push('+' + l));
    } else if (f.append != null) {
      String(f.append).split('\n').forEach((l) => lines.push('+' + l));
    }
    if (!lines.length) return '';
    return `<div class="fd-section-title" style="margin-top:10px;">${escapeHtml(f.path || '')}</div><pre class="diff-block">${lines.map(diffLineHtml).join('')}</pre>`;
  }).join('');
  return summaryHtml + fileBlocks;
}

export function runCardHtml(run) {
  const meta = agentMeta(run.agent);
  const timeStr = run.startedAt ? formatRelativeTime(run.startedAt) : '';
  const statusCls = run.status === 'running' ? 'in_review' : (run.status === 'error' || run.status === 'cancelled') ? 'high' : 'closed';
  const statusText = run.status === 'running' ? 'Running' : run.status === 'error' ? 'Error' : run.status === 'cancelled' ? 'Cancelled' : 'Done';

  let verdictHtml = '';
  if (run.verdict && typeof run.verdict === 'object') {
    const v = run.verdict;
    const badgeFields = VERDICT_BADGE_FIELDS.filter((k) => v[k]);
    const otherFields = Object.keys(v).filter((k) => !VERDICT_SKIP_FIELDS.has(k) && v[k] != null && v[k] !== '' && !(Array.isArray(v[k]) && !v[k].length));
    // Real evidence of what a fix run actually wrote — its own diff block, not the generic grid.
    const appliedDiffHtml = v.applied_diff
      ? `<div class="fd-section-title" style="margin-top:10px;">Applied diff</div><pre class="diff-block">${v.applied_diff.split('\n').map(diffLineHtml).join('')}</pre>`
      : '';
    verdictHtml = `
      ${badgeFields.length ? `<div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px;">${badgeFields.map((k) => `<span class="badge ${escapeHtml(String(v[k]))}">${escapeHtml(String(v[k]))}</span>`).join('')}</div>` : ''}
      ${v.reasoning ? `<div class="fd-verdict-reasoning">${formatInlineText(v.reasoning)}</div>` : ''}
      ${otherFields.length ? `
        <div class="fd-verdict-grid" style="margin-top:8px;">
          ${otherFields.map((k) => `<div class="fd-verdict-item"><b>${escapeHtml(verdictFieldLabel(k))}</b><div class="fd-verdict-value">${Array.isArray(v[k]) ? verdictArrayHtml(v[k], k) : formatInlineText(String(v[k]))}</div></div>`).join('')}
        </div>
      ` : ''}
      ${correctedCodeHtml(v.corrected_code)}
      ${editPlanHtml(v.edit_plan)}
      ${appliedDiffHtml}
    `;
  } else if (run.status === 'error') {
    verdictHtml = '<div class="fd-verdict-reasoning">Run failed — no verdict produced.</div>';
  } else if (run.status === 'running') {
    verdictHtml = '<div class="fd-verdict-reasoning">Still running…</div>';
  }

  // Only runs started this browser session have console text; historical ones have none.
  const consoleRun = state.stageConsoles.get(run.runId);

  return `
    <div class="fd-run-card">
      <div class="fd-run-head">
        <span class="fd-run-agent" style="color:${meta.color};">${icon(meta.icon)}${escapeHtml(meta.label)}</span>
        <span class="badge ${statusCls}">${escapeHtml(statusText)}</span>
        <span class="fd-run-time">${escapeHtml(timeStr)}</span>
        ${consoleRun ? consoleToggleButtonHtml(consoleRun) : ''}
      </div>
      ${consoleRun ? consolePanelHtml(consoleRun, 'stage-console') : ''}
      ${verdictHtml}
    </div>
  `;
}
