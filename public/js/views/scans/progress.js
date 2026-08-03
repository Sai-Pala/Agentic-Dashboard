/**
 * Live scan-card instrumentation
 *
 * The three engine bars (pattern match / reasoning / dependency audit), the severity chip row
 * and live findings list, and the tool/file/token/elapsed counters. Everything here mutates a
 * `run` tracking object's cached DOM refs directly rather than re-rendering the card.
 */

import { truncate, formatElapsed, formatTokenCount } from '../../lib/format.js';
import { SEV_VAR, SEV_ORDER } from '../../lib/meta.js';
import { trackConsoleText } from '../../components/console.js';

const SEV_TAG_RE = /\[(critical|high|medium|low|informational)\]\s+([^[]*)/gi;

export function updateScanElapsed(run) {
  if (run.elapsedEl) run.elapsedEl.textContent = formatElapsed(Date.now() - run.startTime);
}

export function stopScanElapsedTimer(run) {
  if (run.elapsedTimer) {
    clearInterval(run.elapsedTimer);
    run.elapsedTimer = null;
  }
  updateScanElapsed(run);
}

function renderScanSevChips(run) {
  if (!run.chipsEl) return;
  const total = SEV_ORDER.reduce((n, s) => n + run.sevCounts[s], 0);
  if (!total) {
    run.chipsEl.innerHTML = '<span class="hint">No candidates yet</span>';
    return;
  }
  run.chipsEl.innerHTML = SEV_ORDER
    .filter((s) => run.sevCounts[s] > 0)
    .map((s) => `<span class="sev-chip" style="color:${SEV_VAR[s]}; background:color-mix(in srgb, ${SEV_VAR[s]} 16%, transparent);">${run.sevCounts[s]} ${s}</span>`)
    .join('');
}

/** Parses `[severity] message` lines out of assistant text — real narration or synthesized. */
function trackScanCandidates(run, event) {
  if (event.type !== 'assistant' || !event.message || !Array.isArray(event.message.content)) return;
  let found = false;
  for (const block of event.message.content) {
    if (block.type !== 'text' || !block.text) continue;
    const re = new RegExp(SEV_TAG_RE.source, SEV_TAG_RE.flags);
    let m;
    while ((m = re.exec(block.text))) {
      const sev = m[1].toLowerCase();
      const text = truncate(m[2].replace(/\s+/g, ' ').trim(), 180);
      run.sevCounts[sev] = (run.sevCounts[sev] || 0) + 1;
      found = true;
      if (run.findingsEl && text) {
        const row = document.createElement('div');
        row.className = 'scan-live-row';
        row.innerHTML = `<span class="sev-dot ${sev}"></span><span class="scan-live-text"></span>`;
        row.querySelector('.scan-live-text').textContent = text;
        run.findingsEl.appendChild(row);
        run.findingsEl.scrollTop = run.findingsEl.scrollHeight;
      }
    }
  }
  if (found) renderScanSevChips(run);
}

/** Written against a run object's field names, not against one surface. */
function trackRunToolActivity(run, event) {
  if (event.type !== 'assistant' || !event.message || !Array.isArray(event.message.content)) return;
  let sawTool = false;
  for (const block of event.message.content) {
    if (block.type !== 'tool_use') continue;
    sawTool = true;
    run.toolCount++;
    if (block.name === 'Read') run.fileCount++;
  }
  if (!sawTool) return;
  if (run.toolsEl) run.toolsEl.textContent = String(run.toolCount);
  if (run.filesEl) run.filesEl.textContent = String(run.fileCount);
}

function trackRunTokens(run, event) {
  if (event.type !== 'assistant' || !event.message || !event.message.usage) return;
  const u = event.message.usage;
  run.tokenCount += (u.input_tokens || 0) + (u.output_tokens || 0) + (u.cache_creation_input_tokens || 0) + (u.cache_read_input_tokens || 0);
  if (run.tokensEl) run.tokensEl.textContent = formatTokenCount(run.tokenCount);
}

/**
 * `total` is the count of agents relevant to THIS target, not the registered total — most repos
 * legitimately skip a dozen. The "N n/a" suffix and tooltip make that selection visible;
 * "17/17 agents done" alone reads as though 17 were the whole engine.
 */
export function updateDetBar(run, done, total, skipped) {
  if (!run.detFillEl) return;
  run.detDone = done;
  run.detTotal = total;
  if (Array.isArray(skipped)) run.detSkipped = skipped;
  const pct = total ? Math.round((done / total) * 100) : 0;
  run.detFillEl.style.width = pct + '%';
  run.detFillEl.classList.toggle('done', done >= total && total > 0);
  const nSkipped = (run.detSkipped || []).length;
  run.detStatEl.textContent = total
    ? `${done}/${total} agents done${nSkipped ? ` · ${nSkipped} n/a` : ''}`
    : 'Starting…';
  run.detStatEl.title = nSkipped
    ? `${total} of ${total + nSkipped} agents apply to this codebase.\n\n`
      + `Not applicable here (skipped by their own relevance check):\n`
      + (run.detSkipped || []).map((n) => `• ${n}`).join('\n')
    : '';
}

/** One atomic audit call, so this only ever jumps from 0% to 100%. */
export function updateScaBar(run, done, total, failed) {
  if (!run.scaFillEl) return;
  const complete = done >= total && total > 0;
  const pct = total ? Math.round((done / total) * 100) : 0;
  run.scaFillEl.style.width = pct + '%';
  // A failed audit must never render as done — the accompanying scan-warning says what broke.
  run.scaFillEl.classList.toggle('done', complete && !failed);
  run.scaFillEl.classList.toggle('failed', !!failed);
  run.scaStatEl.textContent = failed ? 'Failed' : (total && complete ? 'Done' : 'Starting…');
}

/** Real aggregated spend, reported by the server — not a token-count estimate. */
function reasoningCostSuffix(run) {
  return run.reasoningCostUsd ? ` · $${run.reasoningCostUsd.toFixed(2)}` : '';
}

/**
 * Fallback display for when only one reasoning pass runs: an indeterminate fill driven by
 * tool-call count. With both passes running, updateReasoningModuleProgress() owns this bar.
 */
function updateReasoningBar(run) {
  if (!run.reasoningFillEl) return;
  if (run.reasoningModulesTotal > 1) return;
  const pct = Math.min(90, run.toolCount * 8);
  run.reasoningFillEl.style.width = pct + '%';
  run.reasoningStatEl.textContent = (run.toolCount
    ? `${run.toolCount} tool call${run.toolCount === 1 ? '' : 's'}`
    : 'Starting…') + reasoningCostSuffix(run);
}

/** Sent once per completed reasoning pass. total <= 1 falls back to the estimate above. */
export function updateReasoningModuleProgress(run, done, total, costUsd) {
  if (!run.reasoningFillEl) return;
  run.reasoningModulesDone = done;
  run.reasoningModulesTotal = total;
  if (typeof costUsd === 'number') run.reasoningCostUsd = costUsd;
  if (total <= 1) { updateReasoningBar(run); return; }
  const pct = Math.round((done / total) * 100);
  run.reasoningFillEl.style.width = pct + '%';
  run.reasoningFillEl.classList.toggle('done', done >= total);
  run.reasoningStatEl.textContent = `${done}/${total} passes done` + reasoningCostSuffix(run);
}

export function markReasoningBarDone(run) {
  if (!run.reasoningFillEl) return;
  run.reasoningFillEl.style.width = '100%';
  run.reasoningFillEl.classList.add('done');
}

export function handleScanRawEvent(run, event) {
  trackRunToolActivity(run, event);
  trackRunTokens(run, event);
  trackScanCandidates(run, event);
  trackConsoleText(run, event);
  updateReasoningBar(run);
}
