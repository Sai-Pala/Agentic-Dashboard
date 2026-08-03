/**
 * Insights
 *
 * How the scan behaved — deliberately not what it found (Agent Triage) and not what the target
 * exposes (Attack Surface). This screen answers a third question those two cannot: can the result
 * be trusted, and on how much of the codebase.
 *
 * The numbers here exist nowhere else once a scan ends: the live scan panel is discarded on
 * reload, and without this screen a scan that read 6 of 161 files and one that read all of them
 * collapse to the same timeline entry — "DONE, N findings created".
 *
 * WRITTEN FOR SOMEONE IMPROVING THE ENGINE, not for a status check. That is why nothing here is
 * a sample: every excluded file is listed, every agent appears whether or not it ran, and the
 * recon evidence that gating decisions were made on is published in full. A count tells you
 * something was dropped; only the list tells you whether dropping it was right.
 *
 * Reads GET /api/scans/:id/surface, which carries the scan's own record alongside the target's
 * manifest.
 */

import { state } from '../state.js';
import { getScanSurface } from '../api.js';
import { escapeHtml } from '../lib/html.js';
import { scanFilterLabel } from '../lib/format.js';
import { loadScans } from './scans/index.js';

export function openInsightsView() {
  renderInsightsScanPicker();
  if (!state.scansList.length) loadScans().then(renderInsightsScanPicker);
  const done = state.scansList.filter((s) => s.status === 'done');
  if (!state.insightsScanId && done.length) state.insightsScanId = done[0].id;
  if (state.insightsScanId) loadInsights(state.insightsScanId);
  else renderInsightsView();
}

async function loadInsights(scanId) {
  const el = document.getElementById('insights-content');
  if (el) el.innerHTML = '<div class="placeholder-panel">Loading…</div>';
  try {
    const res = await getScanSurface(scanId);
    state.insightsData = res.ok ? res.surface : { unavailable: res.error };
  } catch (err) {
    state.insightsData = { unavailable: err.message };
  }
  renderInsightsView();
  renderInsightsScanPicker();
}

function renderInsightsScanPicker() {
  const btn = document.getElementById('insights-scan-btn');
  const menu = document.getElementById('insights-scan-menu');
  if (!btn || !menu) return;
  const done = state.scansList.filter((s) => s.status === 'done');
  const current = done.find((s) => s.id === state.insightsScanId);
  btn.textContent = current ? scanFilterLabel(current) : (done.length ? 'Select a scan' : 'No completed scans');
  btn.disabled = !done.length;
  menu.innerHTML = done.map((s) =>
    `<button type="button" class="scan-filter-item${s.id === state.insightsScanId ? ' active' : ''}" data-scan-id="${s.id}">${escapeHtml(scanFilterLabel(s))}</button>`
  ).join('') || '<div class="scan-filter-empty">Run a scan first.</div>';
  menu.querySelectorAll('[data-scan-id]').forEach((b) => {
    b.onclick = () => { state.insightsScanId = b.dataset.scanId; menu.hidden = true; loadInsights(state.insightsScanId); };
  });
  btn.onclick = (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; };
}

/* ── small building blocks ──────────────────────────────────────────────────────────────── */

/** A headline number with a label. `tone` colours the number: ok | warn | err | plain. */
function metric(value, label, tone = 'plain', sub = '') {
  return `<div class="ins-metric">
    <div class="ins-metric-value ins-${tone}">${value}</div>
    <div class="ins-metric-label">${label}</div>
    ${sub ? `<div class="ins-metric-sub">${sub}</div>` : ''}
  </div>`;
}

function section(title, note, body, count = null) {
  if (!body) return '';
  return `<section class="ins-section">
    <header class="ins-section-head">
      <h3>${title}${count != null ? `<span class="ins-count">${count}</span>` : ''}</h3>
      ${note ? `<p class="ins-note">${note}</p>` : ''}
    </header>
    ${body}
  </section>`;
}

/** A `<details>` block whose summary stays readable when collapsed. */
function drill(summary, body, tone = 'plain') {
  return `<details class="ins-drill">
    <summary class="ins-drill-summary ins-${tone}">${summary}</summary>
    <div class="ins-drill-body">${body}</div>
  </details>`;
}

/** A scrollable monospace file listing. The point of this screen — never truncated by us. */
function fileList(files, truncated = false) {
  if (!files || !files.length) return '<div class="ins-empty">None.</div>';
  return `<div class="ins-files">${files.map((f) => `<code>${escapeHtml(f)}</code>`).join('')}
    ${truncated ? '<div class="ins-empty">Listing capped — more files were excluded than are shown.</div>' : ''}
  </div>`;
}

function chips(values) {
  return `<div class="ins-chips">${values.map((v) => `<span class="ins-chip">${escapeHtml(String(v))}</span>`).join('')}</div>`;
}

/* ── sections ───────────────────────────────────────────────────────────────────────────── */

/** The scan's own parameters, so a surprising result can be checked against its inputs first. */
function inputsSection(data, scan) {
  const cov = data.coverage;
  const ig = cov && !cov.error ? cov.ignoreFiles : null;
  const rows = [
    ['Target', `<code>${escapeHtml(data.path || '')}</code>`],
    ['Scope', scan ? (scan.scope === 'diff' ? `Changed files only, against <code>${escapeHtml(scan.baseBranch || 'base')}</code>` : 'Full tree') : '—'],
    ['Reasoning budget', scan ? (scan.budgetEnabled ? 'Capped' : '<span class="ins-warn">Uncapped</span>') : '—'],
    ['.gitignore', ig
      ? (ig.gitignore.present
        ? `<span class="ins-warn">Honoured</span> — ${ig.gitignore.patterns} pattern${ig.gitignore.patterns === 1 ? '' : 's'}, anything matching was never opened`
        : 'Not present')
      : '—'],
    ['.sast-engineignore', ig
      ? (ig.sastEngineIgnore.present ? `Honoured — ${ig.sastEngineIgnore.patterns} pattern${ig.sastEngineIgnore.patterns === 1 ? '' : 's'}` : 'Not present')
      : '—'],
  ];
  const body = `<table class="ins-table ins-kv"><tbody>${rows.map(([k, v]) =>
    `<tr><th>${k}</th><td>${v}</td></tr>`).join('')}</tbody></table>`;
  return section('Inputs', 'The path, scope, and ignore rules this scan ran under.', body);
}

/**
 * What was read and what was dropped, with every dropped file named.
 *
 * Ordered worst-surprise-first: an ignore file silently removing real source is the exclusion a
 * user is least likely to expect and most likely to care about, so it leads.
 */
function fileSection(data) {
  const cov = data.coverage;
  if (!cov) return '';
  if (cov.error) {
    return section('Files', '', `<div class="ins-empty">${escapeHtml(cov.error)}</div>`);
  }

  const REASONS = [
    ['ignored', 'Excluded by an ignore file', 'err',
      'Real source, with a scannable extension, that the engine never opened. Nothing inside these files could have been reported.'],
    ['tooLarge', 'Over the file-size cap', 'warn', 'Skipped whole. Usually generated bundles, sometimes real source.'],
    ['unreadable', 'Could not be read', 'warn', 'A permission error or a broken symlink.'],
    ['extension', 'Not a source extension', 'plain', ''],
    ['filename', 'Filename on the skip list', 'plain', ''],
    ['minified', 'Minified bundle', 'plain', ''],
  ];

  const dropped = cov.considered - cov.scanned;
  const pct = cov.considered ? Math.round((cov.scanned / cov.considered) * 100) : 0;

  const metrics = `<div class="ins-metrics">
    ${metric(cov.scanned, 'files read', pct >= 80 ? 'ok' : 'warn', `${pct}% of everything present`)}
    ${metric(dropped, 'never opened', dropped ? 'warn' : 'ok', 'all named below')}
    ${metric(cov.prunedDirCount, 'directories pruned', 'plain', cov.prunedDirs.slice(0, 4).map((d) => escapeHtml(d.name)).join(', '))}
  </div>`;

  const blocks = REASONS
    .filter(([key]) => cov.dropped[key] && cov.dropped[key].count)
    .map(([key, label, tone, why]) => {
      const d = cov.dropped[key];
      return drill(
        `<span class="ins-drill-n">${d.count}</span> ${label}`,
        (why ? `<p class="ins-note">${why}</p>` : '') + fileList(d.files, d.truncated),
        tone,
      );
    }).join('');

  const pruned = cov.prunedDirCount
    ? drill(`<span class="ins-drill-n">${cov.prunedDirs.length}</span> Skipped directory names, never descended into`,
      chips(cov.prunedDirs.map((d) => (d.count > 1 ? `${d.name} ×${d.count}` : d.name))))
    : '';

  return section('Files', 'What the engine opened, and every file it did not. Expand a row for the full list.',
    metrics + blocks + pruned, `${cov.scanned}/${cov.considered}`);
}

/**
 * The evidence gating decisions were made on.
 *
 * Published rather than interpreted: `shouldRun()` returns a bare boolean with no reason string,
 * so this screen can state that an agent did not run and show what the engine believed about the
 * codebase, but cannot claim which of those beliefs caused it.
 */
function reconSection(data) {
  const r = data.recon;
  if (!r) return '';
  const signals = r.signals.map((s) =>
    `<tr><th>${escapeHtml(s.label)}</th><td>${chips(s.values)}</td></tr>`).join('');
  const flags = `<tr><th>Infrastructure</th><td>${r.flags.map((f) =>
    `<span class="ins-chip ${f.present ? '' : 'ins-chip-off'}">${escapeHtml(f.label)}${f.present ? '' : ' — absent'}</span>`).join('')}</td></tr>`;

  const body = `<table class="ins-table ins-kv"><tbody>${signals}${flags}
    <tr><th>Route signals</th><td>${r.routeCount}<div class="ins-sub">Recon's own tally, used only for gating. Attack Surface holds the real enumeration and will not match this.</div></td></tr>
    <tr><th>Config files</th><td>${r.configFileCount}</td></tr>
  </tbody></table>`;

  return section('Detected stack',
    'What recon found in the codebase. Every pattern agent decides whether to run by reading these signals — though the engine records only the decision, never its reason, so the link between the two is yours to draw.',
    body);
}

const AGENT_STATUS = {
  failed: ['Failed', 'err'],
  unknown: ['No result', 'warn'],
  ran: ['Ran', 'ok'],
  skipped: ['Not applicable', 'plain'],
};

/** Every agent the engine has, and what happened to it. */
function agentSection(data) {
  const roster = (data.agents && data.agents.roster) || [];
  if (!roster.length) {
    // Pre-roster scans still have the counts.
    const a = data.agents || {};
    if (a.run == null) return '';
    return section('Pattern agents',
      'This scan ran before the per-agent record was captured, so only the counts survive.',
      `<div class="ins-metrics">${metric(a.run, 'ran')}${metric(a.skipped.length, 'not applicable')}${metric(a.failed.length, 'failed', a.failed.length ? 'err' : 'ok')}</div>`);
  }

  const by = (s) => roster.filter((x) => x.status === s);
  const totalFindings = roster.reduce((n, x) => n + x.findingCount, 0);
  const totalSuppressed = roster.reduce((n, x) => n + x.suppressedCount, 0);

  const metrics = `<div class="ins-metrics">
    ${metric(by('ran').length, 'ran', 'ok')}
    ${metric(by('skipped').length, 'not applicable', 'plain', 'gated out before reading a single file')}
    ${metric(by('failed').length, 'failed', by('failed').length ? 'err' : 'ok', by('failed').length ? 'their vulnerability classes went unchecked' : '')}
    ${metric(totalFindings, 'findings', 'plain', 'raw, before dedupe and adjudication')}
    ${totalSuppressed ? metric(totalSuppressed, 'suppressed', 'warn', 'withheld by the agent that found them') : ''}
  </div>`;

  const rows = roster.map((a) => {
    const [label, tone] = AGENT_STATUS[a.status] || AGENT_STATUS.skipped;
    return `<tr class="ins-agent-${a.status}">
      <td class="ins-agent-name">${escapeHtml(a.name)}
        ${a.description ? `<div class="ins-sub">${escapeHtml(a.description)}</div>` : ''}
        ${a.error ? `<div class="ins-sub ins-err">${escapeHtml(a.error)}</div>` : ''}</td>
      <td class="ins-agent-cat">${escapeHtml(a.category)}</td>
      <td><span class="ins-status ins-${tone}">${label}</span></td>
      <td class="ins-num">${a.status === 'ran' ? a.findingCount : '—'}</td>
      <td class="ins-num">${a.suppressedCount || ''}</td>
    </tr>`;
  }).join('');

  const table = `<table class="ins-table ins-agents">
    <thead><tr><th>Agent</th><th>Category</th><th>Status</th><th class="ins-num">Found</th><th class="ins-num">Suppressed</th></tr></thead>
    <tbody>${rows}</tbody></table>`;

  return section('Pattern agents',
    'Every agent in the engine, not just the ones that ran. A list of only the survivors would make gating invisible.',
    metrics + table, roster.length);
}

/** How much of the attack surface the expensive pass actually opened. */
function reviewSection(data) {
  const r = data.reviewCoverage;
  if (!r) return '';

  const unscoped = r.totalRoutes === 0;
  const metrics = `<div class="ins-metrics">
    ${metric(unscoped ? '—' : r.reviewedRoutes, 'endpoints reviewed', unscoped || r.skippedRoutes ? 'warn' : 'ok',
    unscoped ? 'no routes were enumerated, so the review ran unscoped over the whole tree' : `of ${r.totalRoutes} found`)}
    ${metric(r.shards, 'shards', 'plain', 'grouped by file, riskiest first')}
    ${metric(r.adjudicated, 'findings re-checked', r.adjudicable > r.adjudicated ? 'warn' : 'ok',
    r.adjudicable > r.adjudicated ? `${r.adjudicable - r.adjudicated} kept the pattern verdict without review` : `of ${r.adjudicable} eligible`)}
  </div>`;

  const shardRows = (r.shardFiles || []).filter((s) => s.files && s.files.length).map((s) =>
    drill(`<span class="ins-drill-n">${s.routeCount}</span> Shard ${s.index} — ${s.files.length} file${s.files.length === 1 ? '' : 's'}`,
      fileList(s.files))).join('');

  const unreviewed = (r.unreviewedFiles || []).length
    ? drill(`<span class="ins-drill-n">${r.unreviewedFiles.length}</span> Files with endpoints the review never opened`,
      '<p class="ins-note">Their endpoints were found during enumeration but fell outside the shard budget. Nothing looked for authorization or business-logic flaws in them.</p>'
      + fileList(r.unreviewedFiles), 'err')
    : '';

  return section('Reasoning review',
    'The reasoning pass is budgeted and does not see everything. This is what it reached.',
    metrics + unreviewed + shardRows);
}

/**
 * Where this scan's findings came from.
 *
 * `both` is the number worth watching: two engines independently reporting one location is the
 * strongest signal the app produces.
 */
function provenanceSection(scanId) {
  const mine = state.findings.filter((f) => f.sourceScanId === scanId);
  if (!mine.length) return '';

  const triage = (f) => ((f.stageRuns && f.stageRuns.triage && f.stageRuns.triage.verdict) || {});
  const bySource = { 'sast-engine-verifier': 0, 'reasoning-adjudication': 0, 'reasoning-scan': 0, other: 0 };
  let corroborated = 0;
  let closed = 0;
  for (const f of mine) {
    const v = triage(f);
    if (v.corroborated) corroborated++;
    if (f.status === 'closed') closed++;
    if (bySource[v.source] !== undefined) bySource[v.source]++;
    else bySource.other++;
  }
  const patternOrigin = bySource['sast-engine-verifier'] + bySource['reasoning-adjudication'];
  const closedPct = Math.round((closed / mine.length) * 100);

  const rows = [
    [mine.length, 'Findings this scan produced', ''],
    [patternOrigin, 'From the pattern engine', ''],
    [bySource['reasoning-scan'], 'From the reasoning pass alone',
      'Business-logic and authorization flaws that no fixed rule set can express.'],
    [corroborated, 'From <strong>both</strong> engines, same line',
      corroborated ? 'The strongest signal this app produces — structured detail from one engine, the explanation from the other.' : ''],
    [`${closed} (${closedPct}%)`, 'Closed by the adjudicator',
      closedPct > 40 ? 'A share this high means the pattern engine is over-reporting on this codebase.' : ''],
  ];

  const body = `<table class="ins-table ins-kv"><tbody>${rows.map(([n, label, sub]) =>
    `<tr><th class="ins-num">${n}</th><td>${label}${sub ? `<div class="ins-sub">${sub}</div>` : ''}</td></tr>`).join('')}</tbody></table>`;

  return section('Finding sources', 'Which engine produced each finding in this scan.', body);
}

/**
 * What the merge removed or rewrote between the engines and the findings list.
 *
 * The counterpart to the disposition tags in Agent Triage: those say what happened to one
 * finding, this says how often it happened and what the raw engine output was before any of it.
 * Both halves of each row are shown — what went in and what came out — because a drop count with
 * no denominator is not checkable.
 */
function dispositionSection(data) {
  const d = data.dispositions;
  if (!d) return '';

  const rows = [
    [d.patternRaw, 'Pattern-engine findings, before merging', 'The raw count, so everything below has a denominator.'],
    [d.collapsedAdjacent, 'Folded into a nearby match', 'One rule firing repeatedly within a few lines is treated as one condition, not several sites. These exist nowhere as findings — the survivor carries a “+N collapsed” tag.', d.collapsedAdjacent > 0],
    [d.reasoningRaw, 'Reasoning-pass findings, before merging', ''],
    [d.mergedIntoPattern, 'Merged with a pattern finding', 'Both engines hit the same line. One finding, not two: structured fields from the pattern engine, the explanation from the reasoning pass.'],
    [d.duplicateReasoning, 'Dropped as a repeat', 'A second reasoning finding within two lines of one already kept.', d.duplicateReasoning > 0],
    [d.malformedReasoning, 'Dropped as malformed', 'No title or no description. Skipped rather than failing the scan.', d.malformedReasoning > 0],
    [d.severityChanged, 'Severity rewritten', 'The adjudicator overruled the engine, and its call was applied — those rows show a severity the engine did not assign.', d.severityChanged > 0],
    [d.closedAsFalsePositive, 'Closed as a false positive', 'Still listed and still inspectable. A wrong call here costs visibility, not evidence.'],
  ];

  const body = `<table class="ins-table ins-kv"><tbody>${rows.map(([n, label, sub, bad]) =>
    `<tr><th class="ins-num${bad ? ' ins-warn' : ''}">${n}</th><td>${label}${sub ? `<div class="ins-sub">${sub}</div>` : ''}</td></tr>`).join('')}</tbody></table>`;

  return section('Merge and dedupe',
    'Findings an engine reported that never reached the list, and the ones that changed on the way.',
    body);
}

/** Cost and wall-clock, so the expensive half's price sits next to what it bought. */
function costSection(scan) {
  if (!scan) return '';
  const secs = scan.finishedAt && scan.startedAt ? Math.round((scan.finishedAt - scan.startedAt) / 1000) : null;
  const cost = typeof scan.reasoningCostUsd === 'number' ? scan.reasoningCostUsd : null;
  if (secs == null && cost == null) return '';
  return section('Cost', '', `<div class="ins-metrics">
    ${cost != null ? metric(`$${cost.toFixed(2)}`, 'reasoning passes', 'plain', scan.budgetEnabled ? 'budget cap on' : 'budget cap off') : ''}
    ${secs != null ? metric(`${Math.floor(secs / 60)}m ${secs % 60}s`, 'wall clock', 'plain', 'all three engines') : ''}
  </div>`);
}

/* ── render ─────────────────────────────────────────────────────────────────────────────── */

function renderInsightsView() {
  const el = document.getElementById('insights-content');
  if (!el) return;

  const data = state.insightsData;
  if (!data) {
    el.innerHTML = '<div class="placeholder-panel">Run a scan, then pick it above to see how it behaved.</div>';
    return;
  }
  if (data.unavailable) {
    el.innerHTML = `<div class="placeholder-panel">${escapeHtml(data.unavailable)}</div>`;
    return;
  }

  const scan = state.scansList.find((s) => s.id === data.scanId);
  const sections = inputsSection(data, scan) + fileSection(data) + reconSection(data)
    + agentSection(data) + reviewSection(data) + dispositionSection(data)
    + provenanceSection(data.scanId) + costSection(scan);

  el.innerHTML = sections
    || '<div class="placeholder-panel">This scan ran before its behaviour was recorded, so there is nothing to show for it. The next scan will have it.</div>';
}

export function wireInsights() {
  document.addEventListener('click', () => {
    const menu = document.getElementById('insights-scan-menu');
    if (menu && !menu.hidden) menu.hidden = true;
  });
}
