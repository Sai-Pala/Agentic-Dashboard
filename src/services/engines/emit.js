/**
 * Synthesized scan events.
 *
 * The reasoning half streams real `assistant` events out of `claude -p`. The three deterministic
 * engines have no such stream, but the client renders one console, so they fake the same shape to
 * land in it. Kept in one place because the nesting is deep enough to get subtly wrong, and a
 * frame the client cannot parse fails silently — the scan looks like it produced no output.
 */

/** Push a block of already-formatted lines into a scan's event stream as assistant text. */
function sendScanText(send, scan, lines) {
  send({
    type: 'scan-event',
    runId: scan.runId,
    scanId: scan.id,
    event: { type: 'assistant', message: { content: [{ type: 'text', text: lines.join('\n') }] } },
  });
}

module.exports = { sendScanText };
