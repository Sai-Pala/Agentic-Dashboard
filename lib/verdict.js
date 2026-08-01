/**
 * The agent verdict contract
 * ==========================
 *
 * Every agent `.md` ends with an instruction to close its response with exactly one fenced
 * JSON block. This is the whole of the server's side of that contract: find the first such
 * block in the accumulated assistant text and parse it. There is no schema validation — the
 * client renders arbitrary verdict keys generically, so an agent can add fields without any
 * server change (see CLAUDE.md's "The verdict contract").
 *
 * Extracted from server.js unchanged. Pure: no I/O, no module state.
 */

/**
 * Pull the first ```json fenced block out of `text` and parse it. Returns null when there is
 * no block or it does not parse — never throws, because a malformed verdict must degrade to
 * "no verdict" rather than take down the run's close handler.
 *
 * The fence match is case-INSENSITIVE. It used to be case-sensitive, and the failure was
 * silent and total: a model emitting ```JSON produced a run that completed "successfully"
 * with verdict null, so the finding got no triage, no status change, and no error anywhere.
 * A whole paid agent run produced nothing and looked healthy doing it.
 */
function extractVerdict(text) {
  const match = String(text || '').match(/```json\s*([\s\S]*?)```/i);
  if (!match) return null;
  try {
    return JSON.parse(match[1]);
  } catch (err) {
    return null;
  }
}

module.exports = { extractVerdict };
