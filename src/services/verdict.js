/**
 * The agent verdict contract: find the first fenced JSON block in an agent's response and
 * parse it. No schema validation — the client renders arbitrary verdict keys generically.
 */

/**
 * Returns null when there is no block or it does not parse — never throws, because a malformed
 * verdict must degrade to "no verdict" rather than take down the run's close handler.
 *
 * The fence match must stay case-INSENSITIVE: a model emitting ```JSON otherwise yields a run
 * that completes "successfully" with a null verdict, silently, with no error anywhere.
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
