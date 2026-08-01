/**
 * Cross-site WebSocket hijacking guard
 * ====================================
 *
 * The same-origin policy does NOT cover WebSockets: a page on evil.example can open a socket
 * to http://127.0.0.1:4500 and the browser will connect. Binding to loopback does not help,
 * because the request originates from the user's own browser. Nothing in this app requires
 * auth, and `remediate_fix` writes to disk — so without this check, visiting a web page was
 * enough to let that page start scans and apply edit plans to the user's repository.
 *
 * This is the one hole where "local single-user tool" stops being an adequate excuse: the
 * attacker never needs access to the machine.
 *
 * Extracted from server.js unchanged. Pure: no I/O, no module state. The port is a parameter
 * rather than a module import specifically so it stays trivially testable.
 */

/**
 * Should this WebSocket handshake be accepted?
 *
 * A browser ALWAYS sends Origin on a WebSocket handshake and script cannot forge it, so:
 *   - Origin present -> must be one of our own loopback origins on the served port.
 *   - Origin absent  -> not a browser (curl, a test, a CLI). Allowed: anything running
 *                       locally outside a browser already has this user's privileges, so
 *                       rejecting it buys nothing and would break the test suite.
 */
function isAllowedWsOrigin(origin, port) {
  if (!origin) return true;
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return false; // unparseable Origin is not something we should be lenient about
  }
  // Scheme is part of an origin by definition, so check it rather than comparing host/port
  // alone. Only http/https can be a real browser page origin here; anything else (file:,
  // data:, a custom scheme) is not something this app is ever served over.
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  // A real Origin header is scheme://host:port with no path, so anything carrying one did
  // not come from a browser's origin serialization and should not be treated as ours.
  if (parsed.pathname !== '/' && parsed.pathname !== '') return false;
  const hostOk = parsed.hostname === 'localhost'
    || parsed.hostname === '127.0.0.1'
    || parsed.hostname === '[::1]'
    || parsed.hostname === '::1';
  // Compare the port explicitly: another service on a different loopback port is still a
  // different origin, and one of them being localhost does not make it ours.
  const portOk = parsed.port === String(port);
  return hostOk && portOk;
}

module.exports = { isAllowedWsOrigin };
