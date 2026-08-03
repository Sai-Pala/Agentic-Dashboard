/**
 * Cross-site WebSocket hijacking guard. The same-origin policy does NOT cover WebSockets, and
 * loopback binding does not help because the request comes from the user's own browser.
 * The port is a parameter rather than a config import so this stays trivially testable.
 */

/**
 * A browser ALWAYS sends Origin on a WebSocket handshake and script cannot forge it, so an
 * absent Origin means "not a browser" (curl, a test, a CLI) and is allowed: anything running
 * locally outside a browser already has this user's privileges.
 */
function isAllowedWsOrigin(origin, port) {
  if (!origin) return true;
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  // Scheme is part of an origin by definition; only http/https can be a real page origin here.
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  // A real Origin header is scheme://host:port with no path. Anything carrying one did not
  // come from a browser's origin serialization.
  if (parsed.pathname !== '/' && parsed.pathname !== '') return false;
  const hostOk = parsed.hostname === 'localhost'
    || parsed.hostname === '127.0.0.1'
    || parsed.hostname === '[::1]'
    || parsed.hostname === '::1';
  // Another service on a different loopback port is still a different origin.
  const portOk = parsed.port === String(port);
  return hostOk && portOk;
}

module.exports = { isAllowedWsOrigin };
