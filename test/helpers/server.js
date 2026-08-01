'use strict';

/**
 * Boot/teardown helper for the characterization tests.
 *
 * server.js calls `server.listen(PORT)` unguarded at top level and exports
 * nothing, so it cannot be imported without booting. Until that changes, the
 * only way to exercise its HTTP surface is to run it as a child process and
 * talk to it over the network — which is what this helper does.
 *
 * Boot it once per test file (a `before` hook) and always stop it from an
 * `after` hook, so a failing assertion can never leave an orphan node process
 * holding the port.
 */

const { spawn } = require('node:child_process');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// Deliberately not 4500: that is the app's default, i.e. whatever the user is
// running locally while these tests execute.
const DEFAULT_PORT = 4571;

// The app loads a fair amount at boot; on a cold filesystem cache this can take
// a while. Poll rather than assuming it is up.
const DEFAULT_READY_TIMEOUT_MS = 90_000;
const POLL_INTERVAL_MS = 250;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Spawn `node server.js` on `port` and resolve once it answers HTTP.
 *
 * @param {{port?: number, readyTimeoutMs?: number}} [options]
 * @returns {Promise<{baseUrl: string, port: number, pid: number, stop: () => Promise<void>, output: () => string}>}
 */
async function startServer(options = {}) {
  const port = options.port || DEFAULT_PORT;
  const readyTimeoutMs = options.readyTimeoutMs || DEFAULT_READY_TIMEOUT_MS;
  const baseUrl = `http://127.0.0.1:${port}`;

  const child = spawn(process.execPath, ['server.js'], {
    cwd: REPO_ROOT,
    env: { ...process.env, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'],
    // Own process group, so stop() can take down anything the server itself
    // spawned (it shells out to `claude` / package-manager audits) rather than
    // just the node process in front of them.
    detached: true,
  });

  let log = '';
  child.stdout.on('data', (d) => { log += d.toString(); });
  child.stderr.on('data', (d) => { log += d.toString(); });

  let exited = null;
  child.on('exit', (code, signal) => { exited = { code, signal }; });

  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const closed = new Promise((resolve) => child.once('exit', resolve));
    killGroup(child.pid, 'SIGTERM');
    const settled = await Promise.race([closed.then(() => true), sleep(5000).then(() => false)]);
    if (!settled) {
      killGroup(child.pid, 'SIGKILL');
      await Promise.race([closed, sleep(2000)]);
    }
  };

  const deadline = Date.now() + readyTimeoutMs;
  for (;;) {
    if (exited) {
      throw new Error(
        `server.js exited before it was ready (code=${exited.code}, signal=${exited.signal}).\n${log}`,
      );
    }
    if (await probe(baseUrl)) {
      return { baseUrl, port, pid: child.pid, stop, output: () => log };
    }
    if (Date.now() > deadline) {
      await stop();
      throw new Error(`server.js did not respond on ${baseUrl} within ${readyTimeoutMs}ms.\n${log}`);
    }
    await sleep(POLL_INTERVAL_MS);
  }
}

async function probe(baseUrl) {
  try {
    const res = await fetch(`${baseUrl}/api/findings`, {
      signal: AbortSignal.timeout(2000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

function killGroup(pid, signal) {
  try {
    process.kill(-pid, signal);
  } catch {
    try {
      process.kill(pid, signal);
    } catch {
      /* already gone */
    }
  }
}

module.exports = { startServer, DEFAULT_PORT, REPO_ROOT };
