/**
 * Entry point: build the Express app, mount the routers, attach the WebSocket server, listen.
 * Everything else lives under src/.
 */

const express = require('express');
const http = require('http');

const { PORT, HOST, PUBLIC_DIR } = require('./src/config');
const { attachWebSocketServer } = require('./src/ws');

const app = express();
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

app.use(require('./src/routes/agents'));
app.use(require('./src/routes/scans'));
app.use(require('./src/routes/findings'));
app.use(require('./src/routes/timeline'));
app.use(require('./src/routes/session'));

const server = http.createServer(app);
attachWebSocketServer(server);

// Only bind a port when this file is *run*, not when it is require()d — importing it from a
// test must never start a listener, or the test process would never exit.
if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`Findings Agent App listening on http://${HOST}:${PORT}`);
    if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
      console.log(`WARNING: bound to ${HOST}, not loopback. This app has no authentication and`);
      console.log('         its WebSocket can write to your files. Anyone who can reach this');
      console.log('         port has the same power over this machine as you do.');
    }
  });
}

module.exports = { app, server };
