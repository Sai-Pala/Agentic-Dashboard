// GOLDEN-MASTER FIXTURE — deliberately insecure test input. See README.md in this directory.
// Frozen: editing this file shifts line numbers and breaks the recorded snapshots.

function query(sql, paramsOrCb, maybeCb) {
  const cb = typeof paramsOrCb === 'function' ? paramsOrCb : maybeCb;
  cb(null, []);
}

function allUsers() {
  return [];
}

module.exports = { query, allUsers };
