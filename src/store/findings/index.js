/**
 * The findings store. Session-lifetime and in-memory — everything resets on restart.
 *
 * Split by job: state (the Maps), status (run history -> derived status), list-item (the wire
 * shape), factories (engine output -> Finding), flow (dataflow spans), csv (export). This file
 * is the single import surface for the rest of the app.
 */

module.exports = {
  ...require('./state'),
  ...require('./status'),
  ...require('./list-item'),
  ...require('./factories'),
  ...require('./flow'),
  ...require('./csv'),
};
