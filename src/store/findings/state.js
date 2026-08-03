/**
 * The in-memory findings state. Session-lifetime only — lost on restart.
 * Its own module so every other part of the store can read it without a require cycle.
 */

const findings = new Map(); // id -> finding record
const runIndex = new Map(); // runId -> { findingId, run }, for O(1) lookup on done/error/cancel

module.exports = { findings, runIndex };
