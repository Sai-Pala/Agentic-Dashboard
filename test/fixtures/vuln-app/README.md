# Golden-master fixture — TEST DATA, NOT PART OF THE APP

This directory contains a deliberately insecure miniature Express app. It exists for exactly
one reason: the deterministic scan engine is a pure function (same directory in, same findings
out, no LLM), so a fixed input with a recorded output is what lets a refactor prove it did not
change behaviour.

**This is not planted vulnerability data in the application.** The application's own planted
fixtures were removed in commit f7bb4ac. This is scoped test input:

- it lives under `test/`, never imported by `server.js` or `sast-engine/`
- `.sast-engineignore` excludes `test/fixtures/`, so a real scan of this repo never reads it
- nothing here is executable in the app; no route registers it, no build copies it

If a scan ever reports a finding from this directory, the exclusion has regressed — treat that
as a bug in `.sast-engineignore`, not as a real finding.

## Why it must stay stable

The golden-master snapshots record `(rule, file, line, severity)` tuples from this directory.
Editing a file here shifts line numbers and fails the snapshots. That is intentional: the
snapshot is only meaningful if the input is frozen. To add coverage for a new rule, add a NEW
file rather than editing an existing one, then re-record.
