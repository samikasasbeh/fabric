# Live evidence

`docs/live-evidence/<appId>/actions.json` holds what each app's live tests proved, as `node scripts/live-certify.mjs` wrote it (step 12, `docs/F10.12-BUILD-MAP.md`). Fabric's start and the template check (`scripts/app-template-check.mjs`, check 6) read it through one rule, `evidencePasses()` in `lib/action-catalog.mjs`: an action becomes active only when its reviewed file names `certified` and a record under its id passed, with the current pins of every transform it names and its definition hash (I8).

Calendar's 13 actions are certified from run MBIDCUUG (step 14, 2026-10-29). Each app folder also holds `sign-in.json`, the sign-in records check 7 reads: one record per kind, `passed` true only where the session showed exactly that kind (see the file's note).

## What a file holds

One record per action id that a run's tests called. A later run replaces the records of the actions it called and keeps the rest.

- `schemaVersion` (1), `passed`, `definitionHash`, `runId`, `ranAt`.
- `transforms`: each transform the action names, with its code hash computed when the run ended. `passed` is true only when each equals its pin.
- `harnessHash` and `runtime` (`node`, `tz`, `icu`, `unicode`): notes. A difference from an earlier run is never a failure.
- `tests`: for each test that called the action, its `jobs` (id, status, error code, and each approval's phase and time), its `requests` from the guard's trace (method, path template, body HMAC, provider status, the created item's identity), its `checks` by name and whether each passed, and its `undo` (its own jobs, requests and checks, the later test that undoes it, or why there is none). `passed` is true only when every test and undo that used the action passed. An undo given as a later test (`{test}`) is recorded by name only: that test calls no action of its own, or certifies its own, so it does not count here, and the `run` key shows whether it passed (MBIDCUUG's C13 did not).

A top-level `run` key holds the run's id, app, start and end, harness hash and runtime, the tests that call no action (C13's deletes), and the owner's row changes (`row`, `label`, and when Ask, Allow and Never were read). The start and check 6 look up action ids only, so they ignore it.

## What a file never holds

No token, header or body, no plain email address, and no unsalted hash of an address or of a body. Every address and every email-shaped string, calendar ids included, appears only as `hmac:` and 32 hex characters: HMAC-SHA256 under a random key made when the run starts, kept in memory only and never written down. Body digests use the same key. So the hashes compare within one run and cannot be confirmed by guessing an address. A resumed run gets a new key. Sign-in traffic (token, identity and probe requests) is never in a test's trace. `assertEvidenceSafe()` in `lib/live-certify.mjs` refuses to write a file that holds a known address or its sha256, any email-shaped string, a `bodySha256` key, a Bearer credential or a token-shaped value.

## Committing it

Muse commits these files only with the owner's OK. The run state and the guard's own files stay in the certification folder (`<folder>/live-certify/`, mode 600) and are never committed.
