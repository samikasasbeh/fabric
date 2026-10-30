# Fabric

Fabric is integration infrastructure for AI agents. It handles the parts every agent needs before it can act in someone else's apps: sign-in, permissions, approvals and safe API calls.

- **Sign-in.** OAuth with PKCE, encrypted refresh tokens, renewal that keeps the same account, and partial grants that say plainly what is missing.
- **Permissions.** Each account gets Allow, Ask or Never per permission. Some permissions are locked by Fabric and stay at Never.
- **Approvals.** An action that asks shows the exact request to the owner, and runs only after they approve that exact request.
- **Actions.** Typed, reviewed operations with input checks, a proxy for raw requests that follows the same permissions, and a read-back that checks what a write really did.
- **Evidence.** Actions are certified against real accounts by a live test harness. The records are in [docs/live-evidence](docs/live-evidence).

## Status

The current work is five apps done in depth.

| App | Actions | Certified live |
| --- | --- | --- |
| Gmail | 13 | 13 |
| Google Calendar | 13 | 13 |
| GitHub | 15 | 15 |
| Notion | 16 | 16 |
| Slack | 13 | 13 |

Fabric is not hosted yet. It runs on your own machine.

## Run the checks

Node.js 24 or newer is required (Fabric uses the built-in SQLite).

```sh
npm ci
npm run verify:foundation
```

`verify:foundation` runs the type check, the syntax check and the full test suite. Tests use temporary folders, loopback ports and provider simulators, never real accounts.

`node scripts/seeded-faults.mjs` plants known bugs one at a time and checks that a test catches each one. It needs a clean working tree.

## Layout

| Folder | What is in it |
| --- | --- |
| `lib/` | The runtime: sign-in, permissions, approvals, actions, the proxy and the vault |
| `catalog/` | Apps, providers, sign-in definitions, permission rows, actions and live test plans |
| `public/` | The hosted Connect and app pages |
| `scripts/` | The test runner, the live test harness and the checks |
| `test/` | Unit, simulator and seeded-fault tests |
| `docs/live-evidence/` | Records from live test runs |

Comments in the code sometimes name design notes under `docs/`. Those notes are kept private.

## License

Fabric is source-available under the [PolyForm Shield License 1.0.0](LICENSE.md). You may read, run and change the code for any purpose except to provide a product that competes with Fabric. Copyright Sami Kasasbeh.
