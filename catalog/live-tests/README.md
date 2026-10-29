# Live test plans

One file per app, `<appId>.json`, holds the live write tests the owner runs once with `node scripts/live-certify.mjs <appId> --folder <absolute path>` (step 12, `docs/F10.12-BUILD-MAP.md`). Each test sends real requests to the owner's test areas, the way an agent sends them: on a client grant made for that test, one approval at a time on Fabric's approve page, through a guard (`lib/live-guard.mjs`) that refuses anything outside those areas before it leaves the machine.

Calendar's plan, `google-calendar.json` (C0 to C13), ships with step 13, beside Calendar's action file its action names resolve to, and runs in step 14. GitHub's plan, `github.json` (H0 to H11), ships with step 17 and runs in step 18, in the sandbox repository only. `node scripts/live-certify.mjs [<appId>] --check` checks the plans here offline: it starts nothing and sends nothing. Slack's plan, `slack.json` (S0 to S6), ships with step 21 and runs in step 22, after Muse's Slack checklist, in `#fabric-test` and your own direct message. `node scripts/live-certify.mjs [<appId>] --check` checks the plans here offline: it starts nothing and sends nothing.

Notion's plan, `notion.json` (N0 to N11), ships with step 19 and runs in step 20, on the synthetic pages A and B, the synthetic database under A and what the run itself makes; N11 deletes the run's two comments through the one-time Ask on "Permanently delete comments and views". On a new Notion run the command first asks Notion's token introspection once (never traced, never an agent's call) and writes `docs/live-evidence/notion/introspection.json`: whether the token is active, its scope, and whether that scope lists the integration's capabilities.

Gmail's plan, `gmail.json` (G0 to G10), ships with step 15 beside Gmail's action file and runs in step 16. Every email it sends goes to the owner's own address. No Gmail action deletes, so the undos that delete the run's drafts, filter and label are owner steps in Gmail, each waiting until its read answers 404.

`checkPlan()` in `lib/live-certify.mjs` is the one rule for this format. Every object below is closed: a field not named here is refused.

## The file

| Field | What it holds |
| --- | --- |
| `schemaVersion` | `1` |
| `appId` | The app, as the file is named |
| `note` | What the plan covers, in words |
| `recorded` | Names Muse records before the run, each with words that say what it is. The command asks for each as `--record <name>=<value>` |
| `readRows` | The read rows (by id) readbacks use. Each test's grant holds them as proxy rows |
| `timeZone` | Optional `{path, pointer}`: a read whose answer gives the owner's time zone. Without it, this machine's zone is used |
| `gone` | Optional `{pointer, equals}`: what a deleted item reads as when the provider still answers 200 (Calendar: `/status` equals `cancelled`) |
| `tests` | The tests, in the order they run |

## A test

`{id, name, steps, undo}`. The id is a short name such as `C2`, unique in the file. A test that writes needs an `undo`, exactly one of:

- `{test: "<later test>"}`: a later test undoes it (C12 undoes C2 to C5);
- `{steps: [...]}`: steps run right after, approved like any write (`call`, `read`, `owner` or `ask` steps);
- `{none: "<why>"}`.

## A step

Exactly one of six kinds:

- `call`: `{action: "<key>@<version>", args, expect, save, checks}`. `expect` is `succeeded` (the default) or `{failed: <HTTP status>}`. `save` names values to keep, each `name: "<pointer into the output>"`. `checks` run on the output.
- `race`: `{action, args, status, readback: {path, params, query, pointer, output}}`. The action is prepared twice before either card is shown, so both read the same version. One job must succeed and one must fail with `status` (412 for Calendar); then the readback's `pointer` must equal the successful job's output at `output`.
- `read`: `{path, params, query, checks, save}`, a readback `GET` through the proxy. `method`, if given, is `GET`.
- `owner`: `{words, until}`. The words are for Muse, then Enter. `until` is an optional read (`{path, params, query, checks}`) polled once a second for up to 5 minutes until its checks hold.
- `oneTimeAsk`: `{row, requests}`, for a row at Never (C13's "Permanently delete calendars or clear all events"). The runner prints "Set <row> to Ask", waits until the row reads Ask (Allow stops the run), sends each request (`{method, path, params, query}`) on a grant of that one row after its approval, prints "Reset <row> to Never", and waits until the row reads Never again. Both times go into the evidence.
- `ask`: `{row, requests}`, for a proxied write on a row that already reads Ask (step 17: deleting a run's branches on "Push code and manage repositories"). The runner reads the row: Never refuses the step and Allow stops the run, as a one-time Ask does, with nothing sent. At Ask it sends each request (`{method, path, params, query}`, 1 to 5) on a grant of that one row, each approved like any proxied write. It never asks for a row to change and changes none. The plan check refuses a row that is Never by default (that takes a `oneTimeAsk`) and a row Fabric locks.

Every action of the app's file must be called by some `call` or `race`, so each one gets evidence. A key@version names a current action, never a superseded one.

## Paths

A path starts with `/`, below the app's proxy base and inside its proxy prefixes, and holds no query. `{name}` is one segment and `{+name}` one or more; each has exactly one `params` entry. `query` names parameters and their values.

## Checks

| Check | Holds when |
| --- | --- |
| `{status: 404}` or `{status: [404, 410]}` | The read's HTTP status is one of these |
| `{pointer, equals}` | The value at the pointer equals this one |
| `{pointer, present}` | A value is there (`true`) or not (`false`) |
| `{pointer, count}` | A list of exactly this many entries is there |
| `{pointer, oneOf}` | The value is one of these |
| `{pointer, where, field, equals}` | In the list at the pointer, exactly one entry has every `where` pointer equal to its value, and its `field` equals this one (C9's attendee) |
| `{gone: true}` | The read answers 404 or 410, or 200 with the plan's `gone` |

A call's checks read its output, so `status` and `gone` are for reads.

## Placeholders

A closed set, each alone in its object:

| Placeholder | Gives |
| --- | --- |
| `{$text: "<words>"}` | `[SYNTHETIC] Fabric <test> <runId> <words>`, the only text the guard lets a test write |
| `{$text: {words, day}}` | The same, with the date of that day (7 to 13, as `$day`) where `{date}` stands in the words, which hold it once: Calendar's quick add (C5) reads its date from the text |
| `{$saved: "<name>"}` | A value an earlier step saved. Used before it is saved, the plan is refused |
| `{$recorded: "<name>"}` | A value declared in `recorded` and given with `--record` |
| `{$day: <n>}` | The date n days after the run date, in the owner's zone. n is 7 to 13: the guard's window |
| `{$at: {day, time}}` | That day at `HH:MM`, RFC 3339 with the owner's offset on that day |
| `{$local: {day, time}}` | The same day and time as a local wall time, `YYYY-MM-DDTHH:MM:SS` in the owner's zone, as Calendar's actions take times (F10.13). A time a daylight-saving change skips is refused |
| `{$owner: "email"}` or `{$owner: "timeZone"}` | The owner's address, from the account, or the owner's zone |
| `{$in: {minutes}}` | The UTC instant that many whole minutes (1 to 1,440) after the step runs, in whole seconds, as Slack's schedule time and status expiry take an instant (F10.21) |
| `{$branch: ""}` or `{$branch: "<suffix>"}` | This run's own branch, `fabric/test-<runId>`, or `fabric/test-<runId>-<suffix>` with a suffix of 1 to 16 lowercase letters or digits: the only branches the GitHub guard lets a test create, write, merge into and delete (F10.17) |

## Writes and the guard

Every write placement of a called action must fit a method and path on the guard's list for the app (`allowlist` in `lib/live-guard.mjs` `RULES`). The plan check does not judge content: the guard reads the exact bytes at the network seam, and the runner also runs it on each card's prepared bytes before printing the approve link. A card it refuses prints "Reject this card" and stops the run.
