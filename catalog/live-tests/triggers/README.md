# Trigger plans and read probes

This folder holds what Iteration 9 asks of a real provider. `node scripts/live-certify.mjs --check` reads only the top-level names of `catalog/live-tests`, so nothing here reads as an app.

`<appId>.probes.json` holds read probes, part 3g of `docs/I07-BUILD-MAP.md`. Each is a live test plan in the format of `catalog/live-tests/README.md`, with `probes: true`. A simulator is written from what a provider answers, so these run first.

```
node --env-file-if-exists=.env scripts/live-certify.mjs <appId> --folder <absolute path> --probes [--record <name>=<value>]...
```

A probes plan differs from an action plan in five ways:

- **It only reads.** Its steps are `read` steps, with no `undo` and no `cleanup`, so it sends no write and shows no card on an Allow row.
- **It owes no action.** It is exempt from "every action called", so a run writes no evidence. `--probes` is the only way to run such a file, and it runs nothing else.
- **Each test is one question.** The run prints `yes` when its checks hold and `no` when they do not, with the status of its last read, since a 429 also reads as a no. `not answered` means the read itself failed. No answer stops the next probe, and no value is printed.
- **A read is sent once.** A check for a 404 or a 410 does not read again here, because the probe asks what the answer is.
- **It can use headers.** `headers` sends `Accept`, `If-None-Match` or `If-Modified-Since`. `saveHeaders` keeps `etag`, `last-modified`, `link` or `x-ratelimit-remaining`, each named as `/<name>`, for a later test to use as `{"$saved": "<name>"}`. A check of `{header, present}`, `{header, equals}` or `{header, includes}` reads the same four. `x-poll-interval` does not come back through the proxy, so a probe cannot read it.

Answers go in section 12 of the build map by hand. Probes that need a write run inside step 9's tests.

## Trigger plans

Step 9 adds each app's trigger plan here as `<appId>.json`, in the format of `catalog/live-tests/README.md` with `triggers: true` and the four steps below.

```
node --env-file-if-exists=.env scripts/live-certify.mjs <appId> --folder <absolute path> --triggers --leave [--record <name>=<value>]... [--resume <runId> [--from <test>]]
```

`--triggers` runs only a plan marked `triggers`, and a plan marked `triggers` runs only with the flag. The run writes `docs/live-evidence/<appId>/triggers.json` and leaves `actions.json` and `introspection.json` alone. `checkTriggerPlan()` checks a plan: every trigger of the app's file is watched and polled, each watch's first poll asserts 0, a poll, an unwatch or an age names a watch, and every write has its undo, as in an action plan. Unlike an action plan, it need not call every action.

The four steps hold a watch across tests, on one grant for the whole run, since a subscription ends with its grant:

- **`{"watch": {"trigger": "new-message@1", "args": {...}, "save": {"sub1": "/id"}}}`** is the real `triggers.subscribe`. It prints one card, waits for the owner, then polls until the watch is `active`. The owner approves the card on Fabric's own page, and nothing in the harness can. Put watches in tests of their own, with no write after the watch: a resume runs those tests again, since the watches ended with the old grant, and a write it finds already done is not sent twice.
- **`{"poll": {"subscription": {"$saved": "sub1"}, "events": 1, ...}}`** polls and reads what the watch told. The count is exact, of events and of gaps. `within` is seconds: with `events` above 0 it polls 10 seconds apart until the count is reached or the time ends, and with `events: 0` it waits the time out and polls once. A zero passes only if the run record shows the provider answered, and that read reached the end of a request: a skip, a limit or a failure is no answer. `gaps` is the count of gaps, 0 if left out, since a gap says something was not told. `itemsRead` asks that the read saw at least that many items, so a re-poll of a list cannot pass on an empty list. `floor` asks that the wait a provider names, such as GitHub's `X-Poll-Interval`, holds the watch at least that many seconds after the poll. No probe can read that header through the proxy, so this is where a run reads it. `where` maps pointers in an event to values and counts only those, for a feed that also holds what a run did not make. `checks` read `{events, gaps}` and `{status}`, the status of the last run.
- **`{"poll": {"subscription": {"$saved": "sub1"}, "paused": "<reason>"}}`** turns the step round. It passes only on no request, that reason and no provider answer, and it holds nothing else.
- **`{"unwatch": {"subscription": {"$saved": "sub1"}}}`** is the real `triggers.unsubscribe`.
- **`{"age": {"subscription": {"$saved": "sub1"}, "value": "<stale value>"}}`** writes a stale value over a watch's sync or history cursor. It runs only in a certification Fabric, and it is the only code that writes a cursor by hand. Put it and the polls that read its gap in one test: they read what the provider said to the stale value, which is what proves a resync. In that test an event told twice fails the poll.

Two placeholders are for these plans. `{"$mention": "<recorded name>"}` is the synthetic marker and that recorded member, as `<@U...>`: the one text Slack's guard lets a test post with a mention, in TR3 alone. `{"$localIn": {"minutes": 10}}` is that many minutes after the step runs, as a wall time in the run's zone, which is what Calendar's actions take, for TC-soon.

Each plan runs whole on its app's simulator in `test/live-plans.test.mjs`, behind the real guard, with `--leave`. No plan asks the owner to delete anything, and what a run makes stays, marked synthetic. So each test's `undo` says what stays, and no plan holds a `cleanup` test.

What a plan has to get right, which the run shows at once on a simulator:

- A name saved by a step and a watch's name share one space, so a save must not reuse a watch's name.
- One write can reach several watches, and a count is exact. So a test polls every watch its write reaches, or the next test reads what is left over. A self-sent mail is an inbox event and a sent event.
- A proof reads a watch's polls in one test, and `afterWrite` is the first poll that told something after a write. So a poll and its re-poll sit together, with no write between, and they sit in the test that holds the write. A `race` step counts as no write here.
- A read that asks a provider something and must not stop a pass on a no saves what it finds under a name, for you to read in the run file, and its check only asks that the answer is not empty. A `read` that compares nothing and saves nothing named passes on an empty answer, and `test/live-plans.test.mjs` refuses one.
- A resume watches again, and a new watch's baseline holds everything so far. So a test reads only what its own writes told, or a resume past it fails. An event a test cannot read in place takes a test of its own, right after, as TC-soon-told does. A stop after a test's write cannot prove that test again, since its stored job sends nothing: that takes a new run.
- `itemsRead` fits only a read that returns its items on a quiet poll. A feed with an ETag answers 304 and reads none, so a zero there leans on the provider's answer alone.
- A proxied read gives the guard bytes, so a list read through a `read` step lists nothing for the guard. A mail a run did not make needs `find-emails@1`, an action's search, before the next poll.

A proof in `triggers.json` comes from one watch's polls in one test. `afterWrite` is the first poll after a write that told something, `repoll` is the next poll with no write between, and `resync` is a poll that heard the provider refuse the stale value and told a gap. An owner's hand step counts as a write. `ask` and `oneTimeAsk` requests may hold a `body`, an object, with placeholders.
