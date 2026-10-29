# Reviewed action files

One file per app, named `<appId>.json`, in the action format of `docs/F10.9-BUILD-MAP.md` part f (with the poll block of part h). `loadActions()` in `lib/actions.mjs` reads every `*.json` here, refuses a file not named after its `appId`, and validates each with `validateActionFile()`. It ignores this README, and git keeps the folder because of it.

Each action carries its id, `<appId>.action.<key>.v<version>.<24 hex characters>`: the hash of its content without `id`, `certified` and `poll`, with the pin of every transform it names and the resolved request of every choice lookup. A stored id must equal the computed one, so any change to an action gives it a new id that a review sees. `actionIds()` gives the ids (and the definition hash a `certified` block carries) to write. An old id goes in the file's `superseded` list with what replaced it.

Google Calendar ships the first file, `google-calendar.json` (F10.13): its 13 actions stay candidates until step 14's live evidence certifies them. Gmail, GitHub, Notion and Slack add theirs in F10.15 to F10.21, each with its live pass. Calendar's steps place only through Google's method map, so where no Calendar map is stored yet the file is refused rather than run: Find free time is a reviewed-read POST, which counts as a write until it places (F10.10). Fabric loads the file again when the map is stored.

Gmail's file, `gmail.json`, ships with step 15 (F10.15): its 13 actions stay candidates until step 16's live evidence certifies them. Where no Gmail map is stored yet they load unplaced, valid in shape and never run; none is refused, since none is a reviewed-read POST. Fabric places them when the map is stored.

GitHub's file, `github.json` (F10.17), holds 15 actions that stay candidates until step 18's live evidence certifies them. GitHub's rows list their request templates, so its steps place with no map and the file loads wherever Fabric runs.

Notion ships `notion.json` (F10.19): its 16 actions place by method and path, with no map, and stay candidates until step 20's live evidence certifies them.

Slack ships `slack.json` (F10.21): its 13 actions stay candidates until step 22's live evidence certifies them. Slack's steps are request templates, so its file needs no map and loads wherever Fabric runs.

Since F10.11 the owner's Fabric loads this folder at start, with its stored maps, through `lib/action-gate.mjs` (the one guarded import of an action module), and writes each action's status: active only when its file is reviewed, it is certified with passing live evidence (`docs/live-evidence/<appId>/actions.json`), every step places, and every transform it names keeps its pinned code. A bad file refuses only its own app. A folder that will not load at all leaves every action unsupported and every stored active action a candidate, and Fabric still starts. Developer environments read the statuses `node cli.mjs tenant catalog actions [APP_ID] --root ROOT` writes into the platform catalog, and the developer server serves none more active than the catalog it loads at start computes.
