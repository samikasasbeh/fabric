# Reviewed choice sources

One file per app, named `<appId>.json`, in the options version 2 format of `docs/F10.9-BUILD-MAP.md` section 9. `loadChoiceSources()` in `lib/choice-sources.mjs` reads every `*.json` here, refuses a file not named after its `appId`, and validates each with `validateChoiceSources()`. It ignores this README, and git keeps the folder because of it. `loadActions()` loads this folder when it is given no choice sources.

A choice source names the reviewed read that lists the values an action input may take: a typed operation, or a GET or reviewed-read POST template, of a read row, never on a member that is unavailable or marked `sensitive: 'secrets'`. It names where the value, the label and any detail sit in the answer, the type of its values, how it pages and searches, and the values it never offers. It has no `serves` field: an action names it by id in its `choices`, and version 1 option sources in `catalog/options/` keep their own loader and readers, so nothing here reaches `POST /v1/options` (R10).

A list is advisory: every value sent is checked again by the action, so a list source's definition is not part of any action id. A `lookup` source reads one item by its id and runs as a prepare step, so its resolved request is part of the id of every action that uses it (R12).

No app ships a choices file in F10.9. The app slices of F10.13 to F10.21 add them with their live passes.
