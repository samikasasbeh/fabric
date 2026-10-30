// The in-person test pass of 2026-10-30 (docs/MANUAL-TESTS.md): one seeded fault per bug it found, in the format of test/faults/registry.mjs.
// Each of these passed every automated test until a real provider or a real page showed it. Data only: nothing here reads or changes a file.
const STEP = 'F10.24';

export const FAULTS = Object.freeze([
  {id: 'hand-delete-body', step: STEP, name: 'A request body goes out with no declared length, so a DELETE carries none and a GitHub disconnect never revokes the token.',
    file: 'lib/network.mjs', from: "headers: body === undefined ? cleanHeaders : {...cleanHeaders, 'Content-Length': Buffer.byteLength(body)}, agent: false", to: 'headers: cleanHeaders, agent: false', tests: ['test/network.test.mjs']},
  {id: 'hand-readonly-alias', step: STEP, name: 'Google\'s name for the email scope counts as another app scope, so a live read-only account reads Custom.',
    file: 'lib/access-levels.mjs', from: 'const onlyRead = raw.every(scope => readScopes.includes(scope) || identity.includes(scope));', to: 'const onlyRead = raw.every(scope => readScopes.includes(scope) || (access.identityScopes || []).includes(scope));', tests: ['test/auth-v2.test.mjs']},
  {id: 'hand-readonly-any', step: STEP, name: 'Any other app scope still reads Read-only once the alias is known.',
    file: 'lib/access-levels.mjs', from: 'const onlyRead = raw.every(scope => readScopes.includes(scope) || identity.includes(scope));', to: 'const onlyRead = true;', tests: ['test/auth-v2.test.mjs']},
  {id: 'hand-never-alternative', step: STEP, name: 'A scope Fabric never asks for counts as a way around a missing one, so a refused sign-in names no permission.',
    file: 'lib/app-detail.mjs', from: 'scopeSets.every(set => set.some(scope => missing.has(scope) || never.has(scope)))', to: 'scopeSets.every(set => set.some(scope => missing.has(scope)))', tests: ['test/partial-grant.test.mjs']},
  {id: 'hand-never-alone', step: STEP, name: 'A sign-in missing something else names every permission only a never-asked scope serves.',
    file: 'lib/app-detail.mjs', from: ' && scopeSets.some(set => set.some(scope => missing.has(scope)));', to: ';', tests: ['test/partial-grant.test.mjs']},
  {id: 'hand-slack-line', step: STEP, name: 'Slack\'s distributed line never reaches the app page.',
    file: 'public/hosted-app.js', from: 'limits: detail.limits ?? [],', to: 'limits: [],', tests: ['test/slack-limits.test.mjs']},
  {id: 'hand-slack-field', step: STEP, name: 'The view stops carrying the limits the page draws.',
    file: 'lib/app-detail.mjs', from: '...(limits.length ? {limits} : {}),', to: '', tests: ['test/slack-limits.test.mjs']},
  {id: 'hand-discovery-unconnected', step: STEP, name: 'An app with active actions says it is undiscovered until an account connects.',
    file: 'lib/app-detail.mjs', from: "discovery: map || this.store.list('capabilities').some(capability => capability.appId === appId && capability.driver === 'action' && capability.status === 'active') ? {state: 'ready'}", to: "discovery: map || rows.some(row => row.members.some(member => member.capability?.driver === 'action')) ? {state: 'ready'}", tests: ['test/rows-every-app.test.mjs']},
  {id: 'hand-discovery-candidates', step: STEP, name: 'An app whose actions are only candidates reads as discovered.',
    file: 'lib/app-detail.mjs', from: "capability.driver === 'action' && capability.status === 'active') ? {state: 'ready'}", to: "capability.driver === 'action') ? {state: 'ready'}", tests: ['test/rows-every-app.test.mjs']},
  {id: 'hand-activity-null', step: STEP, name: 'The workspace Activity page hands a null to replaceChildren, which prints the word.',
    file: 'public/app.js', from: "main.replaceChildren(...[head('Activity', 'See what Fabric has done and what needs your attention.'), pending.length", to: "main.replaceChildren(head('Activity', 'See what Fabric has done and what needs your attention.'), pending.length",
    also: [{from: ', audit].filter(Boolean));', to: ', audit);'}], tests: ['test/owner-start.test.mjs']},
  {id: 'hand-start-trace', step: STEP, name: 'A second copy on the same folder prints a stack trace.',
    file: 'server.mjs', from: 'const release=await lockDataDir(dataDir).catch(stop);', to: 'const release=await lockDataDir(dataDir);', tests: ['test/owner-start.test.mjs']},
]);
