// F03.11 security review, group d (governance and the proxy): one seeded fault per fix, in the format of
// test/faults/registry.mjs. `from` is copied exactly from the current file and occurs there once; `to` is the faulty
// replacement test/review-d.test.mjs must catch. Data only: nothing here reads or changes a file.
const TESTS = ['test/review-d.test.mjs'];
/** GOV-2, GOV-3 and GOV-6 were held by the Iteration 8 lock file; F10.3 retired it, and these entries now point at the rows that replace it. */
const MOVED = 'Moved to locked rows in F10.3.';

export const FAULTS = Object.freeze([
  {id: 'review-d-gov2-team-membership', step: 'F03.11', name: 'GOV-2: leave GitHub\'s team membership grant out of the T4 lock file.',
    file: 'catalog/permissions/github.json', from: '"PUT /orgs/{org}/teams/{team_slug}/memberships/{username}",', to: '', note: MOVED, tests: TESTS},
  {id: 'review-d-gov6-org-id-form', step: 'F03.11', name: 'GOV-6: leave the id form of the org invitation out of the T4 lock file.',
    file: 'catalog/permissions/github.json', from: '"POST /organizations/{organization_id}/invitations",', to: '', note: MOVED, tests: TESTS},
  {id: 'review-d-gov3-graphql-lock', step: 'F03.11', name: 'GOV-3: stop locking GraphQL requests to an app with locked entries.',
    file: 'lib/proxy-policy.mjs', from: "const graphqlLocked = match.kind === 'graphql' && definition.groups.some(group => group.locked === 'fabric');", to: 'const graphqlLocked = false;',
    note: `${MOVED} The clamp is seen only by the isolating GOV-3 (F10.3) case, whose GraphQL row still offers Ask.`, tests: TESTS},
  {id: 'review-d-gov3-graphql-row', step: 'F03.11', name: 'GOV-3: let the GraphQL proxy row of a locked app be opened to Ask again.',
    file: 'lib/proxy-policy.mjs', from: "    if (row === 'graphql' && definition?.groups.some(entry => entry.locked === 'fabric')) return ['deny'];", to: '    /* seeded: GraphQL row keeps Ask */', note: MOVED, tests: TESTS},
  {id: 'review-d-gov3-never-only-reads-ask', step: 'F03.11', name: 'GOV-3: read a saved mode a Never-only row cannot take as Ask.',
    file: 'lib/proxy-policy.mjs', from: "mode = entry.allowedModes.includes('ask') ? 'ask' : 'deny';", to: "mode = 'ask';", tests: TESTS},
  {id: 'review-d-gov4-reset-clamp', step: 'F03.11', name: 'GOV-4: judge the Reset clamp on the mode under the ceiling only.',
    file: 'lib/tenant/app-pages.mjs', from: "(member.decision.mode === 'allow' || (member.decision.defaultMode === 'allow' && member.decision.locked !== true))", to: "member.decision.mode === 'allow'", tests: TESTS},
  {id: 'review-d-gov5-account-name', step: 'F03.11', name: 'GOV-5: the hosted approve page names no account again.',
    file: 'lib/tenant/approvals.mjs', from: '{...this.#names(env), accountName, now:', to: '{...this.#names(env), now:', tests: TESTS},
  {id: 'review-d-gov5-page-line', step: 'F03.11', name: 'GOV-5: the approve page drops the account line on a developer\'s link.',
    file: 'public/hosted-approve.js', from: 'tenant ? (model.account ? `On your account ${model.account}` : null)', to: 'tenant ? null', tests: TESTS},
  {id: 'review-d-iso4-list-scan', step: 'F03.11', name: 'ISO-4: expire kept bodies by listing the whole response collection on every call.',
    file: 'lib/proxy-runtime.mjs', from: '  indexOnce(store);', to: "  for (const entry of store.list('proxyResponses')) if (Date.parse(entry.expiresAt) <= now) store.delete('proxyResponses', entry.id);", tests: TESTS},
  {id: 'review-d-iso4-index-once', step: 'F03.11', name: 'ISO-4: skip indexing the bodies kept before holders had an index.',
    file: 'lib/proxy-runtime.mjs', from: "  if (store.get('proxyResponses', INDEXED)) return;", to: '  return;', tests: TESTS},
  {id: 'review-d-iso4-quota', step: 'F03.11', name: 'ISO-4: stop counting the holder\'s kept bytes toward its quota.',
    file: 'lib/proxy-runtime.mjs', from: 'const used = index.entries.reduce((sum, entry) => sum + entry.bytes, 0);', to: 'const used = 0;', tests: TESTS},
  {id: 'review-d-iso4-expiry', step: 'F03.11', name: 'ISO-4: never expire the holder\'s kept bodies.',
    file: 'lib/proxy-runtime.mjs', from: "const live = Date.parse(entry.expiresAt) > now; if (!live) store.delete('proxyResponses', entry.id); return live;", to: 'return true;', tests: TESTS},
]);
