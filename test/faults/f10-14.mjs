// F10.14 live session 1 (2026-10-29, run TOQJPGEU and the S7.13 sign-ins): seeded faults for what the session found and step 14 fixed
// before the Calendar run is repeated, in the format of test/faults/registry.mjs. Data only: nothing here reads or changes a file.
const STEP = 'F10.14';
const FILE = 'catalog/actions/google-calendar.json', FILE_TESTS = ['test/actions-google-calendar.test.mjs'];
const SIM = 'test/fixtures/provider-simulators/google-calendar.mjs', SIM_TESTS = ['test/provider-simulator-google-calendar.test.mjs', 'test/actions-google-calendar.test.mjs'];
const STARTS = '{"step":"check","equals":{"pointer":"/start","value":{"step":"move","pointer":"/start"}}},{"step":"check","equals":{"pointer":"/end","value":{"step":"move","pointer":"/end"}}}';

export const FAULTS = Object.freeze([
  // ---- C8: a move reads back with a newer etag ---------------------------------------------------------------------------------------
  {id: 'f1014-move-etag', step: STEP, name: 'Move event verifies on the etag its move answered, so a real move ends uncertain.',
    file: FILE, from: `"assert": [${STARTS}]`, to: '"assert": [{"step":"check","equals":{"pointer":"/etag","value":{"step":"move","pointer":"/etag"}}}]', tests: FILE_TESTS},
  {id: 'f1014-move-unchecked', step: STEP, name: 'Move event checks no field of its readback, so an event whose start changed verifies.',
    file: FILE, from: `"assert": [${STARTS}]`, to: '"assert": []', tests: FILE_TESTS},
  {id: 'f1014-sim-move-etag', step: STEP, name: 'The Calendar simulator keeps the move answer\'s etag, as Google does not.',
    file: SIM, from: '    next.etag = this.#etag(state);\n    return ok(answer, {etag: answer.etag});', to: '    return ok(answer, {etag: answer.etag});', tests: SIM_TESTS},
  // ---- the order of the pending undos ---------------------------------------------------------------------------------------------------
  {id: 'f1014-undo-order', step: STEP, name: 'Pending undos run oldest test first, so calendars are deleted before their events are put back.',
    file: 'lib/live-certify.mjs', from: '  return pending.reverse();\n', to: '  return pending;\n', tests: ['test/live-certify.test.mjs']},
  // ---- S5.6: the refusal names the permissions a fresh discovery leaves without access ------------------------------------------------
  {id: 'f1014-explain-candidates', step: STEP, name: 'A refused sign-in names only active operations, so a fresh discovery names none.',
    file: 'lib/app-detail.mjs', from: "!['active', 'candidate'].includes(capability.status)", to: "capability.status !== 'active'", tests: ['test/partial-grant.test.mjs']},
  {id: 'f1014-explain-disabled', step: STEP, name: 'A refused sign-in also names disabled operations.',
    file: 'lib/app-detail.mjs', from: "!['active', 'candidate'].includes(capability.status)", to: "!['active', 'candidate', 'disabled'].includes(capability.status)", tests: ['test/partial-grant.test.mjs']},
  // ---- a read that checks something is gone (live run MBIDCUUG, C13) --------------------------------------------------------------------
  {id: 'f1014-gone-once', step: STEP, name: 'A read that checks something is gone reads once, so a delete Google has not settled fails the test.',
    file: 'lib/live-certify.mjs', from: '(body.checks ?? []).some(absence)', to: 'false', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-gone-any', step: STEP, name: 'Every read retries, so a wrong answer to a check that something is there is read again.',
    file: 'lib/live-certify.mjs', from: '(body.checks ?? []).some(absence)', to: '(body.checks ?? []).length > 0', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-gone-cap', step: STEP, name: 'A read that checks something is gone asks one time too many.',
    file: 'lib/live-certify.mjs', from: 'for (let reads = 1; reads < PLAN_LIMITS.goneReads', to: 'for (let reads = 0; reads < PLAN_LIMITS.goneReads', tests: ['test/live-certify.test.mjs']},
  // ---- Gmail's owner cleanup comes once, at the end (live run LQ23SCN5 stopped at G2 waiting on Gmail) -----------------------------------
  {id: 'f1014-gmail-g2-early', step: STEP, name: 'G2 discards its drafts at once instead of in G11, so the run waits on Gmail mid-way.',
    file: 'catalog/live-tests/gmail.json', from: '{"$recorded": "handDraft"}}]}}\n   ],\n   "undo": {"test": "G11"}\n', to: '{"$recorded": "handDraft"}}]}}\n   ],\n   "undo": {"steps": [{"owner": {"words": "In Gmail, discard the run draft, then press Enter.", "until": {"path": "/gmail/v1/users/me/drafts/{draft}", "params": {"draft": {"$saved": "draft1"}}, "checks": [{"gone": true}]}}}]}\n',
    tests: ['test/actions-gmail.test.mjs']},
  // ---- the step 11 churn test: live passes move the evidence checks, and only those ---------------------------------------------------------
  {id: 'f1014-churn-evidence', step: STEP, name: 'The step 11 churn test stops putting the evidence checks back, so the live passes read as unlisted churn.',
    file: 'test/f10-11-churn.test.mjs', from: "    for (const checks of Object.values(ratchet.apps)) Object.assign(checks, {'live-evidence': false, 'sign-in-evidence': false});\n", to: '',
    tests: ['test/f10-11-churn.test.mjs']},
  {id: 'f1014-churn-wide', step: STEP, name: 'The step 11 churn test also puts back the closure check, so a moved closure would pass unseen.',
    file: 'test/f10-11-churn.test.mjs', from: "Object.assign(checks, {'live-evidence': false, 'sign-in-evidence': false});", to: "Object.assign(checks, {'live-evidence': false, 'sign-in-evidence': false, closure: !checks.closure});",
    tests: ['test/f10-11-churn.test.mjs']},
  {id: 'f1014-gmail-g11-label', step: STEP, name: 'G2 is undone by G10 again, whose first step needs G5\'s label, so a stop before G5 never discards its drafts.',
    file: 'catalog/live-tests/gmail.json', from: '{"$recorded": "handDraft"}}]}}\n   ],\n   "undo": {"test": "G11"}\n', to: '{"$recorded": "handDraft"}}]}}\n   ],\n   "undo": {"test": "G10"}\n',
    tests: ['test/actions-gmail.test.mjs']},
  // ---- the branch review: the gone read's wait and status forms, request ids that stay put, undo chains -----------------------------------
  {id: 'f1014-gone-wait', step: STEP, name: 'A gone read asks again at once, with no poll between the reads.',
    file: 'lib/live-certify.mjs', from: "    await ctx.wait(PLAN_LIMITS.pollMs);\n    response = await proxyRead(ctx, test, grant, body, into, 'r');", to: "    response = await proxyRead(ctx, test, grant, body, into, 'r');", tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-gone-status', step: STEP, name: 'A 404 or 410 status check is not read as a check that something is gone, so it never asks again.',
    file: 'lib/live-certify.mjs', from: "(Object.hasOwn(check, 'status') && [check.status].flat().every(status => status === 404 || status === 410))", to: 'false', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-gone-list', step: STEP, name: 'A status check given as a list of 404 and 410 never asks again.',
    file: 'lib/live-certify.mjs', from: "[check.status].flat().every(status => status === 404 || status === 410)", to: '(check.status === 404 || check.status === 410)', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-retry-ids', step: STEP, name: 'A gone read\'s re-reads take the next ids of the test, so a later call\'s id moves with Google\'s timing.',
    file: 'lib/live-certify.mjs', from: "response = await proxyRead(ctx, test, grant, body, into, 'r');", to: 'response = await proxyRead(ctx, test, grant, body, into);', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-poll-ids', step: STEP, name: 'An owner step\'s polls take the next ids of the test, so a later call\'s id moves with how long the owner took.',
    file: 'lib/live-certify.mjs', from: "const response = await proxyRead(ctx, test, grant, body.until, into, 'p');", to: 'const response = await proxyRead(ctx, test, grant, body.until, into);', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-undo-chain', step: STEP, name: 'After a stop, an undo test that a later test undoes in turn leaves that later test pending and unrun.',
    file: 'lib/live-certify.mjs', from: "next = pendingUndos(ctx).filter(item => !tried.has(`${item.kind} ${item.id}`) && !(ctx.leave && cleanup(item)))", to: 'next = []', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-undo-failed', step: STEP, name: 'An undo test that fails after a stop is not named as left in place.',
    file: 'lib/live-certify.mjs', from: "if (item.kind === 'test' ? result?.passed !== true : result?.undo.passed !== true) failed.push(`${item.words} failed.`);", to: '', tests: ['test/live-certify.test.mjs']},
  // ---- cleanup the owner may leave (Sami, 2026-10-29) --------------------------------------------------------------------------------------
  {id: 'f1014-leave-skip', step: STEP, name: 'With leave, the cleanup tests run anyway.',
    file: 'lib/live-certify.mjs', from: '    if (leave && item.cleanup) { leftByChoice(ctx, item); continue; }\n', to: '', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-leave-pending', step: STEP, name: 'With leave, a stop still offers the cleanup test a pending undo names.',
    file: 'lib/live-certify.mjs', from: 'const pending = pendingUndos(ctx).filter(item => !(ctx.leave && cleanup(item))), made', to: 'const pending = pendingUndos(ctx), made', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-cleanup-calls', step: STEP, name: 'A cleanup test may call an action, so leaving it would take an action\'s evidence with it.',
    file: 'lib/live-certify.mjs', from: "      if (item.steps.some(step => step.call !== undefined || step.race !== undefined)) fail(where, `${item.id} is cleanup, so it calls no action`);\n", to: '', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-cleanup-last', step: STEP, name: 'A real test may follow a cleanup test, so leaving cleanup would skip it.',
    file: 'lib/live-certify.mjs', from: " else if (plan.tests.slice(0, index).some(other => other.cleanup === true)) fail(where, `${item.id} comes after a cleanup test: cleanup tests come last`);", to: '', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-cleanup-undo', step: STEP, name: 'A cleanup test may name an undo, which leaving it would never run.',
    file: 'lib/live-certify.mjs', from: "      if (item.undo !== undefined && item.undo.none === undefined) fail(`${where}.undo`, `${item.id} is cleanup, so it undoes nothing`);\n", to: '', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-cli-leave', step: STEP, name: 'The command ignores --leave.',
    file: 'scripts/live-certify.mjs', from: "    else if (arg === '--leave') options.leave = true;\n", to: '', tests: ['test/live-certify.test.mjs']},
  {id: 'f1014-plans-cleanup', step: STEP, name: 'GitHub\'s branch deletes go back inside H9\'s undo, so leaving cleanup would fail the merge test.',
    file: 'catalog/live-tests/github.json', from: '"params": {"n": {"$saved": "h9Pull"}}, "checks": [{"pointer": "/merged", "equals": true}, {"pointer": "/merge_commit_sha", "present": true}]}}\n   ],\n   "undo": {"test": "H12"}',
    to: '"params": {"n": {"$saved": "h9Pull"}}, "checks": [{"pointer": "/merged", "equals": true}, {"pointer": "/merge_commit_sha", "present": true}]}}\n   ],\n   "undo": {"steps": [{"ask": {"row": "github.code.write", "requests": [{"method": "DELETE", "path": "/repos/samikasasbeh/fabric-sandbox-test/git/refs/heads/{+branch}", "params": {"branch": {"$branch": "base"}}}]}}]}',
    tests: ['test/actions-github.test.mjs']},
  // ---- Sign in again on an account that must reconnect (live check of 2026-10-29) ---------------------------------------------------------
  {id: 'f1014-renew-missing', step: STEP, name: 'An account that must sign in again offers no way to, only Add account.',
    file: 'lib/app-detail.mjs', from: "['reconnect_required', 'expired'].includes(connection.status)", to: 'false', tests: ['test/app-detail.test.mjs']},
  {id: 'f1014-renew-expired', step: STEP, name: 'An account whose sign-in expired offers no Sign in again.',
    file: 'lib/app-detail.mjs', from: "['reconnect_required', 'expired'].includes(connection.status)", to: "connection.status === 'reconnect_required'", tests: ['test/app-detail.test.mjs']},
  {id: 'f1014-renew-new-account', step: STEP, name: 'Sign in again names no account, so it makes a new one without the old settings.',
    file: 'lib/app-detail.mjs', from: "body: {appId, connectionId: connection.id}}} : {}),", to: "body: {appId}}} : {}),", tests: ['test/app-detail.test.mjs']},
  {id: 'f1014-renew-page', step: STEP, name: 'The app page drops Sign in again.',
    file: 'public/hosted-app.js', from: "    renew: detail.renew ? {label: detail.renew.label, ...signInAction(detail.renew)} : null,\n", to: '', tests: ['test/app-detail.test.mjs']},
  // ---- the sign-in return banner ---------------------------------------------------------------------------------------------------------
  {id: 'f1014-banner-google', step: STEP, name: 'The sign-in return banner says Google whichever provider returned.',
    file: 'public/app.js', from: "'Sign-in returned. Choose the connected app to review your account access.'", to: "'Google authorization returned. Choose the connected app to review your account access.'", tests: ['test/page-confirms.test.mjs']},
]);
