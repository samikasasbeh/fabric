import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';

// F10.3 listed churn (docs/F10-FIVE-APPS-DEEP.md section 2.2; docs/F10.3-BUILD-MAP.md section 6 and correction 5): the
// proxy-row bindings of the five apps, recorded before the data change in test/fixtures/access/f10-3-bindings.before.json.
// While an app's rows file is version 1 no binding moves. Once it is version 2, exactly the listed rows change, appear or
// disappear, and the rows the owner may set to Allow for the proxy keep their bindings.
const BEFORE = JSON.parse(readFileSync(new URL('./fixtures/access/f10-3-bindings.before.json', import.meta.url), 'utf8'));
const OTHER = ['other-reads', 'other-changes', 'other-deletes', 'graphql'];
const CHURN = {
  // F10.7 part e: the Gmail delete split moves three members out of gmail.permanent.delete into a new row.
  gmail: {changed: ['group:gmail.settings.write', 'group:gmail.messages.trash', 'group:gmail.permanent.delete', ...OTHER], added: ['group:gmail.access.grant', 'group:gmail.items.delete'], removed: ['group:gmail.notifications.watch']},
  'google-calendar': {changed: ['group:google-calendar.sharing.write', ...OTHER], added: ['group:google-calendar.access.grant'], removed: ['group:google-calendar.notifications.watch']},
  // F10.7 part d (critique 11): the {+ref} templates move github.repos.read's binding too; no proxyAllowable row moves.
  github: {changed: ['group:github.permanent.delete', 'group:github.code.write', 'group:github.repos.read', ...OTHER], added: ['group:github.access.grant'], removed: []},
  notion: {changed: 'every row', added: [], removed: []},
  // F10.7 part e: files.remote.share and conversations.declineSharedInvite move into slack.admin (Slack's only Other row is other-changes).
  slack: {changed: ['group:slack.files.write', 'group:slack.channels.manage', 'group:slack.admin', 'other-changes'], added: [], removed: []},
};

function bindingsNow(appId) {
  const config = PROXY_CONFIGS.get(appId), definition = PERMISSION_GROUPS.get(appId), policy = new ProxyPolicy({store: null});
  const templates = templatesFor(definition, config, BEFORE.maps[appId] ?? null);
  assert.ok(templates, `${appId}: the recorded map still covers every reviewed operation`);
  const context = {connection: BEFORE.connections[appId], config, templates};
  return Object.fromEntries(policy.rows({config, definition}).map(({row}) => [row, policy.binding(context, row)]));
}

test('the recorded bindings cover every row of the five apps', () => {
  assert.deepEqual(Object.keys(BEFORE.bindings).sort(), [...PROXY_CONFIGS.keys()].sort());
  for (const [appId, rows] of Object.entries(BEFORE.bindings)) for (const [row, hash] of Object.entries(rows)) assert.match(hash, /^[a-f0-9]{64}$/, `${appId} ${row}`);
});

test('proxy-row bindings move only as listed, and never for a row the owner may set to Allow', () => {
  for (const appId of Object.keys(BEFORE.bindings)) {
    const before = BEFORE.bindings[appId], now = bindingsNow(appId);
    for (const id of PROXY_CONFIGS.get(appId).proxyAllowable) assert.equal(now[`group:${id}`], before[`group:${id}`], `${id} is proxyAllowable`);
    if (PERMISSION_GROUPS.get(appId).schemaVersion === 1) {assert.deepEqual(now, before, `${appId}: version 1 rows keep every binding`); continue;}
    const churn = CHURN[appId], kept = Object.keys(before).filter(row => !churn.removed.includes(row));
    assert.deepEqual(Object.keys(now).sort(), [...kept, ...churn.added].sort(), `${appId}: rows added and removed`);
    const changed = kept.filter(row => now[row] !== before[row]).sort();
    assert.deepEqual(changed, churn.changed === 'every row' ? [...kept].sort() : [...churn.changed].sort(), `${appId}: rows whose binding changed`);
  }
});
