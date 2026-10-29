import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {tenantApps, consentSheet, signInOf} from '../lib/tenant/views.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';

// Exit check 8, the consent-sheet part (docs/F03-DEVELOPER-LAYER.md section 9): for every app a developer's end user
// can connect, the consent sheet carries every Muse part named in section 6.4 and every part Fabric adds, with Fabric's
// own words and reviewed links, and the hosted Connect page's sheet screen reads each of those fields.
const ORIGIN = 'http://127.0.0.1:1';
const PROJECT = {appName: 'Acme App', logoUrl: '/assets/logos/p/h', dataUse: {text: 'Note', learnMoreUrl: 'https://acme.example/data'}};
const DEVELOPER_APPS = ['notion', 'slack'];
const sheetFor = (id, extra = {}) => consentSheet(id, {origin: ORIGIN, project: PROJECT, providerApp: DEVELOPER_APPS.includes(id) ? {kind: 'developer', consentScreenName: 'Acme Agent'} : null, ...extra});
const PROVIDERS = JSON.parse(readFileSync(new URL('../catalog/providers.json', import.meta.url), 'utf8')).providers;
const DOC = readFileSync(new URL('./fixtures/docs/f03-section-6.4.md', import.meta.url), 'utf8');
const SCRIPT = readFileSync(new URL('../public/connect.js', import.meta.url), 'utf8');
const STYLE = readFileSync(new URL('../public/connect.css', import.meta.url), 'utf8');

// Section 6.4's Muse table, one row per part: the sheet fields that carry it, and the names the sheet screen reads.
// `points[reaches]` is the point whose kind is reaches. The developer's logo is drawn by topBar(view), which sheetScreen
// calls first, from the view's developer; test/tenant-logo.test.mjs pins that it equals the sheet's developer.logoUrl.
//
// | Muse part (section 6.4)                                      | Sheet fields                                         | Read by the sheet screen as                                  |
// | ------------------------------------------------------------ | ---------------------------------------------------- | ------------------------------------------------------------ |
// | Gmail logo and name                                          | app.iconUrl, app.name, developer.appName/logoUrl     | sheet.app.iconUrl, sheet.app.name, sheet.developer.appName, developer?.logoUrl |
// | "You can give read-only or read and write access"            | accessLine                                           | sheet.accessLine                                             |
// | What it reaches                                              | points[reaches].title/text                           | sheet.points, point.title, point.text                        |
// | "You choose what Muse can do"                                | points[control].title/text                           | sheet.points, point.title, point.text                        |
// | "Keep an eye on things"                                      | points[caution].title/text                           | sheet.points, point.title, point.text                        |
// | The app's data-use disclosure, with Learn more               | finePrint[developer_data_use].text/learnMoreUrl      | sheet.finePrint, item.text, item.learnMoreUrl                |
// | Exchanges information with the provider; terms and privacy   | finePrint[provider].text/termsUrl/privacyUrl         | sheet.finePrint, item.text, item.termsUrl, item.privacyUrl   |
// | One full-width Connect button; close at top right            | action.label                                         | sheet.action.label, api('close'                              |
const MUSE_PARTS = [
  {muse: 'Gmail logo and name', fields: ['app.iconUrl', 'app.name', 'developer.appName', 'developer.logoUrl'], reads: ['sheet.app.iconUrl', 'sheet.app.name', 'sheet.developer.appName', 'developer?.logoUrl']},
  {muse: '"You can give read-only or read and write access"', fields: ['accessLine'], reads: ['sheet.accessLine']},
  {muse: 'What it reaches', fields: ['points[reaches].title', 'points[reaches].text'], reads: ['sheet.points', 'point.title', 'point.text']},
  {muse: '"You choose what Muse can do"', fields: ['points[control].title', 'points[control].text'], reads: ['sheet.points', 'point.title', 'point.text']},
  {muse: '"Keep an eye on things"', fields: ['points[caution].title', 'points[caution].text'], reads: ['sheet.points', 'point.title', 'point.text']},
  {muse: 'The app\'s data-use disclosure, with Learn more', fields: ['finePrint[developer_data_use].text', 'finePrint[developer_data_use].learnMoreUrl'], reads: ['sheet.finePrint', 'item.text', 'item.learnMoreUrl']},
  {muse: 'Exchanges information with the provider; terms and privacy', fields: ['finePrint[provider].text', 'finePrint[provider].termsUrl', 'finePrint[provider].privacyUrl'], reads: ['sheet.finePrint', 'item.text', 'item.termsUrl', 'item.privacyUrl']},
  {muse: 'One full-width Connect button; close at top right', fields: ['action.label'], reads: ['sheet.action.label', 'api(\'close\'']},
];

// Section 6.4's "What Fabric adds to the sheet", matched to its bullet by a phrase from it.
//
// | Fabric addition (section 6.4)                      | Sheet fields                   | Read by the sheet screen as                      |
// | -------------------------------------------------- | ------------------------------ | ------------------------------------------------ |
// | the name the provider's own consent screen shows   | providerApp.consentScreenName  | sheet.providerApp.consentScreenName              |
// | "Connecting for <userHint>"                        | userHint                       | sheet.userHint                                   |
// | shared Google app in Testing mode notice           | notices                        | sheet.notices                                    |
// | a level choice where one is offered                | levels                         | sheet.levels, level.label, level.isDefault       |
// | one line on the defaults                           | defaultsLine                   | sheet.defaultsLine                               |
const ADDITIONS = [
  {phrase: 'consent screen will show', fields: ['providerApp.consentScreenName'], reads: ['sheet.providerApp.consentScreenName']},
  {phrase: 'Connecting for <userHint>', fields: ['userHint'], reads: ['sheet.userHint']},
  {phrase: 'Testing mode', fields: ['notices'], reads: ['sheet.notices']},
  {phrase: 'a level choice', fields: ['levels'], reads: ['sheet.levels', 'level.label', 'level.isDefault']},
  {phrase: 'one line on the defaults', fields: ['defaultsLine'], reads: ['sheet.defaultsLine']},
];

/** A dotted path into the sheet; `name[kind]` picks the list item with that kind. */
const at = (sheet, path) => path.split('.').reduce((value, part) => {
  const match = /^(\w+)\[(\w+)\]$/.exec(part);
  return match ? value?.[match[1]]?.find(item => item.kind === match[2]) : value?.[part];
}, sheet);
const filled = value => Array.isArray(value) ? value.length > 0 : typeof value === 'string' && value.trim().length > 0;

/** Section 6.4 of the spec, up to section 6.5. */
function section64() {
  const start = DOC.indexOf('### 6.4 What the end user sees'), end = DOC.indexOf('### 6.5', start);
  assert.ok(start >= 0 && end > start, 'section 6.4 is in the spec');
  return DOC.slice(start, end);
}
/** One top-level function of connect.js, from its declaration to the closing brace at column 0. */
function functionSource(name) {
  const start = SCRIPT.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} is in connect.js`);
  const end = SCRIPT.indexOf('\n}\n', start);
  assert.ok(end > start, `${name} ends`);
  return SCRIPT.slice(start, end + 2);
}

test('every connectable app gets a full consent sheet in Fabric\'s words, with the developer\'s note and the provider\'s reviewed links', () => {
  const apps = tenantApps();
  assert.ok(apps.length > 0, 'there are connectable apps');
  for (const id of DEVELOPER_APPS) assert.ok(apps.some(app => app.id === id), `${id} is connectable, so the developer-app sheet is covered`);
  for (const app of apps) {
    const id = app.id, sheet = sheetFor(id), where = `${id}`;
    assert.ok(sheet, where);
    assert.equal(typeof sheet.accessLine, 'string', `${where}: accessLine`);
    assert.ok(sheet.accessLine.trim().length > 0, `${where}: accessLine is not empty`);
    if (id === 'notion') assert.match(sheet.accessLine, /shares only the pages you pick/, 'Notion grants pages the person picks, on a developer\'s own app too');
    assert.ok(filled(sheet.app.name), `${where}: app name`);
    assert.equal(sheet.app.name, app.name, `${where}: the catalog's name`);
    assert.equal(sheet.app.iconUrl, `${ORIGIN}/assets/icons/${id}`, `${where}: the bundled icon`);
    assert.deepEqual(sheet.developer, {appName: 'Acme App', logoUrl: '/assets/logos/p/h'}, where);
    assert.deepEqual(sheet.points.map(point => point.kind), ['reaches', 'control', 'caution'], where);
    const firstRead = PERMISSION_GROUPS.get(id)?.groups?.find(group => group.effect === 'read');
    assert.ok(firstRead, `${where}: has a reviewed read row`);
    assert.ok(sheet.points[0].text.includes(firstRead.label.toLowerCase()), `${where}: the reaches point names "${firstRead.label.toLowerCase()}" in ${sheet.points[0].text}`);
    assert.ok(sheet.points[1].title.includes('Acme App'), `${where}: the control point names the developer's app`);
    assert.ok(filled(sheet.points[2].title) && filled(sheet.points[2].text), `${where}: caution point`);
    assert.deepEqual(sheet.finePrint[0], {kind: 'developer_data_use', text: 'Note', learnMoreUrl: 'https://acme.example/data'}, where);
    const {providerId} = signInOf(id), reviewed = PROVIDERS[providerId];
    assert.ok(reviewed, `${where}: ${providerId} is in catalog/providers.json`);
    const provider = sheet.finePrint.find(item => item.kind === 'provider');
    assert.ok(provider && filled(provider.text), `${where}: provider line`);
    assert.equal(provider.termsUrl, reviewed.termsUrl, `${where}: reviewed terms`);
    assert.equal(provider.privacyUrl, reviewed.privacyUrl, `${where}: reviewed privacy`);
    assert.match(provider.termsUrl, /^https:\/\//, where); assert.match(provider.privacyUrl, /^https:\/\//, where);
    const custody = sheet.finePrint.find(item => item.kind === 'custody');
    assert.ok(custody && filled(custody.text), `${where}: custody line`);
    assert.deepEqual(sheet.finePrint.map(item => item.kind), ['developer_data_use', 'provider', 'custody'], where);
    assert.ok(filled(sheet.providerApp.consentScreenName), `${where}: consent screen name`);
    if (DEVELOPER_APPS.includes(id)) assert.deepEqual(sheet.providerApp, {kind: 'developer', consentScreenName: 'Acme Agent'}, where);
    else assert.equal(sheet.providerApp.kind, 'shared', where);
    assert.equal(sheet.action.label, `Connect ${sheet.app.name}`, where);
    assert.match(sheet.etag, /^[0-9a-f]{32}$/, `${where}: etag`);
    assert.equal(sheetFor(id).etag, sheet.etag, `${where}: the same sheet has the same etag`);
    assert.notEqual(consentSheet(id, {origin: ORIGIN, project: {...PROJECT, appName: 'Beta App'}}).etag, sheet.etag, `${where}: another sheet has another etag`);
  }
});

test('the sheet has a field for every Muse part and every Fabric addition named in section 6.4', () => {
  const section = section64();
  const tableStart = section.indexOf('| Muse |'), table = section.slice(tableStart, section.indexOf('\n\n', tableStart)).split('\n');
  const museRows = table.slice(2).map(line => line.split('|')[1].trim());
  assert.equal(museRows.length, 8, 'section 6.4 names eight Muse parts');
  assert.deepEqual(MUSE_PARTS.map(part => part.muse), museRows, 'the test\'s table lists exactly the Muse parts in section 6.4, in order');
  const addsStart = section.indexOf('**What Fabric adds to the sheet:**'), adds = section.slice(addsStart, section.indexOf('\n\n', addsStart)).split('\n').filter(line => line.startsWith('- '));
  assert.equal(adds.length, ADDITIONS.length, 'one entry per Fabric addition');
  for (const line of adds) assert.equal(ADDITIONS.filter(addition => line.includes(addition.phrase)).length, 1, `exactly one entry for: ${line}`);

  for (const app of tenantApps()) {
    const sheet = sheetFor(app.id);
    for (const part of MUSE_PARTS) for (const field of part.fields) assert.ok(filled(at(sheet, field)), `${app.id}: ${part.muse} -> ${field}`);
    assert.ok(filled(at(sheet, 'providerApp.consentScreenName')) && filled(sheet.defaultsLine), app.id);
  }
  // The additions that appear only sometimes, shown together: a hint, a shared Google app in Testing mode, two levels.
  const gmail = sheetFor('gmail', {userHint: 'sam@acme.example'});
  for (const addition of ADDITIONS) for (const field of addition.fields) assert.ok(filled(at(gmail, field)), `gmail: ${addition.phrase} -> ${field}`);
  assert.equal(gmail.userHint, 'sam@acme.example');
  assert.match(gmail.notices[0], /access lasts 7 days/);
  assert.deepEqual(gmail.providerApp, {kind: 'shared', consentScreenName: 'Fabric', testing: {maxUsers: 100, expiresAfterDays: 7}});
  assert.ok(gmail.levels.length > 1, 'Gmail offers a level choice');
  assert.equal(gmail.levels.filter(level => level.isDefault).length, 1, 'one level is the default');
  assert.ok(gmail.levels.every(level => filled(level.label)));
  // A developer's own Google app has no Testing-mode notice; nothing is said that is not true.
  assert.deepEqual(consentSheet('gmail', {origin: ORIGIN, project: PROJECT, providerApp: {kind: 'developer', consentScreenName: 'Acme Agent'}}).notices, []);
  // The developer's note is never invented: without one, there is no data-use line.
  assert.equal(consentSheet('gmail', {origin: ORIGIN, project: {appName: 'Acme App'}}).finePrint.some(item => item.kind === 'developer_data_use'), false);
});

test('the Connect page\'s sheet screen reads every one of those fields', () => {
  const sheetScreen = functionSource('sheetScreen'), topBar = functionSource('topBar');
  assert.match(sheetScreen, /\btopBar\(view\)/, 'the sheet screen draws the developer bar first');
  const code = `${sheetScreen}\n${topBar}`;
  for (const part of [...MUSE_PARTS, ...ADDITIONS]) for (const name of part.reads) assert.ok(code.includes(name), `${part.muse || part.phrase}: the sheet screen reads ${name}`);
  // The kinds are rendered in the order the sheet gives them, and the Connect button is the full-width primary one.
  assert.match(sheetScreen, /sheet\.points\.map\(point =>/);
  assert.match(sheetScreen, /sheet\.finePrint\.map\(item =>/);
  assert.match(sheetScreen, /const connect = button\(sheet\.action\.label, /);
  assert.match(SCRIPT, /const button = \(label, onClick, kind = 'primary'\)/);
  assert.match(STYLE, /\.primary,\.secondary\{[^}]*width:100%/, 'Connect is full width');
  assert.match(STYLE, /\.close\{margin-left:auto/, 'Close sits at the right of the top bar');
  assert.match(topBar, /api\('close', \{\}\)/, 'Close cancels the session');
  // Only the developer's note is theirs, and it goes in as text.
  assert.equal(/innerHTML|outerHTML|insertAdjacentHTML/.test(sheetScreen), false);
});
