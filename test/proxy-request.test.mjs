import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeProxyRequest, normalizePath, LIMITS} from '../lib/proxy-request.mjs';
import {templatesFor, matchRequest} from '../lib/proxy-match.mjs';
import {readFileSync} from 'node:fs';
import {PERMISSION_GROUPS, validatePermissionGroups, parseTemplate, groupFor, looseShape} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS, validateProxyConfig} from '../lib/proxy-config.mjs';

// F08.0a (docs/F08.0-GOVERNED-PROXY.md sections 3 and 4): the request normalizer and the row matcher.
// Pure functions: no network, no store, no policy. Fixture data only.
// GitHub's own route list (MIT, github/rest-api-description), shipped as reviewed data in catalog/proxy.
const ROUTES = JSON.parse(readFileSync(new URL('../catalog/proxy/github.routes.json', import.meta.url), 'utf8'));
const GITHUB = {apiBase: 'https://api.github.com', style: 'rest', aliases: [{from: '/repos/{owner}/{repo}', to: '/repositories/{repository_id}'}], documented: ROUTES.routes};
const SLACK = {apiBase: 'https://slack.com/api', style: 'rpc', reservedParameters: ['token'], reservedBodyFields: ['token'], inheritFamilies: ['admin', 'oauth', 'openid', 'apps', 'auth']};
const GMAIL = {apiBase: 'https://gmail.googleapis.com', style: 'rest', pathPrefixes: ['/gmail/v1/'], reservedParameters: ['key']};
const CALENDAR = {apiBase: 'https://www.googleapis.com/calendar/v3', style: 'rest', reservedParameters: ['key']};
const code = (input, config = GITHUB, options) => {try {normalizeProxyRequest(input, config, options); return 'ok';} catch (error) {return error.code || error.message;}};
const get = (path, extra = {}) => ({method: 'GET', path, ...extra});

test('a request becomes one canonical URL: sorted, strictly encoded query, and exactly the bytes that are sent', () => {
  const request = normalizeProxyRequest({method: 'POST', path: '/repos/o/r/issues', query: {z: '1', a: "it's (x)*!"}, headers: {accept: 'application/json', 'If-Match': '"abc"'}, body: {title: 'Bug', n: 1}}, GITHUB);
  assert.equal(request.url, 'https://api.github.com/repos/o/r/issues?a=it%27s%20%28x%29%2A%21&z=1');
  assert.equal(new URL(request.url).href, request.url, 'the URL parser changes nothing');
  assert.deepEqual(request.headers, {Accept: 'application/json', 'If-Match': '"abc"'});
  assert.equal(request.body, '{"title":"Bug","n":1}'); assert.equal(request.bodyBytes, 21); assert.match(request.bodyHash, /^[a-f0-9]{64}$/);
  assert.equal(request.timeoutMs, LIMITS.timeoutDefault);
  assert.equal(normalizeProxyRequest(get('/gmail/v1/users/me/messages'), GMAIL).url, 'https://gmail.googleapis.com/gmail/v1/users/me/messages');
  assert.equal(normalizeProxyRequest(get('/calendars/primary/events'), CALENDAR).url, 'https://www.googleapis.com/calendar/v3/calendars/primary/events');
  assert.equal(normalizeProxyRequest({method: 'POST', path: '/chat.postMessage', body: {channel: 'C1', text: 'hi'}}, SLACK).url, 'https://slack.com/api/chat.postMessage');
});

test('paths: decoding once and re-encoding is stable, and the matched path is the sent path', () => {
  for (const path of ['/repos/o/r', '/rep%6Fs/o/r', '/a/%E2%82%AC', "/a/b@c:d!$&'()*+,=", '/a/%EF%BC%8E%EF%BC%8E', '/a/%3F%23']) {
    const once = normalizePath(path), twice = normalizePath(once.path);
    assert.equal(twice.path, once.path, path); assert.deepEqual(twice.segments, once.segments, path);
  }
  assert.deepEqual(normalizePath('/rep%6Fs/o').segments, ['repos', 'o']);
  assert.equal(normalizePath('/rep%6Fs/o').path, '/repos/o');
  assert.equal(normalizePath('/a/%EF%BC%8E%EF%BC%8E').path, '/a/%EF%BC%8E%EF%BC%8E', 'fullwidth dots stay percent-encoded and are not dot segments');
  assert.deepEqual(normalizePath('/'), {segments: [], path: '/'});
  // Dot segments are refused by the normalizer itself, not only by the final URL comparison.
  for (const path of ['/a/..', '/a/.', '/%2e%2e', '/a/%2E/b']) assert.throws(() => normalizePath(path), error => error.code === 'invalid_path', path);
});

test('path traversal, encoded slashes, double and overlong encoding, and host tricks are refused', () => {
  for (const path of ['/%EF%BB%BF', '/repos/o/r/../../user', '/repos/%2e%2e/x', '/repos/%2E%2e/x', '/.', '/./x', '/..;/x', '/a%252e%252e', '/a%c0%ae%c0%ae', '/a\\b', '/a\tb', '/a\nb', '/a b',
    '/repos/o/r/contents/a%2Fb', '/o%2Fr', '/a%5Cb', '//api.github.com/user', '/repos//r', '/repos/o/', 'https://evil.example/x', 'http:/x', 'repos/o', '/a?b=1', '/a#x', '/a%zz', '/a/%00', '/a/%E2%80%AE', '/a/%EF%BB%BF', '/__proto__', '']) {
    assert.equal(code(get(path)), 'invalid_path', JSON.stringify(path));
  }
  // The host is never part of the path: an "@" segment stays a segment on the reviewed origin.
  const at = normalizeProxyRequest(get('/@evil.example/x'), GITHUB);
  assert.equal(new URL(at.url).hostname, 'api.github.com'); assert.equal(new URL(at.url).pathname, '/@evil.example/x');
  assert.equal(code(get('/gmail/v1/../../x'), GMAIL), 'invalid_path');
  assert.equal(code(get('/upload/gmail/v1/users/me/messages'), GMAIL), 'invalid_path', 'outside the reviewed prefix');
  assert.equal(code(get('/../../drive/v3/files'), CALENDAR), 'invalid_path');
  assert.equal(code(get('/gmail/v1'), GMAIL), 'invalid_path', 'the prefix must be followed by a segment');
});

test('credentials, host and method-override headers are refused, not dropped', () => {
  for (const name of ['Authorization', 'Cookie', 'Proxy-Authorization', 'X-Api-Key', 'Host', 'X-Forwarded-Host', 'Forwarded', 'X-Original-URL', 'X-Rewrite-URL',
    'X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override', 'X_HTTP_METHOD_OVERRIDE', 'X-GitHub-Api-Version', 'Notion-Version', 'Content-Type']) {
    assert.equal(code(get('/x', {headers: {[name]: 'v'}})), 'header_not_allowed', name);
  }
  assert.equal(code(get('/x', {headers: {Accept: 'text/html'}})), 'header_not_allowed', 'only reviewed Accept values');
  assert.equal(code(get('/x', {headers: {'If-Match': 'a', 'if-match': 'b'}})), 'header_not_allowed', 'repeated case-insensitively');
  assert.equal(code(get('/x', {headers: {'If-Match': 'a\r\nX: y'}})), 'header_not_allowed');
  assert.equal(code(get('/x', {headers: Object.fromEntries(Array.from({length: 17}, (_, i) => [`If-Match${i}`, 'a']))})), 'request_too_large');
  assert.equal(code(get('/x', {headers: {'If-Match': 'a'.repeat(1025)}})), 'request_too_large');
});

test('credential, callback, override and Google system parameters are refused in the query and body', () => {
  for (const name of ['access_token', 'ACCESS_TOKEN', 'oauth_token', 'api_key', 'apikey', 'client_secret', 'callback', 'jsonp', '_method', 'x-http-method-override', '$key', '$callback', '$ct', '$userProject', 'password', 'passwd', 'alt', 'uploadType', 'upload_protocol', '__proto__', 'a b', '']) {
    assert.equal(code(get('/x', {query: {[name]: 'v'}})), 'parameter_not_allowed', name);
  }
  assert.equal(code({method: 'GET', path: '/chat.postMessage', query: {token: 'xoxb'}}, SLACK), 'parameter_not_allowed');
  assert.equal(code({method: 'POST', path: '/chat.postMessage', body: {token: 'xoxb', text: 'x'}}, SLACK), 'parameter_not_allowed');
  assert.equal(code(get('/gmail/v1/users/me/messages', {query: {key: 'k'}}), GMAIL), 'parameter_not_allowed');
  assert.equal(code({method: 'POST', path: '/x', body: {_method: 'DELETE'}}), 'parameter_not_allowed');
  assert.equal(code(get('/x', {query: {channel: ['A', 'B']}})), 'parameter_not_allowed', 'repeated values only for reviewed names');
  assert.equal(normalizeProxyRequest(get('/x', {query: {labelIds: ['A', 'B']}}), {...GITHUB, arrayParameters: ['labelIds']}).query, 'labelIds=A&labelIds=B');
  assert.equal(code(get('/calendars/primary/events', {query: {maxResults: '5', sneaky: '1'}}), {...CALENDAR, queryParameters: ['maxResults']}), 'parameter_not_allowed', 'Google: documented parameters only');
  assert.equal(code(get('/x', {query: {q: 'a\u0000'}})), 'parameter_not_allowed');
  assert.equal(code(get('/x', {query: {q: 1}})), 'parameter_not_allowed');
});

test('methods, bodies, sizes and timeouts', () => {
  for (const method of ['HEAD', 'OPTIONS', 'TRACE', 'CONNECT', 'get', 'GET ', '']) assert.equal(code({method, path: '/x'}), 'method_not_allowed', JSON.stringify(method));
  assert.equal(code({method: 'PUT', path: '/chat.postMessage'}, SLACK), 'method_not_allowed');
  assert.equal(code({method: 'DELETE', path: '/chat.delete'}, SLACK), 'method_not_allowed');
  assert.equal(code({method: 'GET', path: '/x', body: {}}), 'unsupported_body');
  assert.equal(code({method: 'POST', path: '/chat.postMessage', query: {channel: 'C'}, body: {}}, SLACK), 'parameter_not_allowed', 'RPC: one argument cannot hide in two places');
  assert.equal(code({method: 'GET', path: '/a/b'}, SLACK), 'invalid_path', 'RPC methods are one segment');
  assert.equal(code({method: 'POST', path: '/x', body: {a: 'x'.repeat(LIMITS.body)}}), 'request_too_large');
  let deep = 1; for (let i = 0; i < 33; i++) deep = [deep];
  assert.equal(code({method: 'POST', path: '/x', body: deep}), 'unsupported_body');
  assert.equal(code({method: 'POST', path: '/x', body: JSON.parse('{"__proto__": {"x": 1}}')}), 'unsupported_body');
  assert.equal(code({method: 'POST', path: '/x', body: {n: Infinity}}), 'unsupported_body');
  assert.equal(code(get(`/${'a'.repeat(2048)}`)), 'request_too_large');
  assert.equal(code(get(`/${Array.from({length: 33}, () => 'a').join('/')}`)), 'request_too_large');
  assert.equal(code(get('/x', {query: Object.fromEntries(Array.from({length: 51}, (_, i) => [`q${i}`, '1']))})), 'request_too_large');
  assert.equal(code(get('/x', {query: {a: 'x'.repeat(2048), b: 'x'.repeat(2048), c: 'x'.repeat(2048), d: 'x'.repeat(2048), e: 'x'}})), 'request_too_large');
  for (const timeoutMs of [999, 30001, 1.5, '1000']) assert.equal(code(get('/x'), GITHUB, {timeoutMs}), 'invalid_request', String(timeoutMs));
  assert.equal(normalizeProxyRequest(get('/x'), GITHUB, {timeoutMs: 30000}).timeoutMs, 30000);
  assert.equal(code({method: 'GET', path: '/x', extra: 1}), 'invalid_request');
  assert.equal(code(get('/x'), {apiBase: 'http://api.github.com', style: 'rest'}), 'proxy_unavailable');
  assert.equal(code(get('/x'), {apiBase: 'https://api.github.com', style: 'graphql'}), 'proxy_unavailable');
});

// F10.3 (docs/F10-FIVE-APPS-DEEP.md section F10.3, critique test 11): reserved body fields are refused at any depth, within
// the depth limit of 32. NOTION lists the names F10.3 reserves for Notion, so the rule is checked before the data moves.
const NOTION = {apiBase: 'https://api.notion.com', style: 'rest', reservedBodyFields: ['in_trash', 'archived', 'is_archived', 'erase_content', 'is_locked', 'allow_deleting_content', 'display_name']};
const nested = (depth, leaf) => {let body = leaf; for (let i = 1; i < depth; i++) body = {a: body}; return body;};
test('reserved body fields are refused at any depth: inside objects and arrays, and in a top-level array', () => {
  for (const body of [{a: {token: 'xoxb'}}, [{token: 'xoxb'}], {blocks: [{metadata: {token: 'x'}}]}, {text: 'x', attachments: [[{token: 'x'}]]}])
    assert.equal(code({method: 'POST', path: '/chat.postMessage', body}, SLACK), 'parameter_not_allowed', JSON.stringify(body));
  for (const body of [{update_content: {in_trash: true}}, {children: [{archived: true}]}, {replace_content: {allow_deleting_content: true}}, {update_content: {erase_content: true}},
    {properties: {Status: {is_archived: false}}}, {children: [{paragraph: {is_locked: true}}]}, {owner: {display_name: 'x'}}])
    assert.equal(code({method: 'PATCH', path: '/v1/pages/abc', body}, NOTION), 'parameter_not_allowed', JSON.stringify(body));
  assert.match((() => {try {normalizeProxyRequest({method: 'PATCH', path: '/v1/pages/abc', body: {a: [{in_trash: true}]}}, NOTION);} catch (error) {return error.message;}})(), /^The body field in_trash is reserved\.$/);
  for (const body of [{a: {_method: 'DELETE'}}, [{_method: 'DELETE'}], {list: [1, {x: {_method: 'GET'}}]}]) assert.equal(code({method: 'POST', path: '/x', body}), 'parameter_not_allowed', JSON.stringify(body));
  assert.equal(code({method: 'POST', path: '/x', body: nested(32, {_method: 'x'})}), 'parameter_not_allowed', 'a reserved key on the 32nd level is refused as reserved');
  assert.equal(code({method: 'POST', path: '/x', body: nested(33, {_method: 'x'})}), 'unsupported_body', '33 levels are too deep, whatever they hold');
  assert.equal(code({method: 'POST', path: '/x', body: nested(31, {name: 'x'})}), 'ok', 'an ordinary key whose value sits on the 32nd level');
  assert.equal(code({method: 'POST', path: '/x', body: nested(32, {})}), 'ok');
  for (const body of [{a: {Token: 'x'}}, {a: {TOKEN: 'x'}}, {a: {tokens: 'x'}}, {a: 'token'}, {a: ['token']}, {channel: 'C', blocks: [{text: {type: 'mrkdwn', text: 'token'}}]}])
    assert.equal(code({method: 'POST', path: '/chat.postMessage', body}, SLACK), 'ok', JSON.stringify(body));
  for (const body of [{update_content: {In_Trash: true}}, {properties: {title: 'archived'}}, {children: [{type: 'paragraph'}]}])
    assert.equal(code({method: 'PATCH', path: '/v1/pages/abc', body}, NOTION), 'ok', JSON.stringify(body));
});

// Critique test 11 on the shipped settings: Notion reserves the seven names of F10.3 (D2), so a raw request can trash, erase or
// delete content only through its reviewed routes, and a markdown replace is an ordinary body the rows place.
test('critique test 11: the shipped Notion settings refuse the trash, erase and delete fields at any depth', () => {
  const notion = PROXY_CONFIGS.get('notion');
  assert.deepEqual(notion.reservedBodyFields, NOTION.reservedBodyFields);
  for (const body of [{update_content: {in_trash: true}}, {update_content: {erase_content: true}}, {replace_content: {allow_deleting_content: true}}, {children: [{archived: true}]}, {in_trash: false}, [{is_archived: true}]])
    assert.equal(code({method: 'PATCH', path: '/v1/pages/abc', body}, notion), 'parameter_not_allowed', JSON.stringify(body));
  assert.equal(code({method: 'PATCH', path: '/v1/pages/abc/markdown', body: {type: 'replace_content', replace_content: {new_str: '# New'}}}, notion), 'ok');
  assert.deepEqual(PROXY_CONFIGS.get('slack').reservedBodyFields, ['token'], 'Slack keeps its one reserved name');
});

// ---- matching ----------------------------------------------------------------------------
const sample = template => template.segments.flatMap(part => part.kind === 'literal' ? [part.value] : part.kind === 'param' ? ['p1'] : ['a', 'b']);
const STYLES = {github: GITHUB, notion: {style: 'rest'}, slack: SLACK};

test('every reviewed template, filled in, lands in its own row (GitHub, Notion, Slack: 759 templates; F10.7 added the Notion view-query delete)', () => {
  let count = 0;
  for (const [appId, config] of Object.entries(STYLES)) {
    const templates = templatesFor(PERMISSION_GROUPS.get(appId), config);
    for (const template of templates.filter(template => !template.unreviewed && !template.request.includes('/repositories/{repository_id}'))) {
      const match = matchRequest(templates, {method: template.method, segments: sample(template)}, config);
      assert.equal(match.kind, 'group', template.request); assert.equal(match.groupId, template.groupId, `${appId}: ${template.request}`);
      count++;
    }
  }
  assert.equal(count, 759);
});

test('the most specific template wins, multi-segment parameters match, and case folding is ASCII only', () => {
  const templates = templatesFor(PERMISSION_GROUPS.get('github'), GITHUB);
  const match = (method, path) => matchRequest(templates, {method, segments: normalizePath(path).segments});
  assert.equal(match('GET', '/user/repos').groupId, 'github.repos.read', 'a literal beats /user/{account_id}');
  assert.equal(match('GET', '/user/issues').groupId, match('GET', '/repos/o/r/issues').groupId);
  assert.equal(match('GET', '/user/12345').groupId, 'github.profile.read');
  assert.equal(match('PATCH', '/repos/o/r/git/refs/heads/main').groupId, 'github.code.write', 'F10.7: GitHub writes a ref as heads/<branch>, so Fabric reviews the ref routes as multi-segment');
  assert.equal(match('PUT', '/repos/o/r/contents/.github/workflows/x.yml').template, 'PUT /repos/{owner}/{repo}/contents/{+path}');
  assert.equal(match('DELETE', '/Repos/o/r').groupId, match('DELETE', '/repos/o/r').groupId, 'ASCII case folds');
  assert.equal(match('GET', '/rep%6Fs/o/r/issues').groupId, match('GET', '/repos/o/r/issues').groupId, 'decoded before matching');
  assert.equal(match('GET', '/repos/o/r/forks').groupId, 'github.repos.read');
  assert.equal(match('GET', '/repos/o/r/for%E2%84%AAs').kind, 'other-reads', 'the Kelvin sign never folds into the "k" of a literal');
  assert.equal(match('DELETE', '/repositories/123').groupId, match('DELETE', '/repos/o/r').groupId, 'alias routes land in the same row');
});

test('effects are never weaker than the row, and RPC apps match by path alone', () => {
  const slack = templatesFor(PERMISSION_GROUPS.get('slack'), SLACK);
  const viaGet = matchRequest(slack, {method: 'GET', segments: ['chat.postMessage']}, SLACK);
  const viaPost = matchRequest(slack, {method: 'POST', segments: ['chat.postMessage']}, SLACK);
  assert.equal(viaGet.groupId, viaPost.groupId); assert.equal(viaGet.effect, 'write', 'a GET to a write method is a write');
  // A writing method in a read row is a write unless that member was reviewed as a read.
  const notion = templatesFor(PERMISSION_GROUPS.get('notion'), {style: 'rest'});
  const views = matchRequest(notion, {method: 'POST', segments: ['v1', 'views', 'v1', 'queries']});
  assert.equal(views.groupId, 'notion.content.read'); assert.equal(views.effect, 'write'); assert.equal(views.reviewedRead, false);
  const search = matchRequest(notion, {method: 'POST', segments: ['v1', 'search']});
  assert.equal(search.effect, 'read'); assert.equal(search.reviewedRead, true);
  const github = templatesFor(PERMISSION_GROUPS.get('github'), GITHUB);
  for (const template of github.filter(template => !template.unreviewed && !template.reviewedRead)) {
    const match = matchRequest(github, {method: template.method, segments: sample(template)});
    assert.ok({read: 0, write: 1, delete: 2}[match.effect] >= {read: 0, write: 1, delete: 2}[template.effect], template.request);
  }
});

test('unmatched requests go to the Other rows and carry the rows whose Never they inherit', () => {
  const github = templatesFor(PERMISSION_GROUPS.get('github'), GITHUB);
  const match = (method, path) => matchRequest(github, {method, segments: normalizePath(path).segments});
  assert.equal(match('GET', '/some/new/endpoint').kind, 'other-reads');
  assert.equal(match('POST', '/some/new/endpoint').kind, 'other-changes');
  const deletion = match('DELETE', '/repos/o/r/x/y');
  assert.equal(deletion.kind, 'other-deletes'); assert.equal(deletion.effect, 'delete');
  assert.ok(deletion.inheritFrom.includes(match('DELETE', '/repos/o/r').groupId), 'DELETE /repos/{owner}/{repo} passes on its row');
  const graph = match('POST', '/graphql');
  assert.equal(graph.kind, 'graphql'); assert.equal(graph.effect, 'write');
  const slack = templatesFor(PERMISSION_GROUPS.get('slack'), SLACK);
  const admin = matchRequest(slack, {method: 'GET', segments: ['admin.users.brandNew']}, SLACK);
  assert.equal(admin.kind, 'other-changes'); assert.equal(admin.effect, 'write');
  const adminRow = matchRequest(slack, {method: 'POST', segments: [slack.find(template => template.request.includes('/admin.')).segments[0].value]}, SLACK).groupId;
  assert.ok(admin.inheritFrom.includes(adminRow), 'an unknown admin.* method inherits the admin row');
});

test('apps reviewed by operation id match through the stored application map, and have no proxy without one', () => {
  const gmail = PERMISSION_GROUPS.get('gmail');
  assert.equal(templatesFor(gmail, GMAIL, null), null, 'no stored map: proxy_unavailable, never "Other"');
  const send = gmail.groups.find(group => group.operations.includes('gmail.users.messages.send'));
  const ids = gmail.groups.flatMap(group => group.operations);
  const map = {operations: ids.map(id => ({id, method: 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`}))};
  const templates = templatesFor(gmail, GMAIL, map);
  assert.equal(templates.length, ids.length);
  const match = matchRequest(templates, {method: 'POST', segments: normalizePath('/gmail/v1/users/me/messages/send').segments});
  assert.equal(match.groupId, send.id); assert.equal(match.effect, 'write');
  assert.equal(matchRequest(templates, {method: 'POST', segments: normalizePath('/gmail/v1/users/me/brand/new').segments}).kind, 'other-changes');
});

test('the validator refuses ambiguous or malformed templates', () => {
  const base = {schemaVersion: 1, appId: 'demo'};
  const groups = (...list) => ({...base, groups: list.map((requests, i) => ({id: `demo.g${i}`, label: `G${i}`, effect: 'read', defaultMode: 'allow', requests}))});
  assert.throws(() => validatePermissionGroups(groups(['GET /a/{x}'], ['GET /A/{y}'])), /routes the same requests/);
  assert.throws(() => validatePermissionGroups(groups(['GET /a/{+x}/b'])), /before the last segment/);
  assert.throws(() => validatePermissionGroups(groups(['GET /a/b{x}'])), /inside a segment/);
  assert.throws(() => validatePermissionGroups(groups(['GET /a/{x}'], ['GET /a/{+x}'].map(r => r))), /routes the same|both/, 'one shape counted once');
  assert.doesNotThrow(() => validatePermissionGroups(groups(['GET /a/{x}'], ['GET /a/b'])), 'a literal and a parameter differ in shape');
  assert.throws(() => parseTemplate('GET /a//b'), /empty segment/);
  const rpc = validatePermissionGroups(groups(['GET /chat.x'], ['POST /chat.x']));
  assert.throws(() => templatesFor(rpc, {style: 'rpc'}), /two methods/);
});

test('typed operations still find their row when the reviewed template marks a multi-segment parameter', () => {
  const github = PERMISSION_GROUPS.get('github');
  const group = groupFor(PERMISSION_GROUPS, 'github', {id: 'repos/create-or-update-file-contents', method: 'PUT', path: '/repos/{owner}/{repo}/contents/{path}'});
  assert.ok(group && group.requests.includes('PUT /repos/{owner}/{repo}/contents/{+path}'));
  assert.equal(groupFor(PERMISSION_GROUPS, 'github', {id: 'x', method: 'GET', path: '/repos/{owner}/{repo}/compare/{basehead}'})?.id, github.groups.find(g => g.requests.includes('GET /repos/{owner}/{repo}/compare/{+basehead}')).id);
});

test('review fixes: a byte-order mark never becomes an empty segment, and lone surrogates are refused with a code', () => {
  for (const path of ['/%EF%BB%BF', '/a/%EF%BB%BF/b', '/%EF%BB%BFrepos/o/r', '/%EF%BB%BF/repos/o/r', '/%EF%BB%BF/evil.example/x', '/repos/%EF%BB%BF/r']) assert.equal(code(get(path)), 'invalid_path', path);
  assert.equal(code(get('/gmail/v1/%EF%BB%BF'), GMAIL), 'invalid_path');
  assert.equal(code({method: 'POST', path: '/%EF%BB%BF', body: {}}, SLACK), 'invalid_path');
  for (const value of ['a\uD800', '\uDFFF', '\uDC00b', JSON.parse('"\\ud800"')]) assert.equal(code(get('/search/issues', {query: {q: value}})), 'parameter_not_allowed', JSON.stringify(value));
  assert.equal(code(get('/x', {query: {labelIds: ['ok', 'a\uD800']}}), {...GITHUB, arrayParameters: ['labelIds']}), 'parameter_not_allowed');
});

test('review fixes: ordinary names such as prototype and constructor are allowed; only __proto__ is refused', () => {
  assert.equal(code(get('/repos/prototypejs/prototype')), 'ok');
  assert.equal(code(get('/users/constructor')), 'ok');
  assert.equal(code({method: 'PATCH', path: '/v1/pages/abc', body: {properties: {prototype: {checkbox: true}, constructor: 'x'}}}, {apiBase: 'https://api.notion.com', style: 'rest'}), 'ok');
  assert.equal(code(get('/__proto__')), 'invalid_path');
  assert.equal(code({method: 'POST', path: '/x', body: {a: JSON.parse('{"__proto__": 1}')}}), 'unsupported_body');
});

test('every documented GitHub route lands in its own reviewed row or in Other, never in a broader row', () => {
  const github = templatesFor(PERMISSION_GROUPS.get('github'), GITHUB);
  const catalog = new Map(PERMISSION_GROUPS.get('github').groups.flatMap(group => group.requests.map(request => [looseShape(parseTemplate(request)), group.id])));
  let reviewed = 0, other = 0;
  for (const route of ROUTES.routes) {
    const parsed = parseTemplate(route), expected = catalog.get(looseShape(parsed));
    const match = matchRequest(github, {method: parsed.method, segments: parsed.segments.map(part => part.kind === 'literal' ? part.value : 'p1')});
    if (expected) { assert.equal(match.groupId, expected, route); reviewed++; }
    else { assert.notEqual(match.kind, 'group', `${route} is not reviewed, so it must land in Other`); other++; }
  }
  assert.equal(reviewed + other, ROUTES.routes.length); assert.equal(reviewed, 390);
  const match = (method, path) => matchRequest(github, {method, segments: normalizePath(path).segments});
  assert.equal(match('GET', '/user/emails').kind, 'other-reads'); assert.equal(match('GET', '/user/emails').documented, 'GET /user/emails');
  assert.equal(match('GET', '/user/12345').groupId, 'github.profile.read');
  assert.equal(match('GET', '/repos/o/r/branches/main/protection').kind, 'other-reads');
  assert.equal(match('GET', '/repos/o/r/branches/feature/x').kind, 'other-reads', 'branch names with slashes are not multi-segment: only the four git ref routes (matching-refs, ref, and refs by PATCH and DELETE) are reviewed as such');
  assert.equal(match('GET', '/repos/o/r/compare/main...feature/x').groupId, 'github.repos.read', 'GitHub documents basehead as multi-segment');
  // The {+name} marks in the catalog are exactly GitHub's own marks (multiSegment) and Fabric's reviewed reading of GitHub's prose
  // (reviewedMultiSegment), on the routes the catalog reviews.
  const marked = new Set(PERMISSION_GROUPS.get('github').groups.flatMap(group => group.requests.filter(request => request.includes('{+'))));
  const lists = [...ROUTES.multiSegment, ...ROUTES.reviewedMultiSegment];
  for (const entry of lists) {
    const [route, name] = entry.split('|');
    if (route.endsWith(`{${name}}`) && catalog.has(looseShape(parseTemplate(route)))) assert.ok(marked.has(route.replace(`{${name}}`, `{+${name}}`)), entry);
  }
  assert.equal([...marked].every(request => lists.includes(`${request.replace(/\{\+([^}]+)\}$/, '{$1}')}|${/\{\+([^}]+)\}$/.exec(request)[1]}`)), true, 'no guessed marks');
  assert.deepEqual(ROUTES.reviewedMultiSegment, ['GET /repos/{owner}/{repo}/git/matching-refs/{ref}|ref', 'GET /repos/{owner}/{repo}/git/ref/{ref}|ref', 'PATCH /repos/{owner}/{repo}/git/refs/{ref}|ref', 'DELETE /repos/{owner}/{repo}/git/refs/{ref}|ref'],
    'exactly the four git ref routes, never branches/{branch} (open question 15)');
});

test('F10.7: refs with slashes land in their rows in both forms; branch names with slashes still go to Other', () => {
  const github = templatesFor(PERMISSION_GROUPS.get('github'), GITHUB);
  const match = (method, path) => matchRequest(github, {method, segments: normalizePath(path).segments});
  for (const base of ['/repos/o/r', '/repositories/9']) {
    for (const [method, rest, row] of [['GET', '/git/ref/heads/feature/x', 'github.repos.read'], ['GET', '/git/ref/tags/v1', 'github.repos.read'], ['GET', '/git/matching-refs/heads/feature', 'github.repos.read'],
      ['GET', '/git/matching-refs/heads', 'github.repos.read'], ['PATCH', '/git/refs/heads/feature/x', 'github.code.write'], ['DELETE', '/git/refs/heads/feature/x', 'github.code.write'], ['DELETE', '/git/refs/tags/v1/rc', 'github.code.write']]) {
      const hit = match(method, `${base}${rest}`);
      assert.deepEqual([hit.kind, hit.groupId], ['group', row], `${method} ${base}${rest}`);
    }
    assert.equal(match('POST', `${base}/git/refs`).groupId, 'github.code.write', 'creating a ref is a single literal route, unchanged');
    for (const rest of ['/branches/feature/x', '/branches/feature/x/protection', '/branches/feature/x/protection/required_status_checks'])
      assert.equal(match('GET', `${base}${rest}`).kind, 'other-reads', `GET ${base}${rest}`);
    assert.equal(match('POST', `${base}/branches/feature/x/rename`).kind, 'other-changes', 'a slashed branch rename is not reviewed');
  }
});

// F10.7: a slashed value at a reviewed {+x} position never pulls a documented, unreviewed deeper route into the row. Each documented
// route that starts with a {+x} template's fixed part and is not reviewed lands in Other, a parameter at the {+x} position filled with "a/b".
function captured(definition) {
  const github = templatesFor(definition, GITHUB), reviewed = new Set(definition.groups.flatMap(group => group.requests.map(request => looseShape(parseTemplate(request)))));
  const out = [];
  for (const request of definition.groups.flatMap(group => group.requests).filter(request => request.includes('{+'))) {
    const template = parseTemplate(request), at = template.segments.length - 1;
    for (const route of ROUTES.routes) {
      const parsed = parseTemplate(route);
      if (parsed.method !== template.method || parsed.segments.length <= at || reviewed.has(looseShape(parsed))) continue;
      if (!template.segments.slice(0, at).every((part, index) => part.kind !== 'literal' ? parsed.segments[index].kind !== 'literal' : parsed.segments[index].kind === 'literal' && parsed.segments[index].value === part.value)) continue;
      const segments = parsed.segments.flatMap((part, index) => part.kind === 'literal' ? [part.value] : index === at ? ['a', 'b'] : ['p1']);
      if (matchRequest(github, {method: parsed.method, segments}).kind === 'group') out.push(route);
    }
  }
  return out.sort();
}

test('F10.7: no reviewed {+x} template captures a documented route GitHub keeps apart, which is why branches/{branch} stays one segment', () => {
  assert.deepEqual(captured(PERMISSION_GROUPS.get('github')), []);
  const raw = JSON.parse(readFileSync(new URL('../catalog/permissions/github.json', import.meta.url), 'utf8'));
  const branch = validatePermissionGroups({...raw, groups: raw.groups.map(group => ({...group, requests: group.requests?.map(request => request === 'GET /repos/{owner}/{repo}/branches/{branch}' ? 'GET /repos/{owner}/{repo}/branches/{+branch}' : request)}))});
  const pulled = captured(branch);
  assert.ok(pulled.includes('GET /repos/{owner}/{repo}/branches/{branch}/protection'), 'a {+branch} mark would pull protection reads on slashed branches into "Access repositories and code"');
  assert.ok(pulled.every(route => route.startsWith('GET /repos/{owner}/{repo}/branches/{branch}/')), pulled.join(', '));
});

test('F10.7: the loader refuses a guessed multi-segment mark, and reads GitHub\'s marks and Fabric\'s reviewed list without hashing the reviewed list', () => {
  const directory = new URL('../catalog/', import.meta.url), read = name => JSON.parse(readFileSync(new URL(name, directory), 'utf8'));
  const raw = read('proxy/github.json'), rows = read('permissions/github.json'), origins = read('apps.json').find(app => app.id === 'github').allowedOrigins;
  const load = ({definition = rows, routes = ROUTES} = {}) => validateProxyConfig(raw, {groups: new Map([['github', validatePermissionGroups(definition)]]), allowedOrigins: origins, routes});
  const remark = (from, to) => ({...rows, groups: rows.groups.map(group => ({...group, requests: group.requests?.map(request => request === from ? to : request)}))});
  assert.equal(load().configHash, PROXY_CONFIGS.get('github').configHash);
  // A {+x} mark in neither list is a guess.
  assert.throws(() => load({definition: remark('GET /repos/{owner}/{repo}/branches/{branch}', 'GET /repos/{owner}/{repo}/branches/{+branch}')}),
    /Proxy settings for github: GET \/repos\/\{owner\}\/\{repo\}\/branches\/\{\+branch\} marks a parameter as multi-segment, but neither the provider's own marks nor Fabric's reviewed list name it/);
  assert.throws(() => load({routes: {...ROUTES, reviewedMultiSegment: ROUTES.reviewedMultiSegment.filter(entry => !entry.startsWith('PATCH '))}}), /PATCH \/repos\/\{owner\}\/\{repo\}\/git\/refs\/\{\+ref\} marks a parameter as multi-segment/);
  assert.throws(() => load({routes: {...ROUTES, multiSegment: ROUTES.multiSegment.filter(entry => !entry.startsWith('GET /repos/{owner}/{repo}/contents/'))}}), /GET \/repos\/\{owner\}\/\{repo\}\/contents\/\{\+path\} marks a parameter/);
  assert.throws(() => load({definition: remark('GET /repos/{owner}/{repo}/git/ref/{+ref}', 'GET /repos/{owner}/{repo}/git/ref/{+name}')}), /git\/ref\/\{\+name\} marks a parameter as multi-segment/, 'the mark names the parameter GitHub names');
  // Each reviewed entry is a documented route GitHub does not mark, read at its last parameter, listed once.
  for (const entry of ['GET /repos/{owner}/{repo}/git/nope/{ref}|ref', 'GET /repos/{owner}/{repo}/contents/{path}|path', 'GET /repos/{owner}/{repo}/git/ref/{ref}|owner', 'GET /repos/{owner}/{repo}/git/ref/{ref}',
    'GET /repos/{owner}/{repo}/git/ref/{ref}|ref|x', 'GET /repos/{owner}/{repo}/git/ref/{ref}|ref', 'POST /repos/{owner}/{repo}/git/refs|refs', 7])
    assert.throws(() => load({routes: {...ROUTES, reviewedMultiSegment: [...ROUTES.reviewedMultiSegment, entry]}}), /reviewedMultiSegment/, String(entry));
  for (const value of ['GET /x|x', null, {}]) assert.throws(() => load({routes: {...ROUTES, reviewedMultiSegment: value}}), /reviewedMultiSegment/, JSON.stringify(value));
  for (const value of ['GET /x|x', [7]]) assert.throws(() => load({routes: {...ROUTES, multiSegment: value}}), /multiSegment/, JSON.stringify(value));
  // Fabric's reviewed list and its note are not hashed (open question 16); the routes GitHub publishes are.
  const {reviewedNote, reviewedMultiSegment, ...github} = ROUTES;
  assert.equal(load({routes: {...ROUTES, reviewedNote: 'Reworded.', reviewedMultiSegment: [...reviewedMultiSegment].reverse()}}).configHash, load().configHash);
  assert.equal(typeof reviewedNote, 'string');
  assert.notEqual(load({routes: {...github, reviewedNote, reviewedMultiSegment, retrieved: '2026-10-13'}}).configHash, load().configHash);
  assert.notEqual(load({routes: {...ROUTES, note: 'Reworded.'}}).configHash, load().configHash, 'GitHub\'s own note stays hashed');
  // The shipped list records both lists, so every mark is compared; GitHub's marks alone do not cover the refs. A route list that
  // records neither says nothing about marks.
  assert.ok(Array.isArray(ROUTES.multiSegment) && Array.isArray(ROUTES.reviewedMultiSegment));
  assert.throws(() => load({routes: github}), /GET \/repos\/\{owner\}\/\{repo\}\/git\/matching-refs\/\{\+ref\} marks a parameter as multi-segment/);
  assert.ok(load({routes: {routes: ROUTES.routes}}));
});

test('apps reviewed by operation id need every reviewed operation in the stored map; custom-verb segments match', () => {
  const gmail = PERMISSION_GROUPS.get('gmail');
  const ids = gmail.groups.flatMap(group => group.operations);
  const full = {operations: ids.map(id => ({id, method: 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`}))};
  full.operations[full.operations.findIndex(op => op.id === 'gmail.users.messages.send')] = {id: 'gmail.users.messages.send', method: 'POST', path: '/gmail/v1/users/{userId}/messages/send'};
  assert.ok(templatesFor(gmail, GMAIL, full));
  assert.equal(templatesFor(gmail, GMAIL, {operations: full.operations.slice(1)}), null, 'a reviewed operation missing from the map: proxy_unavailable');
  assert.equal(templatesFor(gmail, GMAIL, {operations: full.operations.map((op, i) => i ? op : {...op, path: '/gmail/v1/users/{userId}/bad{x}seg'})}), null, 'an unparseable path: proxy_unavailable');
  // Google custom verbs: {keyPairId}:obliterate is one segment ending in a literal verb.
  const verbs = {schemaVersion: 1, appId: 'demo', groups: [{id: 'demo.settings.write', label: 'Change settings', effect: 'write', defaultMode: 'ask', operations: ['k.disable']}, {id: 'demo.permanent.delete', label: 'Permanently delete', effect: 'delete', defaultMode: 'deny', operations: ['k.obliterate']}]};
  const templates = templatesFor(validatePermissionGroups(verbs), {style: 'rest'}, {operations: [{id: 'k.disable', method: 'POST', path: '/v1/keypairs/{keyPairId}:disable'}, {id: 'k.obliterate', method: 'POST', path: '/v1/keypairs/{keyPairId}:obliterate'}]});
  assert.equal(matchRequest(templates, {method: 'POST', segments: ['v1', 'keypairs', 'kp1:obliterate']}).groupId, 'demo.permanent.delete');
  assert.equal(matchRequest(templates, {method: 'POST', segments: ['v1', 'keypairs', 'kp1:DISABLE']}).groupId, 'demo.settings.write');
  assert.equal(matchRequest(templates, {method: 'POST', segments: ['v1', 'keypairs', ':obliterate']}).kind, 'other-changes', 'the parameter part cannot be empty');
});

test('the validator refuses {x} and {+y} at one position in different rows', () => {
  const definition = {schemaVersion: 1, appId: 'demo', groups: [{id: 'demo.files.edit', label: 'Edit files', effect: 'write', defaultMode: 'ask', requests: ['DELETE /v1/files/{file_id}']}, {id: 'demo.permanent.delete', label: 'Permanently delete', effect: 'delete', defaultMode: 'deny', requests: ['DELETE /v1/files/{+path}']}]};
  assert.throws(() => validatePermissionGroups(definition), /routes the same requests/);
});

test('Slack inherits Never only from a dot-prefix method or a reviewed family', () => {
  const slack = templatesFor(PERMISSION_GROUPS.get('slack'), SLACK);
  const inherit = name => matchRequest(slack, {method: 'POST', segments: [name]}, SLACK).inheritFrom;
  assert.deepEqual(inherit('chat.unfurl').includes('slack.permanent.delete'), false, 'chat.delete does not make every chat.* method Never');
  assert.equal(inherit('users.identity').includes('slack.admin'), false);
  assert.ok(inherit('chat.delete.scheduled').includes('slack.permanent.delete'), 'a dot-prefix method passes on its row');
  assert.ok(inherit('admin.users.brandNew').includes('slack.admin'), 'the admin family is reviewed');
});

// F10.9 part b (docs/F10.9-BUILD-MAP.md, I1): the reserved query names and the caller headers become exports, so the proxy and the action
// validator read one list. The answers are the ones the normalizer gave before: this is that list, copied from the code as it stood.
test('F10.9: reservedQueryName() gives the answers the normalizer gave before, for every app, and the normalizer still refuses exactly those', async () => {
  const {reservedQueryName, CALLER_HEADERS} = await import('../lib/proxy-request.mjs');
  const ALWAYS = ['access_token', 'oauth_token', 'api_key', 'apikey', 'client_secret', 'callback', 'jsonp', '_method', 'x-http-method-override', 'x-http-method', 'x-method-override', 'password', 'passwd', 'alt', 'uploadtype', 'upload_protocol'];
  const before = (name, config) => new Set([...ALWAYS, ...(config.reservedParameters || []).map(item => item.toLowerCase())]).has(name.toLowerCase());
  const names = [...ALWAYS, ...ALWAYS.map(name => name.toUpperCase()), 'uploadType', 'Alt', 'key', 'KEY', 'quotaUser', 'quotauser', 'userIp', 'token', 'Token', 'q', 'pageToken', 'labelIds', 'per_page', 'cursor', 'keys', 'access-token'];
  for (const [appId, config] of [...PROXY_CONFIGS, ['slack-fixture', SLACK], ['gmail-fixture', GMAIL], ['none', {}]]) {
    for (const name of names) {
      assert.equal(reservedQueryName(name, config), before(name, config), `${appId}: ${name}`);
      if (config.apiBase) assert.equal(code(get(`${config.pathPrefixes?.[0] ?? '/'}x`, {query: {[name]: 'v'}}), config), reservedQueryName(name, config) ? 'parameter_not_allowed' : 'ok', `${appId}: ${name}`);
    }
  }
  assert.equal(reservedQueryName('quotaUser', PROXY_CONFIGS.get('gmail')), true, 'an app\'s own reserved names count');
  assert.equal(reservedQueryName('quotaUser', PROXY_CONFIGS.get('github')), false);
  assert.deepEqual(CALLER_HEADERS, ['Accept', 'If-Match', 'If-None-Match', 'If-Modified-Since', 'If-Unmodified-Since']);
  assert.ok(Object.isFrozen(CALLER_HEADERS));
  for (const header of CALLER_HEADERS) assert.equal(code(get('/user', {headers: {[header]: header === 'Accept' ? 'application/json' : '"x"'}})), 'ok', header);
  assert.equal(code(get('/user', {headers: {Authorization: 'x'}})), 'header_not_allowed');
});
