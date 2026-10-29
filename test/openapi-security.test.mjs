import test from 'node:test';
import assert from 'node:assert/strict';
import {securityRequirements, assertServable, credentialLocations, exchangeUrls, schemeKind} from '../lib/openapi-security.mjs';
import {compileOpenApi, credentialName, finalizeCapability, prepareRequest, validateCapability} from '../lib/compiler.mjs';
import {runCoverage} from '../scripts/coverage.mjs';

// F09.1a safety floor (docs/F09-COMPILER-COVERAGE.md): the security model, credential-shaped inputs and credential
// exchanges. Hand-written documents only.
const SCHEMES = {
  oauth: {type: 'oauth2', flows: {authorizationCode: {authorizationUrl: 'https://api.example.com/v1/oauth/authorize', tokenUrl: 'oauth/token', scopes: {read: 'Read'}}}},
  bearer: {type: 'http', scheme: 'bearer'}, Bearer: {type: 'http', scheme: 'Bearer'}, basic: {type: 'http', scheme: 'basic'},
  key: {type: 'apiKey', in: 'query', name: 'AppID'}, headerKey: {type: 'apiKey', in: 'header', name: 'X-Api-Key'}, cookieKey: {type: 'apiKey', in: 'cookie', name: 'sid'},
  alias: {$ref: '#/components/securitySchemes/bearer'},
};
const ok = {200: {description: 'OK'}};
function doc(paths, security) {
  return {openapi: '3.0.3', info: {title: 'Security fixture', version: '1'}, servers: [{url: 'https://api.example.com/v1'}], ...(security ? {security} : {}), components: {securitySchemes: SCHEMES}, paths};
}
const compiled = (paths, security) => compileOpenApi({appId: 'fixture', document: doc(paths, security)});
const only = result => { assert.equal(result.capabilities.length, 1); return result.capabilities[0]; };
const refused = (paths, pattern, security) => assert.throws(() => compiled(paths, security), pattern);

test('security alternatives: any one servable alternative is enough, every scheme in it must be servable', () => {
  const stripe = securityRequirements(doc({}), {security: [{basic: []}, {bearer: []}]});
  assert.deepEqual(stripe.alternatives, [{schemes: ['bearer'], kinds: ['bearer'], scopes: []}]);
  assert.deepEqual(stripe.dropped, [{schemes: ['basic'], reason: 'Security scheme basic is not supported by the bearer-credential broker.'}]);
  const both = securityRequirements(doc({}), {security: [{key: [], oauth: ['read']}]});
  assert.deepEqual(both.alternatives, []); assert.throws(() => assertServable(both), /Security scheme key is not supported/);
  assert.deepEqual(securityRequirements(doc({}), {security: [{Bearer: []}]}).alternatives[0].kinds, ['bearer'], 'the HTTP scheme name is case-insensitive');
  assert.deepEqual(securityRequirements(doc({}), {security: [{alias: []}]}).alternatives[0].kinds, ['bearer']);
  assert.deepEqual(securityRequirements(doc({}), {security: [{oauth: ['read', 'read']}, {}]}).alternatives, [{schemes: ['oauth'], kinds: ['oauth'], scopes: ['read']}, {schemes: [], kinds: [], scopes: []}]);
  assert.equal(securityRequirements(doc({}), {}).declared, false);
  assert.equal(securityRequirements(doc({}, [{oauth: []}]), {}).declared, true, 'document security applies when the operation has none');
  assert.equal(securityRequirements(doc({}, [{oauth: []}]), {security: []}).declared, false, 'an empty operation list overrides the document');
  assert.throws(() => securityRequirements(doc({}), {security: [{nope: []}]}), /Missing security scheme nope/);
  assert.throws(() => securityRequirements(doc({}), {security: [JSON.parse('{"__proto__": []}')]}), /Missing security scheme/);
  assert.equal(schemeKind(SCHEMES.cookieKey), 'api-key:cookie:sid');
  assert.deepEqual([...credentialLocations(doc({}))].sort(), ['cookie:sid', 'header:x-api-key', 'query:appid']);
  assert.deepEqual([...exchangeUrls(doc({}), 'https://api.example.com/v1')].sort(), ['https://api.example.com/oauth/token', 'https://api.example.com/v1/oauth/authorize', 'https://api.example.com/v1/oauth/token']);
});

test('credential-shaped names are read at word boundaries; identifiers of credentials are not credentials', () => {
  for (const name of ['AuthToken', 'authToken', 'X-Auth-Token', 'appKey', 'AppKey', 'api_secret', 'x-api-key', 'X-Api-Key', 'apikey', 'APIKEY', 'api.key', 'client_secret', 'clientSecret', 'refresh_token',
    'accessToken', 'id_token', 'oidc_token', 'sas_token', 'sasToken', 'token', 'password', 'newPassword', 'passwordConfirmation', 'passwd', 'webhookSecret', 'secret', 'signingKey', 'privateKey', 'private_key', 'privateKeyData', 'secretValue', 'apiKeyValue', 'sessionid', 'Cookie', 'Authorization', 'credentials', 'botToken', 'password_hash'])
    assert.equal(credentialName(name), true, name);
  for (const name of ['pageToken', 'nextPageToken', 'syncToken', 'continuationToken', 'next_token', 'secret_name', 'secretName', 'key_id', 'keyId', 'token_id', 'tokenType', 'publicKey', 'key', 'password_policy',
    'client_secret_expires_at', 'AccountSid', 'appId', 'monkey', 'keyboard', 'tokenizer', 'secretary', 'name', 'q', 'state', 'owner',
    'secret_scanning', 'secret_scanning_push_protection', 'secret_scanning_generic_secrets', 'organization_secrets', 'secrets', 'hide_secret', 'has_password', 'include_secrets', 'api_key_uuid', 'session_id', 'sessionId', 'secretsCount', 'token_type_hint'])
    assert.equal(credentialName(name), false, name);
});

test('a parameter that carries a credential is refused when required and left out when optional', () => {
  refused({'/a': {get: {parameters: [{name: 'AuthToken', in: 'query', required: true, schema: {type: 'string'}}], responses: ok}}}, /AuthToken carries a credential/);
  refused({'/a/{api_key}': {get: {parameters: [{name: 'api_key', in: 'path', required: true, schema: {type: 'string'}}], responses: ok}}}, /api_key carries a credential/);
  const capability = only(compiled({'/a': {get: {parameters: [{name: 'appKey', in: 'query', schema: {type: 'string'}}, {name: 'q', in: 'query', schema: {type: 'string'}}], responses: ok}}}));
  assert.deepEqual(Object.keys(capability.inputSchema.properties), ['q']);
  assert.deepEqual(capability.request.queryParameters, ['q']);
  assert.match(compiled({'/a': {get: {parameters: [{name: 'appKey', in: 'query', schema: {type: 'string'}}], responses: ok}}}).warnings.join(), /Optional credential-shaped parameter appKey omitted/);
  // The document's own API-key location, matched case-insensitively, is never an input either.
  refused({'/a': {get: {parameters: [{name: 'appid', in: 'query', required: true, schema: {type: 'string'}}], responses: ok}}}, /appid carries a credential/);
  assert.deepEqual(only(compiled({'/a': {get: {parameters: [{name: 'APPID', in: 'query', schema: {type: 'string'}}, {name: 'q', in: 'query', schema: {type: 'string'}}], responses: ok}}})).request.queryParameters, ['q']);
  // A credential-exchange parameter refuses the operation even when optional.
  refused({'/a': {get: {parameters: [{name: 'grant_type', in: 'query', schema: {type: 'string'}}], responses: ok}}}, /grant_type carries a credential/);
  // Prepared requests and previews therefore never carry the key.
  assert.doesNotMatch(prepareRequest(capability, {q: 'x'}).url, /appKey/i);
});

test('body properties at any depth: credentials are left out when optional and refuse the operation when required; exchanges always refuse it', () => {
  const body = (schema, method = 'post') => ({'/a': {[method]: {requestBody: {required: true, content: {'application/json': {schema}}}, responses: ok}}});
  const nested = only(compiled(body({type: 'object', properties: {name: {type: 'string'}, config: {type: 'object', properties: {url: {type: 'string'}, webhook_secret: {type: 'string'}}}}})));
  assert.deepEqual(Object.keys(nested.inputSchema.properties.body.properties.config.properties), ['url']);
  refused(body({type: 'object', required: ['password'], properties: {user: {type: 'string'}, password: {type: 'string'}}}), /password: credentials and credential exchanges are not agent inputs/);
  refused(body({type: 'object', properties: {code: {type: 'string'}, grant_type: {type: 'string'}}}), /exchanges credentials/);
  refused(body({type: 'object', properties: {items: {type: 'array', items: {type: 'object', properties: {refresh_token: {type: 'string'}}}}}}), /exchanges credentials/);
});

test('no capability can carry a credential input, however it was made: the check is in validateCapability', () => {
  const base = only(compiled({'/a': {post: {requestBody: {required: true, content: {'application/json': {schema: {type: 'object', properties: {name: {type: 'string'}}}}}}, responses: ok}}}));
  const withBody = properties => finalizeCapability({...base, provenance: {...base.provenance, kind: 'manual'}, inputSchema: {...base.inputSchema, properties: {body: {type: 'object', additionalProperties: false, properties}}}});
  assert.throws(() => withBody({nested: {type: 'object', additionalProperties: false, properties: {api_key: {type: 'string'}}}}), /api_key: credentials and credential exchanges are not agent inputs/);
  assert.throws(() => withBody({list: {type: 'array', items: {type: 'object', additionalProperties: false, properties: {client_assertion: {type: 'string'}}}}}), /client_assertion: credentials/);
  const {bodyParameter, ...request} = base.request;
  assert.throws(() => finalizeCapability({...base, inputSchema: {type: 'object', additionalProperties: false, required: ['AuthToken'], properties: {AuthToken: {type: 'string'}}}, request: {...request, queryParameters: ['AuthToken']}}), /AuthToken: credentials and credential exchanges are not agent inputs/);
  assert.equal(validateCapability(withBody({name: {type: 'string'}})).inputSchema.properties.body.properties.name.type, 'string');
});

test('exchange fields are recognised in any spelling, and a template segment that can reach a token endpoint is refused', () => {
  const body = schema => ({'/a': {post: {requestBody: {required: true, content: {'application/json': {schema}}}, responses: ok}}});
  refused(body({type: 'object', properties: {grantType: {type: 'string'}, subjectToken: {type: 'string'}}}), /exchanges credentials/);
  refused(body({type: 'object', properties: {name: {type: 'string'}, clientSecret: {type: 'string'}}}), /exchanges credentials/, undefined);
  refused(body({type: 'object', properties: {codeVerifier: {type: 'string'}}}), /exchanges credentials/);
  refused({'/oauth/{endpoint}': {post: {parameters: [{name: 'endpoint', in: 'path', required: true, schema: {type: 'string'}}], responses: ok}}}, /exchanges credentials/);
  refused({'/{area}/{endpoint}': {post: {parameters: [{name: 'area', in: 'path', required: true, schema: {type: 'string'}}, {name: 'endpoint', in: 'path', required: true, schema: {type: 'string'}}], responses: ok}}}, /exchanges credentials/);
  assert.equal(only(compiled({'/oauth/{endpoint}/status': {get: {parameters: [{name: 'endpoint', in: 'path', required: true, schema: {type: 'string'}}], responses: ok}}})).request.method, 'GET', 'a deeper path cannot reach the endpoint');
});

test('direct import reads security: an operation with no servable alternative is refused, not sent with a bearer token', () => {
  refused({'/a': {get: {security: [{key: []}], responses: ok}}}, /Security scheme key is not supported/);
  refused({'/a': {get: {security: [{basic: []}], responses: ok}}}, /Security scheme basic is not supported/);
  refused({'/a': {get: {security: [{undefinedScheme: []}], responses: ok}}}, /Missing security scheme undefinedScheme/);
  assert.equal(only(compiled({'/a': {get: {security: [{basic: []}, {bearer: []}], responses: ok}}})).request.method, 'GET');
  assert.equal(only(compiled({'/a': {get: {responses: ok}}}, [{headerKey: []}, {oauth: ['read']}])).request.method, 'GET');
  refused({'/a': {get: {responses: ok}}}, /Security scheme headerKey is not supported/, [{headerKey: []}]);
});

test('an operation at a declared OAuth endpoint exchanges credentials, even through a relative token URL', () => {
  refused({'/oauth/token': {post: {responses: ok}}}, /exchanges credentials/);
  refused({'/oauth/authorize': {get: {responses: ok}}}, /exchanges credentials/);
  assert.equal(only(compiled({'/oauth/tokens-list': {get: {responses: ok}}})).request.method, 'GET');
});

test('discovery resolves a security scheme that refers to another scheme, as it did before F09.1', async () => {
  const document = doc({'/aliased': {get: {operationId: 'aliased', security: [{alias: ['read']}], responses: ok}}});
  const result = await runCoverage({appId: 'fixture', document, sourceUrl: 'https://specs.example.com/openapi.json', apiOrigins: ['https://api.example.com']});
  assert.deepEqual(result.discovery.operations.map(operation => [operation.id, operation.support, operation.scopeSets]), [['aliased', 'candidate', [['read']]]]);
});

test('discovery: scopes come only from servable alternatives, dropped ones become gaps, and credential locations come from the whole source', async () => {
  const document = doc({
    '/stripe-shaped': {get: {operationId: 'stripeShaped', security: [{basic: []}, {oauth: ['read']}], responses: ok}},
    // This operation's own security names only oauth, so a scoped document would not carry the key scheme.
    '/uses-key-name': {get: {operationId: 'usesKeyName', security: [{oauth: ['read']}], parameters: [{name: 'appid', in: 'query', required: true, schema: {type: 'string'}}], responses: ok}},
    '/at-token-url': {post: {operationId: 'atTokenUrl', security: [{oauth: ['read']}], responses: ok}},
  });
  document.paths['/oauth/token'] = document.paths['/at-token-url']; delete document.paths['/at-token-url'];
  const result = await runCoverage({appId: 'fixture', document, sourceUrl: 'https://specs.example.com/openapi.json', apiOrigins: ['https://api.example.com']});
  const byId = Object.fromEntries(result.discovery.operations.map(operation => [operation.id, operation]));
  assert.equal(byId.stripeShaped.support, 'candidate'); assert.deepEqual(byId.stripeShaped.scopeSets, [['read']]);
  assert.equal(byId.usesKeyName.support, 'unsupported'); assert.match(byId.usesKeyName.reason, /appid carries a credential/);
  assert.equal(byId.atTokenUrl.support, 'unsupported'); assert.match(byId.atTokenUrl.reason, /exchanges credentials/);
});
