import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {deflateSync, crc32} from 'node:zlib';
import {createDeveloperApp} from '../developer-server.mjs';
import {checkedBrand, brandCss, BrandError, DEFAULT_BRAND} from '../lib/tenant/brand.mjs';

// F03.11 security review, group c: branding, logos and the registry (authz-2, BRW-1, ISO-6).
const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const pngChunk = (type, data) => { const length = Buffer.alloc(4); length.writeUInt32BE(data.length); const body = Buffer.concat([Buffer.from(type, 'latin1'), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body)); return Buffer.concat([length, body, crc]); };
/** A plain RGBA PNG; `fill` changes the pixels so each size and fill gives a different logo. */
function png(side, fill = 0) {
  const header = Buffer.alloc(13); header.writeUInt32BE(side, 0); header.writeUInt32BE(side, 4); header[8] = 8; header[9] = 6;
  const raw = Buffer.alloc((side * 4 + 1) * side, fill);
  for (let row = 0; row < side; row++) raw[row * (side * 4 + 1)] = 0; // each row's filter byte
  return Buffer.concat([SIGNATURE, pngChunk('IHDR', header), pngChunk('IDAT', deflateSync(raw)), pngChunk('IEND', Buffer.alloc(0))]);
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review-c-'));
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const customer = (name, {production = false} = {}) => {
    const org = app.registry.createOrganization({name}), project = app.registry.createProject({organizationId: org.id, name, appName: `${name} Notes`});
    const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
    const prod = app.registry.createEnvironment({projectId: project.id, kind: 'production'}, app.stores);
    if (production) app.registry.enableProduction(prod.id);
    return {project, dev, prod, devKey: app.keys.mint({environmentId: dev.id, preset: 'standard'}).token, prodKey: app.keys.mint({environmentId: prod.id, preset: 'standard'}).token};
  };
  const call = async (key, method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  const upload = async (key, bytes) => { const response = await fetch(`${app.origin}/v1/project/logo`, {method: 'PUT', headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'image/png'}, body: bytes}); return {status: response.status, body: await response.json()}; };
  return {app, root, customer, call, upload};
}

// authz-2 (L10): branding a development key set while production was off has never been reviewed by the operator.
test('authz-2: branding set before production is enabled waits for the operator when production goes live', async t => {
  const {app, customer, call, upload} = await setup(t);
  const acme = customer('Acme');
  const set = await call(acme.devKey, 'PATCH', '/v1/project', {appName: 'Google Account Security', supportEmail: 'help@security-google.example', dataUse: {text: 'Google requires this check to keep your account safe.'}, brand: {light: {accent: '#5b21b6'}}});
  assert.equal(set.status, 200, 'before production, development changes apply directly');
  assert.equal(set.body.project.appName, 'Google Account Security');
  assert.equal((await upload(acme.devKey, png(128))).status, 200);
  const liveLogo = app.registry.get('projects', acme.project.id).logo.hash;

  app.registry.enableProduction(acme.prod.id);
  // Production end users see only what the operator approved: the name given at create, no logo, note or colours.
  const shown = (await call(acme.prodKey, 'GET', '/v1/project')).body.project;
  assert.equal(shown.appName, 'Acme Notes');
  assert.equal(shown.supportEmail, null); assert.equal(shown.dataUse, undefined); assert.equal(shown.logoUrl, undefined); assert.equal(shown.brand, undefined);
  assert.equal(shown.pendingReview, true); assert.deepEqual(shown.pendingFields, ['appName', 'brand', 'dataUse', 'logo', 'supportEmail']);
  const sheet = (await call(acme.prodKey, 'GET', '/v1/apps/github/consent-sheet')).body;
  assert.equal(JSON.stringify(sheet).includes('Google Account Security'), false, 'the unreviewed name never reaches the consent sheet');
  assert.equal((await fetch(`${app.origin}/assets/logos/${acme.project.id}/${liveLogo}`)).status, 404, 'the unreviewed logo is not served');

  // The operator reviews exactly the held branding, logo bytes included, and approves it with its digest.
  const review = app.registry.pendingBranding(acme.project.id);
  assert.equal(review.pending.appName, 'Google Account Security'); assert.equal(review.pending.logo.hash, liveLogo); assert.ok(review.logoBytes?.length);
  app.registry.approveBranding(acme.project.id, review.digest);
  const approved = (await call(acme.prodKey, 'GET', '/v1/project')).body.project;
  assert.equal(approved.appName, 'Google Account Security'); assert.equal(approved.pendingReview, undefined); assert.match(approved.logoUrl, new RegExp(`${liveLogo}$`));
  // After approval, a later change still waits for review, as before.
  assert.equal((await call(acme.devKey, 'PATCH', '/v1/project', {appName: 'Another'})).status, 202);
});

test('authz-2: enabling production holds nothing when the branding is the reviewed one, and is a no-op when already enabled', async t => {
  const {app, customer} = await setup(t);
  const plain = customer('Plain');
  app.registry.enableProduction(plain.prod.id);
  assert.equal(app.registry.get('projects', plain.project.id).pendingBranding, undefined, 'the name the operator gave at create is reviewed');
  // A project recorded before the review snapshot existed: only the operator's project name counts as reviewed.
  const older = customer('Older'), legacy = {...app.registry.get('projects', older.project.id)};
  delete legacy.reviewedBranding;
  app.registry.put('projects', legacy);
  app.registry.enableProduction(older.prod.id);
  const held = app.registry.get('projects', older.project.id);
  assert.equal(held.appName, 'Older'); assert.deepEqual(held.pendingBranding, {appName: 'Older Notes'});
  app.registry.enableProduction(older.prod.id);
  assert.deepEqual(app.registry.get('projects', older.project.id), held, 'enabling again changes nothing');
});

// BRW-1: a project:write key (no decision power) must not hide Fabric's warnings, Reject, Disconnect or fine print.
test('BRW-1: every text colour stays readable on both surfaces, and the defaults pass', () => {
  assert.doesNotThrow(() => checkedBrand({light: {...DEFAULT_BRAND.light}, dark: {...DEFAULT_BRAND.dark}}));
  const refused = [
    [{light: {muted: '#f4f5f2'}}, /muted text and the page/],
    [{light: {danger: '#f4f5f2'}}, /danger text and the page/],
    [{light: {attention: '#f4f5f2'}}, /attention text and the page/],
    [{dark: {muted: '#151817'}}, /muted text and the page/],
    [{dark: {danger: '#202523'}}, /danger text and the page/],
    [{light: {accent: '#f4f5f3', onAccent: '#172e2d'}}, /accent text and the page/], // readable button, unreadable links
    [{light: {surfaceRaised: '#e0e3de'}}, /muted text and the cards/], // a darker card under Fabric's muted text
    // A dark set given as the light one: readable on its own surfaces, unreadable on Fabric's light hover colour.
    [{light: {surface: '#000000', surfaceRaised: '#111111', ink: '#ffffff', muted: '#bbbbbb', accent: '#5fd0bb', onAccent: '#0b1f1b', danger: '#ff8b80', attention: '#5fd0bb'}}, /hover colour/],
  ];
  for (const [value, message] of refused) assert.throws(() => checkedBrand(value), error => error instanceof BrandError && message.test(error.message), JSON.stringify(value));
  // The check uses the hover colours the pages draw (public/hosted.css), which a brand cannot change.
  const css = readFileSync(new URL('../public/hosted.css', import.meta.url), 'utf8');
  for (const hover of ['--surface-hover:#eef1ed', '--surface-hover:#2a302d']) assert.ok(css.includes(hover), hover);
  // A brand stored before these checks is no longer served: the set that fails falls back to Fabric's own colours.
  assert.deepEqual(brandCss({light: {muted: '#f4f5f2', danger: '#f4f5f2'}, dark: {accent: '#c4b5fd', onAccent: '#1e1b4b'}}), {dark: {'--accent': '#c4b5fd', '--on-accent': '#1e1b4b'}});
});

test('BRW-1: a standard key cannot hide the muted, warning and attention text, and a stored unreadable brand is not served', async t => {
  const {app, customer, call} = await setup(t);
  const acme = customer('Acme');
  const hidden = await call(acme.devKey, 'PATCH', '/v1/project', {brand: {light: {muted: '#f4f5f2', danger: '#f4f5f2', attention: '#f4f5f2'}, dark: {muted: '#151817', danger: '#151817', attention: '#151817'}}});
  assert.equal(hidden.status, 400); assert.equal(hidden.body.error.code, 'invalid_request');
  assert.equal(app.registry.get('projects', acme.project.id).brand, undefined);
  // A brand accepted before the fix: the page view drops the unreadable set and keeps the readable one.
  app.registry.put('projects', {...app.registry.get('projects', acme.project.id), brand: {light: {muted: '#f4f5f2', danger: '#f4f5f2', attention: '#f4f5f2'}, dark: {accent: '#c4b5fd', onAccent: '#1e1b4b'}}});
  const created = (await call(acme.devKey, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body, binding = 'browser-review-c-binding-01';
  app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
  assert.deepEqual(app.sessions.view(created.id, binding).developer.brand, {dark: {'--accent': '#c4b5fd', '--on-accent': '#1e1b4b'}});
});

// ISO-6 (N1): one tenant's logo upload must not read every tenant's stored logo bytes.
test('ISO-6: a logo upload looks up its own project\'s logos by id and never lists every project\'s logos', async t => {
  const {app, customer, upload} = await setup(t);
  const other = customer('Other');
  assert.equal((await upload(other.devKey, png(128, 7))).status, 200);
  const otherLogo = app.registry.get('projects', other.project.id).logo.hash;
  const beta = customer('Beta'), acme = customer('Acme', {production: true});
  const listed = [], list = app.registry.list.bind(app.registry);
  app.registry.list = collection => { listed.push(collection); return list(collection); };
  t.after(() => { delete app.registry.list; });
  const logoRow = (project, hash) => app.registry.get('projectLogos', `${project.id}.${hash}`);
  const record = project => app.registry.get('projects', project.id);
  // Before production: a new logo replaces the shown one, and the replaced row is deleted.
  assert.equal((await upload(beta.devKey, png(128, 1))).status, 200); const first = record(beta.project).logo.hash;
  assert.equal((await upload(beta.devKey, png(128, 2))).status, 200); const second = record(beta.project).logo.hash;
  assert.equal(logoRow(beta.project, first), null, 'the replaced logo is deleted'); assert.ok(logoRow(beta.project, second));
  // In production: the approved logo stays while a newer pending one replaces an older pending one.
  assert.equal((await upload(acme.devKey, png(128, 3))).status, 202);
  const approve = () => app.registry.approveBranding(acme.project.id, app.registry.pendingBranding(acme.project.id).digest);
  approve(); const approved = record(acme.project).logo.hash;
  assert.equal((await upload(acme.devKey, png(128, 4))).status, 202); const older = record(acme.project).pendingBranding.logo.hash;
  assert.equal((await upload(acme.prodKey, png(128, 5))).status, 202); const newer = record(acme.project).pendingBranding.logo.hash;
  assert.equal(logoRow(acme.project, older), null, 'the superseded pending logo is deleted');
  assert.ok(logoRow(acme.project, approved), 'the approved logo stays'); assert.ok(logoRow(acme.project, newer), 'the pending logo stays');
  // Approving the pending logo deletes the one it replaces.
  approve();
  assert.equal(logoRow(acme.project, approved), null); assert.ok(logoRow(acme.project, newer));
  assert.ok(logoRow(other.project, otherLogo), 'another project\'s logo is untouched');
  assert.equal(listed.includes('projectLogos'), false, `listed: ${listed.join(', ')}`);
});
