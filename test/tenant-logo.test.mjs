import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {deflateSync, crc32} from 'node:zlib';
import {createDeveloperApp} from '../developer-server.mjs';
import {registryCommand} from '../scripts/tenant-admin.mjs';
import {checkedLogo, LOGO_MAX_BYTES} from '../lib/tenant/logos.mjs';

// F03.6b: the developer's logo. PNG or WebP only, size and shape checked, rebuilt from the image alone (no metadata),
// served with a fixed type; once production is live, a new logo waits for the operator's approval.
const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const pngChunk = (type, data) => { const length = Buffer.alloc(4); length.writeUInt32BE(data.length); const body = Buffer.concat([Buffer.from(type, 'latin1'), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body)); return Buffer.concat([length, body, crc]); };
function png(width, height, extra = [], {depth = 8, colour = 6, compression = 0, idat, iend = Buffer.alloc(0), after = []} = {}) {
  const header = Buffer.alloc(13); header.writeUInt32BE(width, 0); header.writeUInt32BE(height, 4); header[8] = depth; header[9] = colour; header[10] = compression;
  return Buffer.concat([SIGNATURE, pngChunk('IHDR', header), ...extra.map(([type, data]) => pngChunk(type, Buffer.from(data))), ...(idat ?? [deflateSync(Buffer.alloc((width * 4 + 1) * height))]).map(data => pngChunk('IDAT', data)),
    ...after.map(([type, data]) => pngChunk(type, Buffer.from(data))), pngChunk('IEND', iend)]);
}
const riffChunk = (type, data) => { const head = Buffer.alloc(8); head.write(type, 0, 'latin1'); head.writeUInt32LE(data.length, 4); return Buffer.concat([head, data, ...(data.length & 1 ? [Buffer.alloc(1)] : [])]); };
function webp(width, height, extra = [], {version = 0, after = []} = {}) {
  const frame = Buffer.alloc(12); frame[0] = 0x2f; frame.writeUInt32LE(((((width - 1) & 0x3fff) | (((height - 1) & 0x3fff) << 14)) | (version << 29)) >>> 0, 1);
  return riff([...extra.map(([type, data]) => riffChunk(type, Buffer.from(data))), riffChunk('VP8L', frame), ...after.map(([type, data]) => riffChunk(type, Buffer.from(data)))]);
}
/** A lossy key frame: tag (key frame, profile 0, shown, first partition 2 bytes), start code, size, a few bytes. */
function vp8(width, height) { const frame = Buffer.alloc(14); frame.writeUIntLE((2 << 5) | (1 << 4), 0, 3); frame[3] = 0x9d; frame[4] = 0x01; frame[5] = 0x2a; frame.writeUInt16LE(width, 6); frame.writeUInt16LE(height, 8); return frame; }
function riff(chunks) { const body = Buffer.concat(chunks), head = Buffer.alloc(12); head.write('RIFF', 0, 'latin1'); head.writeUInt32LE(body.length + 4, 4); head.write('WEBP', 8, 'latin1'); return Buffer.concat([head, body]); }

/** IHDR, IDAT, a tEXt chunk, IDAT, IEND: image data that is not in one run. */
function splitAround(compressed) {
  const header = Buffer.alloc(13); header.writeUInt32BE(128, 0); header.writeUInt32BE(128, 4); header[8] = 8; header[9] = 6;
  return [pngChunk('IHDR', header), pngChunk('IDAT', compressed.subarray(0, 40)), pngChunk('tEXt', Buffer.from('k\0v')), pngChunk('IDAT', compressed.subarray(40)), pngChunk('IEND', Buffer.alloc(0))];
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-logo-'));
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const customer = (name, {production = false} = {}) => {
    const org = app.registry.createOrganization({name}), project = app.registry.createProject({organizationId: org.id, name, appName: `${name} Assistant`});
    const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
    let prodKey = null;
    if (production) { const prod = app.registry.createEnvironment({projectId: project.id, kind: 'production'}, app.stores); app.registry.enableProduction(prod.id); prodKey = app.keys.mint({environmentId: prod.id, preset: 'full'}).token; }
    return {project, dev, key: app.keys.mint({environmentId: dev.id, preset: 'full'}).token, narrow: app.keys.mint({environmentId: dev.id, preset: 'connect-only'}).token, prodKey};
  };
  const upload = async (key, bytes, type = 'image/png') => { const response = await fetch(`${app.origin}/v1/project/logo`, {method: 'PUT', headers: {Authorization: `Bearer ${key}`, 'Content-Type': type}, body: bytes}); return {status: response.status, body: await response.json()}; };
  const call = async (key, method, route, body) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body ? {'Content-Type': 'application/json'} : {})}, ...(body ? {body: JSON.stringify(body)} : {})}); return {status: response.status, body: await response.json()}; };
  return {app, root, customer, upload, call};
}

test('a PNG logo is checked, rebuilt without its metadata, and shown on the consent sheet and the Connect page', async t => {
  const {app, customer, upload, call} = await setup(t);
  const acme = customer('Acme');
  const raw = Buffer.alloc((128 * 4 + 1) * 128);
  const original = png(128, 128, [['tEXt', 'Comment\0GPS 51.5,-0.1 private note'], ['eXIf', 'camera-serial-123'], ['gAMA', 'owner=someone@example.com oversized gamma']],
    {idat: [Buffer.concat([deflateSync(raw), Buffer.from('hidden-after-the-zlib-stream')])]});
  const uploaded = await upload(acme.key, original);
  assert.equal(uploaded.status, 200);
  assert.match(uploaded.body.logoUrl, new RegExp(`^${app.origin}/assets/logos/${acme.project.id}/[0-9a-f]{32}$`));
  const served = await fetch(uploaded.body.logoUrl), bytes = Buffer.from(await served.arrayBuffer());
  assert.equal(served.status, 200); assert.equal(served.headers.get('content-type'), 'image/png');
  assert.equal(served.headers.get('x-content-type-options'), 'nosniff'); assert.match(served.headers.get('content-security-policy'), /default-src 'none'; sandbox/);
  assert.ok(bytes.subarray(0, 8).equals(SIGNATURE)); assert.ok(bytes.includes(Buffer.from('IDAT')));
  for (const hidden of ['GPS 51.5', 'private note', 'camera-serial-123', 'tEXt', 'eXIf', 'someone@example.com', 'gAMA', 'hidden-after-the-zlib-stream']) assert.equal(bytes.includes(Buffer.from(hidden)), false, hidden);
  assert.ok(checkedLogo(bytes, 'image/png').bytes.equals(bytes), 'the served file passes the same check and rebuilds to itself');
  assert.ok(bytes.length < original.length);
  assert.equal((await call(acme.key, 'GET', '/v1/project')).body.project.logoUrl, uploaded.body.logoUrl);
  assert.equal((await call(acme.key, 'GET', '/v1/apps/github/consent-sheet')).body.developer.logoUrl, uploaded.body.logoUrl);
  const created = (await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body;
  app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), 'browser-logo-binding');
  const view = app.sessions.view(created.id, 'browser-logo-binding');
  assert.equal(view.developer.logoUrl, uploaded.body.logoUrl); assert.equal(view.sheet.developer.logoUrl, uploaded.body.logoUrl);
  // Same bytes for another project's path, or an unknown hash: nothing.
  const other = customer('Beta');
  assert.equal((await fetch(uploaded.body.logoUrl.replace(acme.project.id, other.project.id))).status, 404);
  assert.equal((await fetch(uploaded.body.logoUrl.replace(/[0-9a-f]{32}$/, '0'.repeat(32)))).status, 404);
  assert.ok(app.registry.activity().some(event => event.type === 'tenant.logo_uploaded'));
});

test('anything that is not a sound PNG or WebP of a sensible size and shape is refused', async t => {
  const {customer, upload, call} = await setup(t);
  const acme = customer('Acme');
  const refused = async (bytes, type, pattern) => { const response = await upload(acme.key, bytes, type); assert.equal(response.status, 400, `${type} ${response.body.error?.message}`); assert.equal(response.body.error.code, 'invalid_request'); if (pattern) assert.match(response.body.error.message, pattern); };
  await refused(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), 'image/svg+xml', /image\/png or image\/webp/);
  await refused(Buffer.from('<html><script>alert(1)</script></html>'), 'image/png', /not a PNG/);
  await refused(png(128, 128), 'image/webp', /not a WebP/);
  const damaged = png(128, 128); damaged[damaged.length - 20] ^= 0xff;
  await refused(damaged, 'image/png', /damaged|malformed/);
  await refused(png(64, 64), 'image/png', /128 to 1024 pixels/);
  await refused(png(1040, 1040), 'image/png', /128 to 1024 pixels/);
  await refused(png(256, 128), 'image/png', /square/);
  await refused(png(128, 128, [['ABCD', 'unknown critical']]), 'image/png', /feature Fabric does not accept/);
  await refused(Buffer.concat([png(128, 128), Buffer.from('trailing')]), 'image/png', /malformed/);
  const tooLarge = await upload(acme.key, Buffer.alloc(LOGO_MAX_BYTES + 1, 1));
  assert.equal(tooLarge.status, 413); assert.match(tooLarge.body.error.message, /256 KiB/, 'a clear answer, not a dropped connection');
  // PNGs no decoder can read: wrong compression method, a depth the colour type does not allow, a palette image with
  // no palette, a non-empty IEND, image data split around another chunk, image data of the wrong size.
  await refused(png(128, 128, [], {compression: 1}), 'image/png', /malformed/);
  await refused(png(128, 128, [], {depth: 1}), 'image/png', /malformed/);
  // Colour type 6 never has 1-bit samples, even when the data is exactly the size such an image would have.
  await refused(png(128, 128, [], {depth: 1, idat: [deflateSync(Buffer.alloc(128 * (1 + Math.ceil(128 * 4 / 8))))]}), 'image/png', /malformed/);
  await refused(png(128, 128, [], {colour: 3, depth: 8, idat: [deflateSync(Buffer.alloc(129 * 128))]}), 'image/png', /palette/);
  await refused(png(128, 128, [], {iend: Buffer.from('x')}), 'image/png', /malformed/);
  const half = deflateSync(Buffer.alloc((128 * 4 + 1) * 128));
  await refused(Buffer.concat([SIGNATURE, ...splitAround(half)]), 'image/png', /one run/);
  await refused(png(128, 128, [], {idat: [deflateSync(Buffer.alloc(10))]}), 'image/png', /size/);
  await refused(webp(128, 128, [['ANIM', 'xxxxxx']]), 'image/webp', /still image/);
  await refused(webp(128, 128, [], {version: 1}), 'image/webp', /malformed/);
  await refused(webp(200, 100), 'image/webp', /square/);
  assert.equal((await upload(acme.narrow, png(128, 128))).body.error.code, 'forbidden_scope', 'a key without project:write');
  assert.equal((await call(acme.key, 'PUT', '/v1/project/logo', {logo: 'x'})).status, 400, 'JSON is not a logo');
  assert.equal((await call(acme.key, 'GET', '/v1/project')).body.project.logoUrl, undefined, 'nothing was stored');
});

test('a WebP logo keeps its image and loses its EXIF and XMP; an animated PNG keeps only its first frame', async t => {
  const {customer, upload} = await setup(t);
  const acme = customer('Acme');
  const uploaded = await upload(acme.key, webp(128, 128, [['EXIF', 'owner=someone@example.com'], ['XMP ', '<x:xmpmeta>private</x:xmpmeta>']]), 'image/webp');
  assert.equal(uploaded.status, 200);
  const bytes = Buffer.from(await (await fetch(uploaded.body.logoUrl)).arrayBuffer());
  assert.equal(bytes.toString('latin1', 0, 4), 'RIFF'); assert.ok(bytes.includes(Buffer.from('VP8L')));
  for (const hidden of ['EXIF', 'XMP ', 'someone@example.com', 'private']) assert.equal(bytes.includes(Buffer.from(hidden)), false, hidden);
  assert.equal(bytes.readUInt32LE(4), bytes.length - 8, 'the rebuilt RIFF size is exact');
  const animated = checkedLogo(png(128, 128, [['acTL', Buffer.alloc(8)]]), 'image/png');
  assert.equal(animated.bytes.includes(Buffer.from('acTL')), false);
  // Lossy WebP with alpha: a raw alpha plane is cut to one byte per pixel; alpha after the frame is dropped, as decoders ignore it.
  const alpha = Buffer.concat([Buffer.from([0]), Buffer.alloc(128 * 128, 0xff), Buffer.from('hidden-after-the-alpha-plane')]);
  const withAlpha = checkedLogo(riff([riffChunk('ALPH', alpha), riffChunk('VP8 ', vp8(128, 128))]), 'image/webp');
  assert.ok(withAlpha.bytes.includes(Buffer.from('ALPH'))); assert.equal(withAlpha.bytes.includes(Buffer.from('hidden-after-the-alpha-plane')), false);
  const late = checkedLogo(riff([riffChunk('VP8 ', vp8(128, 128)), riffChunk('ALPH', alpha)]), 'image/webp');
  assert.equal(late.bytes.includes(Buffer.from('ALPH')), false);
  assert.throws(() => checkedLogo(riff([riffChunk('ALPH', Buffer.from([0x03, 1, 2])), riffChunk('VP8 ', vp8(128, 128))]), 'image/webp'), /malformed/, 'an alpha header with an unknown compression');
});

test('once production is live, a new logo waits for the operator, whichever key sends it, and is not served until approved', async t => {
  const {app, root, customer, upload, call} = await setup(t);
  const acme = customer('Acme', {production: true});
  for (const [key, size] of [[acme.key, 160], [acme.prodKey, 192]]) {
    const pending = await upload(key, png(size, size));
    assert.equal(pending.status, 202); assert.equal(pending.body.pendingReview, true);
  }
  assert.equal(app.registry.list('projectLogos').filter(item => item.projectId === acme.project.id).length, 1, 'the superseded pending upload is deleted');
  const project = (await call(acme.key, 'GET', '/v1/project')).body.project;
  assert.equal(project.logoUrl, undefined); assert.equal(project.pendingReview, true);
  const hash = app.registry.get('projects', acme.project.id).pendingBranding.logo.hash;
  assert.equal((await fetch(`${app.origin}/assets/logos/${acme.project.id}/${hash}`)).status, 404, 'a pending logo is never served');
  assert.equal((await call(acme.key, 'GET', '/v1/apps/github/consent-sheet')).body.developer.logoUrl, undefined);
  // A development key also changes the help address and the data-use note: those wait for review too.
  const patched = await call(acme.key, 'PATCH', '/v1/project', {supportEmail: 'help@acme.example', dataUse: {text: 'We use your data to answer you.', learnMoreUrl: 'https://acme.example/privacy'}});
  assert.equal(patched.status, 202); assert.deepEqual(patched.body.project.pendingFields, ['dataUse', 'logo', 'supportEmail']);
  assert.equal(patched.body.project.dataUse, undefined, 'not shown to end users until approved');
  // The operator reviews exactly what is pending (the logo written to a file to look at) and approves with its digest.
  await app.close();
  const logoFile = path.join(root, 'pending-logo.png');
  const shown = registryCommand(['project', 'show-branding', acme.project.id, '--logo-out', logoFile, '--root', root]);
  assert.equal(shown.pending.logo.hash, hash); assert.match(shown.digest, /^[0-9a-f]{32}$/);
  assert.throws(() => registryCommand(['project', 'approve-branding', acme.project.id, '--root', root]), /changed since it was reviewed|no digest/);
  assert.throws(() => registryCommand(['project', 'approve-branding', acme.project.id, '--digest', '0'.repeat(32), '--root', root]), /changed since it was reviewed/);
  const approved = registryCommand(['project', 'approve-branding', acme.project.id, '--digest', shown.digest, '--root', root]);
  assert.equal(approved.logo.hash, hash);
  assert.throws(() => registryCommand(['project', 'approve-branding', acme.project.id, '--digest', shown.digest, '--root', root]), /no branding waiting/);
});
