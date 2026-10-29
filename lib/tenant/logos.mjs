// F03.6b (docs/F03-DEVELOPER-LAYER.md sections 5.3 and 6.3): a developer's logo. Fabric accepts PNG or WebP bytes only,
// square, 128 to 1,024 pixels, at most 256 KiB, and rebuilds the file. A PNG keeps only its header, palette and
// transparency, and its pixels are inflated to their exact size and deflated again, so nothing hidden survives. A WebP
// keeps its one frame and its alpha; every other chunk (EXIF, XMP, colour profiles, animation) is dropped, and the
// compressed frame bytes are kept as sent because checking them would need a full decoder. Served with a fixed type.
import {createHash} from 'node:crypto';
import {crc32, deflateSync, inflateSync} from 'node:zlib';

export const LOGO_MAX_BYTES = 256 * 1024;
// The spec's defaults (docs/F03-DEVELOPER-LAYER.md section 2): square, 128 to 1,024 pixels, at most 256 KiB.
export const LOGO_MIN_SIDE = 128, LOGO_MAX_SIDE = 1024;
export const LOGO_TYPES = Object.freeze(['image/png', 'image/webp']);

export class LogoError extends Error {
  constructor(message) { super(message); this.code = 'invalid_request'; }
}
const fail = message => { throw new LogoError(message); };

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
// Allowed bit depths per PNG colour type, and the samples per pixel of each.
const PNG_DEPTHS = {0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16]};
const PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4};

function shape(width, height) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width !== height) fail('A logo is square.');
  if (width < LOGO_MIN_SIDE || width > LOGO_MAX_SIDE) fail(`A logo is ${LOGO_MIN_SIDE} to ${LOGO_MAX_SIDE} pixels on each side.`);
}
const pngChunk = (type, data) => { const length = Buffer.alloc(4); length.writeUInt32BE(data.length); const body = Buffer.concat([Buffer.from(type, 'latin1'), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body)); return Buffer.concat([length, body, crc]); };

/** The exact size of a PNG's filtered pixel data, row filter bytes included, for plain and Adam7-interlaced images. */
function filteredSize(width, height, bitsPerPixel, interlace) {
  const row = w => 1 + Math.ceil(w * bitsPerPixel / 8);
  if (!interlace) return height * row(width);
  const passes = [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]];
  let total = 0;
  for (const [x0, y0, dx, dy] of passes) {
    const w = Math.ceil((width - x0) / dx), h = Math.ceil((height - y0) / dy);
    if (w > 0 && h > 0) total += h * row(w);
  }
  return total;
}
/** Every row starts with a filter type of 0 to 4. */
function checkFilters(pixels, width, height, bitsPerPixel, interlace) {
  const passes = interlace ? [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]] : [[0, 0, 1, 1]];
  let offset = 0;
  for (const [x0, y0, dx, dy] of passes) {
    const w = Math.ceil((width - x0) / dx), h = Math.ceil((height - y0) / dy);
    if (w <= 0 || h <= 0) continue;
    const row = 1 + Math.ceil(w * bitsPerPixel / 8);
    for (let y = 0; y < h; y++, offset += row) if (pixels[offset] > 4) fail('The PNG image data is malformed.');
  }
}

function png(bytes) {
  if (bytes.length < 8 + 25 + 12 || !bytes.subarray(0, 8).equals(PNG_SIGNATURE)) fail('This is not a PNG file.');
  let offset = 8, header = null, palette = null, transparency = null, ended = false, dataStarted = false, dataEnded = false;
  const data = [];
  while (offset < bytes.length) {
    if (offset + 12 > bytes.length) fail('The PNG file is cut short.');
    const length = bytes.readUInt32BE(offset), type = bytes.toString('latin1', offset + 4, offset + 8);
    if (!/^[A-Za-z]{4}$/.test(type) || length > bytes.length - offset - 12) fail('The PNG file is malformed.');
    const body = bytes.subarray(offset + 4, offset + 8 + length), chunk = body.subarray(4), crc = bytes.readUInt32BE(offset + 8 + length);
    if (crc32(body) !== crc) fail('The PNG file is damaged (a checksum does not match).');
    if (header === null && type !== 'IHDR') fail('The PNG file is malformed.');
    if (dataStarted && type !== 'IDAT') dataEnded = true;
    if (type === 'IHDR') {
      if (header !== null || length !== 13) fail('The PNG file is malformed.');
      header = {width: chunk.readUInt32BE(0), height: chunk.readUInt32BE(4), depth: chunk[8], colour: chunk[9], compression: chunk[10], filter: chunk[11], interlace: chunk[12]};
      if (!PNG_DEPTHS[header.colour]?.includes(header.depth) || header.compression !== 0 || header.filter !== 0 || header.interlace > 1) fail('The PNG file is malformed.');
    } else if (type === 'PLTE') {
      if (palette || dataStarted || length === 0 || length % 3 || length > 768 || header.colour === 0 || header.colour === 4) fail('The PNG file is malformed.');
      // A suggested palette in a truecolour image never draws anything: dropped.
      if (header.colour === 3) palette = Buffer.from(chunk);
    } else if (type === 'tRNS') {
      if (transparency || dataStarted) fail('The PNG file is malformed.');
      const allowed = header.colour === 0 ? length === 2 : header.colour === 2 ? length === 6 : header.colour === 3 ? palette && length >= 1 && length <= palette.length / 3 : false;
      if (header.colour === 3 && !palette) fail('The PNG file is malformed.');
      // Transparency that is not valid for the colour type is dropped, as decoders do.
      if (allowed) transparency = Buffer.from(chunk);
    } else if (type === 'IDAT') {
      if (dataEnded) fail('The PNG image data must be in one run.');
      if (header.colour === 3 && !palette) fail('A palette image needs its palette before its image data.');
      dataStarted = true; data.push(chunk);
    } else if (type === 'IEND') {
      if (length !== 0) fail('The PNG file is malformed.');
      ended = true; offset += 12; break;
    } else if (/^[A-Z]/.test(type)) fail('The PNG file uses a feature Fabric does not accept.');
    // Every other ancillary chunk (text, EXIF, colour profiles, gamma, animation, ...) is dropped.
    offset += 12 + length;
  }
  if (!header || !data.length || !ended || offset !== bytes.length) fail('The PNG file is malformed.');
  shape(header.width, header.height);
  // The pixel data is inflated to exactly the size the header promises and deflated again, so nothing can ride inside
  // or after the compressed stream.
  const bitsPerPixel = header.depth * PNG_CHANNELS[header.colour], expected = filteredSize(header.width, header.height, bitsPerPixel, header.interlace);
  let pixels;
  try { pixels = inflateSync(Buffer.concat(data), {maxOutputLength: expected + 1}); } catch { fail('The PNG image data is malformed.'); }
  if (pixels.length !== expected) fail('The PNG image data does not match its size.');
  checkFilters(pixels, header.width, header.height, bitsPerPixel, header.interlace);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(header.width, 0); ihdr.writeUInt32BE(header.height, 4); ihdr[8] = header.depth; ihdr[9] = header.colour; ihdr[12] = header.interlace;
  const out = [PNG_SIGNATURE, pngChunk('IHDR', ihdr), ...(palette ? [pngChunk('PLTE', palette)] : []), ...(transparency ? [pngChunk('tRNS', transparency)] : []), pngChunk('IDAT', deflateSync(pixels)), pngChunk('IEND', Buffer.alloc(0))];
  return {bytes: Buffer.concat(out), width: header.width, height: header.height};
}

function webp(bytes) {
  if (bytes.length < 30 || bytes.toString('latin1', 0, 4) !== 'RIFF' || bytes.toString('latin1', 8, 12) !== 'WEBP' || bytes.readUInt32LE(4) !== bytes.length - 8) fail('This is not a WebP file.');
  const chunks = [];
  let offset = 12;
  while (offset < bytes.length) {
    if (offset + 8 > bytes.length) fail('The WebP file is cut short.');
    const type = bytes.toString('latin1', offset, offset + 4), size = bytes.readUInt32LE(offset + 4), padded = size + (size & 1);
    if (offset + 8 + padded > bytes.length) fail('The WebP file is malformed.');
    chunks.push({type, data: bytes.subarray(offset + 8, offset + 8 + size)});
    offset += 8 + padded;
  }
  if (offset !== bytes.length) fail('The WebP file is malformed.');
  const frames = chunks.filter(chunk => chunk.type === 'VP8 ' || chunk.type === 'VP8L');
  if (frames.length !== 1 || chunks.some(chunk => chunk.type === 'ANIM' || chunk.type === 'ANMF')) fail('A logo is one still image.');
  const frame = frames[0], frameAt = chunks.indexOf(frame);
  let width, height;
  if (frame.type === 'VP8L') {
    if (frame.data.length < 6 || frame.data[0] !== 0x2f) fail('The WebP file is malformed.');
    const bits = frame.data.readUInt32LE(1);
    if (bits >>> 29 !== 0) fail('The WebP file is malformed.');
    width = (bits & 0x3fff) + 1; height = ((bits >>> 14) & 0x3fff) + 1;
  } else {
    if (frame.data.length < 10 || frame.data[3] !== 0x9d || frame.data[4] !== 0x01 || frame.data[5] !== 0x2a) fail('The WebP file is malformed.');
    const tag = frame.data.readUIntLE(0, 3), keyFrame = (tag & 1) === 0, profile = (tag >> 1) & 7, shown = (tag >> 4) & 1, firstPart = tag >>> 5;
    if (!keyFrame || profile > 3 || !shown || firstPart >= frame.data.length - 10) fail('The WebP file is malformed.');
    width = frame.data.readUInt16LE(6) & 0x3fff; height = frame.data.readUInt16LE(8) & 0x3fff;
  }
  shape(width, height);
  // Alpha belongs to a lossy frame only, comes before it (decoders ignore it after), and has a checked header; a raw
  // alpha plane is cut to exactly one byte per pixel. Compressed frame and alpha data are kept as sent: checking them
  // would need a full decoder.
  const alphas = chunks.filter(chunk => chunk.type === 'ALPH'), before = chunks.slice(0, frameAt).filter(chunk => chunk.type === 'ALPH');
  if (alphas.length > 1) fail('The WebP file is malformed.');
  let alpha = frame.type === 'VP8 ' && before.length === 1 ? before[0].data : null;
  if (alpha) {
    const head = alpha[0], compression = head & 3, filtering = (head >> 2) & 3, preprocessing = (head >> 4) & 3;
    if (head >> 6 || compression > 1 || preprocessing > 1 || alpha.length < 2) fail('The WebP file is malformed.');
    void filtering;
    if (compression === 0) {
      if (alpha.length < 1 + width * height) fail('The WebP file is malformed.');
      alpha = alpha.subarray(0, 1 + width * height);
    }
  }
  const out = [];
  const chunk = (type, data) => { const head = Buffer.alloc(8); head.write(type, 0, 'latin1'); head.writeUInt32LE(data.length, 4); out.push(head, data, ...(data.length & 1 ? [Buffer.alloc(1)] : [])); };
  if (alpha) {
    const vp8x = Buffer.alloc(10); vp8x[0] = 0x10; // alpha flag only
    vp8x.writeUIntLE(width - 1, 4, 3); vp8x.writeUIntLE(height - 1, 7, 3);
    chunk('VP8X', vp8x); chunk('ALPH', alpha);
  }
  chunk(frame.type, frame.data);
  const body = Buffer.concat(out), riff = Buffer.alloc(12);
  riff.write('RIFF', 0, 'latin1'); riff.writeUInt32LE(body.length + 4, 4); riff.write('WEBP', 8, 'latin1');
  return {bytes: Buffer.concat([riff, body]), width, height};
}

/** The checked, rebuilt logo, or a LogoError naming what is wrong. The declared type must match the bytes. */
export function checkedLogo(bytes, contentType) {
  const type = String(contentType || '').split(';')[0].trim().toLowerCase();
  if (!LOGO_TYPES.includes(type)) fail('Send the logo as image/png or image/webp.');
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) fail('The logo is empty.');
  if (bytes.length > LOGO_MAX_BYTES) fail(`A logo is at most ${LOGO_MAX_BYTES / 1024} KiB.`);
  const image = type === 'image/png' ? png(bytes) : webp(bytes);
  return {contentType: type, ...image, hash: createHash('sha256').update(image.bytes).digest('hex').slice(0, 32)};
}

/** Where a project's approved logo is served, or null. */
export function logoUrl(project, origin) {
  return project?.logo?.hash ? `${origin}/assets/logos/${project.id}/${project.logo.hash}` : null;
}
