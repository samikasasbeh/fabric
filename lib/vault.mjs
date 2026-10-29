import { mkdirSync, chmodSync, readFileSync, writeFileSync, renameSync, unlinkSync, existsSync, lstatSync, readdirSync, constants, openSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'node:crypto';

// Local-development protection at rest, NOT an OS keychain or a defense against a compromised local user.
// The key and encrypted records share a restricted directory. Back up/migrate both together.
export class Vault {
  constructor(dataDir) {
    this.dir = join(dataDir, 'vault');
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (lstatSync(this.dir).isSymbolicLink()) throw new Error('Vault directory cannot be a symbolic link.');
    chmodSync(this.dir, 0o700);
    const path = join(this.dir, 'master.key');
    if (!existsSync(path)) {
      if (readdirSync(this.dir).some(f => f.endsWith('.enc'))) throw new Error('Vault key is missing; restore it before opening existing connections.');
      try { writeFileSync(path, randomBytes(32), { flag: 'wx', mode: 0o600 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    }
    if (lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()) throw new Error('Invalid vault key file.');
    chmodSync(path, 0o600);
    this.key = this.read(path);
    if (this.key.length !== 32) throw new Error('Invalid vault master key.');
  }
  read(path) { const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); try { return readFileSync(fd); } finally { closeSync(fd); } }
  path(id) { if (typeof id !== 'string' || !id) throw new Error('Vault id required.'); return join(this.dir, `${createHash('sha256').update(id).digest('hex')}.enc`); }
  set(id, value) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce);
    cipher.setAAD(Buffer.from(id));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    const packed = JSON.stringify({ version: 1, nonce: nonce.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') });
    const path = this.path(id), temp = `${path}.${randomBytes(8).toString('hex')}.tmp`;
    try { writeFileSync(temp, packed, { flag: 'wx', mode: 0o600 }); renameSync(temp, path); } finally { if (existsSync(temp)) unlinkSync(temp); }
  }
  get(id) {
    const path = this.path(id);
    if (!existsSync(path)) return null;
    try {
      const packed = JSON.parse(this.read(path));
      if (packed.version !== 1) throw new Error('version');
      const decipher = createDecipheriv('aes-256-gcm', this.key, Buffer.from(packed.nonce, 'base64'));
      decipher.setAAD(Buffer.from(id));
      decipher.setAuthTag(Buffer.from(packed.tag, 'base64'));
      return JSON.parse(Buffer.concat([decipher.update(Buffer.from(packed.ciphertext, 'base64')), decipher.final()]).toString('utf8'));
    } catch { throw new Error('Credential record cannot be decrypted.'); }
  }
  delete(id) { const path = this.path(id); if (existsSync(path)) unlinkSync(path); }
}
