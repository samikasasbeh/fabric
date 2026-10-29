import { mkdir, readdir, readFile, writeFile, rename, lstat, realpath, unlink } from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

const hash = value => createHash('sha256').update(value).digest('hex');
const MAX_BYTES = 1_000_000;
export const workspaceCapabilities = [
  { id: 'workspace.list.v1', name: 'List workspace files', action: { op: 'list' }, effect: 'read', inputSchema: {type:'object',properties:{},additionalProperties:false} },
  { id: 'workspace.read.v1', name: 'Read a workspace file', action: { op: 'read' }, effect: 'read', inputSchema: {type:'object',properties:{path:{type:'string',minLength:1,maxLength:160}},required:['path'],additionalProperties:false} },
  { id: 'workspace.write.v1', name: 'Write a workspace file', action: { op: 'write' }, effect: 'write', inputSchema: {type:'object',properties:{path:{type:'string',minLength:1,maxLength:160},content:{type:'string',maxLength:MAX_BYTES}},required:['path','content'],additionalProperties:false} },
].map(c => ({ specVersion:'fabric/0.1', version:1, appId:'workspace', driver:'workspace', status:'active', description:'Real files in Fabric’s dedicated workspace only.', provenance:{kind:'builtin',source:'reviewed local driver v1'}, verification:{kind:'independent-readback'}, ...c }));

export class LocalDriver {
  constructor(root) { this.root = path.resolve(root); }
  async init() {
    await mkdir(this.root,{recursive:true,mode:0o700});
    if ((await lstat(this.root)).isSymbolicLink()) throw new Error('Workspace root cannot be a symlink.');
    this.realRoot = await realpath(this.root);
  }
  async resolve(name) {
    // Deliberately flat in v0.1: no traversal, hidden files, or symlink parents.
    if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,159}$/.test(name) || name.includes('..')) throw new Error('Use a simple filename inside the Fabric workspace.');
    if (await realpath(this.root) !== this.realRoot) throw new Error('Workspace location changed.');
    const target = path.join(this.realRoot,name);
    try { const stat=await lstat(target); if(!stat.isFile() || stat.isSymbolicLink()) throw new Error('Target must be a regular file, not a symlink.'); if(stat.size>MAX_BYTES) throw new Error('File exceeds 1 MB limit.'); } catch(e) { if(e.code!=='ENOENT') throw e; }
    return target;
  }
  async snapshot(name) {
    const target=await this.resolve(name);
    try {const data=await readFile(target); return {path:name,exists:true,sha256:hash(data),bytes:data.length};} catch(e) {if(e.code==='ENOENT') return {path:name,exists:false,sha256:null}; throw e;}
  }
  async execute(action,args,precondition,authorize=()=>{}) {
    authorize();
    if(action.op==='list') {
      const files=[];
      for(const item of await readdir(this.realRoot,{withFileTypes:true})) if(item.isFile()&&!item.name.startsWith('.')) {authorize();files.push(await this.snapshot(item.name));}
      authorize();
      return {data:{files},verification:{status:'observed',kind:'filesystem-directory',checkedAt:new Date().toISOString()}};
    }
    const target=await this.resolve(args.path);
    if(action.op==='read') {
      authorize();
      const data=await readFile(target); if(data.length>MAX_BYTES) throw new Error('File exceeds 1 MB limit.');
      authorize();
      return {data:{path:args.path,content:data.toString('utf8'),sha256:hash(data)},verification:{status:'observed',kind:'filesystem-read',checkedAt:new Date().toISOString()}};
    }
    if(action.op!=='write') throw new Error('Unsupported workspace operation.');
    if(Buffer.byteLength(args.content)>MAX_BYTES) throw new Error('Content exceeds 1 MB limit.');
    const before=await this.snapshot(args.path);
    if(!precondition || before.sha256!==precondition.sha256 || before.exists!==precondition.exists) throw new Error('File changed since approval was requested. Create a new job to review it.');
    const temporary=path.join(this.realRoot,`.fabric-${randomUUID()}`);
    try {
      authorize();
      await writeFile(temporary,args.content,{mode:0o600,flag:'wx'});
      const latest=await this.snapshot(args.path);
      if(latest.sha256!==before.sha256 || latest.exists!==before.exists) throw new Error('File changed before commit.');
      authorize();
      await rename(temporary,target);
    } finally {await unlink(temporary).catch(e=>{if(e.code!=='ENOENT') throw e;});}
    authorize();
    const observed=await this.snapshot(args.path);
    return {data:observed,verification:{status:observed.sha256===hash(args.content)?'verified':'failed',kind:'independent-filesystem-readback',expectedSha256:hash(args.content),observedSha256:observed.sha256,checkedAt:new Date().toISOString()}};
  }
}
