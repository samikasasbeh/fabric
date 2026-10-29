import path from 'node:path';
import {constants} from 'node:fs';
import {lstat,realpath,opendir,open} from 'node:fs/promises';

const MANIFEST_LIMIT=65536;
const CHILD_LIMIT=512;
const FABRIC_ORIGIN='http://127.0.0.1:4188/*';
const validPath=value=>typeof value==='string'&&value.length<=4096&&path.isAbsolute(value)&&!/[\u0000-\u001f\u007f]/.test(value);
const sameFile=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs;

function isFabricManifest(value){
  return Boolean(value&&typeof value==='object'&&!Array.isArray(value)
    &&value.manifest_version===3&&value.name==='Fabric Local Bridge'
    &&typeof value.version==='string'&&/^\d+(?:\.\d+){0,3}$/.test(value.version)
    &&value.background?.service_worker==='background.js'
    &&value.action?.default_popup==='popup.html'
    &&Array.isArray(value.host_permissions)&&value.host_permissions.includes(FABRIC_ORIGIN)
    &&Array.isArray(value.content_scripts)&&value.content_scripts.some(script=>
      Array.isArray(script?.matches)&&script.matches.includes(FABRIC_ORIGIN)
      &&Array.isArray(script.js)&&script.js.includes('fabric-handoff.js')));
}

async function plainFile(location,directory){
  const metadata=await lstat(location);
  if(!metadata.isFile()||metadata.isSymbolicLink()||await realpath(location)!==path.join(directory,path.basename(location)))return null;
  return metadata;
}

async function candidate(directory,canonicalRoot){
  try{
    const folder=await lstat(directory);
    if(!folder.isDirectory()||folder.isSymbolicLink())return false;
    const canonicalDirectory=await realpath(directory);
    if(path.dirname(canonicalDirectory)!==canonicalRoot)return false;
    const location=path.join(directory,'manifest.json');
    const metadata=await plainFile(location,canonicalDirectory);
    if(!metadata||metadata.size>MANIFEST_LIMIT)return false;
    // O_NOFOLLOW prevents a manifest swapped for a symlink between the checks
    // and open. Read one bounded buffer, never an arbitrarily growing file.
    const handle=await open(location,constants.O_RDONLY|constants.O_NOFOLLOW);
    let text;
    try{
      const opened=await handle.stat();
      if(!opened.isFile()||!sameFile(metadata,opened))return false;
      const buffer=Buffer.alloc(MANIFEST_LIMIT+1);
      let length=0;
      while(length<buffer.length){const {bytesRead}=await handle.read(buffer,length,buffer.length-length,length);if(!bytesRead)break;length+=bytesRead;}
      if(length>MANIFEST_LIMIT||!sameFile(opened,await handle.stat()))return false;
      text=buffer.subarray(0,length).toString('utf8');
    }finally{await handle.close();}
    if(!isFabricManifest(JSON.parse(text)))return false;
    for(const name of ['background.js','popup.html','fabric-handoff.js'])if(!await plainFile(path.join(directory,name),canonicalDirectory))return false;
    const current=await lstat(directory);
    return current.isDirectory()&&!current.isSymbolicLink()&&current.dev===folder.dev&&current.ino===folder.ino&&await realpath(directory)===canonicalDirectory;
  }catch{return false;}
}

// A folder name is presentation, not helper identity. Only immediate, real
// children of the trusted application root are considered; no search escapes
// this root, no symlinks are followed, and no copy is preferred on ambiguity.
export async function resolveHelperDirectory({root}={}){
  if(!validPath(root))throw new Error('Helper discovery requires an absolute local application directory.');
  root=path.resolve(root);
  const missing={status:'missing',directory:null,reason:'The Fabric browser helper folder is missing, incomplete, or unreadable.'};
  try{
    const rootMetadata=await lstat(root);
    if(!rootMetadata.isDirectory()||rootMetadata.isSymbolicLink())return {status:'unavailable',directory:null,reason:'The Fabric application directory must be a real local folder, not a symbolic link.'};
    const canonicalRoot=await realpath(root),matches=[];
    let children=0;
    for await(const entry of await opendir(root)){
      if(++children>CHILD_LIMIT)return {status:'unavailable',directory:null,reason:'The Fabric application directory has too many entries to identify the browser helper safely.'};
      if(!entry.isDirectory()||entry.isSymbolicLink()||entry.name.startsWith('.')||/[\u0000-\u001f\u007f]/.test(entry.name))continue;
      const directory=path.join(root,entry.name);
      if(await candidate(directory,canonicalRoot))matches.push(directory);
    }
    const currentRoot=await lstat(root);
    if(!currentRoot.isDirectory()||currentRoot.isSymbolicLink()||currentRoot.dev!==rootMetadata.dev||currentRoot.ino!==rootMetadata.ino||await realpath(root)!==canonicalRoot)return {status:'unavailable',directory:null,reason:'The Fabric application directory changed during helper discovery. Try again.'};
    if(!matches.length)return missing;
    if(matches.length>1)return {status:'ambiguous',directory:null,reason:'More than one Fabric browser helper folder was found. Keep one intended helper folder in this application directory; no folder was selected or changed.'};
    return {status:'ready',directory:matches[0]};
  }catch{return missing;}
}
