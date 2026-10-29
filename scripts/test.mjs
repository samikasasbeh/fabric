import path from 'node:path';
import {readdir,lstat,realpath} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolveHelperDirectory} from '../lib/helper-directory.mjs';

export async function discoverTestFiles(root){
  const helper=await resolveHelperDirectory({root});
  if(helper.status!=='ready')throw new Error(helper.reason);
  const files=[];
  for(const directory of [path.join(root,'test'),path.join(helper.directory,'test')]){
    const previousCount=files.length;
    const metadata=await lstat(directory);
    if(!metadata.isDirectory()||metadata.isSymbolicLink())throw new Error('Fabric test folders must be real local directories.');
    const canonicalDirectory=await realpath(directory);
    for(const entry of await readdir(directory,{withFileTypes:true})){
      if(!entry.name.endsWith('.test.mjs'))continue;
      if(entry.isSymbolicLink())throw new Error('Fabric test files must stay inside their test directory.');
      if(!entry.isFile())continue;
      const location=path.join(directory,entry.name);
      if((await lstat(location)).isSymbolicLink()||await realpath(location)!==path.join(canonicalDirectory,entry.name))throw new Error('Fabric test files must stay inside their test directory.');
      files.push(location);
    }
    if(files.length===previousCount)throw new Error('A Fabric test directory contains no test files; refusing to skip a test suite.');
  }
  if(!files.length)throw new Error('No Fabric tests were found.');
  return files.sort();
}

// Operator settings exported in a shell (relay base, provider clients, model gateway) must not change what tests
// exercise or reach a real service. Tests that need them set their own values. The data directory and port stay.
const OPERATOR_SETTING=/^FABRIC_(PUBLIC_CALLBACK_BASE|MODEL_(URL|API_KEY|NAME)|[A-Z0-9_]+_CLIENT_(ID|SECRET)|[A-Z0-9_]+_PUBLISHING|SLACK_DISTRIBUTION|[A-Z0-9_]+_CONSENT_DAYS)$/;
export function testEnvironment(env){return Object.fromEntries(Object.entries(env).filter(([key])=>!OPERATOR_SETTING.test(key)));}
// Named *.test.mjs arguments run just those discovered files (npm run verify:layer); other arguments go to node --test.
export function testArguments(argv,files,root){
  const named=argv.filter(arg=>arg.endsWith('.test.mjs')),options=argv.filter(arg=>!arg.endsWith('.test.mjs'));
  const chosen=named.map(arg=>{const file=path.resolve(root,arg);if(!files.includes(file))throw new Error(`${arg} is not a Fabric test file.`);return file;});
  return ['--test',...options,...(chosen.length?chosen:files)];
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
    const files=await discoverTestFiles(root);
    const child=spawn(process.execPath,testArguments(process.argv.slice(2),files,root),{cwd:root,env:testEnvironment(process.env),stdio:'inherit',shell:false});
    child.on('error',error=>{console.error(`Could not start Fabric tests: ${error.message}`);process.exitCode=1;});
    child.on('exit',(code,signal)=>{process.exitCode=signal?1:code??1;});
  }catch(error){console.error(`Could not discover Fabric tests: ${error.message}`);process.exitCode=1;}
}
