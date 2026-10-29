import {readdir} from 'node:fs/promises';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
async function walk(dir){const files=[];for(const e of await readdir(dir,{withFileTypes:true})){if(e.name.startsWith('.')||e.name==='node_modules')continue;const p=path.join(dir,e.name);if(e.isDirectory()) files.push(...await walk(p));else if(/\.(mjs|js|mts)$/.test(p))files.push(p);}return files;}
let failures=0;for(const file of await walk(root)){const result=spawnSync(process.execPath,['--check',file],{encoding:'utf8'});if(result.status){console.error(result.stderr);failures++;}}
if(failures)process.exitCode=1;else console.log('All JavaScript and native TypeScript modules passed syntax checks.');
