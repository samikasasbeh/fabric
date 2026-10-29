import path from 'node:path';
import os from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {access,stat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolveHelperDirectory} from './helper-directory.mjs';

const runFile=promisify(execFile);
const HELPER_ORIGIN='http://127.0.0.1:4188';
const APP_ID=/^[a-z][a-z0-9-]{0,63}$/;
const ACTIONS=new Set(['open-fabric','open-extensions','reveal-extension']);
const BROWSERS=Object.freeze([
  Object.freeze({id:'chrome',name:'Google Chrome',bundle:'com.google.Chrome',application:'Google Chrome.app',extensions:'chrome://extensions/'}),
  Object.freeze({id:'edge',name:'Microsoft Edge',bundle:'com.microsoft.edgemac',application:'Microsoft Edge.app',extensions:'edge://extensions/'}),
]);
const validDirectory=value=>typeof value==='string'&&value.length<=4096&&path.isAbsolute(value)&&!/[\u0000-\u001f\u007f]/.test(value);

// Construction options belong to the trusted local host, never the HTTP body.
// This service only opens fixed setup destinations after an explicit UI action.
// It cannot install an extension, change a preference, or approve site access.
export class BrowserSetup {
  constructor({root,origin,platform=process.platform,executeFile=runFile,fileAccess=access,fileStat=stat,homeDirectory=os.homedir()}={}){
    if(!validDirectory(root)||!validDirectory(homeDirectory))throw new Error('Browser setup requires a local application directory.');
    let parsed;try{parsed=new URL(origin);}catch{throw new Error('Browser setup requires the explicit local loopback origin.');}
    if(typeof origin!=='string'||parsed.protocol!=='http:'||parsed.hostname!=='127.0.0.1'||parsed.username||parsed.password||parsed.pathname!=='/'||parsed.search||parsed.hash||parsed.origin!==origin)throw new Error('Browser setup requires the explicit local loopback origin.');
    if(typeof platform!=='string'||![executeFile,fileAccess,fileStat].every(value=>typeof value==='function'))throw new Error('Invalid browser setup host configuration.');
    Object.assign(this,{root:path.resolve(root),origin,platform,executeFile,fileAccess,fileStat,homeDirectory});
  }

  async extensionAvailable(){
    return (await resolveHelperDirectory({root:this.root})).status==='ready';
  }

  async installed(browser){
    if(this.platform!=='darwin')return false;
    for(const directory of ['/Applications',path.join(this.homeDirectory,'Applications')]){
      const location=path.join(directory,browser.application);
      try{await this.fileAccess(location,constants.R_OK);if((await this.fileStat(location)).isDirectory())return true;}catch{/* Missing known installation is not an error or permission request. */}
    }
    return false;
  }

  async status(){
    const [helper,browsers]=await Promise.all([resolveHelperDirectory({root:this.root}),Promise.all(BROWSERS.map(async browser=>({id:browser.id,name:browser.name,installed:await this.installed(browser)})))]);
    const extensionAvailable=helper.status==='ready';
    const supported=this.platform==='darwin'&&this.origin===HELPER_ORIGIN;
    const reason=this.platform!=='darwin'?'Automatic browser setup currently supports macOS only.':this.origin!==HELPER_ORIGIN?'This browser helper requires Fabric at http://127.0.0.1:4188.':helper.reason;
    return {platform:this.platform,supported,extensionAvailable,directory:helper.directory,browsers,...(reason?{reason}:{})};
  }

  async perform(input){
    if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(key=>!['action','browser','appId'].includes(key)))throw new Error('Choose a supported browser setup action.');
    const {action,browser:browserId,appId}=input;
    const browser=BROWSERS.find(item=>item.id===browserId);
    if(typeof action!=='string'||!ACTIONS.has(action)||typeof browserId!=='string'||!browser)throw new Error('Choose a supported browser and setup action.');
    if(typeof appId!=='string'||!APP_ID.test(appId))throw new Error('Choose a valid application before opening Fabric.');
    if(this.platform!=='darwin')throw new Error('Automatic browser setup currently supports macOS only.');
    if(this.origin!==HELPER_ORIGIN)throw new Error('This browser helper requires Fabric at http://127.0.0.1:4188. No setup window was opened.');
    if(action!=='reveal-extension'&&!await this.installed(browser))throw new Error(`${browser.name} is not installed in a supported Applications folder.`);
    const helper=await resolveHelperDirectory({root:this.root});
    if(helper.status!=='ready')throw new Error(`${helper.reason} No setup window was opened.`);
    const target=action==='open-fabric'?`${this.origin}/#connectors/${encodeURIComponent(appId)}`:browser.extensions;
    const args=action==='reveal-extension'?['-R',helper.directory]:['-b',browser.bundle,target];
    try{await this.executeFile('/usr/bin/open',args,{shell:false,timeout:8000,maxBuffer:16384,killSignal:'SIGKILL',encoding:'utf8',windowsHide:true,env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin',LANG:'C',LC_ALL:'C'}});}
    catch{throw new Error('Fabric could not open the setup destination. Try the setup button again; no extension was installed or account connected.');}
    return {action,browser:browser.id,opened:true,directory:helper.directory,connectionEstablished:false,installationPerformed:false,message:action==='reveal-extension'?'Asked Finder to reveal the exact helper folder. Select this folder in Load unpacked.':action==='open-extensions'?`Asked ${browser.name} to open extension settings. Loading the helper and approving access remain your choices.`:`Asked ${browser.name} to open Fabric. After loading the helper, reload this Fabric tab before connecting.`};
  }
}
