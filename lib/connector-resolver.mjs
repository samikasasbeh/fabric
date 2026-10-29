import {createHash} from 'node:crypto';
import {isIP} from 'node:net';
import {safeRequest} from './network.mjs';
import {ApplicationIndex,publicMetadataUrl,specificationOrigins} from './application-index.mjs';

const normalize=value=>String(value).toLowerCase().replace(/[^a-z0-9]/g,'');
const aliases={twitter:'x',googlecalendar:'google-calendar',calendar:'google-calendar',googlemail:'gmail',mac:'local-device',macbook:'local-device',computer:'local-device',hardware:'local-device',usb:'local-device',device:'local-device',files:'workspace'};
const clean=value=>String(value).replace(/<[^>]*>/g,'').replace(/&#(\d+);/g,(_,n)=>Number(n)>31&&Number(n)<127?String.fromCharCode(Number(n)):'').replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&lt;|&gt;/g,'').replace(/[\u0000-\u001f\u007f]/g,' ').replace(/\s+/g,' ').trim().slice(0,100);

export function websiteUrl(value) {
  let url;
  try {url=new URL(/^https?:\/\//i.test(value)?value:`https://${value}`);} catch {throw new Error('Enter the application’s HTTPS website.');}
  if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search||(url.port&&url.port!=='443')||isIP(url.hostname)||!url.hostname.includes('.')||/\.(local|internal|localhost|test|invalid)$/i.test(url.hostname)||url.hostname==='localhost') throw new Error('Use a public HTTPS website, without passwords or private-network addresses.');
  return url;
}

// Every hop is separately DNS-checked and pinned by safeRequest. This discovery
// transport never carries credentials, executes page code, or follows login flows.
async function publicGet(request,url,options={}) {
  const {metadataUrl=false,deadlineMs=null,...limits}=options;
  const validate=metadataUrl?publicMetadataUrl:websiteUrl;
  let target=validate(url);
  for(let hop=0;hop<4;hop++) {
    const remaining=deadlineMs===null?6000:deadlineMs-Date.now();if(remaining<1)throw new Error('Public metadata request deadline reached.');
    const response=await request({url:target.href,method:'GET',allowedOrigins:[target.origin],headers:{Accept:limits.responseType==='buffer'?'image/png,image/x-icon,image/jpeg,image/webp':'text/html,application/json'},maxBytes:512*1024,allowRedirectResponse:true,...limits,timeoutMs:Math.min(limits.timeoutMs||6000,remaining)});
    if(response.status>=300&&response.status<400) {
      if(!response.headers?.location) throw new Error('The website redirected without a destination.');
      target=validate(new URL(response.headers.location,target).href);continue;
    }
    if(response.status<200||response.status>=300) throw new Error(`The website returned HTTP ${response.status}.`);
    return {...response,url:target};
  }
  throw new Error('The website redirected too many times.');
}

export function publisherIconLinks(html,pageUrl){
  if(typeof html!=='string'||Buffer.byteLength(html)>512*1024)return [];
  const links=[],markup=html.replace(/<!--[\s\S]*?-->/g,'').replace(/<(?:script|style)\b[^>]*>[\s\S]*?<\/(?:script|style)\s*>/gi,'');
  let visited=0;
  for(const match of markup.matchAll(/<link\b[^>]{0,4096}>/gi)){
    if(++visited>100||links.length>=3)break;
    const attrs={};for(const token of match[0].matchAll(/([a-zA-Z][\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g)){const key=token[1].toLowerCase();if(!Object.hasOwn(attrs,key))attrs[key]=token[2]??token[3]??token[4];}
    if(!/(?:^|\s)(?:icon|apple-touch-icon|apple-touch-icon-precomposed)(?:\s|$)/i.test(attrs.rel||'')||!attrs.href||/svg/i.test(attrs.type||''))continue;
    try{const url=publicMetadataUrl(new URL(attrs.href.replace(/&amp;/g,'&'),pageUrl).href);if(/\.svg$/i.test(url.pathname))continue;if(!links.includes(url.href))links.push(url.href);}catch{}
  }
  return links;
}
function rasterImage(data){
  if(!Buffer.isBuffer(data)||data.length<4||data.length>128*1024)return null;
  const type=data.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))?'image/png':data[0]===0&&data[1]===0&&data[2]===1&&data[3]===0?'image/x-icon':data[0]===255&&data[1]===216&&data[2]===255?'image/jpeg':data.length>12&&data.toString('ascii',0,4)==='RIFF'&&data.toString('ascii',8,12)==='WEBP'?'image/webp':null;
  return type?{data,type}:null;
}

// oauthRoute(appId) -> {providerId,name,configured} | null comes from the server's
// reviewed provider registry; without it only the original Google route is described.
const signInRoute=(appId,{googleOAuthConfigured=false,oauthRoute}={})=>typeof oauthRoute==='function'?oauthRoute(appId):['gmail','google-calendar'].includes(appId)?{providerId:'google',name:'Google',configured:googleOAuthConfigured}:null;
export function planConnection(app,settings={}) {
  const routes=[],signIn=signInRoute(app.id,settings);
  if(app.id==='local-device') routes.push({method:'device',label:'This computer',available:true,capabilities:['System information','Connected USB inventory','Installed command-line tools'],requires:['Your approval to connect this computer'],limitation:'Inventory only. Device control and arbitrary command execution are not implemented.'});
  if(app.id==='workspace') routes.push({method:'workspace',label:'Local workspace',available:true,capabilities:['Read files','Write approved files'],requires:['Your approval to connect the Fabric folder']});
  if(signIn) routes.push({method:'oauth',label:`Sign in with ${signIn.name}`,available:Boolean(signIn.configured&&(signIn.available??true)),requires:signIn.configured?(signIn.available===false?[signIn.reason]:[`${signIn.name} sign-in and consent`]):[`Fabric owner must configure ${signIn.name} sign-in`],limitation:'Only provider-authorized API operations are accessible.'});
  if((app.webOrigins||app.browserOrigins||[]).length) routes.push({method:'browser',label:'Use your browser',available:true,capabilities:['Inspect this page','Read a page element','Click an observed control','Fill an observed field'],requires:['Fabric helper in Chrome or Edge','Approval for the chosen website and tab'],limitation:'Every click or fill requires approval. No passwords, payment fields, native desktop control, or whole-account access. Browser sign-in stays with the application.'});
  return {appId:app.id,routes,recommended:routes.find(route=>route.available)?.method||null,connectionEstablished:false};
}

export class ConnectorResolver {
  constructor({store,catalog,request=safeRequest,settings=()=>({}),index}) {Object.assign(this,{store,catalog,request,settings});this.index=index||new ApplicationIndex({store,request});this.icons=new Map();this.inflight=new Map();this.iconActive=0;this.iconWaiting=[];}
  search(query='') {const key=normalize(query);return this.catalog().filter(app=>!key||normalize(app.name).includes(key)||normalize(app.id).includes(key)||aliases[key]===app.id).map(app=>({...app,iconUrl:`/api/icons/${encodeURIComponent(app.id)}`,plan:planConnection(app,this.settings())}));}
  async lookup(query){
    if(typeof query!=='string'||!query.trim()||query.length>500)throw new Error('Enter an application name or website (up to 500 characters).');
    const key=normalize(query),known=this.catalog().find(app=>normalize(app.name)===key||normalize(app.id)===key||aliases[key]===app.id);
    if(known||query.includes('.')||query.includes('://'))return {...await this.resolve(query),query,candidates:[],index:this.index.status()};
    return this.index.lookup(query.trim());
  }
  async select(candidateId){
    const {candidate,document,fingerprint,fetchedAt}=await this.index.specification(candidateId);
    const existing=this.catalog().find(app=>app.indexIdentity?.candidateId===candidate.id||app.discovery?.url===candidate.discovery.url);
    if(existing)return {status:'resolved',app:{...existing,iconUrl:`/api/icons/${encodeURIComponent(existing.id)}`},created:false,plan:planConnection(existing,this.settings())};
    const extracted=specificationOrigins(document,candidate.discovery.kind);
    const id=`indexed-${createHash('sha256').update(candidate.id).digest('hex').slice(0,20)}`;
    // Documentation/contact references deliberately do not become browser app
    // origins. Nor does a spec establish OAuth, account identity, or API access.
    const website=candidate.website?publicMetadataUrl(candidate.website):null;
    const app={id,name:candidate.name,description:candidate.description||'Application identity found in a public API directory.',category:'Indexed applications',apiOrigins:extracted.apiOrigins,webOrigins:website?[website.origin]:[],website:website?.href||null,publisherReference:candidate.publisher?.website||candidate.documentationUrl||null,metadataLogoUrl:candidate.logoUrl||null,discovery:{kind:candidate.discovery.kind,url:candidate.discovery.url},indexIdentity:{candidateId:candidate.id,providerEntry:candidate.providerEntry,source:candidate.source,publisher:candidate.publisher,selectedAt:new Date().toISOString(),accountConnected:false},discoveryEvidence:{kind:'selected-public-specification',sourceUrl:candidate.discovery.url,specificationFingerprint:fingerprint,observedAt:fetchedAt,accountVerified:false},capabilityDiscovery:{supported:extracted.supported,dialect:extracted.dialect,gaps:extracted.gaps},limitations:['Public directory/specification identity is not an authenticated account connection.','API origins are declared by the selected specification, not live account authorization.','Documentation/contact websites are not inferred to be application sign-in pages.',...extracted.gaps]};
    this.store.put('applications',app);this.store.audit({type:'application.index-selected',appId:id,source:candidate.source.id,originCount:extracted.apiOrigins.length});
    const resolved=this.catalog().find(item=>item.id===id)||app;
    return {status:'resolved',app:{...resolved,iconUrl:`/api/icons/${id}`},created:true,plan:planConnection(resolved,this.settings()),capabilityDiscovery:app.capabilityDiscovery};
  }
  async resolve(query) {
    if(typeof query!=='string'||!query.trim()||query.length>500) throw new Error('Enter an application name or website (up to 500 characters).');
    query=query.trim();const key=normalize(query);
    const match=this.catalog().find(app=>normalize(app.name)===key||normalize(app.id)===key||aliases[key]===app.id);
    if(match) return {status:'resolved',app:{...match,iconUrl:`/api/icons/${encodeURIComponent(match.id)}`},created:false,plan:planConnection(match,this.settings())};
    if(!query.includes('.')&&!query.includes('://')) return {status:'website_required',query,app:null,message:'Enter the app’s website so Fabric can inspect the actual service. Fabric will not guess a website from an unfamiliar name.'};
    const requested=websiteUrl(query);
    const existing=this.catalog().find(app=>(app.webOrigins||app.browserOrigins||[]).includes(requested.origin));
    if(existing) return {status:'resolved',app:{...existing,iconUrl:`/api/icons/${existing.id}`},created:false,plan:planConnection(existing,this.settings())};
    const fetched=await publicGet(this.request,requested.href);
    if(typeof fetched.data!=='string'||!String(fetched.headers?.['content-type']||'').includes('text/html')) throw new Error('This address is not a web application page. Use the app’s website; API schema import is available under Advanced.');
    const finalOrigin=fetched.url.origin;
    const duplicate=this.catalog().find(app=>(app.webOrigins||app.browserOrigins||[]).includes(finalOrigin));
    if(duplicate) return {status:'resolved',app:{...duplicate,iconUrl:`/api/icons/${duplicate.id}`},created:false,plan:planConnection(duplicate,this.settings())};
    const fingerprint=createHash('sha256').update(finalOrigin).digest('hex'),id=`web-${fingerprint.slice(0,20)}`;
    const title=clean(fetched.data.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1]||fetched.url.hostname);
    const app={id,name:title||fetched.url.hostname,description:`Browser connection to ${fetched.url.hostname}. The website was reached; your account is not connected yet.`,category:'Web applications',apiOrigins:[],webOrigins:[finalOrigin],website:finalOrigin,discoveryEvidence:{kind:'public-website',requestedOrigin:requested.origin,observedOrigin:finalOrigin,observedAt:new Date().toISOString(),accountVerified:false},limitations:['Browser controls only; API and native-device support are not inferred from the website.']};
    this.store.put('applications',app);this.store.audit({type:'application.resolved',appId:id,origin:finalOrigin});
    const resolved=this.catalog().find(item=>item.id===id)||app;
    return {status:'resolved',app:{...resolved,iconUrl:`/api/icons/${id}`},created:true,plan:planConnection(resolved,this.settings())};
  }
  async icon(appId) {
    const app=this.catalog().find(item=>item.id===appId);if(!app) throw new Error('Application not found.');
    return this.cachedIcon(app);
  }
  async candidateIcon(candidateId){
    const candidate=this.index.get(candidateId);
    return this.cachedIcon({id:candidate.id,metadataLogoUrl:candidate.logoUrl,website:candidate.website,publisherReference:candidate.publisher?.website||candidate.documentationUrl});
  }
  async cachedIcon(app){
    const appId=app.id;
    const cached=this.icons.get(appId);if(cached&&cached.expires>Date.now()) return cached;
    if(this.inflight.has(appId)) return this.inflight.get(appId);
    const promise=this.iconSlot(()=>this.fetchIcon(app)).finally(()=>this.inflight.delete(appId));this.inflight.set(appId,promise);return promise;
  }
  async iconSlot(work){if(this.iconActive<3)this.iconActive++;else await new Promise(resolve=>this.iconWaiting.push(resolve));try{return await work();}finally{const next=this.iconWaiting.shift();if(next)next();else this.iconActive--;}}
  async fetchIcon(app) {
    let image;
    const deadlineMs=Date.now()+10000;
    const origin=(app.webOrigins||app.browserOrigins||[])[0];
    const load=async url=>{try{const result=await publicGet(this.request,url,{metadataUrl:true,deadlineMs,responseType:'buffer',maxBytes:128*1024,timeoutMs:3000});return rasterImage(result.data);}catch{return null;}};
    if(app.metadataLogoUrl)image=await load(app.metadataLogoUrl);
    const page=app.website||origin||app.publisherReference;
    if(!image&&page)try{
      const result=await publicGet(this.request,page,{metadataUrl:true,deadlineMs,maxBytes:128*1024,timeoutMs:3000});
      if(typeof result.data==='string'&&String(result.headers?.['content-type']||'').toLowerCase().includes('text/html'))for(const url of publisherIconLinks(result.data,result.url.href)){image=await load(url);if(image)break;}
    }catch{}
    if(!image&&page)try{image=await load(new URL('/favicon.ico',publicMetadataUrl(page)).href);}catch{}
    if(!image) image={type:'image/svg+xml',data:Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#eef2f5"/><g fill="none" stroke="#4b6474" stroke-width="3"><circle cx="32" cy="32" r="18"/><ellipse cx="32" cy="32" rx="8" ry="18"/><path d="M14 32h36M18 22h28M18 42h28"/></g></svg>')};
    const cached={...image,expires:Date.now()+60*60_000};this.icons.set(app.id,cached);while(this.icons.size>256)this.icons.delete(this.icons.keys().next().value);return cached;
  }
}
