import {createHash} from 'node:crypto';
import {isIP} from 'node:net';
import {safeRequest} from './network.mjs';

export const INDEX_SOURCES=Object.freeze([
  Object.freeze({id:'google-discovery',name:'Google API Discovery',kind:'official-directory',url:'https://discovery.googleapis.com/discovery/v1/apis?preferred=true',maxBytes:2*1024*1024}),
  Object.freeze({id:'apis-guru',name:'APIs.guru',kind:'community-directory',url:'https://api.apis.guru/v2/list.json',maxBytes:10*1024*1024}),
]);
const TTL=24*60*60_000,MAX_ENTRIES=5000,MAX_RESULTS=30;
const hash=value=>createHash('sha256').update(value).digest('hex');
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const plain=(value,max=500)=>typeof value==='string'?value.replace(/<[^>]*>/g,' ').replace(/[\u0000-\u001f\u007f]/g,' ').replace(/\s+/g,' ').trim().slice(0,max):'';
const normalize=value=>plain(value,500).toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();

// Metadata links are evidence, not permission grants. The network layer also
// DNS-checks and pins every address before the selected link is ever fetched.
export function publicMetadataUrl(value){
  if(typeof value!=='string'||value.length>4096||/[\s\\\u0000-\u001f\u007f{}]/.test(value))throw new Error('Metadata requires a fixed public HTTPS URL.');
  let url;try{url=new URL(value);}catch{throw new Error('Metadata URL is invalid.');}
  const host=url.hostname.replace(/^\[|\]$/g,'');
  if(url.protocol!=='https:'||url.username||url.password||url.hash||(url.port&&url.port!=='443')||isIP(host)||!host.includes('.')||host.endsWith('.')||/(?:^|\.)(?:localhost|local|internal|lan|test|invalid)$/.test(host))throw new Error('Metadata URL must use public HTTPS without credentials or a private destination.');
  if([...url.searchParams.keys()].some(key=>/^(?:access_token|refresh_token|id_token|token|key|api_key|password|secret|code)$/i.test(key)))throw new Error('Credential-bearing metadata URLs are not supported.');
  return url;
}
const optionalUrl=value=>{try{return publicMetadataUrl(value).href;}catch{return null;}};
function sourceLink(value,source){
  const url=publicMetadataUrl(value);
  if(source.id==='google-discovery'&&!/^(?:[a-z0-9-]+\.)?googleapis\.com$/.test(url.hostname))throw new Error('Google discovery source is outside official Google API hosts.');
  if(source.id==='apis-guru'&&(url.origin!=='https://api.apis.guru'||!url.pathname.startsWith('/v2/specs/')||!url.pathname.endsWith('.json')))throw new Error('Directory specification must be an APIs.guru JSON specification URL.');
  return url.href;
}
function publisher(website,evidenceField,source,declaredName=''){
  let domain=null;try{domain=new URL(website).hostname;}catch{}
  if(!domain&&/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(declaredName))domain=declaredName.toLowerCase();
  return {domain,website,evidenceField,verification:source.id==='google-discovery'?'provider-published':'directory-reported'};
}
function entry(source,key,version,info){
  return {id:`idx-${source.id}-${hash(`${key}:${version}`).slice(0,20)}`,providerEntry:key,name:plain(info.name,150)||plain(key,150),description:plain(info.description,500),website:info.website||null,websiteKind:info.websiteKind||null,documentationUrl:info.documentationUrl||null,publisher:info.publisher,discovery:{kind:source.id==='google-discovery'?'google-discovery':'openapi',url:sourceLink(info.discoveryUrl,source),version:plain(version,100),dialect:info.dialect||null},logoUrl:optionalUrl(info.logoUrl),source:{id:source.id,name:source.name,kind:source.kind,url:source.url},accountConnected:false};
}
function parseDirectory(source,data){
  if(!object(data)||Buffer.byteLength(JSON.stringify(data))>source.maxBytes)throw new Error('Directory response is malformed or exceeds the bounded size.');
  const results=[];let skipped=0;
  if(source.id==='google-discovery'){
    if(data.kind!=='discovery#directoryList'||!Array.isArray(data.items)||data.items.length>MAX_ENTRIES)throw new Error('Unsupported Google directory response.');
    for(const item of data.items){try{
      if(!object(item)||item.kind!=='discovery#directoryItem'||typeof item.name!=='string'||typeof item.version!=='string'||item.name.length>100||item.version.length>100)throw new Error('Invalid Google directory item.');
      const docs=optionalUrl(item.documentationLink);
      results.push(entry(source,item.name,item.version,{name:item.title||item.name,description:item.description,documentationUrl:docs,publisher:publisher(docs,'documentationLink',source),discoveryUrl:item.discoveryRestUrl,logoUrl:item.icons?.x32||item.icons?.x16,dialect:'google-discovery-v1'}));
    }catch{skipped++;}}
  }else{
    const rows=Object.entries(data);if(rows.length>MAX_ENTRIES)throw new Error('Directory exceeds the application entry limit.');
    for(const [key,item] of rows){try{
      if(key.length>250||!object(item)||typeof item.preferred!=='string'||item.preferred.length>100||!object(item.versions)||!Object.hasOwn(item.versions,item.preferred))throw new Error('Invalid preferred API version.');
      const version=item.versions[item.preferred],info=version?.info;if(!object(version)||!object(info))throw new Error('Invalid API information.');
      const contact=optionalUrl(info.contact?.url),docs=optionalUrl(version.externalDocs?.url);
      // A contact/documentation URL is not evidence of an application's login
      // page. Only an explicitly published website field gets that designation.
      const website=optionalUrl(info['x-website']);
      results.push(entry(source,key,item.preferred,{name:info.title,description:info.description,website,websiteKind:website?'directory-published-website':null,documentationUrl:docs,publisher:publisher(website||contact||docs,website?'info.x-website':contact?'info.contact.url':docs?'externalDocs.url':'info.x-providerName',source,info['x-providerName']),discoveryUrl:version.swaggerUrl,logoUrl:info['x-logo']?.url,dialect:version.openapiVer||null}));
    }catch{skipped++;}}
  }
  const unique=new Map(results.map(item=>[item.id,item]));
  if(!unique.size)throw new Error('Directory contained no supported public application identities.');
  return {entries:[...unique.values()],skipped};
}
function score(candidate,query){
  const name=normalize(candidate.name),provider=normalize(candidate.providerEntry),joined=`${name} ${provider} ${normalize(candidate.publisher?.domain||'')}`;
  if(name===query||provider===query)return 100;
  if(name.startsWith(query)||provider.startsWith(query))return 80;
  if(name.includes(query)||provider.includes(query))return 60;
  const terms=query.split(' ').filter(Boolean);return terms.length&&terms.every(term=>joined.includes(term))?40:0;
}

export class ApplicationIndex{
  constructor({store,request=safeRequest,now=()=>Date.now(),ttlMs=TTL}={}){
    if(!Number.isInteger(ttlMs)||ttlMs<60000||ttlMs>7*TTL)throw new Error('Invalid application index cache duration.');
    Object.assign(this,{store,request,now,ttlMs});this.cache=new Map();this.inflight=new Map();this.failures=new Map();this.specInflight=new Map();
    for(const source of INDEX_SOURCES){const saved=store?.get?.('applicationIndexes',source.id);if(saved?.sourceUrl===source.url&&Array.isArray(saved.entries)&&saved.entries.length<=MAX_ENTRIES)this.cache.set(source.id,saved);}
  }
  status(){
    const sources=INDEX_SOURCES.map(source=>{const cache=this.cache.get(source.id),failure=this.failures.get(source.id),stale=!cache||Date.parse(cache.expiresAt)<=this.now();return {id:source.id,name:source.name,kind:source.kind,url:source.url,status:cache?(stale?'stale':'ready'):'unavailable',fetchedAt:cache?.fetchedAt||null,count:cache?.entries.length||0,skipped:cache?.skipped||0,...(failure?{error:failure.message}:{}),stale};});
    return {sources,stale:sources.some(source=>source.stale),accountAuthority:false};
  }
  async sync({force=false}={}){
    await Promise.all(INDEX_SOURCES.map(async source=>{
      const cache=this.cache.get(source.id),failure=this.failures.get(source.id);
      if(!force&&cache&&Date.parse(cache.expiresAt)>this.now()||!force&&failure&&failure.retryAt>this.now())return;
      if(this.inflight.has(source.id))return this.inflight.get(source.id);
      const promise=(async()=>{try{
        const url=new URL(source.url),response=await this.request({url:url.href,method:'GET',headers:{Accept:'application/json'},allowedOrigins:[url.origin],timeoutMs:30000,maxBytes:source.maxBytes});
        if(response.status!==200)throw new Error(`Directory returned HTTP ${response.status}.`);
        const parsed=parseDirectory(source,response.data),fetchedAt=new Date(this.now()).toISOString();
        const record={id:source.id,sourceUrl:source.url,fetchedAt,expiresAt:new Date(this.now()+this.ttlMs).toISOString(),...parsed};
        this.store?.put?.('applicationIndexes',record);this.cache.set(source.id,record);this.failures.delete(source.id);
      }catch(cause){this.failures.set(source.id,{message:/^Directory |^Unsupported Google|^Invalid |^Metadata |^Google discovery|^Provider /.test(cause.message)?String(cause.message).slice(0,160):'Public directory could not be refreshed. Cached identities, if any, remain available.',retryAt:this.now()+5*60_000});}})().finally(()=>this.inflight.delete(source.id));
      this.inflight.set(source.id,promise);return promise;
    }));return this.status();
  }
  candidates(query,{limit=MAX_RESULTS}={}){
    if(typeof query!=='string'||!query.trim()||query.length>500)throw new Error('Enter an application search up to 500 characters.');
    if(!Number.isInteger(limit)||limit<1||limit>MAX_RESULTS)throw new Error('Invalid candidate result limit.');
    const normalized=normalize(query);if(!normalized)return [];
    return [...this.cache.values()].flatMap(cache=>cache.entries.map(candidate=>({...candidate,source:{...candidate.source,fetchedAt:cache.fetchedAt},indexStale:Date.parse(cache.expiresAt)<=this.now()}))).map(candidate=>({candidate,score:score(candidate,normalized)})).filter(item=>item.score>0).sort((a,b)=>b.score-a.score||a.candidate.name.localeCompare(b.candidate.name)||a.candidate.id.localeCompare(b.candidate.id)).slice(0,limit).map(({candidate})=>this.publicCandidate(candidate));
  }
  get(id){
    if(typeof id!=='string'||!/^idx-(?:google-discovery|apis-guru)-[a-f0-9]{20}$/.test(id))throw new Error('Choose an application from the indexed search results.');
    for(const cache of this.cache.values()){const candidate=cache.entries.find(item=>item.id===id);if(candidate)return {...candidate,source:{...candidate.source,fetchedAt:cache.fetchedAt},indexStale:Date.parse(cache.expiresAt)<=this.now()};}
    throw new Error('This indexed application is unavailable. Search again to refresh the identity.');
  }
  publicCandidate(candidate){const {logoUrl,...publicFields}=candidate;return {...publicFields,iconUrl:`/api/catalog/icons/${encodeURIComponent(candidate.id)}`};}
  async lookup(query){if(typeof query!=='string'||!query.trim()||query.length>500)throw new Error('Enter an application search up to 500 characters.');await this.sync();const candidates=this.candidates(query);return {status:candidates.length?'candidates':'not_found',query,candidates,index:this.status(),ambiguous:candidates.length>1,message:candidates.length?'Choose the application identity and source. A directory match is not an account connection.':'No match in the available public directories. Supply the exact application website; no domain was guessed.'};}
  async specification(candidateId){
    if(this.specInflight.has(candidateId))return this.specInflight.get(candidateId);
    const candidate=this.get(candidateId),source=INDEX_SOURCES.find(item=>item.id===candidate.source.id),url=new URL(sourceLink(candidate.discovery.url,source));
    const saved=this.store?.get?.('applicationIndexSpecs',candidateId);if(saved?.sourceUrl===url.href&&Date.parse(saved.expiresAt)>this.now())return {candidate,document:saved.document,fingerprint:saved.fingerprint,fetchedAt:saved.fetchedAt};
    const promise=(async()=>{
      const response=await this.request({url:url.href,method:'GET',headers:{Accept:'application/json'},allowedOrigins:[url.origin],timeoutMs:30000,maxBytes:2*1024*1024});
      if(response.status!==200||!object(response.data))throw new Error('The chosen public specification did not return a JSON object.');
      const raw=JSON.stringify(response.data);if(Buffer.byteLength(raw)>2*1024*1024)throw new Error('Chosen specification exceeds the 2 MB inspection limit.');
      const document=response.data;
      if(source.id==='google-discovery'&&(document.kind!=='discovery#restDescription'||document.protocol!=='rest'||document.name!==candidate.providerEntry||document.version!==candidate.discovery.version))throw new Error('The Google specification does not match the selected application and version.');
      if(source.id==='apis-guru'&&!/^3\.(?:0|1|2)\.\d+$/.test(document.openapi||'')&&document.swagger!=='2.0')throw new Error('The chosen specification is not supported OpenAPI or Swagger JSON.');
      const fingerprint=hash(raw),fetchedAt=new Date(this.now()).toISOString();
      this.store?.put?.('applicationIndexSpecs',{id:candidateId,sourceUrl:url.href,document,fingerprint,fetchedAt,expiresAt:new Date(this.now()+this.ttlMs).toISOString()});
      return {candidate,document,fingerprint,fetchedAt};
    })().finally(()=>this.specInflight.delete(candidateId));this.specInflight.set(candidateId,promise);return promise;
  }
}

// A selected spec may declare transport destinations. These are metadata only;
// no credential, account, capability activation or network request is granted.
export function specificationOrigins(document,kind){
  const urls=[],gaps=[];let dialect;
  if(kind==='google-discovery'){
    dialect='google-discovery';const value=document.baseUrl||(typeof document.rootUrl==='string'&&typeof document.servicePath==='string'?document.rootUrl+document.servicePath:null);if(value)urls.push(value);
  }else if(document.swagger==='2.0'){
    dialect='swagger-2';if(typeof document.host==='string'&&Array.isArray(document.schemes)&&document.schemes.includes('https'))urls.push(`https://${document.host}${document.basePath||'/'}`);gaps.push('Swagger/OpenAPI 2 is indexed, but automatic function discovery currently supports OpenAPI 3 only.');
  }else{
    dialect='openapi-3';const add=servers=>{if(servers!==undefined&&!Array.isArray(servers))throw new Error('Specification servers must be an array.');for(const server of servers||[]){if(urls.length>=50)throw new Error('Specification declares too many API servers.');if(typeof server?.url==='string')urls.push(server.url);}};
    add(document.servers);for(const path of Object.values(object(document.paths)?document.paths:{})){if(!object(path))continue;add(path.servers);for(const [method,operation]of Object.entries(path))if(['get','head','post','put','patch','delete','options'].includes(method)&&object(operation))add(operation.servers);}
  }
  const origins=new Set();for(const value of urls){try{const url=publicMetadataUrl(value);if(url.search)throw new Error('Query not supported');origins.add(url.origin);}catch{gaps.push('A relative, templated, private, or otherwise unsupported API server was not adopted.');}}
  if(!origins.size)gaps.push('No fixed public HTTPS API origin was declared by this specification.');
  return {apiOrigins:[...origins],dialect,supported:origins.size>0&&dialect!=='swagger-2',gaps:[...new Set(gaps)]};
}
