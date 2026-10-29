import https from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP, BlockList } from 'node:net';

const forbidden4 = new BlockList();
for (const [address,prefix] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.88.99.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]]) forbidden4.addSubnet(address,prefix,'ipv4');
const global6 = new BlockList(); global6.addSubnet('2000::',3,'ipv6');
const forbidden6 = new BlockList();
for (const [address,prefix] of [['2001::',23],['2001:db8::',32],['2002::',16],['3fff::',20]]) forbidden6.addSubnet(address,prefix,'ipv6');
export function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 4) return !forbidden4.check(address,'ipv4');
  if (family === 6) return global6.check(address,'ipv6') && !forbidden6.check(address,'ipv6');
  return false;
}

// Every error thrown before the transport is called carries sent: false, set where it is thrown, so a write that
// never left the machine is reported as failed rather than uncertain. Errors after that point carry sent: true.
const notSent = message => Object.assign(new Error(message), {sent: false});
const DEFAULT_RESPONSE_HEADERS = ['content-type','etag','retry-after','x-ratelimit-remaining'];

export function createSafeRequester({ lookup = dnsLookup, transport = https.request } = {}) {
  return async function request({ url, method = 'GET', headers = {}, body, allowedOrigins, timeoutMs = 15000, maxBytes = 2 * 1024 * 1024, responseType = 'json', allowRedirectResponse = false, redirect = 'error', responseHeaders = DEFAULT_RESPONSE_HEADERS }) {
    let target;
    try { target = new URL(url); } catch { throw notSent('Invalid request URL.'); }
    if (target.protocol !== 'https:' || target.username || target.password || target.hash || (target.port && target.port !== '443')) throw notSent('Only credential-free HTTPS URLs on port 443 are allowed.');
    if (!Array.isArray(allowedOrigins) || !allowedOrigins.includes(target.origin)) throw notSent('Request origin is outside the connection grant.');
    if (!['json','buffer'].includes(responseType)) throw notSent('Unsupported response type.');
    if (!['error','report'].includes(redirect) || !Array.isArray(responseHeaders) || responseHeaders.some(name => typeof name !== 'string' || !/^[a-z0-9-]{1,64}$/.test(name))) throw notSent('Unsupported response handling.');
    const hostname = target.hostname.replace(/^\[|\]$/g, '');
    if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal')) throw notSent('Private network destinations are not allowed.');
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000 || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 10 * 1024 * 1024) throw notSent('Invalid request limits.');
    if (!/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(method)) throw notSent('Unsupported HTTP method.');
    const cleanHeaders = {};
    for (const [key,value] of Object.entries(headers)) {
      if (/^(host|connection|transfer-encoding|content-length|upgrade|proxy-.*|forwarded|x-forwarded-.*)$/i.test(key) || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(key) || typeof value !== 'string' || /[\r\n]/.test(value)) throw notSent('Unsafe request header.');
      cleanHeaders[key] = value;
    }
    if (body !== undefined && !(typeof body === 'string' || Buffer.isBuffer(body))) throw notSent('Request body must be serialized.');
    if (body !== undefined && Buffer.byteLength(body) > 1024 * 1024) throw notSent('Request body is too large.');
    const start = Date.now();
    let timer;
    let addresses;
    try {
      addresses = isIP(hostname) ? [{address:hostname,family:isIP(hostname)}] : await Promise.race([
        lookup(hostname, { all: true, verbatim: true }),
        new Promise((_,reject) => { timer = setTimeout(() => reject(new Error('timeout')), timeoutMs); }),
      ]);
    } catch { throw notSent('Provider DNS lookup failed or timed out.'); } finally { clearTimeout(timer); }
    if (!Array.isArray(addresses) || !addresses.length || addresses.some(item => !isPublicAddress(item.address))) throw notSent('Private or reserved network destinations are not allowed.');
    const pinned = addresses[0];
    return new Promise((resolve,reject) => {
      let finished = false, started = false;
      const fail = message => { if (!finished) { finished = true; clearTimeout(timer); reject(Object.assign(new Error(message), {sent: started})); } };
      let req;
      try { req = transport(target, {
        method, headers: cleanHeaders, agent: false, servername: isIP(hostname) ? undefined : hostname,
        lookup: (_name, options, callback) => { if (typeof options === 'function') { callback = options; options = {}; } callback(null, options?.all ? [pinned] : pinned.address, pinned.family); },
      }, res => {
        if (res.statusCode >= 300 && res.statusCode < 400) {
          if (redirect === 'report') {
            // Never followed. Allowlisted headers come back; a location only when the provider sent one on the same origin.
            // 304 Not Modified is an answer to a conditional request, not a redirect.
            const kept = {};
            for (const key of responseHeaders) if (key !== 'location' && res.headers[key] !== undefined) kept[key] = Array.isArray(res.headers[key]) ? res.headers[key].join(', ') : String(res.headers[key]);
            if (res.statusCode !== 304 && typeof res.headers.location === 'string' && res.headers.location) { try { const next = new URL(res.headers.location, target); if (next.origin === target.origin) kept.location = next.href; } catch {} }
            finished = true; clearTimeout(timer); resolve({status:res.statusCode,headers:kept,data:null,...(res.statusCode === 304 ? {notModified:true} : {redirected:true})});
          } else if (allowRedirectResponse && method === 'GET' && !Object.keys(cleanHeaders).some(key => /authorization|cookie|token|key/i.test(key))) {
            finished = true; clearTimeout(timer); resolve({status:res.statusCode,headers:{location:String(res.headers.location||'')},data:null});
          } else { fail('Provider redirects are not followed.'); }
          // Discovery consumes only Location. Draining the response after the
          // timer is cleared would leave an unbounded redirect body downloading.
          res.destroy(); req.destroy();
          return;
        }
        const chunks = []; let bytes = 0;
        res.on('data', chunk => { bytes += chunk.length; if (bytes > maxBytes) { fail('Provider response exceeded the size limit.'); req.destroy(); res.destroy(); } else chunks.push(chunk); });
        res.on('error', () => fail('Provider response was interrupted.'));
        res.on('end', () => {
          if (finished) return;
          finished = true; clearTimeout(timer);
          const bytes = Buffer.concat(chunks), raw = responseType === 'buffer' ? null : bytes.toString('utf8');
          let data = responseType === 'buffer' ? bytes : raw;
          if (responseType !== 'buffer') try { data = raw ? JSON.parse(raw) : null; } catch { /* Provider response can be plain text. */ }
          const kept = {};
          for (const key of responseHeaders) if (res.headers[key] !== undefined) kept[key] = Array.isArray(res.headers[key]) ? res.headers[key].join(', ') : String(res.headers[key]);
          // A Location is kept only on the request's own origin, whatever the status.
          if (kept.location !== undefined) { try { const next = new URL(kept.location, target); if (next.origin === target.origin) kept.location = next.href; else delete kept.location; } catch { delete kept.location; } }
          resolve({status:res.statusCode,headers:kept,data});
        });
      }); started = true; } catch { fail('Provider request could not be initialized.'); return; }
      timer = setTimeout(() => { fail('Provider request timed out.'); req.destroy(); }, Math.max(1, timeoutMs - (Date.now() - start)));
      req.on('error', () => fail('Provider connection failed.'));
      if (body !== undefined) req.write(body);
      req.end();
    });
  };
}
export const safeRequest = createSafeRequester();
