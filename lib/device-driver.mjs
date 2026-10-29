import os from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {access, stat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {canonicalHash, validateInput} from './compiler.mjs';

const runFile = promisify(execFile);
const MAX_OUTPUT_BYTES = 512 * 1024;
const COMMAND_TIMEOUT_MS = 6000;
const EMPTY_INPUT = {type:'object', properties:{}, additionalProperties:false};
const clean = value => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 180) : undefined;
const freeze = value => {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
};

// These reviewed definitions are executable authority. Neither agent-supplied
// code nor a command from an imported capability is ever dispatched here.
export const deviceCapabilities = freeze([
  {id:'local-device.system.v1', name:'Read computer overview', action:{op:'system'}, description:'Read the operating system, architecture, processor count, memory capacity, and uptime. Does not read your files or account names.'},
  {id:'local-device.usb.v1', name:'List attached USB devices', action:{op:'usb'}, description:'Read USB device names, manufacturers, and product types on this Mac. Serial numbers and location identifiers are excluded. This does not control devices.'},
  {id:'local-device.tools.v1', name:'Find supported installed command-line tools', action:{op:'tools'}, description:'Check a fixed list of tools in standard installation folders. Does not run those tools, inspect their accounts, or connect to their services.'},
].map(capability => ({specVersion:'fabric/0.1', version:1, appId:'local-device', driver:'device', status:'active', effect:'read', inputSchema:structuredClone(EMPTY_INPUT), provenance:{kind:'builtin', source:'reviewed local device driver v1'}, verification:{kind:'local-observation'}, ...capability})));
const expectedHashes = new Map(deviceCapabilities.map(capability => [capability.id, canonicalHash(capability)]));

export function validateDeviceCapability(capability) {
  if (!capability || !expectedHashes.has(capability.id) || canonicalHash(capability) !== expectedHashes.get(capability.id)) {
    throw new Error('Only unchanged, built-in local device capabilities can execute.');
  }
  return capability;
}

const CLI_NAMES = Object.freeze(['git', 'gh', 'node', 'python3', 'docker', 'ffmpeg']);
const CLI_DIRECTORIES = Object.freeze(['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin']);

function usbInventory(document) {
  if (!document || !Array.isArray(document.SPUSBDataType)) throw new Error('The local USB report was not in the expected format.');
  const devices = [];
  let visited = 0;
  let truncated = false;
  const walk = (items, depth = 0) => {
    for (const item of items) {
      if (++visited > 500 || depth > 12) { truncated = true; return; }
      if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
      // Never spread the provider object: system_profiler can include serials,
      // host-controller addresses, volume names, and other identifying data.
      const name = clean(item._name);
      if (name) devices.push(Object.fromEntries(Object.entries({
        name,
        manufacturer:clean(item.manufacturer),
        vendorId:clean(item.vendor_id),
        productId:clean(item.product_id),
        speed:clean(item.device_speed || item.speed),
        kind:item.host_controller ? 'controller' : 'device',
      }).filter(([, value]) => value !== undefined)));
      if (Array.isArray(item._items)) walk(item._items, depth + 1);
      if (visited > 500) return;
    }
  };
  walk(document.SPUSBDataType);
  return {devices, count:devices.length, truncated, excluded:['serial numbers', 'location identifiers', 'volume information'], readOnly:true};
}

export class DeviceDriver {
  // Dependencies are host construction options for deterministic tests, never
  // accepted from an HTTP request, generated tool, or connection record.
  constructor({system = os, executeFile = runFile, fileAccess = access, fileStat = stat} = {}) {
    Object.assign(this, {system, executeFile, fileAccess, fileStat});
  }

  async init() {
    return {platform:this.system.platform(), capabilities:deviceCapabilities.filter(capability => capability.action.op !== 'usb' || this.system.platform() === 'darwin').map(capability => capability.id)};
  }

  connect() {
    const id = randomUUID();
    const timestamp = new Date().toISOString();
    // An opaque connection identity avoids reading hardware UUIDs or serials.
    // The parent persists this record only after the user chooses Connect.
    return {id, appId:'local-device', driver:'device', label:this.system.platform() === 'darwin' ? 'This Mac' : 'This computer', status:'ready', identity:{id, displayName:this.system.platform() === 'darwin' ? 'This Mac' : 'This computer', platform:this.system.platform(), architecture:this.system.arch()}, authMethod:'local-consent', authRevision:randomUUID(), allowedOrigins:[], createdAt:timestamp, updatedAt:timestamp, lastCheckedAt:timestamp};
  }

  async execute(capability, args = {}, authorize = () => {}) {
    validateDeviceCapability(capability);
    validateInput(capability.inputSchema, args);
    authorize();
    let data;
    if (capability.action.op === 'system') {
      data = {};
      const unavailableFields = [];
      const observations = {platform:()=>this.system.platform(), operatingSystem:()=>this.system.type(), release:()=>this.system.release(), architecture:()=>this.system.arch(), logicalProcessors:()=>this.system.cpus().length, totalMemoryBytes:()=>this.system.totalmem(), uptimeSeconds:()=>Math.floor(this.system.uptime())};
      for (const [field, observe] of Object.entries(observations)) {
        try { data[field] = observe(); } catch { unavailableFields.push(field); }
      }
      if (unavailableFields.length) data.unavailableFields = unavailableFields;
      data.readOnly = true;
    } else if (capability.action.op === 'usb') {
      if (this.system.platform() !== 'darwin') throw new Error('USB inventory currently supports macOS only. No device command was run.');
      let output;
      try {
        output = await this.executeFile('/usr/sbin/system_profiler', ['SPUSBDataType', '-json', '-detailLevel', 'mini'], {shell:false, timeout:COMMAND_TIMEOUT_MS, maxBuffer:MAX_OUTPUT_BYTES, killSignal:'SIGKILL', encoding:'utf8', windowsHide:true, env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin', LANG:'C', LC_ALL:'C'}});
      } catch {
        // Subprocess failures can carry the entire private report in stderr.
        throw new Error('Could not read USB devices within the local command time/output limits. No device settings were changed.');
      }
      authorize();
      if (typeof output?.stdout !== 'string' || Buffer.byteLength(output.stdout) > MAX_OUTPUT_BYTES) throw new Error('The local USB report exceeded its output limit.');
      let parsed;
      try { parsed = JSON.parse(output.stdout); } catch { throw new Error('The local USB report was not valid JSON.'); }
      data = usbInventory(parsed);
    } else if (capability.action.op === 'tools') {
      const tools = [];
      for (const name of CLI_NAMES) {
        for (const directory of CLI_DIRECTORIES) {
          authorize();
          const executablePath = `${directory}/${name}`;
          try {
            const file = await this.fileStat(executablePath);
            if (!file.isFile()) continue;
            await this.fileAccess(executablePath, constants.X_OK);
          } catch { continue; }
          tools.push({name, executablePath, executable:true, accountConnected:false, runnableByFabric:false});
          break;
        }
      }
      data = {tools, count:tools.length, checkedNames:[...CLI_NAMES], readOnly:true, note:'Found on this computer. No command was run and no service account was inspected or connected.'};
    }
    authorize();
    return {data, verification:{status:'observed', kind:'local-device-observation', checkedAt:new Date().toISOString()}};
  }
}
