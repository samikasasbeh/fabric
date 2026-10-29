// F03.7d (docs/F03.7-BUILD-MAP.md slice 4): option sources as reviewed data (catalog/options/<appId>.json). A source
// says which inputs it fills (calendarId, labelIds), which reviewed read operation lists the choices, in which read row
// that operation sits, and where in the answer the value and label are. Kept outside the capability, whose shape is
// closed and whose id hashes its content. Loaded and checked once; an invalid file stops the process at start.
import {readdirSync, readFileSync} from 'node:fs';
import {PERMISSION_GROUPS} from './permission-groups.mjs';

const NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/, POINTER = /^(\/[A-Za-z0-9_.~-]{1,64}){1,6}$/;
const KEYS = 'appId,reviewed,schemaVersion,sources', SOURCE_KEYS = 'args,id,items,label,maxItems,operation,pageToken,row,serves,value';

/** Checks one app's option sources against its reviewed permission rows. */
export function validateOptionSources(file, groups = PERMISSION_GROUPS) {
  const fail = message => { throw new Error(`Option sources for ${file?.appId}: ${message}`); };
  if (!file || Object.keys(file).sort().join() !== KEYS || file.schemaVersion !== 1 || typeof file.reviewed !== 'string') fail('exactly appId, reviewed, schemaVersion 1 and sources.');
  const definition = groups.get(file.appId);
  if (!definition) fail('the app has no reviewed permission rows.');
  if (!Array.isArray(file.sources) || !file.sources.length || file.sources.length > 20) fail('1 to 20 sources.');
  const served = new Set();
  return Object.freeze(file.sources.map(source => {
    if (!source || Object.keys(source).sort().join() !== SOURCE_KEYS || !NAME.test(source.id)) fail('each source has exactly the documented fields.');
    const row = definition.groups.find(group => group.id === source.row);
    // The list is a read, in the row the source names: options can never run a change or leave the person's rows.
    if (!row || row.effect !== 'read' || !row.operations.includes(source.operation)) fail(`${source.id}: ${source.operation} must be an operation of the read row ${source.row}.`);
    if (!Array.isArray(source.serves) || !source.serves.length || source.serves.some(name => !NAME.test(name) || served.has(name))) fail(`${source.id}: serves names inputs, each served once per app.`);
    source.serves.forEach(name => served.add(name));
    if (!source.args || typeof source.args !== 'object' || Array.isArray(source.args) || Object.entries(source.args).some(([name, value]) => !NAME.test(name) || typeof value !== 'string')) fail(`${source.id}: args are fixed strings.`);
    if (!POINTER.test(source.items) || !POINTER.test(source.value) || !Array.isArray(source.label) || !source.label.length || source.label.some(pointer => !POINTER.test(pointer))) fail(`${source.id}: items, value and label are JSON pointers.`);
    if (source.pageToken !== null && (!source.pageToken || !POINTER.test(source.pageToken.response) || !NAME.test(source.pageToken.parameter) || Object.keys(source.pageToken).sort().join() !== 'parameter,response')) fail(`${source.id}: pageToken is null or {response, parameter}.`);
    if (!Number.isSafeInteger(source.maxItems) || source.maxItems < 1 || source.maxItems > 1000) fail(`${source.id}: maxItems is 1 to 1000.`);
    return Object.freeze({...source, serves: Object.freeze([...source.serves]), label: Object.freeze([...source.label]), args: Object.freeze({...source.args})});
  }));
}

const DIR = new URL('../catalog/options/', import.meta.url);
/** appId to its reviewed option sources. GitHub, Slack and Notion have none until their reviewed list reads exist (P14). */
export const OPTION_SOURCES = new Map(readdirSync(DIR).filter(name => name.endsWith('.json')).map(name => {
  const file = JSON.parse(readFileSync(new URL(name, DIR), 'utf8'));
  if (`${file.appId}.json` !== name) throw new Error(`catalog/options/${name} must hold the sources of ${name.slice(0, -5)}.`);
  return [file.appId, validateOptionSources(file)];
}));
/** The source that fills one input of an app, or null. */
export function sourceFor(appId, input) { return (OPTION_SOURCES.get(appId) || []).find(source => source.serves.includes(input)) ?? null; }
