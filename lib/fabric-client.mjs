import {randomUUID} from 'node:crypto';

// Every call result carries Fabric's card for that call. Render it for a chat surface with these;
// pass the Fabric origin you trust, and each renderer refuses a card Fabric could not have built.
export {renderCard, validateCard, cardText, toMarkdown as cardMarkdown, toSlack as cardSlack, toTeams as cardTeams} from './cards.mjs';

/** Small client for the experimental Fabric protocol. Operator provisions grants;
 * consumers still use the normal Connect flow, never this developer credential. */
export class FabricClient {
  constructor({endpoint, token, fetch: request = globalThis.fetch}) {
    const url = new URL(endpoint);
    if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === '127.0.0.1')) || url.username || url.password || url.search || url.hash) throw new Error('Use an HTTPS Fabric endpoint or explicit 127.0.0.1 development endpoint.');
    if (typeof token !== 'string' || !token.startsWith('fab_client.')) throw new Error('A scoped Fabric client grant is required.');
    this.endpoint = url.href; this.token = token; this.request = request;
  }
  async call(method, params = {}, {requestId = randomUUID(), signal = AbortSignal.timeout(45000)} = {}) {
    const response = await this.request(this.endpoint, {method: 'POST', redirect: 'error', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${this.token}`}, body: JSON.stringify({protocol: 'fabric/0.1', id: requestId, method, params}), signal});
    const envelope = await response.json();
    if (envelope.protocol !== 'fabric/0.1' || (envelope.id !== requestId && !(envelope.id === null && envelope.error))) throw new Error('Unexpected Fabric protocol response.');
    if (envelope.error) {const error = new Error(envelope.error.message); error.code = envelope.error.code; throw error;}
    if (!response.ok || !Object.hasOwn(envelope, 'result')) throw new Error('Fabric request failed.');
    return envelope.result;
  }
  discover() {return this.call('fabric.discover');}
  capabilities() {return this.call('capabilities.list');}
  /**
   * Send exactly one of connectionId (a granted account) or appId (ask the owner for access).
   * @param {{connectionId?: string, appId?: string, capabilityId: string, definitionHash: string, args?: Record<string, unknown>, task?: {title: string}}} input
   * @param {{requestId?: string, signal?: AbortSignal}} [options]
   */
  invoke({connectionId, appId, capabilityId, definitionHash, args = {}, task}, options) {
    if ((connectionId === undefined) === (appId === undefined)) {const error = new Error('Send exactly one of connectionId or appId.'); error.code = 'invalid_request'; return Promise.reject(error);}
    return this.call('calls.create', {...(appId === undefined ? {connectionId} : {appId}), capabilityId, definitionHash, args, ...(task === undefined ? {} : {task})}, options);
  }
  /**
   * A governed proxy request on one granted account (F08.0d).
   * @param {{connectionId: string, request: {method: string, path: string, query?: Record<string, unknown>, headers?: Record<string, string>, body?: unknown}, timeoutMs?: number, task?: {title: string}}} input
   * @param {{requestId?: string, signal?: AbortSignal}} [options]
   */
  proxy({connectionId, request, timeoutMs, task}, options) {
    return this.call('proxy.request', {connectionId, request, ...(timeoutMs === undefined ? {} : {timeoutMs}), ...(task === undefined ? {} : {task})}, options);
  }

  getCall(callId) {return this.call('calls.get', {callId});}
  /** Withdraws an account request that the owner has not acted on yet. */
  cancelCall(callId) {return this.call('calls.cancel', {callId});}

  /**
   * The triggers on offer, and this client's own watches with their health.
   * @param {{signal?: AbortSignal}} [options]
   */
  triggers(options) {return this.call('triggers.list', {}, options);}
  /**
   * Asks the owner for one watch. It reads nothing until the owner approves it. The same trigger, account and args return the record this client already holds.
   * @param {{triggerId: string, connectionId: string, args?: Record<string, unknown>, task?: {title: string}}} input
   * @param {{requestId?: string, signal?: AbortSignal}} [options]
   */
  subscribe({triggerId, connectionId, args = {}, task}, options) {
    return this.call('triggers.subscribe', {triggerId, connectionId, args, ...(task === undefined ? {} : {task})}, options);
  }
  /**
   * What this client's watches found, oldest first. Fabric keeps no read position: send the last answer's `next` as `after`.
   * @param {{after?: number, limit?: number, waitSeconds?: number}} [input]
   * @param {{signal?: AbortSignal}} [options]
   */
  events({after, limit, waitSeconds} = {}, options) {
    return this.call('events.list', {...(after === undefined ? {} : {after}), ...(limit === undefined ? {} : {limit}), ...(waitSeconds === undefined ? {} : {waitSeconds})}, options);
  }
  /**
   * Removes this client's own watch and its events. Asking twice answers the same record.
   * @param {string} subscriptionId
   * @param {{signal?: AbortSignal}} [options]
   */
  unsubscribe(subscriptionId, options) {return this.call('triggers.unsubscribe', {subscriptionId}, options);}
}
