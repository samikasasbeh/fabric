import {visible, hasHidden} from '../public/hosted-text.js';
import {operationLabel} from './ui-contracts.mjs';

// In-chat cards (UI-3, docs/UI-3-CARDS.md). A card is a pointer to Fabric, never a decision:
// Fabric builds it from the call's stored state, its only button opens Fabric's own page for
// that exact call, and the owner decides there. One card renders to plain text, Markdown,
// Slack Block Kit and a Teams Adaptive Card, so every chat surface says the same thing.
export const CARD_SCHEMA = 'fabric.card/1';
export const CARD_STATES = Object.freeze(['awaiting_owner', 'signing_in', 'awaiting_confirmation', 'continuing', 'awaiting_approval', 'queued', 'running', 'succeeded', 'failed', 'uncertain', 'cancelled', 'expired', 'closed']);
const OUTCOMES = new Set(['owner_declined', 'client_cancelled', 'client_revoked', 'continuation_expired', 'authority_changed', 'capability_retired', 'policy_denied', 'fabric_failed']);
const ACCOUNT = new Set(['awaiting_owner', 'signing_in', 'awaiting_confirmation']);
const KEYS = 'actions,app,callId,expiresAt,id,kind,operation,outcome,requester,schema,state,summary,text,updatedAt';
const CALL_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const APP_ID = /^[a-z][a-z0-9-]{0,63}$/;
const LINK_GONE = 'Ask the account owner to open Fabric.';

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const canonical = value => typeof value === 'string' && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;
function invalid() {const error = new Error('This is not a valid Fabric card.'); error.code = 'invalid_card'; throw error;}

/** Which card a call state is: an account request, an approval request, or a status line. */
export function kindOf(state) {return ACCOUNT.has(state) ? 'account_request' : state === 'awaiting_approval' ? 'approval_request' : 'status';}

const chars = value => Array.from(value).length;
/** One line of display text: whitespace collapsed, invisible or direction-changing characters shown as markers,
 *  capped by characters (never inside a surrogate pair or a marker). */
function line(value, max, fallback) {
  const raw = typeof value === 'string' && value.trim() ? visible(value.replace(/[\t\n\r ]+/g, ' ').trim()) : fallback;
  const all = Array.from(raw);
  if (all.length <= max) return raw;
  let cut = all.slice(0, max - 1).join('');
  if (cut.lastIndexOf('⟦') > cut.lastIndexOf('⟧')) cut = cut.slice(0, cut.lastIndexOf('⟦'));
  return `${cut}…`;
}

/** The exact Fabric page a card may open: /continue/<handoff> or /approve/<call>, on the trusted origin only. */
export function cardUrl(origin, kind, id) {
  let base;
  try {
    const url = new URL(origin);
    const loopback = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !loopback) || url.username || url.password) return null;
    base = url.origin;
  } catch {return null;}
  if (typeof id !== 'string' || !UUID.test(id)) return null;
  if (kind === 'account_request') return `${base}/continue/${id}`;
  if (kind === 'approval_request') return `${base}/approve/${id}`;
  return null;
}

const CLOSED = {owner_declined: 'Not done: the account owner declined.', client_cancelled: 'Not done: the request was withdrawn.', client_revoked: 'Not done: this agent\'s access was revoked.',
  continuation_expired: 'Not done: the link expired before an account was chosen.', authority_changed: 'Not done: the operation or its permissions changed.',
  capability_retired: 'Not done: the operation is no longer available.', policy_denied: 'Not done: the chosen account may not run this operation.', fabric_failed: 'Not done: Fabric could not continue.'};

/** Fabric's fixed sentence for a state. Never result data, never agent text. A reviewed action whose reads already ran waits with its exact
 *  request prepared (F10.11 part j), so its sentence says so instead of "Nothing has run yet." */
function summaryFor(state, outcome, effect, app, {lapsed = false, linked = true, prepared = false} = {}) {
  const pending = ACCOUNT.has(state) || state === 'awaiting_approval';
  if (pending && lapsed) return 'The link expired. Nothing has run.';
  const sentence = {
    awaiting_owner: `Waiting for the account owner to connect ${app}. Nothing has run yet.`,
    signing_in: `The account owner is connecting ${app}. Nothing has run yet.`,
    awaiting_confirmation: `The account owner is connecting ${app}. Nothing has run yet.`,
    continuing: `${app} is connected. Fabric is continuing this request.`,
    awaiting_approval: prepared ? 'Fabric prepared the exact request. Waiting for approval in Fabric.' : 'Waiting for approval in Fabric. Nothing has run yet.',
    queued: `Running in ${app}.`, running: `Running in ${app}.`,
    succeeded: effect === 'read' ? `Read from ${app}.` : `Done in ${app}.`,
    uncertain: `Sent to ${app}; the result could not be confirmed. Check before trying again.`,
    failed: `Did not complete in ${app}.`,
    cancelled: 'Not done: declined or withdrawn in Fabric.',
    expired: 'Not done: the request expired before anyone acted.',
  }[state] ?? (CLOSED[outcome] || 'Not done: the account request closed.');
  return pending && !linked ? `${sentence} ${LINK_GONE}` : sentence;
}

function actionLabel(state, app) {
  if (state === 'awaiting_approval') return 'Approve or decline';
  if (state === 'awaiting_owner') return `Connect ${app}`.length <= 30 ? `Connect ${app}` : 'Connect account';
  return 'Continue in Fabric';
}

const stamp = iso => `${iso.slice(0, 16).replace('T', ' ')} UTC`;
/** True when a pending card's link has expired: nothing can be approved or chosen from it any more. */
export function lapsed(card) {return card.kind !== 'status' && !card.actions.length && card.summary === summaryFor(card.state, card.outcome, card.operation.effect, card.app.name, {lapsed: true});}

/** What a card shows at a given moment: once its link has expired, no button and a sentence that says so. */
function present(card, now) {
  if (now === undefined || !card.actions.length || Date.parse(card.expiresAt) > now) return {summary: card.summary, actions: card.actions};
  return {summary: summaryFor(card.state, card.outcome, card.operation.effect, card.app.name, {lapsed: true}), actions: []};
}

/** The card's sentence: who asked, which app, which operation. */
export function headline(card) {return `${card.requester.name} asked to use ${card.app.name}: ${card.operation.name}.`;}

/** Plain text, also the notification and screen-reader line. Pass now to drop a link that has expired since. */
export function toText(card, {now} = {}) {
  const {summary, actions: [action]} = present(card, now);
  return `${headline(card)} ${summary}${action ? ` ${action.label}: ${action.url} (expires ${stamp(card.expiresAt)})` : ''}`;
}

/**
 * Builds the agent's card for one call from Fabric's own client view of it (which already excludes
 * account identity, scopes, digests and previews) plus reviewed names. Fabric calls this; nothing
 * on the card comes from model text or call arguments.
 */
export function callCard(view, {requesterName, appId = null, appName, operationName, effect, origin, now = Date.now()} = {}) {
  const handoff = record(view?.handoff) ? view.handoff : null;
  const state = handoff && handoff.state !== 'connected' ? handoff.state : view.status;
  if (!CARD_STATES.includes(state) || typeof view.id !== 'string' || !CALL_ID.test(view.id)) invalid();
  const kind = kindOf(state), callId = handoff && typeof view.resumedCallId === 'string' ? view.resumedCallId : view.id;
  const app = {id: typeof appId === 'string' && APP_ID.test(appId) ? appId : null, name: line(appName, 64, 'the app')};
  const opEffect = ['read', 'write', 'delete'].includes(effect) ? effect : 'write';
  const pointer = kind === 'account_request' ? {url: handoff.url, expiresAt: handoff.expiresAt, id: view.id} : kind === 'approval_request' && record(view.approval) ? {url: view.approval.url, expiresAt: view.approval.expiresAt, id: callId} : null;
  const expiresAt = pointer && canonical(pointer.expiresAt) ? pointer.expiresAt : null;
  const exact = pointer && pointer.url !== null && pointer.url === cardUrl(origin, kind, pointer.id);
  const lapsed = Boolean(expiresAt) && Date.parse(expiresAt) <= now;
  const actions = exact && expiresAt && !lapsed ? [{type: 'open_url', role: 'primary', label: actionLabel(state, app.name), url: pointer.url}] : [];
  const outcome = state === 'closed' && OUTCOMES.has(handoff?.outcome) ? handoff.outcome : null;
  const card = {schema: CARD_SCHEMA, kind, id: view.id, callId, state, outcome,
    requester: {name: line(requesterName, 80, 'An agent')}, app,
    operation: {name: line(operationLabel(operationName), 80, 'An operation').replace(/[.\s]+$/, '') || 'An operation', effect: opEffect},
    summary: summaryFor(state, outcome, opEffect, app.name, {lapsed, linked: actions.length > 0 || lapsed, prepared: state === 'awaiting_approval' && view.approval?.prepared === true}),
    expiresAt: kind === 'status' ? null : expiresAt, actions, updatedAt: canonical(view.updatedAt) ? view.updatedAt : new Date(now).toISOString()};
  card.text = toText(card);
  return validateCard(card, {origin});
}

/**
 * Accepts only a card Fabric could have built: closed keys, a known state and outcome, Fabric's own
 * fixed sentences, and an action that opens exactly this call's page on the trusted origin.
 * Throws invalid_card otherwise; renderers never draw an unchecked card.
 */
export function validateCard(card, {origin} = {}) {
  if (!record(card) || Object.keys(card).sort().join() !== KEYS || card.schema !== CARD_SCHEMA) invalid();
  if (!CARD_STATES.includes(card.state) || card.kind !== kindOf(card.state)) invalid();
  if (typeof card.id !== 'string' || !CALL_ID.test(card.id) || typeof card.callId !== 'string' || !CALL_ID.test(card.callId)) invalid();
  if (card.state === 'closed' ? !(card.outcome === null || OUTCOMES.has(card.outcome)) : card.outcome !== null) invalid();
  const {requester, app, operation} = card;
  const shown = (value, max) => typeof value === 'string' && value.length > 0 && value.isWellFormed() && chars(value) <= max && !hasHidden(value);
  if (!record(requester) || Object.keys(requester).join() !== 'name' || !shown(requester.name, 80)) invalid();
  if (!record(app) || Object.keys(app).sort().join() !== 'id,name' || !(app.id === null || (typeof app.id === 'string' && APP_ID.test(app.id))) || !shown(app.name, 64)) invalid();
  if (!record(operation) || Object.keys(operation).sort().join() !== 'effect,name' || !shown(operation.name, 80) || !['read', 'write', 'delete'].includes(operation.effect)) invalid();
  if (!canonical(card.updatedAt)) invalid();
  if (card.kind === 'status' ? card.expiresAt !== null : !(card.expiresAt === null || canonical(card.expiresAt))) invalid();
  if (!Array.isArray(card.actions) || card.actions.length > 1 || (card.kind === 'status' && card.actions.length)) invalid();
  for (const action of card.actions) {
    if (!record(action) || Object.keys(action).sort().join() !== 'label,role,type,url' || action.type !== 'open_url' || action.role !== 'primary') invalid();
    if (action.label !== actionLabel(card.state, app.name) || card.expiresAt === null) invalid();
    if (action.url !== cardUrl(origin, card.kind, card.kind === 'account_request' ? card.id : card.callId)) invalid();
  }
  const linked = card.actions.length > 0;
  const allowed = [summaryFor(card.state, card.outcome, operation.effect, app.name, {linked}), summaryFor(card.state, card.outcome, operation.effect, app.name, {lapsed: true}),
    ...(card.state === 'awaiting_approval' ? [summaryFor(card.state, card.outcome, operation.effect, app.name, {linked, prepared: true})] : [])];
  if (!allowed.includes(card.summary)) invalid();
  if (typeof card.text !== 'string' || !card.text.isWellFormed() || card.text !== toText(card)) invalid();
  return card;
}

// ---- renderers ------------------------------------------------------------------------
// Every renderer validates first, writes names only as plain text, never adds a callback, a
// confirm dialog or a colored button, and drops the link once the card has expired.

/** Slack chat.postMessage / chat.update body. Buttons are url buttons only: a click opens Fabric and changes nothing. */
export function toSlack(card, {origin, now = Date.now()} = {}) {
  validateCard(card, {origin});
  const esc = value => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const {summary, actions} = present(card, now);
  const block = part => `fabric.${card.id}.${part}`.slice(0, 255);
  const span = (text, bold = false) => ({type: 'text', text, ...(bold ? {style: {bold: true}} : {})});
  // Names and sentences go in rich_text and plain_text, which Slack never parses for formatting or links;
  // only Fabric's own date token and host use mrkdwn.
  return {text: esc(toText(card, {now})), unfurl_links: false, unfurl_media: false, blocks: [
    {type: 'rich_text', block_id: block('h'), elements: [{type: 'rich_text_section', elements: [span(card.requester.name, true), span(' asked to use '), span(card.app.name, true), span(`: ${card.operation.name}`)]}]},
    {type: 'context', block_id: block('m'), elements: [{type: 'plain_text', text: summary, emoji: false},
      ...(actions.length ? [{type: 'mrkdwn', verbatim: true, text: `expires <!date^${Math.floor(Date.parse(card.expiresAt) / 1000)}^{date_short_pretty} {time}|${stamp(card.expiresAt)}> · ${esc(new URL(actions[0].url).host)}`}] : [])]},
    ...(actions.length ? [{type: 'actions', block_id: block('a'), elements: actions.map((action, index) => ({type: 'button', action_id: `fabric.open.${index}`, text: {type: 'plain_text', text: action.label, emoji: false}, url: action.url}))}] : [])]};
}

/** Teams message with one Adaptive Card. Names go only in TextRuns, which Teams does not parse as Markdown. */
export function toTeams(card, {origin, now = Date.now()} = {}) {
  validateCard(card, {origin});
  const {summary, actions} = present(card, now), text = toText(card, {now});
  const run = (value, bold = false) => ({type: 'TextRun', text: value, ...(bold ? {weight: 'Bolder'} : {})});
  return {type: 'message', summary: text, attachments: [{contentType: 'application/vnd.microsoft.card.adaptive', content: {
    $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.5', fallbackText: text,
    body: [
      {type: 'RichTextBlock', inlines: [run(card.requester.name, true), run(' asked to use '), run(card.app.name, true), run(`: ${card.operation.name}`)]},
      {type: 'RichTextBlock', inlines: [run(summary)]},
      ...(actions.length ? [{type: 'FactSet', facts: [{title: 'Expires', value: stamp(card.expiresAt)}, {title: 'Opens', value: new URL(actions[0].url).host}]}] : [])],
    actions: actions.map(action => ({type: 'Action.OpenUrl', title: action.label, url: action.url}))}}]};
}

const MARKDOWN = /[\\`*_{}[\]()<>#+\-.!|~&:]/g;
/** CommonMark. The link is an autolink, so the text a person reads is the address it opens. */
export function toMarkdown(card, {origin, now = Date.now()} = {}) {
  validateCard(card, {origin});
  const md = value => value.replace(MARKDOWN, '\\$&');
  const {summary, actions} = present(card, now);
  const lines = [`**${md(card.requester.name)}** asked to use **${md(card.app.name)}**: ${md(card.operation.name)}\\.`, `${md(summary)}${actions.length ? ` Expires ${stamp(card.expiresAt)}\\.` : ''}`];
  for (const action of actions) lines.push(`${md(action.label)}: <${action.url}>`);
  return lines.join('\n');
}

/** Plain text for SDK users: validates first, like every other renderer. */
export function cardText(card, {origin, now = Date.now()} = {}) {validateCard(card, {origin}); return toText(card, {now});}

/** One entry point for SDK users: surface is text, markdown, slack or teams. */
export function renderCard(card, surface, options = {}) {
  if (surface === 'text') return cardText(card, options);
  const renderer = {markdown: toMarkdown, slack: toSlack, teams: toTeams}[surface];
  if (!renderer) throw new Error('Render a card as text, markdown, slack or teams.');
  return renderer(card, options);
}
