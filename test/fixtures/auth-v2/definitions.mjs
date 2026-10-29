// Version 2 auth definitions for tests (F10.2, F10.5): version 2 shapes of the planned Gmail, Calendar, GitHub, Slack and
// Notion definitions, built on the version 1 copies in ../auth-v1. The checked-in catalog stays version 1 until F10.7.
// GitHub carries the implications of docs/F10-FIVE-APPS-DEEP.md section 5.3, plus write:org granting read:org (F10.5 build
// map correction 9) and admin:public_key for the closure cases, and the address where a person removes the app.
import {v1Definition} from '../auth-v1/urls.mjs';

const G = 'https://www.googleapis.com/auth/';
export const GITHUB_SETTINGS = 'https://github.com/settings/applications';
export const level = (required, optional = [], inContext = []) => ({required, optional, inContext});
export const v2 = (providerId, apps, extra = {}) => {
  const base = v1Definition(providerId);
  return {...base, schemaVersion: 2, apps, scopeImplications: {}, consentPolicy: {testing: 'full', production: 'full'}, ...extra};
};
export const googleV2 = () => v2('google', [
  {appId: 'google-calendar', accessProbe: v1Definition('google').apps[0].accessProbe, access: {default: 'full', grant: 'scope', levels: {full: level([`${G}calendar`]), read: null}}, neverRequest: []},
  {appId: 'gmail', accessProbe: null, access: {default: 'full', grant: 'scope', levels: {full: level([`${G}gmail.modify`], [`${G}gmail.settings.basic`]), read: {required: [`${G}gmail.readonly`], optional: []}}},
    neverRequest: ['https://mail.google.com/', `${G}gmail.settings.sharing`, `${G}gmail.metadata`, `${G}gmail.insert`]},
], {consentPolicy: {testing: 'full', production: 'required'}});
export const githubV2 = () => {
  const value = v2('github', [{appId: 'github', accessProbe: null, access: {default: 'full', grant: 'scope', levels: {full: level(['read:user', 'repo'], ['read:org', 'gist', 'workflow']), read: null}},
    neverRequest: ['delete_repo', 'user', 'admin:public_key', 'admin:gpg_key', 'admin:ssh_signing_key']}],
  {scopeImplications: {repo: ['public_repo', 'repo:status', 'repo_deployment', 'repo:invite', 'security_events'], user: ['read:user', 'user:email', 'user:follow'],
    'admin:org': ['write:org', 'read:org'], 'write:org': ['read:org'], 'admin:repo_hook': ['write:repo_hook', 'read:repo_hook'], 'admin:public_key': ['write:public_key', 'read:public_key']}});
  value.revocation = {...value.revocation, settingsUrl: GITHUB_SETTINGS};
  return value;
};
export const notionV2 = () => v2('notion', [{appId: 'notion', accessProbe: null, access: {default: 'full', grant: 'pages', levels: {full: level([]), read: null}}, neverRequest: []}]);
export const slackV2 = () => v2('slack', [{appId: 'slack', accessProbe: null, access: {default: 'full', grant: 'user_scope', levels: {full: level(['channels:read', 'users:read'], ['chat:write'], [{scope: 'channels:history', rows: ['slack.messages.read']}]), read: null}}, neverRequest: ['admin']}]);
