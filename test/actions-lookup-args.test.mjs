// F10.11 part h: a choice lookup fills each configured argument from the choice's args keyed by the source's argument name, the same
// key checkChoices() validates and /v1/options reads, never by the configured value's own name.
import test from 'node:test';
import assert from 'node:assert/strict';
import {lookupStep} from '../lib/actions-runtime.mjs';

const state = ({list = false} = {}) => ({
  job: {args: {labelId: list ? ['L1', 'L2'] : 'L1', acct: 'A9'}},
  route: {map: null},
  entry: {
    lookups: {labelId: {method: 'GET', template: 'GET /accounts/{account_id}/labels/{label_id}', args: {account_id: {configured: 'who'}, label_id: {value: true}, view: {const: 'basic'}}}},
    action: {choices: [{input: 'labelId', args: {account_id: {input: '/acct'}}}]},
  },
});

test('a lookup fills a configured argument from the choice args under the argument name, not the configured name', () => {
  const step = lookupStep(state(), 'labelId');
  assert.deepEqual(step.params, {account_id: {input: '/acct'}, label_id: {input: '/labelId'}});
  assert.deepEqual(step.query, {view: {const: 'basic'}});
  assert.equal(step.path, '/accounts/{account_id}/labels/{label_id}');
});

test('a list lookup reads each item and still fills the configured argument by its name', () => {
  const step = lookupStep(state({list: true}), 'labelId');
  assert.deepEqual(step.params, {account_id: {input: '/acct'}, label_id: {item: ''}});
  assert.deepEqual(step.forEach.over, {input: '/labelId'});
});
