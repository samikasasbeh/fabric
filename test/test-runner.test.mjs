import test from 'node:test';
import assert from 'node:assert/strict';
import {testEnvironment, testArguments} from '../scripts/test.mjs';

test('the test runner drops operator settings and keeps everything else', () => {
  const env = {PATH: '/bin', HOME: '/h', FABRIC_PUBLIC_CALLBACK_BASE: 'https://connect.example.com', FABRIC_NOTION_CLIENT_ID: 'id', FABRIC_NOTION_CLIENT_SECRET: 'secret',
    FABRIC_GOOGLE_CLIENT_SECRET: 'secret', FABRIC_GOOGLE_PUBLISHING: 'production', FABRIC_SLACK_PUBLISHING: 'testing', FABRIC_MODEL_URL: 'https://model.example', FABRIC_MODEL_API_KEY: 'key', FABRIC_MODEL_NAME: 'name',
    FABRIC_DATA_DIR: '/data', FABRIC_PORT: '4999', FABRIC_REQUIRE_BROWSER_TEST: '1', FABRIC_CLIENT_ID: 'kept: names no provider'};
  assert.deepEqual(testEnvironment(env), {PATH: '/bin', HOME: '/h', FABRIC_DATA_DIR: '/data', FABRIC_PORT: '4999', FABRIC_REQUIRE_BROWSER_TEST: '1', FABRIC_CLIENT_ID: 'kept: names no provider'});
});

test('named test files run alone, through the same scrubbed environment; anything else is refused', () => {
  const root = '/r', files = ['/r/test/a.test.mjs', '/r/test/b.test.mjs'];
  assert.deepEqual(testArguments([], files, root), ['--test', ...files]);
  assert.deepEqual(testArguments(['--test-name-pattern=x'], files, root), ['--test', '--test-name-pattern=x', ...files]);
  assert.deepEqual(testArguments(['test/b.test.mjs'], files, root), ['--test', '/r/test/b.test.mjs']);
  assert.throws(() => testArguments(['../elsewhere/c.test.mjs'], files, root), /is not a Fabric test file/);
  assert.throws(() => testArguments(['test/missing.test.mjs'], files, root), /is not a Fabric test file/);
});
