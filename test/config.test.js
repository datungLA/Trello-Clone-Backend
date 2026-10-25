import { test } from 'node:test';
import assert from 'node:assert/strict';
import { trustedProxy, validateConfig } from '../src/config.js';
const production = { jwtSecret: 'test-secret-of-at-least-thirty-two-characters', nodeEnv: 'production', secure: true, origin: 'https://app.example.com', origins: ['https://admin.example.com'], trustProxy: 1, resendApiKey: 're_test_only', mailFrom: 'Trello <notify@example.com>' };
test('production refuses insecure or incomplete authentication configuration', () => {
  assert.equal(validateConfig(production), production);
  for (const change of [{ secure: false }, { origin: 'http://app.example.com' }, { origin: 'https://app.example.com/path' }, { origins: ['http://admin.example.com'] }, { trustProxy: false }, { trustProxy: true }, { trustProxy: 10 }, { resendApiKey: '' }, { mailFrom: '' }, { devMailDir: '/tmp/mail' }, { setupToken: 'short' }]) assert.throws(() => validateConfig({ ...production, ...change }));
});
test('proxy trust accepts bounded hops or explicit networks and rejects broad trust', () => {
  assert.equal(trustedProxy('1'), 1);
  assert.deepEqual(trustedProxy('127.0.0.1,172.16.0.0/12'), ['127.0.0.1', '172.16.0.0/12']);
  assert.equal(trustedProxy(undefined), false);
  for (const value of ['true', '*', '10', '0.0.0.0/0', '::/0', 'loopback', '127.0.0.1/33']) assert.throws(() => trustedProxy(value));
});
