import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resetDelivery, boundedMailQueue } from '../src/mail.js';

test('Resend reset delivery uses authenticated HTTPS, stable idempotency and single-use expiry instructions', async () => {
  let call;
  const deliver = resetDelivery({ resendApiKey: 'test-key', mailFrom: 'Trello <trello@notify.example.com>' }, async (url, options) => { call = { url, options }; return { ok: true }; });
  await deliver({ to: 'learner@example.com', resetUrl: 'http://localhost:8080/reset-password?token=example&test=true', tokenHash: 'hashed-token' });
  assert.equal(call.url, 'https://api.resend.com/emails');
  assert.equal(call.options.headers.Authorization, 'Bearer test-key');
  assert.equal(call.options.headers['Idempotency-Key'], 'password-reset-hashed-token');
  const body = JSON.parse(call.options.body);
  assert.deepEqual(body.to, ['learner@example.com']);
  assert.match(body.text, /30 minutes/);
  assert.match(body.html, /token=example&amp;test=true/);
  assert.doesNotMatch(JSON.stringify(body), /test-key/);
});

test('provider rejection fails without returning the provider body or credentials', async () => {
  const deliver = resetDelivery({ resendApiKey: 'test-key', mailFrom: 'trello@notify.example.com' }, async () => ({ ok: false }));
  await assert.rejects(deliver({ to: 'learner@example.com', resetUrl: 'http://localhost/reset', tokenHash: 'hash' }), { code: 'MAIL_DELIVERY_FAILED', message: 'Email delivery was rejected.' });
  assert.throws(() => resetDelivery({ resendApiKey: 'test-key' }), /MAIL_FROM/);
  assert.equal(resetDelivery({ nodeEnv: 'production', devMailDir: '/tmp/mail' }), null);
});

test('verification emails use a separate idempotency namespace and 24-hour lifetime', async () => {
  let body, headers;
  const deliver = resetDelivery({ resendApiKey: 'test-key', mailFrom: 'notify@example.com' }, async (url, options) => { body = JSON.parse(options.body); headers = options.headers; return { ok: true }; }, true);
  await deliver({ to: 'learner@example.com', resetUrl: 'https://app.example.com/verify-email?token=sample', tokenHash: 'hash' });
  assert.equal(headers['Idempotency-Key'], 'email-verification-hash');
  assert.match(body.subject, /Verify/);
  assert.match(body.text, /24 hours/);
});
test('mail queue bounds concurrency and capacity and isolates task failure', async () => {
  const queue = boundedMailQueue({ concurrency: 1, capacity: 2 });
  let release, started = 0;
  const blocked = new Promise(resolve => { release = resolve; });
  assert.equal(queue.enqueue(async () => { started++; await blocked; }), true);
  assert.equal(queue.enqueue(async () => { started++; }), true);
  assert.equal(queue.enqueue(async () => {}), false);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(started, 1);
  release();
  await queue.drain();
  assert.equal(started, 2);
});
