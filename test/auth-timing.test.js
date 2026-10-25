import { test } from 'node:test';
import assert from 'node:assert/strict';
import { installAuth } from '../src/auth.js';

test('forgot-password responds before account lookup and delivery for both known and unknown addresses', async () => {
  const sql = [], tasks = [], routes = new Map();
  const app = { use() {}, get() {}, patch() {}, delete() {}, post(path, ...handlers) { routes.set(path, handlers.at(-1)); } };
  const pool = { query: async statement => { sql.push(statement); return { rows: [], rowCount: 1 }; } };
  installAuth(app, { pool, redis: {}, config: {
    jwtSecret: 'test-secret-with-more-than-thirty-two-characters', origin: 'http://localhost:8080', nodeEnv: 'test', authRateLimit: false,
    mailQueue: { enqueue(task) { tasks.push(task); return true; } },
  } });
  const responses = [];
  for (const email of ['known@example.com', 'unknown@example.com']) await routes.get('/api/auth/forgot-password')({ body: { email }, ip: '192.0.2.1' }, { json(value) { responses.push(value); } });
  assert.deepEqual(responses[0], responses[1]);
  assert.equal(tasks.length, 2);
  assert.ok(sql.every(statement => statement.startsWith('INSERT INTO auth_audit')));
});
