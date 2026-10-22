import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createClient } from 'redis';
import { database } from '../src/db.js';
import { migrate } from '../src/migrate.js';
import { createApp } from '../src/app.js';

if (!process.env.TEST_DATABASE_URL) throw new Error('TEST_DATABASE_URL is required; use a disposable test database.');
const pool = database(process.env.TEST_DATABASE_URL);
const redis = createClient({ url: process.env.REDIS_URL });
let server, base, mailDir;
before(async () => {
  await redis.connect();
  await migrate(pool);
  mailDir = await mkdtemp(join(tmpdir(), 'trello-mail-'));
  server = createApp({ pool, redis, config: { jwtSecret: 'test-secret-with-more-than-thirty-two-characters', origin: 'http://localhost:8080', secure: false, nodeEnv: 'test', devMailDir: mailDir, authRateLimit: false } }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}/api`;
});
after(async () => {
  if (server) await new Promise(resolve => server.close(resolve));
  await pool.end();
  if (redis.isOpen) await redis.quit();
  if (mailDir) await rm(mailDir, { recursive: true, force: true });
});
function browser() {
  return {
    cookies: new Map(), token: null,
    async request(path, { method = 'GET', body, status = 200, csrf } = {}) {
      const headers = { 'Content-Type': 'application/json', Origin: 'http://localhost:8080' };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      if (csrf) headers['X-CSRF-Token'] = csrf;
      headers.Cookie = [...this.cookies].map(([key, value]) => `${key}=${value}`).join('; ');
      const result = await fetch(`${base}${path}`, { method, headers, ...(method !== 'GET' ? { body: JSON.stringify(body || {}) } : {}) });
      for (const cookie of result.headers.getSetCookie()) {
        const [pair] = cookie.split(';');
        const split = pair.indexOf('=');
        this.cookies.set(pair.slice(0, split), pair.slice(split + 1));
      }
      const data = await result.json();
      assert.equal(result.status, status, `${method} ${path}: ${JSON.stringify(data)}`);
      if (data.accessToken) this.token = data.accessToken;
      return data;
    },
  };
}
const suffix = randomUUID();
async function account(name) {
  const client = browser();
  const user = (await client.request('/auth/register', { method: 'POST', status: 201, body: { email: `${name}-${suffix}@example.com`, password: 'learning-password-123', displayName: name } })).user;
  return Object.assign(client, { user });
}

test('workspace isolation, invitations, persisted ordering, archives and ownership', async () => {
  const owner = await account('owner');
  const member = await account('member');
  const outsider = await account('outsider');
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Learning workspace' } });
  const board = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'Release board', color: '#0052cc' } });
  const left = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'To do' } });
  const right = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'Done' } });
  const cardId = randomUUID();
  const card = await owner.request(`/lists/${left.id}/cards`, { method: 'POST', status: 201, body: { id: cardId, title: 'Read the plan' } });
  await owner.request(`/lists/${left.id}/cards`, { method: 'POST', status: 201, body: { id: cardId, title: 'Read the plan' } });
  assert.equal((await owner.request(`/boards/${board.id}`)).lists[0].cards.length, 1);
  for (const [path, method, body] of [
    [`/workspaces/${workspace.id}`, 'GET'], [`/boards/${board.id}`, 'GET'],
    [`/cards/${card.id}`, 'GET'], [`/cards/${card.id}`, 'PATCH', { title: 'intrusion' }],
    [`/cards/${card.id}/move`, 'POST', { listId: right.id, position: 0 }],
    [`/boards/${board.id}/preferences`, 'PATCH', { favorite: true }],
    [`/lists/${left.id}`, 'PATCH', { title: 'intrusion' }],
  ]) await outsider.request(path, { method, body, status: 404 });
  const invitation = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: member.user.email } });
  await outsider.request('/invitations/accept', { method: 'POST', status: 400, body: { token: invitation.token } });
  await member.request('/invitations/accept', { method: 'POST', body: { token: invitation.token } });
  await member.request('/invitations/accept', { method: 'POST', status: 400, body: { token: invitation.token } });
  await member.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 403, body: { email: outsider.user.email } });
  await member.request(`/cards/${card.id}`, { method: 'PATCH', body: { description: 'Shared work' } });
  const second = await member.request(`/lists/${left.id}/cards`, { method: 'POST', status: 201, body: { title: 'Second task' } });
  const third = await member.request(`/lists/${left.id}/cards`, { method: 'POST', status: 201, body: { title: 'Third task' } });
  await Promise.all([card, second, third].map(item => member.request(`/cards/${item.id}/move`, { method: 'POST', body: { listId: right.id, position: 0 } })));
  let state = await owner.request(`/boards/${board.id}`);
  assert.equal(state.lists[0].cards.length, 0);
  assert.equal(state.lists[1].cards.length, 3);
  assert.deepEqual(state.lists[1].cards.map(item => item.position), [0, 1, 2]);
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { archived: true } });
  await owner.request(`/lists/${right.id}`, { method: 'PATCH', body: { archived: true } });
  await owner.request(`/lists/${right.id}`, { method: 'PATCH', body: { archived: false } });
  state = await owner.request(`/boards/${board.id}`);
  assert.equal(state.lists[1].cards.find(item => item.id === card.id).archived, true);
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { archived: false } });
  await owner.request(`/cards/${second.id}`, { method: 'PATCH', body: { archived: true } });
  await owner.request(`/cards/${third.id}/move`, { method: 'POST', body: { listId: right.id, position: 0 } });
  state = await owner.request(`/boards/${board.id}`);
  assert.equal(state.lists[1].cards.filter(item => !item.archived)[0].id, third.id);
  await owner.request(`/lists/${right.id}/move`, { method: 'POST', body: { position: 0 } });
  assert.equal((await owner.request(`/boards/${board.id}`)).lists[0].id, right.id);
  await owner.request(`/boards/${board.id}/preferences`, { method: 'PATCH', body: { favorite: true, lastOpenedAt: true } });
  assert.equal((await owner.request(`/boards/${board.id}`)).favorite, true);
  assert.equal((await member.request(`/boards/${board.id}`)).favorite, false);
  await owner.request(`/boards/${board.id}`, { method: 'PATCH', body: { closed: true } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', status: 409, body: { title: 'blocked' } });
  await owner.request(`/boards/${board.id}`, { method: 'PATCH', body: { closed: false } });
  await owner.request(`/workspaces/${workspace.id}/members/${owner.user.id}`, { method: 'DELETE', status: 409 });
  await owner.request(`/workspaces/${workspace.id}/members/${member.user.id}`, { method: 'DELETE' });
  await member.request(`/boards/${board.id}`, { status: 404 });
  await member.request(`/cards/${card.id}/move`, { method: 'POST', status: 404, body: { listId: left.id, position: 0 } });
  const direct = await owner.request(`/cards/${card.id}`);
  assert.equal(direct.boardId, board.id);
  assert.equal(direct.description, 'Shared work');
});

test('renew rotation, CSRF, logout revocation and password reset invalidate credentials', async () => {
  const client = await account('auth');
  const originalAccess = client.token;
  const originalRefresh = client.cookies.get('rt');
  await client.request('/auth/renew', { method: 'POST', status: 403 });
  const { csrfToken } = await client.request('/auth/csrf');
  await client.request('/auth/renew', { method: 'POST', csrf: csrfToken });
  assert.notEqual(client.token, originalAccess);
  assert.notEqual(client.cookies.get('rt'), originalRefresh);
  const rotated = client.cookies.get('rt');
  client.cookies.set('rt', originalRefresh);
  await client.request('/auth/renew', { method: 'POST', csrf: csrfToken, status: 409 });
  client.cookies.set('rt', rotated);
  await client.request('/auth/logout', { method: 'POST', csrf: csrfToken });
  await client.request('/auth/me', { status: 401 });
  client.token = originalAccess;
  await client.request('/auth/me', { status: 401 });
  await client.request('/auth/renew', { method: 'POST', csrf: csrfToken, status: 401 });
  await client.request('/auth/login', { method: 'POST', body: { email: client.user.email, password: 'learning-password-123' } });
  const beforeReset = client.token;
  const response = await client.request('/auth/forgot-password', { method: 'POST', body: { email: client.user.email } });
  const unknown = await client.request('/auth/forgot-password', { method: 'POST', body: { email: `unknown-${suffix}@example.com` } });
  assert.deepEqual(response, unknown);
  const preview = JSON.parse(await readFile(join(mailDir, `${client.user.id}.json`), 'utf8'));
  const resetToken = new URL(preview.resetUrl).searchParams.get('token');
  await client.request('/auth/reset-password', { method: 'POST', body: { token: resetToken, newPassword: 'new-learning-password-456' } });
  client.token = beforeReset;
  await client.request('/auth/me', { status: 401 });
  await client.request('/auth/reset-password', { method: 'POST', status: 400, body: { token: resetToken, newPassword: 'other-learning-password' } });
  await client.request('/auth/login', { method: 'POST', status: 401, body: { email: client.user.email, password: 'learning-password-123' } });
  await client.request('/auth/login', { method: 'POST', body: { email: client.user.email, password: 'new-learning-password-456' } });
  const profile = await client.request('/me', { method: 'PATCH', body: { displayName: 'Updated learner' } });
  assert.equal(profile.displayName, 'Updated learner');
});

test('expired and revoked invitations, cross-board moves and validation', async () => {
  const owner = await account('limits');
  const guest = await account('invitee');
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Boundaries' } });
  for (const mode of ['expired', 'revoked']) {
    const invite = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: guest.user.email } });
    if (mode === 'expired') await pool.query('UPDATE invitations SET expires_at=now()-interval \'1 second\' WHERE id=$1', [invite.id]);
    else await owner.request(`/workspaces/${workspace.id}/invitations/${invite.id}`, { method: 'DELETE' });
    await guest.request('/invitations/accept', { method: 'POST', status: 400, body: { token: invite.token } });
  }
  const firstBoard = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'First' } });
  const secondBoard = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'Second' } });
  const first = await owner.request(`/boards/${firstBoard.id}/lists`, { method: 'POST', status: 201, body: { title: 'First' } });
  const second = await owner.request(`/boards/${secondBoard.id}/lists`, { method: 'POST', status: 201, body: { title: 'Second' } });
  const card = await owner.request(`/lists/${first.id}/cards`, { method: 'POST', status: 201, body: { title: 'Stay here' } });
  await owner.request(`/cards/${card.id}/move`, { method: 'POST', body: { listId: second.id, position: 0 } });
  assert.equal((await owner.request(`/cards/${card.id}`)).listId, second.id);
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', status: 400, body: { archived: 'false' } });
  await owner.request(`/boards/${firstBoard.id}`, { method: 'PATCH', status: 400, body: { color: 'url(evil)' } });
});

test('refresh replay after grace revokes every access and refresh token for the account', async () => {
  const client = await account('replay');
  const originalRefresh = client.cookies.get('rt');
  const { csrfToken } = await client.request('/auth/csrf');
  await client.request('/auth/renew', { method: 'POST', csrf: csrfToken });
  const rotatedRefresh = client.cookies.get('rt');
  await pool.query('UPDATE refresh_tokens SET used_at=now()-interval \'10 seconds\' WHERE token_hash=encode(sha256($1::bytea),\'hex\')', [Buffer.from(originalRefresh)]);
  client.cookies.set('rt', originalRefresh);
  const result = await client.request('/auth/renew', { method: 'POST', status: 401, csrf: csrfToken });
  assert.equal(result.error.code, 'REUSE_DETECTED');
  await client.request('/auth/me', { status: 401 });
  client.cookies.set('rt', rotatedRefresh);
  await client.request('/auth/renew', { method: 'POST', status: 401, csrf: csrfToken });
});


test('rich card metadata, checklists, comments and saved views preserve authorization', async () => {
  const owner = await account('tasks-owner'), member = await account('tasks-member'), outsider = await account('tasks-outsider');
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Task workspace' } });
  const invitation = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: member.user.email } });
  await member.request('/invitations/accept', { method: 'POST', body: { token: invitation.token } });
  const board = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'Tasks' } });
  const list = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'Doing' } });
  const card = await owner.request(`/lists/${list.id}/cards`, { method: 'POST', status: 201, body: { title: 'Polish interface' } });
  const label = await owner.request(`/boards/${board.id}/labels`, { method: 'POST', status: 201, body: { name: 'Design', color: '#0079bf' } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { labelIds: [label.id], assigneeIds: [member.user.id], coverColor: '#123456', startDate: '2026-01-01', dueDate: '2026-01-02', completed: true } });
  await outsider.request(`/cards/${card.id}`, { status: 404 });
  await outsider.request(`/boards/${board.id}/labels`, { method: 'POST', status: 404, body: { name: 'Hidden', color: '#ffffff' } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', status: 400, body: { assigneeIds: [outsider.user.id] } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', status: 400, body: { startDate: '2027-01-01' } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', status: 400, body: { dueDate: '2026-02-30' } });
  const checklist = await owner.request(`/cards/${card.id}/checklists`, { method: 'POST', status: 201, body: { title: 'Ship' } });
  const item = await member.request(`/checklists/${checklist.id}/items`, { method: 'POST', status: 201, body: { title: 'Review' } });
  const other = await member.request(`/checklists/${checklist.id}/items`, { method: 'POST', status: 201, body: { title: 'Publish' } });
  await owner.request(`/checklist-items/${other.id}`, { method: 'PATCH', body: { completed: true, position: 0 } });
  await outsider.request(`/checklist-items/${item.id}`, { method: 'DELETE', status: 404 });
  const comment = await member.request(`/cards/${card.id}/comments`, { method: 'POST', status: 201, body: { body: 'Ready for review' } });
  await owner.request(`/comments/${comment.id}`, { method: 'PATCH', status: 403, body: { body: 'Changed' } });
  await owner.request(`/comments/${comment.id}`, { method: 'DELETE', status: 403 });
  await member.request(`/comments/${comment.id}`, { method: 'PATCH', body: { body: 'Reviewed' } });
  let detail = await owner.request(`/cards/${card.id}`);
  assert.deepEqual(detail.labelIds, [label.id]);
  assert.deepEqual(detail.assigneeIds, [member.user.id]);
  assert.equal(detail.completed, true);
  assert.equal(detail.checklists[0].items[0].id, other.id);
  assert.equal(detail.checklists[0].items[0].completed, true);
  assert.equal(detail.comments[0].body, 'Reviewed');
  assert.ok(detail.activity.some(event => event.action === 'comment.created'));
  assert.equal((await owner.request(`/boards/${board.id}?due=overdue`)).lists[0].cards.length, 0);
  assert.equal((await owner.request(`/boards/${board.id}?query=polish&labelId=${label.id}&assigneeId=${member.user.id}&due=completed`)).lists[0].cards.length, 1);
  const view = await owner.request(`/boards/${board.id}/views`, { method: 'POST', status: 201, body: { name: 'Mine', filters: { query: 'polish', labelIds: [label.id], due: 'completed' } } });
  assert.equal((await owner.request(`/boards/${board.id}/views`))[0].id, view.id);
  assert.equal((await member.request(`/boards/${board.id}/views`)).length, 0);
  await member.request(`/views/${view.id}`, { method: 'DELETE', status: 404 });
  await owner.request(`/workspaces/${workspace.id}/members/${member.user.id}`, { method: 'DELETE' });
  detail = await owner.request(`/cards/${card.id}`);
  assert.deepEqual(detail.assigneeIds, []);
  await member.request(`/cards/${card.id}/comments`, { method: 'POST', status: 404, body: { body: 'No longer allowed' } });
  await owner.request(`/labels/${label.id}`, { method: 'DELETE' });
  assert.deepEqual((await owner.request(`/cards/${card.id}`)).labelIds, []);
});

test('copies are independent, cross-board moves authorize destination, and deletion requires archive confirmation', async () => {
  const owner = await account('copy-owner'), outsider = await account('copy-outsider');
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Copies' } });
  const board = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'Source' } });
  const list = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'Todo' } });
  await owner.request(`/lists/${list.id}`, { method: 'PATCH', body: { wipLimit: 1 } });
  await owner.request(`/lists/${list.id}`, { method: 'PATCH', status: 400, body: { wipLimit: 0 } });
  const card = await owner.request(`/lists/${list.id}/cards`, { method: 'POST', status: 201, body: { title: 'Original' } });
  const checklist = await owner.request(`/cards/${card.id}/checklists`, { method: 'POST', status: 201, body: { title: 'Checklist' } });
  const item = await owner.request(`/checklists/${checklist.id}/items`, { method: 'POST', status: 201, body: { title: 'Task' } });
  await owner.request(`/checklist-items/${item.id}`, { method: 'PATCH', body: { completed: true } });
  const label = await owner.request(`/boards/${board.id}/labels`, { method: 'POST', status: 201, body: { name: 'Label', color: '#123456' } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { labelIds: [label.id] } });
  const copy = await owner.request(`/cards/${card.id}/copy`, { method: 'POST', status: 201, body: { listId: list.id, title: 'Copy' } });
  assert.notEqual(copy.id, card.id);
  let detail = await owner.request(`/cards/${copy.id}`);
  assert.notEqual(detail.checklists[0].id, checklist.id);
  assert.equal(detail.checklists[0].items[0].completed, false);
  await owner.request(`/cards/${copy.id}`, { method: 'PATCH', body: { title: 'Independent' } });
  assert.equal((await owner.request(`/cards/${card.id}`)).title, 'Original');
  const boardCopy = await owner.request(`/boards/${board.id}/copy`, { method: 'POST', status: 201, body: { title: 'Board copy' } });
  let copied = await owner.request(`/boards/${boardCopy.id}`);
  assert.equal(copied.lists[0].wipLimit, 1);
  assert.equal(copied.lists[0].cards.length, 2);
  assert.notEqual(copied.labels[0].id, label.id);
  assert.deepEqual(copied.lists[0].cards[0].labelIds, [copied.labels[0].id]);
  const foreign = await outsider.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Hidden' } });
  const foreignBoard = await outsider.request(`/workspaces/${foreign.id}/boards`, { method: 'POST', status: 201, body: { title: 'Hidden' } });
  const foreignList = await outsider.request(`/boards/${foreignBoard.id}/lists`, { method: 'POST', status: 201, body: { title: 'Hidden' } });
  await owner.request(`/cards/${card.id}/move`, { method: 'POST', status: 404, body: { listId: foreignList.id, position: 0 } });
  await owner.request(`/cards/${card.id}/move`, { method: 'POST', body: { listId: copied.lists[0].id, position: 0 } });
  detail = await owner.request(`/cards/${card.id}`);
  assert.equal(detail.boardId, boardCopy.id);
  assert.deepEqual(detail.labelIds, []);
  await owner.request(`/cards/${copy.id}`, { method: 'DELETE', status: 409, body: { confirm: true } });
  await owner.request(`/cards/${copy.id}`, { method: 'PATCH', body: { archived: true } });
  await owner.request(`/cards/${copy.id}`, { method: 'DELETE', status: 409 });
  await owner.request(`/cards/${copy.id}`, { method: 'DELETE', body: { confirm: true } });
  await owner.request(`/cards/${copy.id}`, { status: 404 });
  await owner.request(`/lists/${list.id}`, { method: 'PATCH', body: { archived: true } });
  await owner.request(`/lists/${list.id}`, { method: 'DELETE', body: { confirm: true } });
});

test('ownership transfer is atomic, owner-only, and leaves a new owner', async () => {
  const owner = await account('transfer-owner'), member = await account('transfer-member'), outsider = await account('transfer-outsider');
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Transfer' } });
  const invitation = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: member.user.email } });
  await member.request('/invitations/accept', { method: 'POST', body: { token: invitation.token } });
  await member.request(`/workspaces/${workspace.id}/transfer`, { method: 'POST', status: 403, body: { userId: owner.user.id } });
  await owner.request(`/workspaces/${workspace.id}/transfer`, { method: 'POST', status: 400, body: { userId: outsider.user.id } });
  const transferred = await owner.request(`/workspaces/${workspace.id}/transfer`, { method: 'POST', body: { userId: member.user.id } });
  assert.equal(transferred.role, 'member');
  assert.equal((await member.request(`/workspaces/${workspace.id}`)).role, 'owner');
  await owner.request(`/workspaces/${workspace.id}`, { method: 'PATCH', status: 403, body: { name: 'Forbidden' } });
  await member.request(`/workspaces/${workspace.id}/members/${member.user.id}`, { method: 'DELETE', status: 409 });
  const recorded = await pool.query('SELECT action,target_id FROM workspace_activity WHERE workspace_id=$1', [workspace.id]);
  assert.equal(recorded.rows[0].action, 'ownership.transferred');
  assert.equal(recorded.rows[0].target_id, member.user.id);
});


test('upgrade from core schema preserves existing card data and migration is repeatable', async () => {
  const client = await pool.connect();
  const schema = `upgrade_${randomUUID().replaceAll('-', '')}`;
  try {
    await client.query(`CREATE SCHEMA ${schema}`);
    await client.query(`SET search_path TO ${schema}`);
    await client.query(await readFile(new URL('../migrations/001_init.sql', import.meta.url), 'utf8'));
    await client.query('CREATE TABLE schema_migrations(name text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())');
    await client.query("INSERT INTO schema_migrations(name) VALUES('001_init.sql')");
    const workspaceId = randomUUID(), boardId = randomUUID(), listId = randomUUID(), cardId = randomUUID();
    await client.query('INSERT INTO workspaces(id,name) VALUES($1,$2)', [workspaceId, 'Existing workspace']);
    await client.query('INSERT INTO boards(id,workspace_id,title) VALUES($1,$2,$3)', [boardId, workspaceId, 'Existing board']);
    await client.query('INSERT INTO lists(id,board_id,title,position) VALUES($1,$2,$3,0)', [listId, boardId, 'Existing list']);
    await client.query('INSERT INTO cards(id,list_id,title,description,position,archived) VALUES($1,$2,$3,$4,2,true)', [cardId, listId, 'Existing card', 'Preserve me']);
    const scopedPool = { connect: async () => ({ query: client.query.bind(client), release() {} }) };
    await migrate(scopedPool);
    await migrate(scopedPool);
    const row = (await client.query('SELECT * FROM cards WHERE id=$1', [cardId])).rows[0];
    assert.equal(row.description, 'Preserve me');
    assert.equal(row.position, 2);
    assert.equal(row.archived, true);
    assert.deepEqual(row.label_ids, []);
    assert.deepEqual(row.assignee_ids, []);
    assert.equal(row.completed, false);
    assert.equal(row.due_date, null);
    assert.equal((await client.query('SELECT wip_limit FROM lists WHERE id=$1', [listId])).rows[0].wip_limit, null);
    assert.equal((await client.query('SELECT count(*)::int AS count FROM schema_migrations')).rows[0].count, 2);
  } finally {
    await client.query('RESET search_path');
    await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    client.release();
  }
});
