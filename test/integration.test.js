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
import { grantAdministrator } from '../src/bootstrap-admin.js';

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
    assert.equal((await client.query('SELECT count(*)::int AS count FROM schema_migrations')).rows[0].count, 3);
    assert.equal((await client.query('SELECT archived FROM workspaces WHERE id=$1', [workspaceId])).rows[0].archived, false);
  } finally {
    await client.query('RESET search_path');
    await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    client.release();
  }
});


test('application administration is separate, audited, confirmed and protects the last active admin', async () => {
  const admin = await account('app-admin'), other = await account('app-admin-other'), user = await account('app-user');
  assert.equal(admin.user.isAdmin, false);
  for (const path of ['/admin/overview', '/admin/users', '/admin/workspaces', '/admin/boards', '/admin/audit']) await user.request(path, { status: 403 });
  await user.request(`/admin/users/${user.user.id}`, { method: 'PATCH', status: 403, body: { isAdmin: true, confirm: true } });
  await assert.rejects(grantAdministrator(pool, `missing-${suffix}@example.com`), error => error.code === 'NOT_FOUND');
  await grantAdministrator(pool, admin.user.email);
  await grantAdministrator(pool, admin.user.email);
  const bootstrap = await pool.query("SELECT * FROM admin_audit WHERE target_id=$1 AND action='user.admin_bootstrapped'", [admin.user.id]);
  assert.equal(bootstrap.rowCount, 1);
  assert.equal(bootstrap.rows[0].actor_id, null);
  assert.equal((await admin.request('/auth/me')).isAdmin, true);
  await admin.request(`/admin/users/${admin.user.id}`, { method: 'PATCH', status: 409, body: { isAdmin: false, confirm: true } });
  await admin.request(`/admin/users/${admin.user.id}`, { method: 'PATCH', status: 409, body: { suspended: true, confirm: true } });
  await admin.request(`/admin/users/${other.user.id}`, { method: 'PATCH', status: 400, body: { isAdmin: true } });
  await admin.request(`/admin/users/${other.user.id}`, { method: 'PATCH', body: { isAdmin: true, confirm: true } });
  assert.equal((await other.request('/auth/me')).isAdmin, true);
  const users = await admin.request(`/admin/users?q=${encodeURIComponent(user.user.email)}&page=1&pageSize=1`);
  assert.equal(users.total, 1);
  assert.equal(users.items[0].id, user.user.id);
  assert.equal('password_hash' in users.items[0], false);
  await admin.request('/admin/users?page=0', { status: 400 });
  const overview = await admin.request('/admin/overview');
  assert.ok(overview.users >= 3);
  assert.equal(overview.admins, 2);
  await other.request(`/admin/users/${admin.user.id}`, { method: 'PATCH', body: { isAdmin: false, confirm: true } });
  await admin.request('/auth/me', { status: 401 });
  await admin.request('/auth/login', { method: 'POST', body: { email: admin.user.email, password: 'learning-password-123' } });
  await admin.request('/admin/overview', { status: 403 });
  await other.request(`/admin/users/${other.user.id}`, { method: 'PATCH', status: 409, body: { suspended: true, confirm: true } });
  const audit = await other.request(`/admin/audit?actorId=${other.user.id}&action=user.updated`);
  assert.ok(audit.items.some(item => item.targetId === admin.user.id && item.details.after.isAdmin === false));
  assert.ok(audit.items.every(item => item.actorId === other.user.id && item.details.outcome === 'success'));
});

test('suspension immediately invalidates access and renewal; restoration requires a fresh login', async () => {
  const admin = await account('suspend-admin'), user = await account('suspend-user');
  await grantAdministrator(pool, admin.user.email);
  const second = browser();
  await second.request('/auth/login', { method: 'POST', body: { email: user.user.email, password: 'learning-password-123' } });
  const { csrfToken } = await user.request('/auth/csrf');
  const oldToken = user.token;
  await admin.request(`/admin/users/${user.user.id}`, { method: 'PATCH', body: { suspended: true, confirm: true } });
  await user.request('/auth/me', { status: 401 });
  await second.request('/auth/me', { status: 401 });
  await user.request('/auth/renew', { method: 'POST', status: 401, csrf: csrfToken });
  await user.request('/auth/login', { method: 'POST', status: 403, body: { email: user.user.email, password: 'learning-password-123' } });
  await user.request('/auth/forgot-password', { method: 'POST', body: { email: user.user.email } });
  const preview = JSON.parse(await readFile(join(mailDir, `${user.user.id}.json`), 'utf8'));
  await user.request('/auth/reset-password', { method: 'POST', body: { token: new URL(preview.resetUrl).searchParams.get('token'), newPassword: 'new-suspended-password-123' } });
  await user.request('/auth/login', { method: 'POST', status: 403, body: { email: user.user.email, password: 'new-suspended-password-123' } });
  await admin.request(`/admin/users/${user.user.id}`, { method: 'PATCH', body: { suspended: false, confirm: true } });
  user.token = oldToken;
  await user.request('/auth/me', { status: 401 });
  await user.request('/auth/login', { method: 'POST', body: { email: user.user.email, password: 'new-suspended-password-123' } });
  assert.equal((await user.request('/auth/me')).id, user.user.id);
});

test('admin metadata access does not expose private boards and archived workspaces reject every scoped write', async () => {
  const admin = await account('metadata-admin'), owner = await account('metadata-owner'), guest = await account('metadata-guest');
  await grantAdministrator(pool, admin.user.email);
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Private metadata scope' } });
  const board = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'Secret board' } });
  const list = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'Secret list' } });
  const card = await owner.request(`/lists/${list.id}/cards`, { method: 'POST', status: 201, body: { title: 'Private content' } });
  const checklist = await owner.request(`/cards/${card.id}/checklists`, { method: 'POST', status: 201, body: { title: 'Private tasks' } });
  const invitation = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: guest.user.email } });
  await admin.request(`/boards/${board.id}`, { status: 404 });
  await admin.request(`/cards/${card.id}`, { status: 404 });
  const rows = await admin.request('/admin/boards?q=Secret%20board');
  assert.equal(rows.items[0].id, board.id);
  assert.equal('lists' in rows.items[0], false);
  assert.equal('cards' in rows.items[0], false);
  const members = await admin.request(`/admin/workspaces/${workspace.id}/members`);
  assert.equal(members[0].id, owner.user.id);
  await admin.request(`/admin/boards/${board.id}`, { method: 'PATCH', body: { closed: true, confirm: true } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', status: 409, body: { title: 'Blocked by close' } });
  await admin.request(`/admin/boards/${board.id}`, { method: 'PATCH', body: { closed: false, confirm: true } });
  await admin.request(`/admin/workspaces/${workspace.id}`, { method: 'PATCH', status: 400, body: { archived: true } });
  await admin.request(`/admin/workspaces/${workspace.id}`, { method: 'PATCH', body: { archived: true, confirm: true } });
  await owner.request(`/workspaces/${workspace.id}`, { status: 409 });
  await owner.request(`/boards/${board.id}`, { status: 409 });
  await owner.request(`/cards/${card.id}`, { status: 409 });
  assert.equal((await owner.request('/workspaces')).some(row => row.id === workspace.id), false);
  for (const [path, method, body] of [
    [`/workspaces/${workspace.id}`, 'PATCH', { name: 'Blocked' }],
    [`/workspaces/${workspace.id}/boards`, 'POST', { title: 'Blocked' }],
    [`/workspaces/${workspace.id}/invitations`, 'POST', { email: guest.user.email }],
    [`/workspaces/${workspace.id}/invitations/${invitation.id}`, 'DELETE', {}],
    [`/workspaces/${workspace.id}/members/${owner.user.id}`, 'DELETE', {}],
    [`/workspaces/${workspace.id}/transfer`, 'POST', { userId: guest.user.id }],
    [`/boards/${board.id}`, 'PATCH', { title: 'Blocked' }],
    [`/boards/${board.id}/preferences`, 'PATCH', { favorite: true }],
    [`/boards/${board.id}/copy`, 'POST', {}],
    [`/boards/${board.id}/labels`, 'POST', { name: 'Blocked', color: '#123456' }],
    [`/lists/${list.id}`, 'PATCH', { title: 'Blocked' }],
    [`/lists/${list.id}/cards`, 'POST', { title: 'Blocked' }],
    [`/cards/${card.id}`, 'PATCH', { title: 'Blocked' }],
    [`/cards/${card.id}/comments`, 'POST', { body: 'Blocked' }],
    [`/checklists/${checklist.id}/items`, 'POST', { title: 'Blocked' }],
  ]) {
    const failure = await owner.request(path, { method, body, status: 409 });
    assert.equal(failure.error.code, 'WORKSPACE_ARCHIVED');
  }
  await guest.request('/invitations/accept', { method: 'POST', status: 409, body: { token: invitation.token } });
  await admin.request(`/cards/${card.id}`, { method: 'PATCH', status: 404, body: { title: 'No override' } });
  await admin.request(`/admin/workspaces/${workspace.id}`, { method: 'PATCH', body: { archived: false, confirm: true } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { title: 'Restored' } });
  await guest.request('/invitations/accept', { method: 'POST', body: { token: invitation.token } });
});

test('session inventory and revocation never expose credentials or another user session', async () => {
  const user = await account('sessions-user'), stranger = await account('sessions-stranger');
  const second = browser(), third = browser();
  for (const client of [second, third]) await client.request('/auth/login', { method: 'POST', body: { email: user.user.email, password: 'learning-password-123' } });
  let sessions = await user.request('/auth/sessions');
  assert.equal(sessions.length, 3);
  assert.equal(sessions.filter(row => row.current).length, 1);
  assert.ok(sessions.every(row => row.userAgent && row.createdAt && row.lastUsedAt && row.expiresAt));
  assert.ok(sessions.every(row => !('token_hash' in row) && !('accessToken' in row)));
  const currentId = sessions.find(row => row.current).id;
  const secondId = (await second.request('/auth/sessions')).find(row => row.current).id;
  await stranger.request(`/auth/sessions/${secondId}`, { method: 'DELETE', status: 404 });
  const { csrfToken } = await second.request('/auth/csrf');
  await second.request('/auth/renew', { method: 'POST', csrf: csrfToken });
  assert.equal((await second.request('/auth/sessions')).find(row => row.current).id, secondId);
  await user.request(`/auth/sessions/${secondId}`, { method: 'DELETE' });
  await second.request('/auth/me', { status: 401 });
  await second.request('/auth/renew', { method: 'POST', csrf: csrfToken, status: 401 });
  await user.request('/auth/sessions/revoke-others', { method: 'POST', status: 400 });
  await user.request('/auth/sessions/revoke-others', { method: 'POST', body: { confirm: true } });
  await third.request('/auth/me', { status: 401 });
  sessions = await user.request('/auth/sessions');
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].id, currentId);
  await user.request(`/auth/sessions/${currentId}`, { method: 'DELETE' });
  await user.request('/auth/me', { status: 401 });
});
