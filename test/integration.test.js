import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile, mkdir, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createClient } from 'redis';
import { database } from '../src/db.js';
import { migrate } from '../src/migrate.js';
import { createApp } from '../src/app.js';
import { hash } from '../src/auth.js';
import { grantAdministrator } from '../src/bootstrap-admin.js';
import { boundedMailQueue } from '../src/mail.js';
import { encryptBackupToken } from '../src/backup.js';

if (!process.env.TEST_DATABASE_URL) throw new Error('TEST_DATABASE_URL is required; use a disposable test database.');
const pool = database(process.env.TEST_DATABASE_URL);
const redis = createClient({ url: process.env.REDIS_URL });
let server, base, mailDir;
const mailQueue = boundedMailQueue();
before(async () => {
  await redis.connect();
  await migrate(pool);
  mailDir = await mkdtemp(join(tmpdir(), 'trello-mail-'));
  server = createApp({ pool, redis, config: { jwtSecret: 'test-secret-with-more-than-thirty-two-characters', origin: 'http://localhost:8080', secure: false, nodeEnv: 'test', devMailDir: mailDir, mailQueue, authRateLimit: false } }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}/api`;
});
after(async () => {
  await mailQueue.drain();
  if (server) await new Promise(resolve => server.close(resolve));
  await pool.end();
  if (redis.isOpen) await redis.quit();
  if (mailDir) await rm(mailDir, { recursive: true, force: true });
});
function browser(root = base) {
  return {
    cookies: new Map(), token: null,
    async request(path, { method = 'GET', body, status = 200, csrf } = {}) {
      const headers = { 'Content-Type': 'application/json', Origin: 'http://localhost:8080' };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      if (csrf) headers['X-CSRF-Token'] = csrf;
      headers.Cookie = [...this.cookies].map(([key, value]) => `${key}=${value}`).join('; ');
      const result = await fetch(`${root}${path}`, { method, headers, ...(method !== 'GET' ? { body: JSON.stringify(body || {}) } : {}) });
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
  const address = `${name}-${suffix}@example.com`;
  await client.request('/auth/register', { method: 'POST', status: 202, body: { email: address, password: 'learning-password-123', displayName: name } });
  await mailQueue.drain();
  const row = (await pool.query('SELECT id FROM users WHERE email=$1', [address])).rows[0];
  const message = JSON.parse(await readFile(join(mailDir, `${row.id}.verify.json`), 'utf8'));
  await client.request('/auth/verify-email', { method: 'POST', body: { token: new URL(message.resetUrl).searchParams.get('token') } });
  const user = (await client.request('/auth/login', { method: 'POST', body: { email: address, password: 'learning-password-123' } })).user;
  return Object.assign(client, { user });
}

test('system backup enforces super-admin scope, OAuth browser/session binding, encrypted tokens and verified uploads', async () => {
  const ordinary = await account('backup-ordinary'), admin = await account('backup-admin'), superAdmin = await account('backup-super');
  await pool.query("UPDATE users SET is_admin=true,app_role='admin' WHERE id=$1", [admin.user.id]);
  await pool.query("UPDATE users SET is_admin=true,app_role='super_admin' WHERE id=$1", [superAdmin.user.id]);
  const key = 'ab'.repeat(32), digest = 'test-checksum';
  let uploadCount = 0, retentionCount = 0, failUpload = false, releaseRetention, enteredRetention;
  const retentionEntered = new Promise(resolve => { enteredRetention = resolve; });
  const backupConfig = {
    clientId: 'test-client.apps.googleusercontent.com', clientSecret: 'test-client-secret', tokenKey: key,
    environment: 'test', origin: 'http://localhost:8080', recipientCertFile: mailDir, configDir: mailDir, workDir: mailDir,
    async fetch(url, options = {}) {
      const value = String(url), json = body => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
      if (value === 'https://oauth2.googleapis.com/token') return json({ access_token: 'access-private', refresh_token: 'refresh-private', scope: 'https://www.googleapis.com/auth/drive.file' });
      if (value.includes('/oauth2/v2/userinfo')) return json({ email: 'backup-owner@example.com' });
      if (value.includes('uploadType=resumable')) return new Response(null, { headers: { location: 'https://www.googleapis.com/upload/drive/v3/files?upload_id=test' } });
      if (value.includes('upload_id=test')) { for await (const chunk of options.body) assert.ok(chunk.length); if (failUpload) return new Response(null, { status: 503 }); uploadCount++; return json({ id: 'file-id' }); }
      if (value.includes('/files/file-id')) return json({ id: 'file-id', size: '9', md5Checksum: digest, trashed: false });
      if (options.method === 'POST' && value.startsWith('https://www.googleapis.com/drive/v3/files')) return json({ id: 'folder-id' });
      if (value.includes('/files/folder-id')) return json({ id: 'folder-id', trashed: false, appProperties: { namespace: (await pool.query('SELECT namespace FROM backup_settings')).rows[0].namespace } });
      if (value.includes('/files?')) { retentionCount++; enteredRetention(); await new Promise(resolve => { releaseRetention = resolve; }); return json({ files: [] }); }
      throw new Error('Unexpected Google request');
    },
    async archive({ directory }) {
      const path = join(directory, 'backup.cms');
      await writeFile(path, 'encrypted');
      return { path, size: 9, checksum: digest };
    },
  };
  const app = createApp({ pool, redis, config: { jwtSecret: 'test-secret-with-more-than-thirty-two-characters', origin: 'http://localhost:8080', secure: false, nodeEnv: 'test', authRateLimit: false, backup: backupConfig } });
  const backupServer = app.listen(0, '127.0.0.1');
  await new Promise(resolve => backupServer.once('listening', resolve));
  const backupBase = `http://127.0.0.1:${backupServer.address().port}/api`;
  const client = browser(backupBase); client.token = superAdmin.token;
  try {
    await browser(backupBase).request('/admin/backup/settings', { status: 401 });
    for (const denied of [ordinary, admin]) {
      const actor = browser(backupBase); actor.token = denied.token;
      await actor.request('/admin/backup/settings', { status: 403 });
      await actor.request('/admin/backup/run', { method: 'POST', status: 403 });
    }
    const settings = await client.request('/admin/backup/settings');
    assert.equal(settings.redirectUri, 'http://localhost:8080/api/backup/oauth/callback');
    assert.equal(settings.connected, false);
    assert.equal(settings.configured, true);
    await client.request('/admin/backup/run', { method: 'POST', status: 503 });
    const oauth = await client.request('/admin/backup/gdrive/oauth/start', { method: 'POST' });
    const authUrl = new URL(oauth.authUrl), state = authUrl.searchParams.get('state');
    assert.equal(authUrl.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(authUrl.searchParams.get('scope').includes('drive.file'));
    const callback = async (value, cookies = client.cookies) => fetch(`${backupBase}/backup/oauth/callback?state=${value}&code=test-code`, { redirect: 'manual', headers: { Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; ') } });
    const connected = await callback(state);
    assert.equal(connected.status, 303);
    assert.ok(connected.headers.get('location').endsWith('backupConnection=connected'));
    assert.ok((await callback(state)).headers.get('location').endsWith('backupConnection=failed'));
    const row = (await pool.query('SELECT token_ciphertext FROM backup_settings')).rows[0];
    assert.equal(row.token_ciphertext.includes('refresh-private'), false);
    const publicValue = await client.request('/admin/backup/settings');
    assert.equal(publicValue.connected, true);
    assert.equal(JSON.stringify(publicValue).includes('refresh-private'), false);
    await client.request('/admin/backup/settings', { method: 'PUT', body: { ...publicValue, remoteFolder: '../escape' }, status: 400 });
    await client.request('/admin/backup/settings', { method: 'PUT', body: { ...publicValue, enabled: true } });
    const run = await client.request('/admin/backup/run', { method: 'POST', status: 202 });
    await Promise.race([retentionEntered, new Promise((resolve, reject) => setTimeout(() => reject(new Error('Retention was not reached')), 3000))]);
    assert.equal((await client.request(`/admin/backup/runs/${run.id}`)).status, 'running');
    await client.request('/admin/backup/run', { method: 'POST', status: 409 });
    await client.request('/admin/backup/gdrive/disconnect', { method: 'POST', body: { confirm: true }, status: 409 });
    releaseRetention();
    let completed;
    for (let attempt = 0; attempt < 100; attempt++) {
      completed = await client.request(`/admin/backup/runs/${run.id}`);
      if (['success', 'failed'].includes(completed.status)) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(completed.status, 'success', completed.error);
    assert.equal(completed.checksum, digest);
    assert.ok(completed.verifiedAt);
    assert.equal(uploadCount, 1);
    assert.equal((await client.request('/admin/backup/runs')).items[0].id, run.id);
    failUpload = true;
    const failed = await client.request('/admin/backup/run', { method: 'POST', status: 202 });
    for (let attempt = 0; attempt < 100; attempt++) {
      completed = await client.request(`/admin/backup/runs/${failed.id}`);
      if (completed.status === 'failed') break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(completed.status, 'failed');
    assert.equal(retentionCount, 1, 'failed uploads must not trigger retention');
    assert.equal((await readdir(mailDir)).some(name => name.startsWith(`run-${failed.id}-`)), false);
    const staleId = randomUUID(), staleDir = join(mailDir, `run-${staleId}-orphan`), finishedDir = join(mailDir, `run-${run.id}-orphan`);
    await mkdir(staleDir); await mkdir(finishedDir);
    await writeFile(join(staleDir, 'private.sql'), 'must be removed');
    await pool.query("INSERT INTO backup_runs(id,kind,status,scope_db,scope_configs,settings,heartbeat_at) VALUES($1,'manual','running',true,true,'{}',now()-interval '5 minutes')", [staleId]);
    await app.locals.backup.start();
    await assert.rejects(access(staleDir)); await assert.rejects(access(finishedDir));
    assert.equal((await client.request(`/admin/backup/runs/${staleId}`)).status, 'failed');
    await client.request('/admin/backup/gdrive/disconnect', { method: 'POST', status: 400 });
    const disconnected = await client.request('/admin/backup/gdrive/disconnect', { method: 'POST', body: { confirm: true } });
    assert.equal(disconnected.connected, false);
    assert.equal(disconnected.enabled, false);
    const second = await client.request('/admin/backup/gdrive/oauth/start', { method: 'POST' });
    assert.ok((await callback(new URL(second.authUrl).searchParams.get('state'), new Map())).headers.get('location').endsWith('backupConnection=failed'));
    await pool.query('UPDATE backup_settings SET token_ciphertext=$1 WHERE id=true', [encryptBackupToken({ refresh_token: 'test' }, key)]);
    const revoked = await client.request('/admin/backup/gdrive/oauth/start', { method: 'POST' });
    await pool.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [superAdmin.user.id]);
    assert.ok((await callback(new URL(revoked.authUrl).searchParams.get('state'))).headers.get('location').endsWith('backupConnection=failed'));
  } finally {
    releaseRetention?.();
    await app.locals.backup.stop();
    await new Promise(resolve => backupServer.close(resolve));
    await pool.query('DELETE FROM backup_runs');
    await pool.query("UPDATE backup_settings SET enabled=false,token_ciphertext=NULL,account_email='',folder_id=NULL,last_slot=NULL");
    await pool.query("UPDATE users SET is_admin=false,app_role='user' WHERE id=ANY($1::uuid[])", [[admin.user.id, superAdmin.user.id]]);
  }
});

test('my tasks follows assignment and current membership across active workspaces', async () => {
  const owner = await account('my-tasks-owner');
  const member = await account('my-tasks-member');
  const outsider = await account('my-tasks-outsider');
  await browser().request('/me/tasks', { status: 401 });
  const cards = [];
  const workspaces = [];
  for (const name of ['First', 'Second']) {
    const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name } });
    workspaces.push(workspace);
    const invitation = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: member.user.email } });
    await member.request('/invitations/accept', { method: 'POST', body: { token: invitation.token } });
    const board = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: `${name} board`, color: '#0052cc' } });
    const list = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'To do' } });
    const card = await owner.request(`/lists/${list.id}/cards`, { method: 'POST', status: 201, body: { title: `${name} task` } });
    await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { assigneeIds: [member.user.id], dueDate: name === 'First' ? '2026-01-01' : null } });
    cards.push({ ...card, boardId: board.id, listId: list.id });
  }
  assert.deepEqual(await owner.request('/me/tasks'), []);
  assert.deepEqual(await outsider.request('/me/tasks'), []);
  let result = await member.request('/me/tasks');
  assert.equal(result.length, 2);
  assert.equal(result[0].id, cards[0].id);
  assert.equal(result[0].workspaceName, 'First');
  assert.equal(result[0].boardTitle, 'First board');
  assert.equal(result[0].listTitle, 'To do');
  assert.equal(result[0].dueDate, '2026-01-01T00:00:00.000Z');
  assert.equal(result[1].dueDate, null);
  assert.equal(result[0].description, undefined);
  await member.request(`/cards/${cards[0].id}`, { method: 'PATCH', body: { completed: true } });
  assert.equal((await member.request('/me/tasks')).find(c => c.id === cards[0].id).completed, true);
  await owner.request(`/cards/${cards[0].id}`, { method: 'PATCH', body: { archived: true } });
  assert.equal((await member.request('/me/tasks')).length, 1);
  await owner.request(`/cards/${cards[0].id}`, { method: 'PATCH', body: { archived: false } });
  await owner.request(`/lists/${cards[0].listId}`, { method: 'PATCH', body: { archived: true } });
  assert.equal((await member.request('/me/tasks')).length, 1);
  await owner.request(`/lists/${cards[0].listId}`, { method: 'PATCH', body: { archived: false } });
  await owner.request(`/boards/${cards[0].boardId}`, { method: 'PATCH', body: { closed: true } });
  assert.equal((await member.request('/me/tasks')).length, 1);
  await owner.request(`/boards/${cards[0].boardId}`, { method: 'PATCH', body: { closed: false } });
  await pool.query('UPDATE workspaces SET archived=true WHERE id=$1', [workspaces[0].id]);
  assert.equal((await member.request('/me/tasks')).length, 1);
  await pool.query('UPDATE workspaces SET archived=false WHERE id=$1', [workspaces[0].id]);
  await owner.request(`/cards/${cards[1].id}`, { method: 'PATCH', body: { assigneeIds: [] } });
  assert.equal((await member.request('/me/tasks')).length, 1);
  await pool.query('DELETE FROM memberships WHERE workspace_id=$1 AND user_id=$2', [workspaces[0].id, member.user.id]);
  assert.deepEqual(await member.request('/me/tasks'), []);
  await pool.query("UPDATE users SET is_admin=true,app_role='admin' WHERE id=$1", [outsider.user.id]);
  try { assert.deepEqual(await outsider.request('/me/tasks'), []); }
  finally { await pool.query("UPDATE users SET is_admin=false,app_role='user' WHERE id=$1", [outsider.user.id]); }
});

test('board dashboard counts active cards without double-counting totals or exposing private boards', async () => {
  const owner = await account('dashboard-owner'), member = await account('dashboard-member'), outsider = await account('dashboard-outsider');
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Dashboard workspace' } });
  const invitation = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: member.user.email } });
  await member.request('/invitations/accept', { method: 'POST', body: { token: invitation.token } });
  const board = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'Dashboard board' } });
  const list = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'Active' } });
  const empty = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'Empty' } });
  const hidden = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'Archived' } });
  for (const [title, dueDate, completed, assigneeIds, listId, archived] of [
    ['Late', '2026-10-24', false, [owner.user.id, member.user.id], list.id, false],
    ['Done', '2026-10-24', true, [member.user.id], list.id, false],
    ['Today', '2026-10-25', false, [owner.user.id], list.id, false],
    ['Later', '2026-10-26', false, [], list.id, false],
    ['Undated', null, false, [], list.id, false],
    ['Hidden card', null, false, [owner.user.id], list.id, true],
    ['Hidden list', null, false, [owner.user.id], hidden.id, false],
  ]) {
    const card = await owner.request(`/lists/${listId}/cards`, { method: 'POST', status: 201, body: { title } });
    await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { dueDate, completed, assigneeIds, archived } });
  }
  await owner.request(`/lists/${hidden.id}`, { method: 'PATCH', body: { archived: true } });
  const endpoint = `/boards/${board.id}/dashboard?today=2026-10-25`;
  const result = await member.request(endpoint);
  assert.deepEqual({ total: result.total, completed: result.completed, incomplete: result.incomplete, overdue: result.overdue, undated: result.undated, asOf: result.asOf }, { total: 5, completed: 1, incomplete: 4, overdue: 1, undated: 1, asOf: '2026-10-25' });
  assert.deepEqual(result.byList.map(({ id, total }) => ({ id, total })), [{ id: list.id, total: 5 }, { id: empty.id, total: 0 }]);
  assert.deepEqual(result.unassigned, { total: 2, completed: 0, overdue: 0 });
  assert.equal(result.byAssignee.find(x => x.id === owner.user.id).total, 2);
  assert.equal(result.byAssignee.find(x => x.id === member.user.id).completed, 1);
  assert.equal(result.byAssignee.find(x => x.id === member.user.id).overdue, 1);
  await browser().request(endpoint, { status: 401 });
  await outsider.request(endpoint, { status: 404 });
  for (const today of ['2026-02-30', 'invalid', '2026-10-25&today=2026-10-26']) await owner.request(`/boards/${board.id}/dashboard?today=${today}`, { status: 400 });
  await owner.request(`/boards/${board.id}`, { method: 'PATCH', body: { closed: true } });
  assert.equal((await owner.request(endpoint)).total, 5);
  await pool.query('DELETE FROM memberships WHERE workspace_id=$1 AND user_id=$2', [workspace.id, member.user.id]);
  await member.request(endpoint, { status: 404 });
  await pool.query('UPDATE workspaces SET archived=true WHERE id=$1', [workspace.id]);
  await owner.request(endpoint, { status: 409 });
});

test('only workspace owners remove members, clear assignments and revoke old pending invitations', async () => {
  const owner = await account('remove-owner'), adminMember = await account('remove-admin-member'), member = await account('remove-member');
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Removal permissions' } });
  for (const person of [adminMember, member]) {
    const invite = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: person.user.email } });
    await person.request('/invitations/accept', { method: 'POST', body: { token: invite.token } });
  }
  const board = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'Shared board' } });
  const list = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'To do' } });
  const card = await owner.request(`/lists/${list.id}/cards`, { method: 'POST', status: 201, body: { title: 'Keep shared content' } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { assigneeIds: [member.user.id] } });
  const pending = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: member.user.email } });
  await pool.query("UPDATE users SET is_admin=true,app_role='admin' WHERE id=$1", [adminMember.user.id]);
  try { await adminMember.request(`/workspaces/${workspace.id}/members/${member.user.id}`, { method: 'DELETE', status: 403 }); }
  finally { await pool.query("UPDATE users SET is_admin=false,app_role='user' WHERE id=$1", [adminMember.user.id]); }
  await owner.request(`/workspaces/${workspace.id}/members/${owner.user.id}`, { method: 'DELETE', status: 409 });
  await owner.request(`/workspaces/${workspace.id}/members/${member.user.id}`, { method: 'DELETE' });
  assert.deepEqual((await owner.request(`/cards/${card.id}`)).assigneeIds, []);
  assert.equal((await owner.request(`/cards/${card.id}`)).title, 'Keep shared content');
  assert.equal((await owner.request(`/workspaces/${workspace.id}/members`)).length, 2);
  for (const path of [`/workspaces/${workspace.id}`, `/boards/${board.id}`, `/cards/${card.id}`]) await member.request(path, { status: 404 });
  assert.deepEqual(await member.request('/me/tasks'), []);
  assert.deepEqual((await member.request('/notifications')).items, []);
  await member.request('/invitations/accept', { method: 'POST', body: { token: pending.token }, status: 400 });
  const log = (await pool.query("SELECT user_id,target_id FROM workspace_activity WHERE workspace_id=$1 AND action='member.removed'", [workspace.id])).rows;
  assert.deepEqual(log, [{ user_id: owner.user.id, target_id: member.user.id }]);
  const fresh = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: member.user.email } });
  await member.request('/invitations/accept', { method: 'POST', body: { token: fresh.token } });
  assert.equal((await member.request(`/boards/${board.id}`)).id, board.id);
});

test('CSRF bootstrap reports cookie presence without exposing the refresh token', async () => {
  const client = browser();
  assert.equal((await client.request('/auth/csrf')).hasSession, false);
  client.cookies.set('rt', 'not-a-valid-refresh-token');
  const data = await client.request('/auth/csrf');
  assert.equal(data.hasSession, true);
  assert.deepEqual(Object.keys(data).sort(), ['csrfToken', 'hasSession']);
  await client.request('/auth/renew', { method: 'POST', csrf: data.csrfToken, status: 401 });
});

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
  await mailQueue.drain();
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


test('profile appearance persists and deletion requires reauthentication while retaining shared content', async () => {
  const owner = await account('profile-owner'), member = await account('profile-member');
  assert.equal((await owner.request('/auth/me')).theme, 'system');
  await owner.request('/me', { method: 'PATCH', body: { displayName: 'New display name', theme: 'dark' } });
  const profile = await owner.request('/auth/me');
  assert.equal(profile.displayName, 'New display name');
  assert.equal(profile.theme, 'dark');
  await owner.request('/me', { method: 'PATCH', status: 400, body: { theme: 'invalid' } });
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Retained work' } });
  const invitation = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: member.user.email } });
  await member.request('/invitations/accept', { method: 'POST', body: { token: invitation.token } });
  const board = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'Shared board' } });
  const list = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'Todo' } });
  const card = await owner.request(`/lists/${list.id}/cards`, { method: 'POST', status: 201, body: { title: 'Retain me' } });
  await owner.request(`/cards/${card.id}/comments`, { method: 'POST', status: 201, body: { body: 'Shared context' } });
  await owner.request('/me', { method: 'DELETE', status: 400 });
  await owner.request('/me', { method: 'DELETE', status: 403, body: { confirm: 'DELETE', password: 'wrong' } });
  assert.equal((await owner.request('/auth/me')).id, owner.user.id);
  await owner.request('/me', { method: 'DELETE', status: 409, body: { confirm: 'DELETE', password: 'learning-password-123' } });
  await owner.request(`/workspaces/${workspace.id}/transfer`, { method: 'POST', body: { userId: member.user.id } });
  await owner.request('/me', { method: 'DELETE', body: { confirm: 'DELETE', password: 'learning-password-123' } });
  await owner.request('/auth/me', { status: 401 });
  const detail = await member.request(`/cards/${card.id}`);
  assert.equal(detail.comments[0].body, 'Shared context');
  assert.equal(detail.comments[0].displayName, 'Deleted user');
  assert.equal(detail.comments[0].userId, null);
});

test('assignment and comment notifications are private, deduplicated, readable and scoped to current membership', async () => {
  const owner = await account('notify-owner'), member = await account('notify-member'), outsider = await account('notify-outsider');
  const workspace = await owner.request('/workspaces', { method: 'POST', status: 201, body: { name: 'Notifications' } });
  const invitation = await owner.request(`/workspaces/${workspace.id}/invitations`, { method: 'POST', status: 201, body: { email: member.user.email } });
  await member.request('/invitations/accept', { method: 'POST', body: { token: invitation.token } });
  const board = await owner.request(`/workspaces/${workspace.id}/boards`, { method: 'POST', status: 201, body: { title: 'Inbox' } });
  const list = await owner.request(`/boards/${board.id}/lists`, { method: 'POST', status: 201, body: { title: 'Todo' } });
  const card = await owner.request(`/lists/${list.id}/cards`, { method: 'POST', status: 201, body: { title: 'Review UI' } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { assigneeIds: [member.user.id] } });
  await owner.request(`/cards/${card.id}`, { method: 'PATCH', body: { assigneeIds: [member.user.id] } });
  let inbox = await member.request('/notifications');
  assert.equal(inbox.unreadCount, 1);
  const first = inbox.items[0];
  assert.equal(first.kind, 'assigned');
  assert.equal(first.cardTitle, 'Review UI');
  assert.equal((await outsider.request('/notifications')).items.length, 0);
  await outsider.request(`/notifications/${first.id}`, { method: 'PATCH', status: 404, body: { read: true } });
  await outsider.request(`/notifications/${first.id}`, { method: 'DELETE', status: 404 });
  await member.request(`/notifications/${first.id}`, { method: 'PATCH', body: { read: true } });
  assert.equal((await member.request('/notifications')).unreadCount, 0);
  await owner.request(`/cards/${card.id}/comments`, { method: 'POST', status: 201, body: { body: 'Please review' } });
  await member.request(`/cards/${card.id}/comments`, { method: 'POST', status: 201, body: { body: 'On it' } });
  inbox = await member.request('/notifications');
  assert.equal(inbox.items.length, 2);
  assert.equal(inbox.unreadCount, 1);
  await member.request('/notifications/read-all', { method: 'PATCH' });
  assert.equal((await member.request('/notifications')).unreadCount, 0);
  await member.request(`/notifications/${first.id}`, { method: 'DELETE' });
  assert.equal((await member.request('/notifications')).items.length, 1);
  await owner.request(`/workspaces/${workspace.id}/members/${member.user.id}`, { method: 'DELETE' });
  assert.equal((await member.request('/notifications')).items.length, 0);
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
    const legacyUser = randomUUID();
    await client.query('INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,$3,$4)', [legacyUser, 'legacy@example.com', 'Legacy learner', 'unused']);
    const workspaceId = randomUUID(), boardId = randomUUID(), listId = randomUUID(), cardId = randomUUID();
    await client.query('INSERT INTO workspaces(id,name) VALUES($1,$2)', [workspaceId, 'Existing workspace']);
    await client.query('INSERT INTO boards(id,workspace_id,title) VALUES($1,$2,$3)', [boardId, workspaceId, 'Existing board']);
    await client.query('INSERT INTO lists(id,board_id,title,position) VALUES($1,$2,$3,0)', [listId, boardId, 'Existing list']);
    await client.query('INSERT INTO cards(id,list_id,title,description,position,archived) VALUES($1,$2,$3,$4,2,true)', [cardId, listId, 'Existing card', 'Preserve me']);
    const scopedPool = { connect: async () => ({ query: client.query.bind(client), release() {} }) };
    await migrate(scopedPool);
    await migrate(scopedPool);
    assert.ok((await client.query('SELECT email_verified_at FROM users WHERE id=$1', [legacyUser])).rows[0].email_verified_at);
    const row = (await client.query('SELECT * FROM cards WHERE id=$1', [cardId])).rows[0];
    assert.equal(row.description, 'Preserve me');
    assert.equal(row.position, 2);
    assert.equal(row.archived, true);
    assert.deepEqual(row.label_ids, []);
    assert.deepEqual(row.assignee_ids, []);
    assert.equal(row.completed, false);
    assert.equal(row.due_date, null);
    assert.equal((await client.query('SELECT wip_limit FROM lists WHERE id=$1', [listId])).rows[0].wip_limit, null);
    const migrations = (await readdir(new URL('../migrations/', import.meta.url))).filter(name => /^\d+_[\w-]+\.sql$/.test(name));
    assert.equal((await client.query('SELECT count(*)::int AS count FROM schema_migrations')).rows[0].count, migrations.length);
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
  await mailQueue.drain();
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

test('new accounts require single-use verification; registration stays generic and issues no session', async () => {
  const client = browser(), address = `verify-${suffix}@example.com`;
  const body = { email: address, password: 'learning-password-123', displayName: 'Verify learner' };
  const first = await client.request('/auth/register', { method: 'POST', status: 202, body });
  await mailQueue.drain();
  const duplicate = await client.request('/auth/register', { method: 'POST', status: 202, body });
  assert.deepEqual(first, duplicate);
  assert.equal(client.token, null);
  assert.equal(client.cookies.has('rt'), false);
  await client.request('/auth/login', { method: 'POST', status: 403, body });
  await mailQueue.drain();
  const user = (await pool.query('SELECT * FROM users WHERE email=$1', [address])).rows[0];
  const message = JSON.parse(await readFile(join(mailDir, `${user.id}.verify.json`), 'utf8'));
  let token = new URL(message.resetUrl).searchParams.get('token');
  await pool.query("UPDATE email_verifications SET expires_at=now()-interval '1 second' WHERE token_hash=$1", [hash(token)]);
  await client.request('/auth/verify-email', { method: 'POST', status: 400, body: { token } });
  await client.request('/auth/resend-verification', { method: 'POST', body: { email: address } });
  await mailQueue.drain();
  token = new URL(JSON.parse(await readFile(join(mailDir, `${user.id}.verify.json`), 'utf8')).resetUrl).searchParams.get('token');
  assert.equal((await pool.query('SELECT 1 FROM email_verifications WHERE token_hash=$1', [token])).rowCount, 0);
  await client.request('/auth/verify-email', { method: 'POST', body: { token } });
  await client.request('/auth/verify-email', { method: 'POST', status: 400, body: { token } });
  await client.request('/auth/login', { method: 'POST', body });
  const audits = (await pool.query('SELECT * FROM auth_audit WHERE user_id=$1', [user.id])).rows;
  assert.ok(audits.some(row => row.action === 'auth.email.verified'));
  assert.doesNotMatch(JSON.stringify(audits), new RegExp(`${token}|learning-password|${address}`));
});

test('password change and explicit logout-all revoke every access and refresh session', async () => {
  const first = await account('password-change'), second = browser();
  const credentials = { email: first.user.email, password: 'learning-password-123' };
  await second.request('/auth/login', { method: 'POST', body: credentials });
  await first.request('/auth/change-password', { method: 'POST', status: 403, body: { currentPassword: 'incorrect-password', newPassword: 'new-learning-password-456' } });
  await first.request('/auth/change-password', { method: 'POST', body: { currentPassword: credentials.password, newPassword: 'new-learning-password-456' } });
  for (const client of [first, second]) {
    await client.request('/auth/me', { status: 401 });
    const { csrfToken } = await client.request('/auth/csrf');
    await client.request('/auth/renew', { method: 'POST', csrf: csrfToken, status: 401 });
    await client.request('/auth/login', { method: 'POST', body: { ...credentials, password: 'new-learning-password-456' } });
  }
  await first.request('/auth/logout-all', { method: 'POST', status: 400 });
  await first.request('/auth/logout-all', { method: 'POST', body: { confirm: true } });
  for (const client of [first, second]) await client.request('/auth/me', { status: 401 });
});

test('rate limits normalize identifiers, enforce minute/hour budgets and exponential login cooldown', async () => {
  const prefix = `test-${randomUUID()}`;
  const limited = createApp({ pool, redis, config: { jwtSecret: 'test-secret-with-more-than-thirty-two-characters', origin: 'http://localhost:8080', nodeEnv: 'test', secure: false, authRatePrefix: prefix, trustProxy: 1 } }).listen(0, '127.0.0.1');
  await new Promise(resolve => limited.once('listening', resolve));
  const endpoint = `http://127.0.0.1:${limited.address().port}/api/auth`;
  const request = (path, address, ip = '192.0.2.10') => fetch(`${endpoint}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip }, body: JSON.stringify({ email: address, password: 'wrong-password-123' }) });
  const address = `rate-${suffix}@example.com`;
  const clearMinute = async (path, ip = '192.0.2.10') => {
    for (const scope of [`ip:${ip}`, `email:${hash(address)}`]) await redis.del(`${prefix}-rate:${hash(`${scope}:${path}:60`)}`);
  };
  try {
    assert.equal((await request('/forgot-password', `  ${address.toUpperCase()}  `)).status, 200);
    const throttled = await request('/forgot-password', address, '192.0.2.11');
    assert.equal(throttled.status, 429);
    assert.ok(Number(throttled.headers.get('Retry-After')) > 0);
    for (let i = 0; i < 2; i++) { await clearMinute('/forgot-password'); assert.equal((await request('/forgot-password', address)).status, 200); }
    await clearMinute('/forgot-password');
    assert.equal((await request('/forgot-password', address)).status, 429);
    for (let i = 0; i < 5; i++) { await clearMinute('/resend-verification'); assert.equal((await request('/resend-verification', address)).status, 200); }
    await clearMinute('/resend-verification');
    assert.equal((await request('/resend-verification', address)).status, 429);
    for (let i = 0; i < 5; i++) assert.equal((await request('/login', i % 2 ? address : ` ${address.toUpperCase()} `)).status, 401);
    const blocked = await request('/login', address, '192.0.2.12');
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get('Retry-After')) >= 900);
    const audit = await pool.query("SELECT 1 FROM auth_audit WHERE action='auth.throttled' AND identifier_hash=$1", [hash(address)]);
    assert.ok(audit.rowCount > 0);
  } finally {
    await new Promise(resolve => limited.close(resolve));
    const keys = [];
    for await (const key of redis.scanIterator({ MATCH: `${prefix}-*`, COUNT: 100 })) keys.push(...(Array.isArray(key) ? key : [key]));
    if (keys.length) await redis.del(keys);
  }
});

test('bootstrap is atomic, survives restart/deletion, protects final super admin and preserves private board scope', async () => {
  const schema = `bootstrap_${randomUUID().replaceAll('-', '')}`;
  await pool.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(process.env.TEST_DATABASE_URL);
  url.searchParams.set('options', `-csearch_path=${schema}`);
  const isolated = database(url.toString());
  const configuration = { jwtSecret: 'test-secret-with-more-than-thirty-two-characters', origin: 'http://localhost:8080', secure: false, nodeEnv: 'test', setupToken: 'test-setup-token-more-than-thirty-two-characters', authRateLimit: false };
  let setupServer;
  const start = async () => {
    setupServer = createApp({ pool: isolated, redis, config: configuration }).listen(0, '127.0.0.1');
    await new Promise(resolve => setupServer.once('listening', resolve));
    return `http://127.0.0.1:${setupServer.address().port}/api`;
  };
  try {
    await migrate(isolated);
    let root = await start();
    const setup = browser(root);
    assert.deepEqual(await setup.request('/auth/bootstrap/status'), { available: true });
    await setup.request('/auth/bootstrap/register', { method: 'POST', status: 404, body: { setupToken: 'incorrect' } });
    const body = { setupToken: configuration.setupToken, email: `super-${suffix}@example.com`, password: 'learning-password-123', displayName: 'Owner' };
    const results = await Promise.all([1, 2].map(index => fetch(`${root}/auth/bootstrap/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...body, email: `super-${index}-${suffix}@example.com` }) })));
    assert.deepEqual(results.map(result => result.status).sort(), [201, 404]);
    const created = await results.find(result => result.status === 201).json();
    assert.equal(created.user.appRole, 'super_admin');
    assert.equal(created.user.isAdmin, true);
    setup.token = created.accessToken;
    await setup.request(`/admin/users/${created.user.id}`, { method: 'PATCH', status: 409, body: { suspended: true, confirm: true } });
    await setup.request('/me', { method: 'DELETE', status: 409, body: { confirm: 'DELETE', password: body.password } });
    const privateOwner = randomUUID(), privateWorkspace = randomUUID(), privateBoard = randomUUID();
    await isolated.query('INSERT INTO users(id,email,display_name,password_hash,email_verified_at) VALUES($1,$2,$3,$4,now())', [privateOwner, 'private@example.com', 'Private owner', 'unused']);
    await isolated.query('INSERT INTO workspaces(id,name) VALUES($1,$2)', [privateWorkspace, 'Private workspace']);
    await isolated.query("INSERT INTO memberships(workspace_id,user_id,role) VALUES($1,$2,'owner')", [privateWorkspace, privateOwner]);
    await isolated.query('INSERT INTO boards(id,workspace_id,title) VALUES($1,$2,$3)', [privateBoard, privateWorkspace, 'Private board']);
    await setup.request(`/boards/${privateBoard}`, { status: 404 });
    await setup.request('/auth/bootstrap/status', { status: 404 });
    await assert.rejects(isolated.query('UPDATE bootstrap_state SET completed_at=NULL'));
    await assert.rejects(isolated.query('DELETE FROM bootstrap_state'));
    await isolated.query('DELETE FROM users WHERE id=$1', [created.user.id]);
    await new Promise(resolve => setupServer.close(resolve));
    root = await start();
    const restarted = browser(root);
    await restarted.request('/auth/bootstrap/status', { status: 404 });
    await restarted.request('/auth/bootstrap/register', { method: 'POST', status: 404, body });
  } finally {
    if (setupServer) await new Promise(resolve => setupServer.close(resolve));
    await isolated.end();
    await pool.query(`DROP SCHEMA ${schema} CASCADE`);
  }
});
