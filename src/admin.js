import { randomUUID } from 'node:crypto';
import { fail } from './auth.js';
import { transaction } from './db.js';

export const adminUser = row => ({ id: row.id, email: row.email, displayName: row.display_name, isAdmin: row.is_admin, suspended: !!row.suspended_at, createdAt: row.created_at });
export async function audit(client, actorId, action, targetType, targetId, details = {}) {
  await client.query('INSERT INTO admin_audit(id,actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5,$6)', [randomUUID(), actorId, action, targetType, targetId, JSON.stringify({ ...details, outcome: 'success' })]);
}
export async function requireAdmin(client, actorId, mutation = false) {
  if (mutation) await client.query('SELECT pg_advisory_xact_lock(721544)');
  const actor = (await client.query('SELECT is_admin,suspended_at FROM users WHERE id=$1', [actorId])).rows[0];
  if (!actor?.is_admin || actor.suspended_at) fail(403, 'ADMIN_REQUIRED', 'Application administrator access required.');
}
export async function workspaceActive(client, workspaceId) {
  const row = (await client.query('SELECT archived FROM workspaces WHERE id=$1', [workspaceId])).rows[0];
  if (row?.archived) fail(409, 'WORKSPACE_ARCHIVED', 'This workspace is archived. Ask an application administrator to restore it.');
}
export function installArchiveGuard(app, { pool }) {
  app.use('/api', async (req, res, next) => {
    if (req.method === 'GET' || req.path.startsWith('/admin/')) return next();
    const [resource, resourceId] = req.path.split('/').filter(Boolean);
    if (!resourceId || !/^[0-9a-f-]{36}$/i.test(resourceId)) return next();
    const lookups = {
      workspaces: 'SELECT id AS workspace_id FROM workspaces WHERE id=$1',
      boards: 'SELECT workspace_id FROM boards WHERE id=$1',
      lists: 'SELECT b.workspace_id FROM lists l JOIN boards b ON b.id=l.board_id WHERE l.id=$1',
      cards: 'SELECT b.workspace_id FROM cards c JOIN lists l ON l.id=c.list_id JOIN boards b ON b.id=l.board_id WHERE c.id=$1',
      labels: 'SELECT b.workspace_id FROM labels l JOIN boards b ON b.id=l.board_id WHERE l.id=$1',
      views: 'SELECT b.workspace_id FROM saved_views v JOIN boards b ON b.id=v.board_id WHERE v.id=$1',
      checklists: 'SELECT b.workspace_id FROM checklists k JOIN cards c ON c.id=k.card_id JOIN lists l ON l.id=c.list_id JOIN boards b ON b.id=l.board_id WHERE k.id=$1',
      'checklist-items': 'SELECT b.workspace_id FROM checklist_items i JOIN checklists k ON k.id=i.checklist_id JOIN cards c ON c.id=k.card_id JOIN lists l ON l.id=c.list_id JOIN boards b ON b.id=l.board_id WHERE i.id=$1',
      comments: 'SELECT b.workspace_id FROM comments m JOIN cards c ON c.id=m.card_id JOIN lists l ON l.id=c.list_id JOIN boards b ON b.id=l.board_id WHERE m.id=$1',
    };
    if (!lookups[resource]) return next();
    const row = (await pool.query(lookups[resource], [resourceId])).rows[0];
    if (row) {
      const membership = await pool.query('SELECT 1 FROM memberships WHERE workspace_id=$1 AND user_id=$2', [row.workspace_id, req.user.id]);
      if (membership.rowCount) await workspaceActive(pool, row.workspace_id);
    }
    next();
  });
}
export function installAdmin(app, { pool, id, bool }) {
  app.use('/api/admin', async (req, res, next) => { await requireAdmin(pool, req.user.id); next(); });
  function confirmed(req) { if (req.body.confirm !== true) fail(400, 'CONFIRM_REQUIRED', 'Confirm this administrator action.'); }
  async function page(req, base, params = [], order = 'id') {
    const number = (value, fallback, max) => {
      if (value === undefined) return fallback;
      if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > max) fail(400, 'VALIDATION_ERROR', 'Invalid pagination.');
      return Number(value);
    };
    const page = number(req.query.page, 1, 1000000), pageSize = number(req.query.pageSize, 20, 100);
    const total = (await pool.query(`SELECT count(*)::int AS total FROM (${base}) result`, params)).rows[0].total;
    const items = (await pool.query(`${base} ORDER BY ${order} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`, [...params, pageSize, (page - 1) * pageSize])).rows;
    return { items, total, page, pageSize };
  }
  function search(req) {
    if (req.query.q !== undefined && (typeof req.query.q !== 'string' || req.query.q.length > 200)) fail(400, 'VALIDATION_ERROR', 'Search must be at most 200 characters.');
    return `%${(req.query.q || '').replace(/[\\%_]/g, value => '\\' + value)}%`;
  }
  app.get('/api/admin/overview', async (req, res) => {
    const row = (await pool.query(`SELECT (SELECT count(*)::int FROM users) AS users,
      (SELECT count(*)::int FROM users WHERE suspended_at IS NULL) AS "activeUsers",
      (SELECT count(*)::int FROM users WHERE suspended_at IS NOT NULL) AS "suspendedUsers",
      (SELECT count(*)::int FROM users WHERE is_admin AND suspended_at IS NULL) AS admins,
      (SELECT count(*)::int FROM workspaces) AS workspaces,
      (SELECT count(*)::int FROM workspaces WHERE archived) AS "archivedWorkspaces",
      (SELECT count(*)::int FROM boards) AS boards,
      (SELECT count(*)::int FROM boards WHERE closed) AS "closedBoards"`)).rows[0];
    res.json(row);
  });
  app.get('/api/admin/users', async (req, res) => {
    const result = await page(req, 'SELECT id,email,display_name,is_admin,suspended_at,created_at FROM users WHERE email ILIKE $1 OR display_name ILIKE $1', [search(req)], 'created_at DESC,id');
    res.json({ ...result, items: result.items.map(adminUser) });
  });
  app.patch('/api/admin/users/:id', async (req, res) => {
    confirmed(req);
    if (req.body.isAdmin === undefined && req.body.suspended === undefined) fail(400, 'VALIDATION_ERROR', 'Choose an account change.');
    const value = await transaction(pool, async client => {
      await requireAdmin(client, req.user.id, true);
      const target = (await client.query('SELECT * FROM users WHERE id=$1 FOR UPDATE', [id(req.params.id)])).rows[0];
      if (!target) fail(404, 'NOT_FOUND', 'Account not found.');
      const isAdmin = req.body.isAdmin === undefined ? target.is_admin : bool(req.body.isAdmin, 'Administrator');
      const suspended = req.body.suspended === undefined ? !!target.suspended_at : bool(req.body.suspended, 'Suspended');
      if (target.is_admin && !target.suspended_at && (!isAdmin || suspended)) {
        const remaining = (await client.query('SELECT count(*)::int AS count FROM users WHERE is_admin AND suspended_at IS NULL AND id<>$1', [target.id])).rows[0].count;
        if (!remaining) fail(409, 'LAST_ADMIN', 'The last active application administrator cannot be suspended or removed.');
      }
      const revoke = (isAdmin !== target.is_admin && !isAdmin) || (suspended && !target.suspended_at);
      const row = (await client.query('UPDATE users SET is_admin=$1,suspended_at=CASE WHEN $2 THEN COALESCE(suspended_at,now()) ELSE NULL END,token_version=token_version+$3 WHERE id=$4 RETURNING *', [isAdmin, suspended, revoke ? 1 : 0, target.id])).rows[0];
      if (revoke) await client.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [target.id]);
      await audit(client, req.user.id, 'user.updated', 'user', target.id, { before: { isAdmin: target.is_admin, suspended: !!target.suspended_at }, after: { isAdmin, suspended } });
      return adminUser(row);
    });
    res.json(value);
  });
  app.get('/api/admin/workspaces', async (req, res) => {
    res.json(await page(req, `SELECT w.id,w.name,w.archived,w.created_at AS "createdAt",
      (SELECT count(*)::int FROM memberships WHERE workspace_id=w.id) AS "memberCount",
      (SELECT count(*)::int FROM boards WHERE workspace_id=w.id) AS "boardCount" FROM workspaces w WHERE w.name ILIKE $1`, [search(req)], 'w.created_at DESC,w.id'));
  });
  app.get('/api/admin/workspaces/:id/members', async (req, res) => {
    const workspace = await pool.query('SELECT 1 FROM workspaces WHERE id=$1', [id(req.params.id)]);
    if (!workspace.rowCount) fail(404, 'NOT_FOUND', 'Workspace not found.');
    res.json((await pool.query('SELECT u.id,u.email,u.display_name AS "displayName",m.role,(u.suspended_at IS NOT NULL) AS suspended FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.workspace_id=$1 ORDER BY u.display_name,u.id', [req.params.id])).rows);
  });
  app.patch('/api/admin/workspaces/:id', async (req, res) => {
    confirmed(req); const archived = bool(req.body.archived, 'Archived');
    const row = await transaction(pool, async client => {
      await requireAdmin(client, req.user.id, true);
      const row = (await client.query('UPDATE workspaces SET archived=$1 WHERE id=$2 RETURNING id,name,archived,created_at AS "createdAt"', [archived, id(req.params.id)])).rows[0];
      if (!row) fail(404, 'NOT_FOUND', 'Workspace not found.');
      await audit(client, req.user.id, archived ? 'workspace.archived' : 'workspace.restored', 'workspace', row.id);
      return row;
    });
    res.json(row);
  });
  app.get('/api/admin/boards', async (req, res) => {
    res.json(await page(req, `SELECT b.id,b.workspace_id AS "workspaceId",w.name AS "workspaceName",b.title,b.closed,w.archived AS "workspaceArchived",b.created_at AS "createdAt" FROM boards b JOIN workspaces w ON w.id=b.workspace_id WHERE b.title ILIKE $1 OR w.name ILIKE $1`, [search(req)], 'b.created_at DESC,b.id'));
  });
  app.patch('/api/admin/boards/:id', async (req, res) => {
    confirmed(req); const closed = bool(req.body.closed, 'Closed');
    const row = await transaction(pool, async client => {
      await requireAdmin(client, req.user.id, true);
      const row = (await client.query('UPDATE boards SET closed=$1 WHERE id=$2 RETURNING id,title,closed,workspace_id AS "workspaceId"', [closed, id(req.params.id)])).rows[0];
      if (!row) fail(404, 'NOT_FOUND', 'Board not found.');
      await audit(client, req.user.id, closed ? 'board.closed' : 'board.reopened', 'board', row.id);
      return row;
    });
    res.json(row);
  });
  app.get('/api/admin/audit', async (req, res) => {
    const params = [], clauses = [];
    if (req.query.actorId !== undefined) { id(req.query.actorId); params.push(req.query.actorId); clauses.push(`a.actor_id=$${params.length}`); }
    if (req.query.action !== undefined) {
      if (typeof req.query.action !== 'string' || req.query.action.length > 80) fail(400, 'VALIDATION_ERROR', 'Invalid audit action.');
      params.push(req.query.action); clauses.push(`a.action=$${params.length}`);
    }
    const base = `SELECT a.id,a.actor_id AS "actorId",u.email AS "actorEmail",a.action,a.target_type AS "targetType",a.target_id AS "targetId",a.created_at AS "createdAt",a.details FROM admin_audit a LEFT JOIN users u ON u.id=a.actor_id${clauses.length ? ` WHERE ${clauses.join(' AND ')}` : ''}`;
    res.json(await page(req, base, params, 'a.created_at DESC,a.id'));
  });
}
