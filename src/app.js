import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { randomUUID } from 'node:crypto';
import { installAuth, fail, text, email, hash, secretToken } from './auth.js';
import { transaction } from './db.js';
import { installAdmin, installArchiveGuard, workspaceActive } from './admin.js';
import { installTaskManagement, cardExtras, cardDetails, editCardExtras, logActivity } from './tasks.js';
import { installNotifications, notifyCard } from './notifications.js';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function id(value) {
  if (value !== undefined && (typeof value !== 'string' || !uuid.test(value))) fail(400, 'VALIDATION_ERROR', 'Invalid ID.');
  return value || randomUUID();
}
function bool(value, name) {
  if (typeof value !== 'boolean') fail(400, 'VALIDATION_ERROR', `${name} must be true or false.`);
  return value;
}
function position(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail(400, 'VALIDATION_ERROR', 'Position must be a nonnegative integer.');
  return value;
}
function color(value) {
  if (typeof value !== 'string' || !/^#[0-9a-f]{6}$/i.test(value)) fail(400, 'VALIDATION_ERROR', 'Use a six-digit hex color.');
  return value;
}
const listData = row => ({ id: row.id, boardId: row.board_id, title: row.title, position: row.position, archived: row.archived, wipLimit: row.wip_limit ?? null });
const cardData = row => ({ id: row.id, listId: row.list_id, title: row.title, description: row.description, position: row.position, archived: row.archived, ...cardExtras(row) });
const boardData = row => ({ id: row.id, workspaceId: row.workspace_id, title: row.title, color: row.color, closed: row.closed, favorite: row.favorite || false, lastOpenedAt: row.last_opened_at || null, workspaceArchived: row.workspace_archived || false });

export function createApp({ pool, redis, config }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet(), express.json({ limit: '64kb' }), cookieParser());
  app.use((req, res, next) => { req.body ||= {}; next(); });
  app.get(['/health', '/api/health'], async (req, res) => {
    await pool.query('SELECT 1');
    await redis.ping();
    res.json({ status: 'ok' });
  });
  const authenticate = installAuth(app, { pool, redis, config });
  app.use('/api', authenticate);
  app.use('/api', (req, res, next) => {
    for (const part of req.path.split('/')) {
      if (part.length === 36 && part.includes('-') && !uuid.test(part)) return next(Object.assign(new Error('Invalid ID.'), { status: 400, code: 'VALIDATION_ERROR' }));
    }
    next();
  });
  installArchiveGuard(app, { pool });
  async function membership(client, workspaceId, userId, owner = false) {
    const { rows: [row] } = await client.query('SELECT w.*,m.role FROM workspaces w JOIN memberships m ON m.workspace_id=w.id WHERE w.id=$1 AND m.user_id=$2', [workspaceId, userId]);
    if (!row) fail(404, 'NOT_FOUND', 'Workspace not found.');
    if (row.archived) fail(409, 'WORKSPACE_ARCHIVED', 'This workspace is archived. Ask an application administrator to restore it.');
    if (owner && row.role !== 'owner') fail(403, 'FORBIDDEN', 'Workspace owner access required.');
    return row;
  }
  async function boardAccess(client, boardId, userId, { lock = false, write = false } = {}) {
    const { rows: [board] } = await client.query(`SELECT b.*,w.archived AS workspace_archived FROM boards b JOIN workspaces w ON w.id=b.workspace_id JOIN memberships m ON m.workspace_id=b.workspace_id WHERE b.id=$1 AND m.user_id=$2${lock ? ' FOR UPDATE OF b' : ''}`, [boardId, userId]);
    if (!board) fail(404, 'NOT_FOUND', 'Board not found.');
    if (board.workspace_archived) fail(409, 'WORKSPACE_ARCHIVED', 'Restore the workspace before editing.');
    if (write && board.closed) fail(409, 'BOARD_CLOSED', 'Reopen the board before editing.');
    return board;
  }
  async function listAccess(client, listId, userId, options) {
    const { rows: [list] } = await client.query('SELECT * FROM lists WHERE id=$1', [listId]);
    if (!list) fail(404, 'NOT_FOUND', 'List not found.');
    await boardAccess(client, list.board_id, userId, options);
    return (await client.query('SELECT * FROM lists WHERE id=$1', [listId])).rows[0];
  }
  async function cardAccess(client, cardId, userId, options) {
    const { rows: [row] } = await client.query('SELECT c.*,l.board_id,b.workspace_id FROM cards c JOIN lists l ON l.id=c.list_id JOIN boards b ON b.id=l.board_id WHERE c.id=$1', [cardId]);
    if (!row) fail(404, 'NOT_FOUND', 'Card not found.');
    await boardAccess(client, row.board_id, userId, options);
    return (await client.query('SELECT c.*,l.board_id,b.workspace_id FROM cards c JOIN lists l ON l.id=c.list_id JOIN boards b ON b.id=l.board_id WHERE c.id=$1', [cardId])).rows[0];
  }
  const workspaceData = row => ({ id: row.id, name: row.name, role: row.role, archived: row.archived || false });
  app.get('/api/workspaces', async (req, res) => {
    const { rows } = await pool.query('SELECT w.*,m.role FROM workspaces w JOIN memberships m ON m.workspace_id=w.id WHERE m.user_id=$1 AND NOT w.archived ORDER BY w.created_at,w.id', [req.user.id]);
    res.json(rows.map(workspaceData));
  });
  app.post('/api/workspaces', async (req, res) => {
    const value = await transaction(pool, async client => {
      const { rows: [workspace] } = await client.query('INSERT INTO workspaces(id,name) VALUES($1,$2) RETURNING *', [id(req.body.id), text(req.body.name, 'Workspace name', 100)]);
      await client.query('INSERT INTO memberships(workspace_id,user_id,role) VALUES($1,$2,\'owner\')', [workspace.id, req.user.id]);
      return { ...workspace, role: 'owner' };
    });
    res.status(201).json(workspaceData(value));
  });
  app.get('/api/workspaces/:id', async (req, res) => res.json(workspaceData(await membership(pool, req.params.id, req.user.id))));
  app.patch('/api/workspaces/:id', async (req, res) => {
    await membership(pool, req.params.id, req.user.id, true);
    const { rows: [row] } = await pool.query('UPDATE workspaces SET name=$1 WHERE id=$2 RETURNING *', [text(req.body.name, 'Workspace name', 100), req.params.id]);
    res.json(workspaceData({ ...row, role: 'owner' }));
  });
  app.get('/api/workspaces/:id/members', async (req, res) => {
    await membership(pool, req.params.id, req.user.id);
    const { rows } = await pool.query('SELECT u.id,u.email,u.display_name,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.workspace_id=$1 ORDER BY m.role DESC,u.display_name', [req.params.id]);
    res.json(rows.map(row => ({ id: row.id, email: row.email, displayName: row.display_name, role: row.role })));
  });
  app.delete('/api/workspaces/:id/members/:userId', async (req, res) => {
    await transaction(pool, async client => {
      await client.query('SELECT id FROM workspaces WHERE id=$1 FOR UPDATE', [req.params.id]);
      await membership(client, req.params.id, req.user.id, true);
      const { rows: [member] } = await client.query('SELECT role FROM memberships WHERE workspace_id=$1 AND user_id=$2', [req.params.id, req.params.userId]);
      if (!member) fail(404, 'NOT_FOUND', 'Member not found.');
      if (member.role === 'owner') {
        const { rows: [count] } = await client.query('SELECT count(*)::int AS count FROM memberships WHERE workspace_id=$1 AND role=\'owner\'', [req.params.id]);
        if (count.count <= 1) fail(409, 'LAST_OWNER', 'The last workspace owner cannot be removed.');
      }
      await client.query('DELETE FROM memberships WHERE workspace_id=$1 AND user_id=$2', [req.params.id, req.params.userId]);
      await client.query('UPDATE cards SET assignee_ids=array_remove(assignee_ids,$1) WHERE list_id IN(SELECT l.id FROM lists l JOIN boards b ON b.id=l.board_id WHERE b.workspace_id=$2)', [req.params.userId, req.params.id]);
    });
    res.json({ message: 'Member removed.' });
  });
  app.post('/api/workspaces/:id/invitations', async (req, res) => {
    await membership(pool, req.params.id, req.user.id, true);
    const normalized = email(req.body.email);
    const token = secretToken();
    const { rows: [row] } = await pool.query('INSERT INTO invitations(id,workspace_id,email,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval \'7 days\') RETURNING *', [randomUUID(), req.params.id, normalized, hash(token)]);
    res.status(201).json({ id: row.id, email: row.email, token, expiresAt: row.expires_at });
  });
  app.get('/api/workspaces/:id/invitations', async (req, res) => {
    await membership(pool, req.params.id, req.user.id, true);
    const { rows } = await pool.query('SELECT id,email,expires_at,accepted_at,revoked FROM invitations WHERE workspace_id=$1 ORDER BY expires_at DESC', [req.params.id]);
    res.json(rows.map(row => ({ id: row.id, email: row.email, expiresAt: row.expires_at, acceptedAt: row.accepted_at, revoked: row.revoked })));
  });
  app.delete('/api/workspaces/:id/invitations/:invitationId', async (req, res) => {
    await membership(pool, req.params.id, req.user.id, true);
    await pool.query('UPDATE invitations SET revoked=true WHERE id=$1 AND workspace_id=$2', [req.params.invitationId, req.params.id]);
    res.json({ message: 'Invitation revoked.' });
  });
  app.post('/api/invitations/accept', async (req, res) => {
    const workspace = await transaction(pool, async client => {
      const { rows: [invitation] } = await client.query('SELECT * FROM invitations WHERE token_hash=$1 AND accepted_at IS NULL AND NOT revoked AND expires_at>now() FOR UPDATE', [hash(text(req.body.token, 'Token'))]);
      if (!invitation || invitation.email !== req.user.email) fail(400, 'INVALID_INVITATION', 'Invitation is invalid, expired, or belongs to another account.');
      await workspaceActive(client, invitation.workspace_id);
      await client.query('INSERT INTO memberships(workspace_id,user_id,role) VALUES($1,$2,\'member\') ON CONFLICT DO NOTHING', [invitation.workspace_id, req.user.id]);
      await client.query('UPDATE invitations SET accepted_at=now() WHERE id=$1', [invitation.id]);
      return membership(client, invitation.workspace_id, req.user.id);
    });
    res.json(workspaceData(workspace));
  });
  const boardsQuery = 'SELECT b.*,w.archived AS workspace_archived,p.favorite,p.last_opened_at FROM boards b JOIN workspaces w ON w.id=b.workspace_id LEFT JOIN board_preferences p ON p.board_id=b.id AND p.user_id=$1';
  app.get('/api/workspaces/:id/boards', async (req, res) => {
    await membership(pool, req.params.id, req.user.id);
    res.json((await pool.query(`${boardsQuery} WHERE b.workspace_id=$2 ORDER BY b.created_at,b.id`, [req.user.id, req.params.id])).rows.map(boardData));
  });
  app.post('/api/workspaces/:id/boards', async (req, res) => {
    await membership(pool, req.params.id, req.user.id);
    const { rows: [board] } = await pool.query('INSERT INTO boards(id,workspace_id,title,color) VALUES($1,$2,$3,$4) RETURNING *', [id(req.body.id), req.params.id, text(req.body.title, 'Board title', 100), req.body.color === undefined ? '#0079bf' : color(req.body.color)]);
    res.status(201).json(boardData(board));
  });
  app.get('/api/boards/:id', async (req, res) => {
    const board = await transaction(pool, async client => {
      await boardAccess(client, req.params.id, req.user.id, { lock: true });
      const { rows: [row] } = await client.query(`${boardsQuery} WHERE b.id=$2`, [req.user.id, req.params.id]);
      const { rows: lists } = await client.query('SELECT * FROM lists WHERE board_id=$1 ORDER BY position,id', [row.id]);
      const { rows: allCards } = await client.query('SELECT c.* FROM cards c JOIN lists l ON l.id=c.list_id WHERE l.board_id=$1 ORDER BY c.position,c.id', [row.id]);
      const query = req.query.query;
      if (query !== undefined && (typeof query !== 'string' || query.length > 200)) fail(400, 'VALIDATION_ERROR', 'Search must be at most 200 characters.');
      for (const key of ['labelId', 'assigneeId']) if (req.query[key] !== undefined) id(req.query[key]);
      const due = req.query.due;
      if (due !== undefined && !['', 'overdue', 'upcoming', 'completed', 'none'].includes(due)) fail(400, 'VALIDATION_ERROR', 'Invalid due filter.');
      const now = Date.now();
      const cards = allCards.filter(card => {
        if (query && !`${card.title} ${card.description}`.toLowerCase().includes(query.toLowerCase())) return false;
        if (req.query.labelId && !card.label_ids.includes(req.query.labelId)) return false;
        if (req.query.assigneeId && !card.assignee_ids.includes(req.query.assigneeId)) return false;
        if (!due) return true;
        if (due === 'completed') return card.completed;
        if (due === 'none') return !card.due_date;
        if (card.completed || !card.due_date) return false;
        const timestamp = new Date(card.due_date).getTime();
        return due === 'overdue' ? timestamp < now : timestamp >= now && timestamp <= now + 7 * 86400000;
      });
      const labels = (await client.query('SELECT id,name,color FROM labels WHERE board_id=$1 ORDER BY name,id', [row.id])).rows;
      return { ...boardData(row), labels, lists: lists.map(list => ({ ...listData(list), cards: cards.filter(card => card.list_id === list.id).map(cardData) })) };
    });
    res.json(board);
  });
  app.patch('/api/boards/:id', async (req, res) => {
    const row = await transaction(pool, async client => {
      const board = await boardAccess(client, req.params.id, req.user.id, { lock: true });
      if (board.closed && req.body.closed !== false) fail(409, 'BOARD_CLOSED', 'Reopen the board before editing.');
      const title = req.body.title === undefined ? board.title : text(req.body.title, 'Board title', 100);
      const background = req.body.color === undefined ? board.color : color(req.body.color);
      const closed = req.body.closed === undefined ? board.closed : bool(req.body.closed, 'Closed');
      return (await client.query('UPDATE boards SET title=$1,color=$2,closed=$3 WHERE id=$4 RETURNING *', [title, background, closed, board.id])).rows[0];
    });
    res.json(boardData(row));
  });
  app.patch('/api/boards/:id/preferences', async (req, res) => {
    await boardAccess(pool, req.params.id, req.user.id);
    const favorite = req.body.favorite === undefined ? null : bool(req.body.favorite, 'Favorite');
    if (req.body.lastOpenedAt !== undefined && req.body.lastOpenedAt !== true) fail(400, 'VALIDATION_ERROR', 'lastOpenedAt must be true.');
    await pool.query('INSERT INTO board_preferences(board_id,user_id,favorite,last_opened_at) VALUES($1,$2,COALESCE($3,false),CASE WHEN $4 THEN now() ELSE NULL END) ON CONFLICT(board_id,user_id) DO UPDATE SET favorite=COALESCE($3,board_preferences.favorite),last_opened_at=CASE WHEN $4 THEN now() ELSE board_preferences.last_opened_at END', [req.params.id, req.user.id, favorite, req.body.lastOpenedAt === true]);
    res.json(boardData((await pool.query(`${boardsQuery} WHERE b.id=$2`, [req.user.id, req.params.id])).rows[0]));
  });
  app.post('/api/boards/:id/lists', async (req, res) => {
    const list = await transaction(pool, async client => {
      await boardAccess(client, req.params.id, req.user.id, { lock: true, write: true });
      const listId = id(req.body.id);
      const title = text(req.body.title, 'List title', 100);
      const existing = (await client.query('SELECT * FROM lists WHERE id=$1', [listId])).rows[0];
      if (existing) {
        if (existing.board_id !== req.params.id || existing.title !== title) fail(409, 'CONFLICT', 'This ID is already used.');
        return existing;
      }
      return (await client.query('INSERT INTO lists(id,board_id,title,position) SELECT $1,$2,$3,COALESCE(max(position)+1,0) FROM lists WHERE board_id=$2 RETURNING *', [listId, req.params.id, title])).rows[0];
    });
    res.status(201).json(listData(list));
  });
  app.patch('/api/lists/:id', async (req, res) => {
    const list = await transaction(pool, async client => {
      const row = await listAccess(client, req.params.id, req.user.id, { lock: true, write: true });
      const limit = req.body.wipLimit === undefined ? row.wip_limit : req.body.wipLimit;
      if (limit !== null && (!Number.isInteger(limit) || limit < 1 || limit > 10000)) fail(400, 'VALIDATION_ERROR', 'WIP limit must be 1 to 10000 or null.');
      return (await client.query('UPDATE lists SET title=$1,archived=$2,wip_limit=$4 WHERE id=$3 RETURNING *', [req.body.title === undefined ? row.title : text(req.body.title, 'List title', 100), req.body.archived === undefined ? row.archived : bool(req.body.archived, 'Archived'), row.id, limit])).rows[0];
    });
    res.json(listData(list));
  });
  async function reorder(client, table, scopeColumn, scopeId, movingId, target) {
    const siblings = (await client.query(`SELECT id,archived FROM ${table} WHERE ${scopeColumn}=$1 AND id<>$2 ORDER BY position,id`, [scopeId, movingId])).rows;
    const rows = siblings.filter(row => !row.archived);
    rows.splice(Math.min(target, rows.length), 0, { id: movingId });
    rows.push(...siblings.filter(row => row.archived));
    for (const [index, row] of rows.entries()) await client.query(`UPDATE ${table} SET position=$1 WHERE id=$2`, [index, row.id]);
  }
  app.post('/api/lists/:id/move', async (req, res) => {
    const result = await transaction(pool, async client => {
      const list = await listAccess(client, req.params.id, req.user.id, { lock: true, write: true });
      if (list.archived) fail(409, 'LIST_ARCHIVED', 'Restore the list before moving it.');
      await reorder(client, 'lists', 'board_id', list.board_id, list.id, position(req.body.position));
      return (await client.query('SELECT * FROM lists WHERE id=$1', [list.id])).rows[0];
    });
    res.json(listData(result));
  });
  app.post('/api/lists/:id/cards', async (req, res) => {
    const card = await transaction(pool, async client => {
      const list = await listAccess(client, req.params.id, req.user.id, { lock: true, write: true });
      if (list.archived) fail(409, 'LIST_ARCHIVED', 'Restore the list before adding cards.');
      const cardId = id(req.body.id);
      const title = text(req.body.title, 'Card title', 200);
      const existing = (await client.query('SELECT * FROM cards WHERE id=$1', [cardId])).rows[0];
      if (existing) {
        if (existing.list_id !== list.id || existing.title !== title) fail(409, 'CONFLICT', 'This ID is already used.');
        return existing;
      }
      return (await client.query('INSERT INTO cards(id,list_id,title,position) SELECT $1,$2,$3,COALESCE(max(position)+1,0) FROM cards WHERE list_id=$2 RETURNING *', [cardId, list.id, title])).rows[0];
    });
    res.status(201).json(cardData(card));
  });
  app.get('/api/cards/:id', async (req, res) => {
    const card = await cardAccess(pool, req.params.id, req.user.id);
    res.json({ ...cardData(card), boardId: card.board_id, workspaceId: card.workspace_id, ...await cardDetails(pool, card.id) });
  });
  app.patch('/api/cards/:id', async (req, res) => {
    const card = await transaction(pool, async client => {
      const row = await cardAccess(client, req.params.id, req.user.id, { lock: true, write: true });
      const list = (await client.query('SELECT archived FROM lists WHERE id=$1', [row.list_id])).rows[0];
      if (list.archived) fail(409, 'LIST_ARCHIVED', 'Restore the parent list before editing its cards.');
      if (req.body.description !== undefined && (typeof req.body.description !== 'string' || req.body.description.length > 20000)) fail(400, 'VALIDATION_ERROR', 'Description must be text up to 20000 characters.');
      await editCardExtras(client, row, req.body, { id, color, bool });
      if (req.body.assigneeIds) await notifyCard(client, row, req.user.id, 'assigned', req.body.assigneeIds.filter(value => !row.assignee_ids.includes(value)));
      await logActivity(client, row, req.user.id, 'card.updated');
      return (await client.query('UPDATE cards SET title=$1,description=$2,archived=$3 WHERE id=$4 RETURNING *', [req.body.title === undefined ? row.title : text(req.body.title, 'Card title', 200), req.body.description ?? row.description, req.body.archived === undefined ? row.archived : bool(req.body.archived, 'Archived'), row.id])).rows[0];
    });
    res.json(cardData(card));
  });
  app.post('/api/cards/:id/move', async (req, res) => {
    const card = await transaction(pool, async client => {
      const row = await cardAccess(client, req.params.id, req.user.id, { lock: true, write: true });
      const destination = await listAccess(client, req.body.listId, req.user.id, { lock: true, write: true });
      if (destination.board_id !== row.board_id) {
        const destBoard = await boardAccess(client, destination.board_id, req.user.id, { write: true });
        if (destBoard.workspace_id !== row.workspace_id) fail(400, 'CROSS_WORKSPACE_MOVE', 'Move cards only between boards in the same workspace.');
        await client.query('UPDATE cards SET label_ids=ARRAY[]::uuid[],assignee_ids=ARRAY(SELECT user_id FROM memberships WHERE workspace_id=$1 AND user_id=ANY($2::uuid[])) WHERE id=$3', [destBoard.workspace_id, row.assignee_ids, row.id]);
        await client.query('UPDATE activity SET board_id=$1 WHERE card_id=$2', [destination.board_id, row.id]);
      }
      const source = (await client.query('SELECT archived FROM lists WHERE id=$1', [row.list_id])).rows[0];
      if (row.archived || source.archived || destination.archived) fail(409, 'ARCHIVED_RESOURCE', 'Restore the card and lists before moving.');
      const target = position(req.body.position);
      await client.query('UPDATE cards SET list_id=$1 WHERE id=$2', [destination.id, row.id]);
      if (destination.id !== row.list_id) {
        const siblings = (await client.query('SELECT id FROM cards WHERE list_id=$1 ORDER BY position,id', [row.list_id])).rows;
        for (const [index, sibling] of siblings.entries()) await client.query('UPDATE cards SET position=$1 WHERE id=$2', [index, sibling.id]);
      }
      await reorder(client, 'cards', 'list_id', destination.id, row.id, target);
      await logActivity(client, { ...row, board_id: destination.board_id }, req.user.id, 'card.moved');
      return (await client.query('SELECT * FROM cards WHERE id=$1', [row.id])).rows[0];
    });
    res.json(cardData(card));
  });
  installNotifications(app, { pool });
  installAdmin(app, { pool, id, bool });
  installTaskManagement(app, { pool, membership, boardAccess, listAccess, cardAccess, id, color, bool, position, cardData, listData, boardData });
  app.use((req, res) => res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Route not found.' } }));
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    let status = error.status || 500;
    let code = error.code || 'INTERNAL_ERROR';
    let message = status < 500 ? error.message : 'Something went wrong. Try again.';
    if (error.code === '23505') { status = 409; code = 'CONFLICT'; message = 'This email or ID is already in use.'; }
    if (error.code === '22P02') { status = 400; code = 'VALIDATION_ERROR'; message = 'Invalid ID.'; }
    if (error.type === 'entity.parse.failed') { status = 400; code = 'VALIDATION_ERROR'; message = 'Invalid JSON request.'; }
    if (status >= 500) console.error('Request failed:', error.code || error.name);
    res.status(status).json({ error: { code, message } });
  });
  return app;
}
