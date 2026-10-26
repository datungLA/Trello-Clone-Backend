import { randomUUID } from 'node:crypto';
import { fail, text } from './auth.js';
import { transaction } from './db.js';
import { notifyCard } from './notifications.js';

export const cardExtras = row => ({ labelIds: row.label_ids || [], assigneeIds: row.assignee_ids || [], coverColor: row.cover_color || null, startDate: row.start_date || null, dueDate: row.due_date || null, completed: row.completed || false });
export async function logActivity(client, card, userId, action) {
  await client.query('INSERT INTO activity(id,board_id,card_id,user_id,action) VALUES($1,$2,$3,$4,$5)', [randomUUID(), card.board_id, card.id, userId, action]);
}
export async function cardDetails(client, cardId) {
  const checklists = (await client.query('SELECT id,title,position FROM checklists WHERE card_id=$1 ORDER BY position,id', [cardId])).rows;
  const items = (await client.query('SELECT i.* FROM checklist_items i JOIN checklists c ON c.id=i.checklist_id WHERE c.card_id=$1 ORDER BY i.position,i.id', [cardId])).rows;
  const comments = (await client.query("SELECT c.id,c.body,c.user_id AS \"userId\",coalesce(u.display_name,'Deleted user') AS \"displayName\",c.created_at AS \"createdAt\",c.updated_at AS \"updatedAt\" FROM comments c LEFT JOIN users u ON u.id=c.user_id WHERE c.card_id=$1 ORDER BY c.created_at,c.id LIMIT 500", [cardId])).rows;
  const activity = (await client.query("SELECT a.id,a.action,a.user_id AS \"userId\",coalesce(u.display_name,'Deleted user') AS \"displayName\",a.created_at AS \"createdAt\" FROM activity a LEFT JOIN users u ON u.id=a.user_id WHERE a.card_id=$1 ORDER BY a.created_at DESC,a.id LIMIT 100", [cardId])).rows;
  return { checklists: checklists.map(c => ({ ...c, items: items.filter(i => i.checklist_id === c.id).map(i => ({ id: i.id, title: i.title, completed: i.completed, position: i.position })) })), comments, activity };
}
export async function editCardExtras(client, row, body, { id, color, bool }) {
  const array = (value, name) => {
    if (!Array.isArray(value) || value.length > 100) fail(400, 'VALIDATION_ERROR', `${name} must contain at most 100 IDs.`);
    for (const item of value) { if (!item) fail(400, 'VALIDATION_ERROR', 'Invalid ID.'); id(item); }
    return [...new Set(value)];
  };
  const labels = body.labelIds === undefined ? row.label_ids : array(body.labelIds, 'Labels');
  const assignees = body.assigneeIds === undefined ? row.assignee_ids : array(body.assigneeIds, 'Assignees');
  if (body.labelIds !== undefined && (await client.query('SELECT id FROM labels WHERE board_id=$1 AND id=ANY($2::uuid[])', [row.board_id, labels])).rowCount !== labels.length) fail(400, 'INVALID_LABEL', 'Labels must belong to this board.');
  if (body.assigneeIds !== undefined && (await client.query('SELECT user_id FROM memberships WHERE workspace_id=$1 AND user_id=ANY($2::uuid[])', [row.workspace_id, assignees])).rowCount !== assignees.length) fail(400, 'INVALID_ASSIGNEE', 'Assignees must belong to this workspace.');
  const date = (value, old) => {
    if (value === undefined) return old;
    if (value === null) return null;
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}(T.*)?$/.test(value) || !Number.isFinite(Date.parse(value))) fail(400, 'VALIDATION_ERROR', 'Use an ISO date or null.');
    const day = value.slice(0, 10);
    if (new Date(`${day}T00:00:00.000Z`).toISOString().slice(0, 10) !== day) fail(400, 'VALIDATION_ERROR', 'Use a valid calendar date.');
    return new Date(value).toISOString();
  };
  const start = date(body.startDate, row.start_date), due = date(body.dueDate, row.due_date);
  if (start && due && new Date(start) > new Date(due)) fail(400, 'VALIDATION_ERROR', 'Due date must follow start date.');
  await client.query('UPDATE cards SET label_ids=$1,assignee_ids=$2,cover_color=$3,start_date=$4,due_date=$5,completed=$6 WHERE id=$7', [labels, assignees, body.coverColor === undefined ? row.cover_color : body.coverColor === null ? null : color(body.coverColor), start, due, body.completed === undefined ? row.completed : bool(body.completed, 'Completed'), row.id]);
}

export function installTaskManagement(app, helpers) {
  const { pool, membership, boardAccess, listAccess, cardAccess, id, color, bool, position, cardData, listData, boardData } = helpers;
  const write = { lock: true, write: true };
  app.get('/api/me/tasks', async (req, res) => {
    const { rows } = await pool.query(`
      SELECT c.id,c.title,c.start_date AS "startDate",c.due_date AS "dueDate",c.completed,
        l.id AS "listId",l.title AS "listTitle",b.id AS "boardId",b.title AS "boardTitle",
        b.color AS "boardColor",w.id AS "workspaceId",w.name AS "workspaceName"
      FROM cards c
      JOIN lists l ON l.id=c.list_id
      JOIN boards b ON b.id=l.board_id
      JOIN workspaces w ON w.id=b.workspace_id
      JOIN memberships m ON m.workspace_id=w.id AND m.user_id=$1
      WHERE $1::uuid=ANY(c.assignee_ids) AND NOT c.archived AND NOT l.archived
        AND NOT b.closed AND NOT w.archived
      ORDER BY c.completed,c.due_date NULLS LAST,c.id`, [req.user.id]);
    res.json(rows);
  });
  async function editableCard(client, cardId, userId) {
    const card = await cardAccess(client, cardId, userId, write);
    const list = (await client.query('SELECT archived FROM lists WHERE id=$1', [card.list_id])).rows[0];
    if (card.archived || list.archived) fail(409, 'ARCHIVED_RESOURCE', 'Restore the card and its list first.');
    return card;
  }
  async function child(client, table, childId, userId) {
    const row = (await client.query(`SELECT * FROM ${table} WHERE id=$1`, [childId])).rows[0];
    if (!row) fail(404, 'NOT_FOUND', 'Item not found.');
    let cardId = row.card_id;
    if (table === 'checklist_items') cardId = (await client.query('SELECT card_id FROM checklists WHERE id=$1', [row.checklist_id])).rows[0].card_id;
    const card = await editableCard(client, cardId, userId);
    return { row, card };
  }
  app.post('/api/boards/:id/labels', async (req, res) => {
    const label = await transaction(pool, async client => {
      await boardAccess(client, req.params.id, req.user.id, write);
      return (await client.query('INSERT INTO labels(id,board_id,name,color) VALUES($1,$2,$3,$4) RETURNING id,name,color', [id(req.body.id), req.params.id, text(req.body.name, 'Label name', 80), color(req.body.color)])).rows[0];
    });
    res.status(201).json(label);
  });
  app.patch('/api/labels/:id', async (req, res) => {
    const label = await transaction(pool, async client => {
      const old = (await client.query('SELECT * FROM labels WHERE id=$1', [req.params.id])).rows[0];
      if (!old) fail(404, 'NOT_FOUND', 'Label not found.');
      await boardAccess(client, old.board_id, req.user.id, write);
      return (await client.query('UPDATE labels SET name=$1,color=$2 WHERE id=$3 RETURNING id,name,color', [req.body.name === undefined ? old.name : text(req.body.name, 'Label name', 80), req.body.color === undefined ? old.color : color(req.body.color), old.id])).rows[0];
    });
    res.json(label);
  });
  app.delete('/api/labels/:id', async (req, res) => {
    await transaction(pool, async client => {
      const label = (await client.query('SELECT * FROM labels WHERE id=$1', [req.params.id])).rows[0];
      if (!label) fail(404, 'NOT_FOUND', 'Label not found.');
      await boardAccess(client, label.board_id, req.user.id, write);
      await client.query('UPDATE cards SET label_ids=array_remove(label_ids,$1) WHERE list_id IN(SELECT id FROM lists WHERE board_id=$2)', [label.id, label.board_id]);
      await client.query('DELETE FROM labels WHERE id=$1', [label.id]);
    });
    res.json({ ok: true });
  });
  app.post('/api/cards/:id/checklists', async (req, res) => {
    const value = await transaction(pool, async client => {
      const card = await editableCard(client, req.params.id, req.user.id);
      const row = (await client.query('INSERT INTO checklists(id,card_id,title,position) SELECT $1,$2,$3,COALESCE(max(position)+1,0) FROM checklists WHERE card_id=$2 RETURNING id,title,position', [id(req.body.id), card.id, text(req.body.title, 'Checklist title', 100)])).rows[0];
      await logActivity(client, card, req.user.id, 'checklist.created');
      return { ...row, items: [] };
    });
    res.status(201).json(value);
  });
  app.patch('/api/checklists/:id', async (req, res) => {
    const value = await transaction(pool, async client => {
      const { row } = await child(client, 'checklists', req.params.id, req.user.id);
      return (await client.query('UPDATE checklists SET title=$1 WHERE id=$2 RETURNING id,title,position', [text(req.body.title, 'Checklist title', 100), row.id])).rows[0];
    });
    res.json(value);
  });
  app.delete('/api/checklists/:id', async (req, res) => {
    await transaction(pool, async client => {
      const { card } = await child(client, 'checklists', req.params.id, req.user.id);
      await client.query('DELETE FROM checklists WHERE id=$1', [req.params.id]);
      await logActivity(client, card, req.user.id, 'checklist.deleted');
    });
    res.json({ ok: true });
  });
  app.post('/api/checklists/:id/items', async (req, res) => {
    const value = await transaction(pool, async client => {
      await child(client, 'checklists', req.params.id, req.user.id);
      return (await client.query('INSERT INTO checklist_items(id,checklist_id,title,position) SELECT $1,$2,$3,COALESCE(max(position)+1,0) FROM checklist_items WHERE checklist_id=$2 RETURNING id,title,completed,position', [id(req.body.id), req.params.id, text(req.body.title, 'Item title', 500)])).rows[0];
    });
    res.status(201).json(value);
  });
  app.patch('/api/checklist-items/:id', async (req, res) => {
    const value = await transaction(pool, async client => {
      const { row, card } = await child(client, 'checklist_items', req.params.id, req.user.id);
      await client.query('UPDATE checklist_items SET title=$1,completed=$2 WHERE id=$3', [req.body.title === undefined ? row.title : text(req.body.title, 'Item title', 500), req.body.completed === undefined ? row.completed : bool(req.body.completed, 'Completed'), row.id]);
      if (req.body.position !== undefined) {
        const siblings = (await client.query('SELECT id FROM checklist_items WHERE checklist_id=$1 AND id<>$2 ORDER BY position,id', [row.checklist_id, row.id])).rows;
        siblings.splice(Math.min(position(req.body.position), siblings.length), 0, row);
        for (const [index, item] of siblings.entries()) await client.query('UPDATE checklist_items SET position=$1 WHERE id=$2', [index, item.id]);
      }
      await logActivity(client, card, req.user.id, 'checklist.item.updated');
      return (await client.query('SELECT id,title,completed,position FROM checklist_items WHERE id=$1', [row.id])).rows[0];
    });
    res.json(value);
  });
  app.delete('/api/checklist-items/:id', async (req, res) => {
    await transaction(pool, async client => {
      await child(client, 'checklist_items', req.params.id, req.user.id);
      await client.query('DELETE FROM checklist_items WHERE id=$1', [req.params.id]);
    });
    res.json({ ok: true });
  });
  app.post('/api/cards/:id/comments', async (req, res) => {
    const value = await transaction(pool, async client => {
      const card = await editableCard(client, req.params.id, req.user.id);
      const row = (await client.query('INSERT INTO comments(id,card_id,user_id,body) VALUES($1,$2,$3,$4) RETURNING id,body,user_id AS "userId",created_at AS "createdAt",updated_at AS "updatedAt"', [id(req.body.id), card.id, req.user.id, text(req.body.body, 'Comment', 10000)])).rows[0];
      await logActivity(client, card, req.user.id, 'comment.created');
      await notifyCard(client, card, req.user.id, 'comment', card.assignee_ids);
      return { ...row, displayName: req.user.display_name };
    });
    res.status(201).json(value);
  });
  app.patch('/api/comments/:id', async (req, res) => {
    const value = await transaction(pool, async client => {
      const { row } = await child(client, 'comments', req.params.id, req.user.id);
      if (row.user_id !== req.user.id) fail(403, 'FORBIDDEN', 'Only the author can edit this comment.');
      return (await client.query('UPDATE comments SET body=$1,updated_at=now() WHERE id=$2 RETURNING id,body,user_id AS "userId",created_at AS "createdAt",updated_at AS "updatedAt"', [text(req.body.body, 'Comment', 10000), row.id])).rows[0];
    });
    res.json({ ...value, displayName: req.user.display_name });
  });
  app.delete('/api/comments/:id', async (req, res) => {
    await transaction(pool, async client => {
      const { row, card } = await child(client, 'comments', req.params.id, req.user.id);
      if (row.user_id !== req.user.id) fail(403, 'FORBIDDEN', 'Only the author can delete this comment.');
      await client.query('DELETE FROM comments WHERE id=$1', [row.id]);
      await logActivity(client, card, req.user.id, 'comment.deleted');
    });
    res.json({ ok: true });
  });
  app.get('/api/boards/:id/views', async (req, res) => {
    await boardAccess(pool, req.params.id, req.user.id);
    res.json((await pool.query('SELECT id,name,filters FROM saved_views WHERE board_id=$1 AND user_id=$2 ORDER BY name,id', [req.params.id, req.user.id])).rows);
  });
  app.post('/api/boards/:id/views', async (req, res) => {
    const value = await transaction(pool, async client => {
      await boardAccess(client, req.params.id, req.user.id, { lock: true });
      const filters = req.body.filters;
      if (!filters || Array.isArray(filters) || typeof filters !== 'object' || Object.keys(filters).some(key => !['query', 'labelIds', 'assigneeIds', 'due'].includes(key))) fail(400, 'VALIDATION_ERROR', 'Invalid filters.');
      if (filters.query !== undefined && (typeof filters.query !== 'string' || filters.query.length > 200)) fail(400, 'VALIDATION_ERROR', 'Search must be at most 200 characters.');
      for (const key of ['labelIds', 'assigneeIds']) if (filters[key] !== undefined) {
        if (!Array.isArray(filters[key]) || filters[key].length > 100) fail(400, 'VALIDATION_ERROR', 'Invalid filter IDs.');
        filters[key].forEach(value => { if (!value) fail(400, 'VALIDATION_ERROR', 'Invalid ID.'); id(value); });
      }
      if (filters.due !== undefined && !['', 'overdue', 'upcoming', 'completed', 'none'].includes(filters.due)) fail(400, 'VALIDATION_ERROR', 'Invalid due filter.');
      return (await client.query('INSERT INTO saved_views(id,board_id,user_id,name,filters) VALUES($1,$2,$3,$4,$5) RETURNING id,name,filters', [id(req.body.id), req.params.id, req.user.id, text(req.body.name, 'View name', 80), JSON.stringify(filters)])).rows[0];
    });
    res.status(201).json(value);
  });
  app.delete('/api/views/:id', async (req, res) => {
    await transaction(pool, async client => {
      const row = (await client.query('SELECT * FROM saved_views WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id])).rows[0];
      if (!row) fail(404, 'NOT_FOUND', 'View not found.');
      await boardAccess(client, row.board_id, req.user.id);
      await client.query('DELETE FROM saved_views WHERE id=$1', [row.id]);
    });
    res.json({ ok: true });
  });
  app.post('/api/workspaces/:id/transfer', async (req, res) => {
    const value = await transaction(pool, async client => {
      await client.query('SELECT id FROM workspaces WHERE id=$1 FOR UPDATE', [req.params.id]);
      await membership(client, req.params.id, req.user.id, true);
      if (!req.body.userId || req.body.userId === req.user.id) fail(400, 'VALIDATION_ERROR', 'Select another existing member.');
      id(req.body.userId);
      const target = await client.query('SELECT 1 FROM memberships WHERE workspace_id=$1 AND user_id=$2', [req.params.id, req.body.userId]);
      if (!target.rowCount) fail(400, 'INVALID_MEMBER', 'The new owner must be a workspace member.');
      await client.query("UPDATE memberships SET role='owner' WHERE workspace_id=$1 AND user_id=$2", [req.params.id, req.body.userId]);
      await client.query("UPDATE memberships SET role='member' WHERE workspace_id=$1 AND user_id=$2", [req.params.id, req.user.id]);
      await client.query('INSERT INTO workspace_activity(id,workspace_id,user_id,action,target_id) VALUES($1,$2,$3,$4,$5)', [randomUUID(), req.params.id, req.user.id, 'ownership.transferred', req.body.userId]);
      const row = await membership(client, req.params.id, req.user.id);
      return { id: row.id, name: row.name, role: row.role };
    });
    res.json(value);
  });
  app.delete('/api/cards/:id', async (req, res) => {
    await transaction(pool, async client => {
      const card = await cardAccess(client, req.params.id, req.user.id, write);
      if (req.body.confirm !== true || !card.archived) fail(409, 'CONFIRM_REQUIRED', 'Archive the card and confirm permanent deletion.');
      await client.query('DELETE FROM cards WHERE id=$1', [card.id]);
    });
    res.json({ ok: true });
  });
  app.delete('/api/lists/:id', async (req, res) => {
    await transaction(pool, async client => {
      const list = await listAccess(client, req.params.id, req.user.id, write);
      if (req.body.confirm !== true || !list.archived) fail(409, 'CONFIRM_REQUIRED', 'Archive the list and confirm permanent deletion.');
      if ((await client.query('SELECT 1 FROM cards WHERE list_id=$1 AND NOT archived LIMIT 1', [list.id])).rowCount) fail(409, 'ACTIVE_CARDS', 'Archive or move every card before deleting the list.');
      await client.query('DELETE FROM lists WHERE id=$1', [list.id]);
    });
    res.json({ ok: true });
  });
  async function copyCard(client, source, listId, title, userId) {
    const destination = await listAccess(client, listId, userId, write);
    if (destination.archived) fail(409, 'LIST_ARCHIVED', 'Restore the destination list first.');
    const board = await boardAccess(client, destination.board_id, userId, write);
    if (source.workspace_id !== board.workspace_id) fail(400, 'CROSS_WORKSPACE_COPY', 'Copy cards only between boards in the same workspace.');
    const row = (await client.query(`INSERT INTO cards(id,list_id,title,description,position,label_ids,assignee_ids,cover_color,start_date,due_date,completed)
      SELECT $1,$2,$3,$4,COALESCE(max(position)+1,0),$5,$6,$7,$8,$9,false FROM cards WHERE list_id=$2 RETURNING *`, [randomUUID(), destination.id, title || source.title, source.description, source.board_id === destination.board_id ? source.label_ids : [], source.workspace_id === board.workspace_id ? source.assignee_ids : [], source.cover_color, source.start_date, source.due_date])).rows[0];
    const checklists = (await client.query('SELECT * FROM checklists WHERE card_id=$1 ORDER BY position,id', [source.id])).rows;
    for (const checklist of checklists) {
      const checklistId = randomUUID();
      await client.query('INSERT INTO checklists(id,card_id,title,position) VALUES($1,$2,$3,$4)', [checklistId, row.id, checklist.title, checklist.position]);
      const items = (await client.query('SELECT * FROM checklist_items WHERE checklist_id=$1 ORDER BY position,id', [checklist.id])).rows;
      for (const item of items) await client.query('INSERT INTO checklist_items(id,checklist_id,title,position) VALUES($1,$2,$3,$4)', [randomUUID(), checklistId, item.title, item.position]);
    }
    await logActivity(client, { ...row, board_id: destination.board_id }, userId, 'card.copied');
    return row;
  }
  app.post('/api/cards/:id/copy', async (req, res) => {
    const row = await transaction(pool, async client => {
      const source = await cardAccess(client, req.params.id, req.user.id, { lock: true });
      return copyCard(client, source, req.body.listId || source.list_id, req.body.title === undefined ? undefined : text(req.body.title, 'Card title', 200), req.user.id);
    });
    res.status(201).json(cardData(row));
  });
  async function copyList(client, source, boardId, title, userId, labelMap) {
    const board = await boardAccess(client, boardId, userId, write);
    const list = (await client.query('INSERT INTO lists(id,board_id,title,position,wip_limit) SELECT $1,$2,$3,COALESCE(max(position)+1,0),$4 FROM lists WHERE board_id=$2 RETURNING *', [randomUUID(), boardId, title || source.title, source.wip_limit])).rows[0];
    const cards = (await client.query('SELECT * FROM cards WHERE list_id=$1 AND NOT archived ORDER BY position,id', [source.id])).rows;
    for (const card of cards) {
      const copy = await copyCard(client, { ...card, board_id: source.board_id, workspace_id: board.workspace_id }, list.id, undefined, userId);
      if (labelMap) await client.query('UPDATE cards SET label_ids=$1 WHERE id=$2', [card.label_ids.map(value => labelMap.get(value)).filter(Boolean), copy.id]);
    }
    return list;
  }
  app.post('/api/lists/:id/copy', async (req, res) => {
    const row = await transaction(pool, async client => {
      const source = await listAccess(client, req.params.id, req.user.id, { lock: true });
      return copyList(client, source, source.board_id, req.body.title === undefined ? undefined : text(req.body.title, 'List title', 100), req.user.id);
    });
    res.status(201).json(listData(row));
  });
  app.post('/api/boards/:id/copy', async (req, res) => {
    const row = await transaction(pool, async client => {
      const source = await boardAccess(client, req.params.id, req.user.id, { lock: true });
      const board = (await client.query('INSERT INTO boards(id,workspace_id,title,color) VALUES($1,$2,$3,$4) RETURNING *', [randomUUID(), source.workspace_id, req.body.title === undefined ? `${source.title} copy` : text(req.body.title, 'Board title', 100), source.color])).rows[0];
      const labels = (await client.query('SELECT * FROM labels WHERE board_id=$1', [source.id])).rows;
      const labelMap = new Map();
      for (const label of labels) {
        const labelId = randomUUID(); labelMap.set(label.id, labelId);
        await client.query('INSERT INTO labels(id,board_id,name,color) VALUES($1,$2,$3,$4)', [labelId, board.id, label.name, label.color]);
      }
      const lists = (await client.query('SELECT * FROM lists WHERE board_id=$1 AND NOT archived ORDER BY position,id', [source.id])).rows;
      for (const list of lists) await copyList(client, list, board.id, undefined, req.user.id, labelMap);
      return board;
    });
    res.status(201).json(boardData(row));
  });
}
