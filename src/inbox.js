import { randomUUID } from 'node:crypto';
import { fail, text } from './auth.js';
import { transaction } from './db.js';
import { logActivity } from './tasks.js';

const itemData = row => ({ id: row.id, title: row.title, description: row.description, position: row.position, createdAt: row.created_at, updatedAt: row.updated_at });

export function installInbox(app, { pool, id, listAccess, cardAccess }) {
  const activeItems = async (client, userId) => (await client.query('SELECT * FROM inbox_items WHERE user_id=$1 AND converted_at IS NULL ORDER BY position,id', [userId])).rows;
  async function ownItem(client, itemId, userId) {
    const row = (await client.query('SELECT * FROM inbox_items WHERE id=$1 AND user_id=$2 FOR UPDATE', [id(itemId), userId])).rows[0];
    if (!row) fail(404, 'NOT_FOUND', 'Inbox item not found.');
    return row;
  }
  async function mutate(userId, operation) {
    return transaction(pool, async client => {
      if (!(await client.query('SELECT id FROM users WHERE id=$1 FOR NO KEY UPDATE', [userId])).rowCount) fail(401, 'TOKEN_INVALID', 'Sign in to continue.');
      return operation(client);
    });
  }
  function unconverted(row) {
    if (row.converted_at) fail(409, 'INBOX_ALREADY_MOVED', 'This item has already been moved to a board.');
  }
  const description = value => {
    if (typeof value !== 'string' || value.length > 10000) fail(400, 'VALIDATION_ERROR', 'Description must be at most 10000 characters.');
    return value;
  };
  app.get('/api/inbox', async (req, res) => res.json((await activeItems(pool, req.user.id)).map(itemData)));
  app.post('/api/inbox', async (req, res) => {
    if (typeof req.body.id !== 'string') fail(400, 'VALIDATION_ERROR', 'Provide a unique capture ID.');
    const itemId = id(req.body.id), title = text(req.body.title, 'Title', 200), details = description(req.body.description ?? '');
    let created = false;
    const row = await mutate(req.user.id, async client => {
      const existing = (await client.query('SELECT * FROM inbox_items WHERE id=$1', [itemId])).rows[0];
      if (existing) {
        if (existing.user_id !== req.user.id) fail(409, 'INBOX_ID_CONFLICT', 'This capture ID is unavailable. Create a new capture.');
        unconverted(existing);
        if (existing.title !== title || existing.description !== details) fail(409, 'INBOX_ID_CONFLICT', 'This capture ID already has different content. Refresh before retrying.');
        return existing;
      }
      if ((await client.query('SELECT count(*)::int AS count FROM inbox_items WHERE user_id=$1 AND converted_at IS NULL', [req.user.id])).rows[0].count >= 1000) fail(409, 'INBOX_FULL', 'Move or delete some inbox items before capturing more. The limit is 1000 items.');
      created = true;
      return (await client.query('INSERT INTO inbox_items(id,user_id,title,description,position) SELECT $1,$2,$3,$4,COALESCE(max(position)+1,0) FROM inbox_items WHERE user_id=$2 AND converted_at IS NULL RETURNING *', [itemId, req.user.id, title, details])).rows[0];
    });
    res.status(created ? 201 : 200).json(itemData(row));
  });
  app.post('/api/inbox/reorder', async (req, res) => {
    if (!Array.isArray(req.body.ids) || req.body.ids.length > 1000 || new Set(req.body.ids).size !== req.body.ids.length) fail(400, 'VALIDATION_ERROR', 'Provide each active inbox item once.');
    const ids = req.body.ids.map(value => { if (typeof value !== 'string') fail(400, 'VALIDATION_ERROR', 'Inbox item IDs must be UUIDs.'); return id(value); });
    const rows = await mutate(req.user.id, async client => {
      const active = await activeItems(client, req.user.id);
      if (active.length !== ids.length || active.some(row => !ids.includes(row.id))) fail(409, 'INBOX_CHANGED', 'Your inbox changed. Refresh before reordering.');
      for (const [index, itemId] of ids.entries()) await client.query('UPDATE inbox_items SET position=$1,updated_at=now() WHERE id=$2 AND user_id=$3', [index, itemId, req.user.id]);
      return activeItems(client, req.user.id);
    });
    res.json(rows.map(itemData));
  });
  app.patch('/api/inbox/:id', async (req, res) => {
    if (req.body.title === undefined && req.body.description === undefined) fail(400, 'VALIDATION_ERROR', 'Choose content to update.');
    const row = await mutate(req.user.id, async client => {
      const existing = await ownItem(client, req.params.id, req.user.id);
      unconverted(existing);
      return (await client.query('UPDATE inbox_items SET title=$1,description=$2,updated_at=now() WHERE id=$3 AND user_id=$4 RETURNING *', [req.body.title === undefined ? existing.title : text(req.body.title, 'Title', 200), req.body.description === undefined ? existing.description : description(req.body.description), existing.id, req.user.id])).rows[0];
    });
    res.json(itemData(row));
  });
  app.delete('/api/inbox/:id', async (req, res) => {
    if (req.body.confirm !== true) fail(400, 'CONFIRM_REQUIRED', 'Confirm deleting this inbox item.');
    await mutate(req.user.id, async client => {
      const existing = await ownItem(client, req.params.id, req.user.id);
      unconverted(existing);
      await client.query('DELETE FROM inbox_items WHERE id=$1 AND user_id=$2', [existing.id, req.user.id]);
    });
    res.json({ message: 'Inbox item deleted.' });
  });
  app.post('/api/inbox/:id/move', async (req, res) => {
    if (req.body.listId === undefined) fail(400, 'VALIDATION_ERROR', 'Choose a destination list.');
    const listId = id(req.body.listId);
    const result = await mutate(req.user.id, async client => {
      const existing = await ownItem(client, req.params.id, req.user.id);
      if (existing.converted_at && !existing.converted_card_id) fail(410, 'INBOX_CARD_REMOVED', 'The card created from this inbox item was removed. It cannot be created again by retrying.');
      if (existing.converted_at && existing.conversion_list_id !== listId) fail(409, 'INBOX_ALREADY_MOVED', 'This item was already moved to a different destination.');
      const workspace = await client.query('SELECT w.id FROM workspaces w JOIN memberships m ON m.workspace_id=w.id JOIN boards b ON b.workspace_id=w.id JOIN lists l ON l.board_id=b.id WHERE l.id=$1 AND m.user_id=$2 FOR NO KEY UPDATE OF w', [listId, req.user.id]);
      if (!workspace.rowCount) fail(404, 'NOT_FOUND', 'Destination list not found.');
      const list = await listAccess(client, listId, req.user.id, { lock: true, write: true });
      if (!list || list.archived) fail(409, 'ARCHIVED_RESOURCE', 'Restore the destination list before moving an inbox item.');
      if (existing.converted_at) {
        const card = await cardAccess(client, existing.converted_card_id, req.user.id, { write: true });
        if (!card || card.archived) fail(409, 'ARCHIVED_RESOURCE', 'The card created from this inbox item is archived. Restore it before opening it.');
        const parent = (await client.query('SELECT archived FROM lists WHERE id=$1', [card.list_id])).rows[0];
        if (parent?.archived) fail(409, 'ARCHIVED_RESOURCE', 'The card list is archived.');
        return { itemId: existing.id, cardId: card.id, boardId: card.board_id, listId: card.list_id };
      }
      const card = (await client.query('INSERT INTO cards(id,list_id,title,description,position) SELECT $1,$2,$3,$4,COALESCE(max(position)+1,0) FROM cards WHERE list_id=$2 RETURNING *', [randomUUID(), list.id, existing.title, existing.description])).rows[0];
      await client.query('UPDATE inbox_items SET converted_at=now(),converted_card_id=$1,conversion_list_id=$2,updated_at=now() WHERE id=$3 AND user_id=$4', [card.id, list.id, existing.id, req.user.id]);
      await logActivity(client, { ...card, board_id: list.board_id }, req.user.id, 'card.created');
      return { itemId: existing.id, cardId: card.id, boardId: list.board_id, listId: list.id };
    });
    res.json(result);
  });
}
