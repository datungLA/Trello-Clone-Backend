import { randomUUID } from 'node:crypto';
import { fail } from './auth.js';

export async function notifyCard(client, card, actorId, kind, recipients) {
  for (const userId of new Set(recipients.filter(value => value !== actorId))) {
    await client.query('INSERT INTO notifications(id,user_id,actor_id,card_id,kind) SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM memberships WHERE workspace_id=$6 AND user_id=$2)', [randomUUID(), userId, actorId, card.id, kind, card.workspace_id]);
  }
}

export function installNotifications(app, { pool }) {
  const scope = 'n.user_id=$1 AND EXISTS(SELECT 1 FROM cards c JOIN lists l ON l.id=c.list_id JOIN boards b ON b.id=l.board_id JOIN memberships m ON m.workspace_id=b.workspace_id WHERE c.id=n.card_id AND m.user_id=$1)';
  app.get('/api/notifications', async (req, res) => {
    const rows = (await pool.query(`SELECT n.id,n.kind,n.card_id AS "cardId",n.read_at AS "readAt",n.created_at AS "createdAt",c.title AS "cardTitle",coalesce(u.display_name,'A former teammate') AS "actorName" FROM notifications n JOIN cards c ON c.id=n.card_id LEFT JOIN users u ON u.id=n.actor_id WHERE ${scope} ORDER BY n.created_at DESC,n.id LIMIT 100`, [req.user.id])).rows;
    const count = (await pool.query(`SELECT count(*)::int AS count FROM notifications n WHERE ${scope} AND n.read_at IS NULL`, [req.user.id])).rows[0].count;
    res.json({ items: rows, unreadCount: count });
  });
  app.patch('/api/notifications/read-all', async (req, res) => {
    await pool.query(`UPDATE notifications n SET read_at=now() WHERE ${scope} AND n.read_at IS NULL`, [req.user.id]);
    res.json({ ok: true });
  });
  app.patch('/api/notifications/:id', async (req, res) => {
    if (typeof req.body.read !== 'boolean') fail(400, 'VALIDATION_ERROR', 'Read must be true or false.');
    const result = await pool.query(`UPDATE notifications n SET read_at=CASE WHEN $3 THEN now() ELSE NULL END WHERE ${scope} AND n.id=$2 RETURNING n.id`, [req.user.id, req.params.id, req.body.read]);
    if (!result.rowCount) fail(404, 'NOT_FOUND', 'Notification not found.');
    res.json({ ok: true });
  });
  app.delete('/api/notifications/:id', async (req, res) => {
    const result = await pool.query('DELETE FROM notifications WHERE user_id=$1 AND id=$2 RETURNING id', [req.user.id, req.params.id]);
    if (!result.rowCount) fail(404, 'NOT_FOUND', 'Notification not found.');
    res.json({ ok: true });
  });
}
