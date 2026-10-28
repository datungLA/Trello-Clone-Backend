import { fail, text } from './auth.js';
import { transaction } from './db.js';

export function plannerInstant(value) {
  if (typeof value !== 'string') fail(400, 'VALIDATION_ERROR', 'Use an ISO date and time with an explicit timezone.');
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?(Z|[+-]\d{2}:\d{2})$/i.exec(value);
  if (!match) fail(400, 'VALIDATION_ERROR', 'Use an ISO date and time with an explicit timezone.');
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(part => Number(part || 0));
  const milliseconds = Number((match[7] || '').padEnd(3, '0'));
  const zone = match[8], offsetHour = zone.length > 1 ? Number(zone.slice(1, 3)) : 0, offsetMinute = zone.length > 1 ? Number(zone.slice(4, 6)) : 0;
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59) fail(400, 'VALIDATION_ERROR', 'Choose a valid date, time and timezone offset.');
  const wall = new Date(0);
  wall.setUTCFullYear(year, month - 1, day); wall.setUTCHours(hour, minute, second, milliseconds);
  if (wall.getUTCFullYear() !== year || wall.getUTCMonth() !== month - 1 || wall.getUTCDate() !== day) fail(400, 'VALIDATION_ERROR', 'Choose a valid calendar date.');
  const offset = (offsetHour * 60 + offsetMinute) * (zone[0] === '-' ? -1 : 1);
  const instant = new Date(wall.getTime() - offset * 60000);
  if (instant.getUTCFullYear() < 1 || instant.getUTCFullYear() > 9999) fail(400, 'VALIDATION_ERROR', 'Choose a date within years 0001 to 9999.');
  return instant.toISOString();
}

export function plannerPayload(body) {
  const title = text(body.title, 'Block title', 200);
  const notes = body.notes === undefined ? '' : body.notes;
  if (typeof notes !== 'string' || notes.length > 10000) fail(400, 'VALIDATION_ERROR', 'Notes must be at most 10000 characters.');
  const startsAt = plannerInstant(body.startsAt), endsAt = plannerInstant(body.endsAt);
  const duration = Date.parse(endsAt) - Date.parse(startsAt);
  if (duration < 60000 || duration > 86400000) fail(400, 'VALIDATION_ERROR', 'A focus block must last between one minute and 24 hours.');
  return { title, notes, startsAt, endsAt };
}

export function plannerRange(from, to) {
  const start = plannerInstant(from), end = plannerInstant(to);
  const duration = Date.parse(end) - Date.parse(start);
  if (duration <= 0 || duration > 62 * 86400000) fail(400, 'VALIDATION_ERROR', 'Choose a positive planner range of at most 62 days.');
  return { from: start, to: end };
}

const blockData = row => ({ id: row.id, title: row.title, notes: row.notes, startsAt: row.starts_at.toISOString(), endsAt: row.ends_at.toISOString(), revision: row.revision, createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString() });
function revision(value) {
  if (!Number.isInteger(value) || value < 1 || value > 2147483646) fail(400, 'VALIDATION_ERROR', 'Provide the current focus block revision.');
  return value;
}

export function installPlanner(app, { pool, id }) {
  async function mutate(userId, operation) {
    return transaction(pool, async client => {
      if (!(await client.query('SELECT id FROM users WHERE id=$1 FOR NO KEY UPDATE', [userId])).rowCount) fail(401, 'TOKEN_INVALID', 'Sign in to continue.');
      return operation(client);
    });
  }
  async function ownedBlock(client, blockId, userId) {
    const row = (await client.query('SELECT * FROM planner_blocks WHERE id=$1 AND user_id=$2 FOR UPDATE', [id(blockId), userId])).rows[0];
    if (!row) fail(404, 'NOT_FOUND', 'Focus block not found.');
    return row;
  }
  function writable(row, expected) {
    if (row.deleted_at) fail(409, 'PLANNER_DELETED', 'This focus block was deleted. Refresh your planner.');
    if (row.revision !== expected) fail(409, 'PLANNER_CHANGED', 'This focus block changed in another session. Refresh before editing.');
  }
  app.get('/api/planner', async (req, res) => {
    const range = plannerRange(req.query.from, req.query.to);
    const rows = (await pool.query('SELECT * FROM planner_blocks WHERE user_id=$1 AND deleted_at IS NULL AND starts_at<$3 AND ends_at>$2 ORDER BY starts_at,ends_at,id', [req.user.id, range.from, range.to])).rows;
    res.json(rows.map(blockData));
  });
  app.post('/api/planner', async (req, res) => {
    if (typeof req.body.id !== 'string') fail(400, 'VALIDATION_ERROR', 'Provide a unique focus block ID.');
    const blockId = id(req.body.id), payload = plannerPayload(req.body);
    let created = false;
    const row = await mutate(req.user.id, async client => {
      const existing = (await client.query('SELECT * FROM planner_blocks WHERE id=$1', [blockId])).rows[0];
      if (existing) {
        if (existing.user_id !== req.user.id || existing.deleted_at || existing.title !== payload.title || existing.notes !== payload.notes || existing.starts_at.toISOString() !== payload.startsAt || existing.ends_at.toISOString() !== payload.endsAt) fail(409, 'PLANNER_ID_CONFLICT', 'This focus block ID is already used. Refresh before retrying.');
        return existing;
      }
      if ((await client.query('SELECT count(*)::int AS count FROM planner_blocks WHERE user_id=$1 AND deleted_at IS NULL', [req.user.id])).rows[0].count >= 1000) fail(409, 'PLANNER_FULL', 'Delete some focus blocks before adding more. The limit is 1000 blocks.');
      const inserted = (await client.query('INSERT INTO planner_blocks(id,user_id,title,notes,starts_at,ends_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING RETURNING *', [blockId, req.user.id, payload.title, payload.notes, payload.startsAt, payload.endsAt])).rows[0];
      if (!inserted) fail(409, 'PLANNER_ID_CONFLICT', 'This focus block ID is already used. Refresh before retrying.');
      created = true;
      return inserted;
    });
    res.status(created ? 201 : 200).json(blockData(row));
  });
  app.patch('/api/planner/:id', async (req, res) => {
    const payload = plannerPayload(req.body), expected = revision(req.body.revision);
    const row = await mutate(req.user.id, async client => {
      const existing = await ownedBlock(client, req.params.id, req.user.id);
      writable(existing, expected);
      return (await client.query('UPDATE planner_blocks SET title=$1,notes=$2,starts_at=$3,ends_at=$4,revision=revision+1,updated_at=now() WHERE id=$5 AND user_id=$6 RETURNING *', [payload.title, payload.notes, payload.startsAt, payload.endsAt, existing.id, req.user.id])).rows[0];
    });
    res.json(blockData(row));
  });
  app.delete('/api/planner/:id', async (req, res) => {
    if (req.body.confirm !== true) fail(400, 'CONFIRM_REQUIRED', 'Confirm deleting this focus block.');
    const expected = revision(req.body.revision);
    await mutate(req.user.id, async client => {
      const existing = await ownedBlock(client, req.params.id, req.user.id);
      writable(existing, expected);
      await client.query('UPDATE planner_blocks SET deleted_at=now(),updated_at=now(),revision=revision+1 WHERE id=$1 AND user_id=$2', [existing.id, req.user.id]);
    });
    res.json({ message: 'Focus block deleted.' });
  });
}
