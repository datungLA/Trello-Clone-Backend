import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { database, transaction } from './db.js';

export async function migrate(pool) {
  await transaction(pool, async client => {
    await client.query('SELECT pg_advisory_xact_lock(721543)');
    await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
    const directory = new URL('../migrations/', import.meta.url);
    for (const name of (await readdir(directory)).filter(name => name.endsWith('.sql')).sort()) {
      const found = await client.query('SELECT 1 FROM schema_migrations WHERE name=$1', [name]);
      if (!found.rowCount) {
        await client.query(await readFile(new URL(name, directory), 'utf8'));
        await client.query('INSERT INTO schema_migrations(name) VALUES($1)', [name]);
      }
    }
  });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const pool = database(process.env.DATABASE_URL);
  try { await migrate(pool); console.log('Migrations applied'); }
  finally { await pool.end(); }
}
