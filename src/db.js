import pg from 'pg';

export function database(url) {
  const pool = new pg.Pool({ connectionString: url, max: 8 });
  pool.on('error', error => console.error('Database connection error:', error.code || error.name));
  return pool;
}

export async function transaction(pool, operation) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const value = await operation(client);
    await client.query('COMMIT');
    return value;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}
