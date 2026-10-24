import { fileURLToPath } from 'node:url';
import { database, transaction } from './db.js';
import { migrate } from './migrate.js';
import { email, fail } from './auth.js';
import { audit, adminUser } from './admin.js';

export async function grantAdministrator(pool, address) {
  const normalized = email(address);
  return transaction(pool, async client => {
    await client.query('SELECT pg_advisory_xact_lock(721544)');
    const user = (await client.query('SELECT * FROM users WHERE email=$1 FOR UPDATE', [normalized])).rows[0];
    if (!user) fail(404, 'NOT_FOUND', 'Register the account before granting administrator access.');
    if (user.suspended_at) fail(409, 'ACCOUNT_SUSPENDED', 'Reactivate this account before granting administrator access.');
    if (!user.is_admin) {
      await client.query('UPDATE users SET is_admin=true WHERE id=$1', [user.id]);
      await audit(client, null, 'user.admin_bootstrapped', 'user', user.id, { source: 'operator-cli' });
    }
    return adminUser({ ...user, is_admin: true });
  });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || !process.env.DATABASE_URL) {
    console.error('Usage: DATABASE_URL=<configured connection> npm run admin:grant -- existing-account-email');
    process.exitCode = 1;
  } else {
    const pool = database(process.env.DATABASE_URL);
    try {
      await migrate(pool);
      await grantAdministrator(pool, process.argv[2]);
      console.log('Administrator access granted to the existing account.');
    } catch (error) {
      console.error(error.status ? error.message : 'Administrator bootstrap failed.');
      process.exitCode = 1;
    } finally { await pool.end(); }
  }
}
