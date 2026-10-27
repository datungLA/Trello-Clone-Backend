import { createClient } from 'redis';
import { database } from './db.js';
import { migrate } from './migrate.js';
import { createApp } from './app.js';
import { trustedProxy, validateConfig } from './config.js';

const config = validateConfig({
  trustProxy: trustedProxy(process.env.TRUST_PROXY),
  origins: (process.env.APP_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean),
  setupToken: process.env.BOOTSTRAP_SETUP_TOKEN,
  jwtSecret: process.env.JWT_SECRET,
  origin: process.env.APP_ORIGIN || 'http://localhost:8080',
  secure: process.env.COOKIE_SECURE === 'true',
  nodeEnv: process.env.NODE_ENV || 'development',
  devMailDir: process.env.DEV_MAIL_DIR,
  resendApiKey: process.env.RESEND_API_KEY,
  mailFrom: process.env.MAIL_FROM,
  backup: {
    clientId: process.env.GOOGLE_DRIVE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_DRIVE_CLIENT_SECRET,
    tokenKey: process.env.BACKUP_TOKEN_KEY,
    origin: process.env.BACKUP_ORIGIN || process.env.APP_ORIGIN || 'http://localhost:8080',
    environment: process.env.BACKUP_ENVIRONMENT || 'dev',
    recipientCertFile: process.env.BACKUP_RECIPIENT_CERT_FILE,
    configDir: process.env.BACKUP_CONFIG_DIR,
    workDir: process.env.BACKUP_WORK_DIR,
    databaseUrl: process.env.DATABASE_URL,
  },
});
const pool = database(process.env.DATABASE_URL);
const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', error => console.error('Redis error:', error.code || error.name));
await redis.connect();
await migrate(pool);
const app = createApp({ pool, redis, config });
await app.locals.backup.start();
const server = app.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('API listening'));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {
  const stopped = app.locals.backup.stop();
  server.close(async () => {
  await stopped;
  await Promise.all([pool.end(), redis.quit()]);
  process.exit(0);
  });
});
