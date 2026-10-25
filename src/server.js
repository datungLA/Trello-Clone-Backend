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
});
const pool = database(process.env.DATABASE_URL);
const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', error => console.error('Redis error:', error.code || error.name));
await redis.connect();
await migrate(pool);
const server = createApp({ pool, redis, config }).listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('API listening'));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(async () => {
  await Promise.all([pool.end(), redis.quit()]);
  process.exit(0);
}));
