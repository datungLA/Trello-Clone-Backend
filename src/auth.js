import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { transaction } from './db.js';
import { resetDelivery } from './mail.js';

export const hash = value => createHash('sha256').update(value).digest('hex');
export const secretToken = () => randomBytes(32).toString('base64url');
export const publicUser = row => ({ id: row.id, email: row.email, displayName: row.display_name, isAdmin: row.is_admin === true, theme: row.theme || 'system' });
export function fail(status, code, message) { throw Object.assign(new Error(message), { status, code }); }
export function text(value, name, max = 200) {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > max) fail(400, 'VALIDATION_ERROR', `${name} is required (maximum ${max} characters).`);
  return value.trim();
}
export function email(value) {
  const result = text(value, 'Email', 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(result)) fail(400, 'VALIDATION_ERROR', 'Enter a valid email address.');
  return result;
}
export function password(value) {
  if (typeof value !== 'string' || value.length < 12 || Buffer.byteLength(value) > 72) fail(400, 'VALIDATION_ERROR', 'Use a password with 12 or more characters, up to 72 bytes.');
  return value;
}

export function installAuth(app, { pool, redis, config }) {
  const deliverReset = resetDelivery(config);
  const cookieName = config.secure ? '__Secure-rt' : 'rt';
  const cookieOptions = { httpOnly: true, secure: config.secure, sameSite: 'lax', path: '/api/auth', maxAge: 604800000 };
  const dummyHash = bcrypt.hashSync('dummy-password-for-timing-only', 12);
  const sign = (user, family) => jwt.sign({ tv: user.token_version, sid: family }, config.jwtSecret, {
    algorithm: 'HS256', issuer: 'trello-api', audience: 'trello-web', subject: user.id,
    jwtid: randomUUID(), expiresIn: '15m', notBefore: 0,
  });
  const issue = async (client, user, res, family = randomUUID(), userAgent = 'Unknown device') => {
    const raw = secretToken();
    await client.query('INSERT INTO refresh_tokens(token_hash,user_id,family_id,expires_at,user_agent) VALUES($1,$2,$3,now()+interval \'7 days\',$4)', [hash(raw), user.id, family, userAgent.slice(0,300)]);
    res.cookie(cookieName, raw, cookieOptions);
    return { user: publicUser(user), accessToken: sign(user, family) };
  };
  const clear = res => res.clearCookie(cookieName, { ...cookieOptions, maxAge: undefined });
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method !== 'GET' && req.headers.origin && req.headers.origin !== config.origin) return next(Object.assign(new Error('Origin rejected.'), { status: 403, code: 'CSRF_INVALID' }));
    if (['POST', 'PATCH', 'PUT'].includes(req.method) && !req.is('application/json')) return next(Object.assign(new Error('JSON request required.'), { status: 415, code: 'INVALID_CONTENT_TYPE' }));
    next();
  });
  const csrf = (req, res, next) => {
    const a = req.cookies.csrf;
    const b = req.get('X-CSRF-Token');
    if (typeof a !== 'string' || typeof b !== 'string' || a.length < 32 || Buffer.byteLength(a) !== Buffer.byteLength(b) || !timingSafeEqual(Buffer.from(a), Buffer.from(b))) return next(Object.assign(new Error('Refresh the page and try again.'), { status: 403, code: 'CSRF_INVALID' }));
    next();
  };
  app.get('/api/auth/csrf', (req, res) => {
    const csrfToken = secretToken();
    res.cookie('csrf', csrfToken, { secure: config.secure, sameSite: 'lax', path: '/api/auth' });
    res.json({ csrfToken, hasSession: Boolean(req.cookies[cookieName]) });
  });
  app.use('/api/auth', async (req, res, next) => {
    if (req.method === 'GET' || config.authRateLimit === false) return next();
    try {
      const identifier = typeof req.body?.email === 'string' ? req.body.email.toLowerCase() : '';
      for (const scope of [`ip:${req.ip}`, ...(identifier ? [`email:${hash(identifier)}`] : [])]) {
        const key = `auth-rate:${hash(`${scope}:${req.path}`)}`;
        const count = await redis.incr(key);
        if (count === 1) await redis.expire(key, 10);
        if (count > 5) { res.set('Retry-After', '10'); fail(429, 'RATE_LIMITED', 'Too many requests. Try again shortly.'); }
      }
      next();
    } catch (error) { next(error); }
  });
  app.post('/api/auth/register', async (req, res) => {
    const normalized = email(req.body.email);
    const passwordHash = await bcrypt.hash(password(req.body.password), 12);
    const name = text(req.body.displayName || normalized.split('@')[0], 'Display name', 80);
    const result = await transaction(pool, async client => {
      const { rows } = await client.query('INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,$3,$4) RETURNING *', [randomUUID(), normalized, name, passwordHash]);
      return issue(client, rows[0], res, undefined, req.get('User-Agent') || 'Unknown device');
    });
    res.status(201).json(result);
  });
  app.post('/api/auth/login', async (req, res) => {
    const normalized = email(req.body.email);
    const { rows: [user] } = await pool.query('SELECT * FROM users WHERE email=$1', [normalized]);
    const valid = await bcrypt.compare(typeof req.body.password === 'string' && Buffer.byteLength(req.body.password) <= 72 ? req.body.password : '', user?.password_hash || dummyHash);
    if (!valid || !user) fail(401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
    if (user.suspended_at) fail(403, 'ACCOUNT_SUSPENDED', 'This account is suspended.');
    res.json(await transaction(pool, async client => {
      const current = (await client.query('SELECT * FROM users WHERE id=$1 FOR SHARE', [user.id])).rows[0];
      if (current.suspended_at) fail(403, 'ACCOUNT_SUSPENDED', 'This account is suspended.');
      if (current.password_hash !== user.password_hash) fail(401, 'INVALID_CREDENTIALS', 'Credentials changed. Sign in again.');
      return issue(client, current, res, undefined, req.get('User-Agent') || 'Unknown device');
    }));
  });
  app.post('/api/auth/renew', csrf, async (req, res) => {
    const raw = req.cookies[cookieName];
    if (!raw) { clear(res); fail(401, 'TOKEN_INVALID', 'Sign in to continue.'); }
    const result = await transaction(pool, async client => {
      const { rows: [token] } = await client.query('SELECT * FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE', [hash(raw)]);
      if (!token || token.revoked || new Date(token.expires_at) <= new Date()) return { invalid: true };
      if ((await client.query('SELECT 1 FROM refresh_tokens WHERE family_id=$1 AND revoked LIMIT 1', [token.family_id])).rowCount) return { invalid: true };
      if (token.used_at) {
        if (Date.now() - new Date(token.used_at).getTime() < 5000) return { race: true };
        await client.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [token.user_id]);
        await client.query('UPDATE users SET token_version=token_version+1 WHERE id=$1', [token.user_id]);
        return { reuse: true };
      }
      await client.query('UPDATE refresh_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL', [hash(raw)]);
      const { rows: [user] } = await client.query('SELECT * FROM users WHERE id=$1 FOR SHARE', [token.user_id]);
      if (!user || user.suspended_at) return { invalid: true };
      return issue(client, user, res, token.family_id, token.user_agent);
    });
    if (result.race) fail(409, 'RENEW_IN_PROGRESS', 'Another tab renewed this session. Try again.');
    if (result.invalid || result.reuse) { clear(res); fail(401, result.reuse ? 'REUSE_DETECTED' : 'TOKEN_INVALID', 'Sign in to continue.'); }
    res.json(result);
  });
  const authenticate = async (req, res, next) => {
    try {
      const raw = req.get('Authorization')?.match(/^Bearer (.+)$/)?.[1];
      if (!raw) fail(401, 'TOKEN_INVALID', 'Sign in to continue.');
      let payload;
      try { payload = jwt.verify(raw, config.jwtSecret, { algorithms: ['HS256'], issuer: 'trello-api', audience: 'trello-web' }); }
      catch (error) { fail(401, error.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID', 'Sign in to continue.'); }
      if (!Number.isInteger(payload.exp) || !Number.isInteger(payload.nbf) || !Number.isInteger(payload.iat) || !Number.isInteger(payload.tv) || typeof payload.jti !== 'string' || typeof payload.sub !== 'string' || typeof payload.sid !== 'string') fail(401, 'TOKEN_INVALID', 'Sign in to continue.');
      const { rows: [user] } = await pool.query('SELECT u.* FROM users u WHERE u.id=$1 AND EXISTS(SELECT 1 FROM refresh_tokens r WHERE r.user_id=u.id AND r.family_id=$2 AND NOT r.revoked AND r.expires_at>now()) AND NOT EXISTS(SELECT 1 FROM refresh_tokens revoked WHERE revoked.family_id=$2 AND revoked.revoked)', [payload.sub, payload.sid]);
      if (!user || user.suspended_at || user.token_version !== payload.tv || await redis.get(`revoked-jti:${payload.jti}`)) fail(401, 'TOKEN_INVALID', 'Sign in to continue.');
      req.user = user;
      req.auth = payload;
      next();
    } catch (error) { next(error); }
  };
  app.get('/api/auth/me', authenticate, (req, res) => res.json(publicUser(req.user)));
  app.post('/api/auth/logout', csrf, authenticate, async (req, res) => {
    await pool.query('UPDATE refresh_tokens SET revoked=true WHERE family_id=$1 AND user_id=$2', [req.auth.sid, req.user.id]);
    await redis.set(`revoked-jti:${req.auth.jti}`, '1', { EX: Math.max(1, req.auth.exp - Math.floor(Date.now() / 1000)) });
    clear(res);
    res.json({ message: 'Signed out.' });
  });
  app.post('/api/auth/forgot-password', async (req, res) => {
    const normalized = email(req.body.email);
    const { rows: [user] } = await pool.query('SELECT id FROM users WHERE email=$1', [normalized]);
    if (user && deliverReset) {
      const raw = secretToken();
      const tokenHash = hash(raw);
      await pool.query('INSERT INTO password_resets(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval \'30 minutes\')', [tokenHash, user.id]);
      const url = new URL('/reset-password', config.origin);
      url.searchParams.set('token', raw);
      try { await deliverReset({ to: normalized, userId: user.id, resetUrl: url.toString(), tokenHash }); }
      catch { console.error('Password reset email delivery failed.'); }
    }
    res.json({ message: 'If the account exists, password-reset instructions will be sent. Check your inbox and spam folder.' });
  });
  app.post('/api/auth/reset-password', async (req, res) => {
    const raw = text(req.body.token, 'Token', 200);
    const passwordHash = await bcrypt.hash(password(req.body.newPassword), 12);
    await transaction(pool, async client => {
      const { rows: [reset] } = await client.query('SELECT * FROM password_resets WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE', [hash(raw)]);
      if (!reset) fail(400, 'INVALID_TOKEN', 'Reset link is invalid or expired.');
      await client.query('UPDATE password_resets SET used_at=now() WHERE user_id=$1', [reset.user_id]);
      await client.query('UPDATE users SET password_hash=$1,token_version=token_version+1 WHERE id=$2', [passwordHash, reset.user_id]);
      await client.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [reset.user_id]);
    });
    clear(res);
    res.json({ message: 'Password updated. Sign in again.' });
  });
  app.get('/api/auth/sessions', authenticate, async (req, res) => {
    const rows = (await pool.query(`SELECT family_id AS id,min(created_at) AS "createdAt",max(created_at) AS "lastUsedAt",max(expires_at) AS "expiresAt",(array_agg(user_agent ORDER BY created_at DESC))[1] AS "userAgent"
      FROM refresh_tokens WHERE user_id=$1 GROUP BY family_id HAVING bool_or(expires_at>now()) AND bool_and(NOT revoked) ORDER BY max(created_at) DESC,family_id`, [req.user.id])).rows;
    res.json(rows.map(row => ({ ...row, current: row.id === req.auth.sid })));
  });
  app.post('/api/auth/sessions/revoke-others', authenticate, async (req, res) => {
    if (req.body.confirm !== true) fail(400, 'CONFIRM_REQUIRED', 'Confirm signing out other sessions.');
    await pool.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1 AND family_id<>$2', [req.user.id, req.auth.sid]);
    res.json({ ok: true });
  });
  app.delete('/api/auth/sessions/:id', authenticate, async (req, res) => {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(req.params.id)) fail(400, 'VALIDATION_ERROR', 'Invalid session ID.');
    const result = await pool.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1 AND family_id=$2 RETURNING family_id', [req.user.id, req.params.id]);
    if (!result.rowCount) fail(404, 'NOT_FOUND', 'Session not found.');
    if (req.params.id === req.auth.sid) clear(res);
    res.json({ ok: true });
  });
  app.patch('/api/me', authenticate, async (req, res) => {
    if (req.body.theme !== undefined && !['system','light','dark'].includes(req.body.theme)) fail(400, 'VALIDATION_ERROR', 'Choose system, light, or dark appearance.');
    const displayName = req.body.displayName === undefined ? req.user.display_name : text(req.body.displayName, 'Display name', 80);
    const theme = req.body.theme === undefined ? req.user.theme || 'system' : req.body.theme;
    const { rows: [user] } = await pool.query('UPDATE users SET display_name=$1,theme=$2 WHERE id=$3 RETURNING *', [displayName, theme, req.user.id]);
    res.json(publicUser(user));
  });
  app.delete('/api/me', authenticate, async (req, res) => {
    if (req.body.confirm !== 'DELETE') fail(400, 'CONFIRM_REQUIRED', 'Type DELETE to confirm account deletion.');
    if (typeof req.body.password !== 'string' || !await bcrypt.compare(req.body.password, req.user.password_hash)) fail(403, 'REAUTH_REQUIRED', 'Your password is incorrect. Try again.');
    await transaction(pool, async client => {
      await client.query('SELECT pg_advisory_xact_lock(721544)');
      const { rows: [user] } = await client.query('SELECT * FROM users WHERE id=$1 FOR UPDATE', [req.user.id]);
      const owned = await client.query("SELECT 1 FROM memberships WHERE user_id=$1 AND role='owner' LIMIT 1", [user.id]);
      if (owned.rowCount) fail(409, 'OWNED_WORKSPACES', 'Transfer ownership of every workspace before deleting this account.');
      if (user.is_admin) {
        const admins = await client.query('SELECT count(*)::int AS count FROM users WHERE is_admin AND suspended_at IS NULL AND id<>$1', [user.id]);
        if (!admins.rows[0].count) fail(409, 'LAST_ADMIN', 'The last active administrator cannot delete their account.');
      }
      await client.query('UPDATE cards SET assignee_ids=array_remove(assignee_ids,$1)', [user.id]);
      await client.query('UPDATE admin_audit SET actor_id=NULL WHERE actor_id=$1', [user.id]);
      await client.query('UPDATE invitations SET revoked=true WHERE lower(email)=lower($1) AND accepted_at IS NULL', [user.email]);
      await client.query('DELETE FROM users WHERE id=$1', [user.id]);
    });
    clear(res);
    await redis.set(`revoked-jti:${req.auth.jti}`, '1', { EX: Math.max(1, req.auth.exp - Math.floor(Date.now() / 1000)) });
    res.json({ message: 'Account deleted.' });
  });
  return authenticate;
}
