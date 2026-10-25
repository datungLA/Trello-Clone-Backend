import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { transaction } from './db.js';
import { resetDelivery, boundedMailQueue } from './mail.js';

export const hash = value => createHash('sha256').update(value).digest('hex');
export const secretToken = () => randomBytes(32).toString('base64url');
export const publicUser = row => ({ id: row.id, email: row.email, displayName: row.display_name, isAdmin: row.is_admin === true, appRole: row.app_role || (row.is_admin ? 'admin' : 'user'), emailVerified: !!row.email_verified_at, theme: row.theme || 'system' });
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
  const deliverVerification = resetDelivery(config, fetch, true);
  const mailQueue = config.mailQueue || boundedMailQueue();
  const securityAudit = (action, outcome, req, userId = null, client = pool) => client.query(
    'INSERT INTO auth_audit(id,user_id,action,outcome,identifier_hash,ip_hash) VALUES($1,$2,$3,$4,$5,$6)',
    [randomUUID(), userId, action, outcome, typeof req.body?.email === 'string' ? hash(req.body.email.trim().toLowerCase()) : null, hash(req.ip || '')]);
  const dispatch = (req, kind) => {
    const normalized = email(req.body.email);
    const accepted = mailQueue.enqueue(async () => {
      const user = (await pool.query('SELECT * FROM users WHERE email=$1', [normalized])).rows[0];
      const deliver = kind === 'verification' ? deliverVerification : deliverReset;
      if (!user || (kind === 'verification' && (user.email_verified_at || user.suspended_at)) || !deliver) return;
      const raw = secretToken(), tokenHash = hash(raw);
      const table = kind === 'verification' ? 'email_verifications' : 'password_resets';
      await transaction(pool, async client => {
        await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [user.id]);
        await client.query(`UPDATE ${table} SET used_at=now() WHERE user_id=$1 AND used_at IS NULL`, [user.id]);
        await client.query(`INSERT INTO ${table}(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '${kind === 'verification' ? '24 hours' : '30 minutes'}')`, [tokenHash, user.id]);
      });
      const url = new URL(kind === 'verification' ? '/verify-email' : '/reset-password', config.origin);
      url.searchParams.set('token', raw);
      try {
        await deliver({ to: normalized, userId: user.id, resetUrl: url.toString(), tokenHash });
        await securityAudit(`auth.${kind}.delivery`, 'success', req, user.id);
      } catch { await securityAudit(`auth.${kind}.delivery`, 'failure', req, user.id); }
    });
    return securityAudit(`auth.${kind}.requested`, accepted ? 'accepted' : 'queue_full', req);
  };
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
    if (req.method !== 'GET' && req.headers.origin && ![config.origin, ...(config.origins || [])].includes(req.headers.origin)) return next(Object.assign(new Error('Origin rejected.'), { status: 403, code: 'CSRF_INVALID' }));
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
      const identifier = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
      const sensitive = ['/register', '/forgot-password', '/resend-verification'].includes(req.path);
      const ratePath = req.path === '/register' ? '/resend-verification' : req.path;
      const scopes = [`ip:${req.ip}`, ...(identifier ? [`email:${hash(identifier)}`] : [])];
      const windows = sensitive ? [[60, 1], [3600, req.path === '/forgot-password' ? 3 : 5]] : [[60, req.path === '/login' ? 20 : 30]];
      for (const scope of scopes) for (const [seconds, limit] of windows) {
        const key = `${config.authRatePrefix || 'auth'}-rate:${hash(`${scope}:${ratePath}:${seconds}`)}`;
        const count = await redis.eval("local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n", { keys: [key], arguments: [String(seconds)] });
        if (count > limit) {
          res.set('Retry-After', String(Math.max(1, await redis.ttl(key))));
          await securityAudit('auth.throttled', 'denied', req);
          fail(429, 'RATE_LIMITED', 'Too many requests. Try again later.');
        }
      }
      next();
    } catch (error) { next(error); }
  });
  const registrationMessage = { message: 'If this address can be registered, verification instructions will be sent. Check your inbox and spam folder.' };
  app.post('/api/auth/register', async (req, res) => {
    const normalized = email(req.body.email);
    const passwordHash = await bcrypt.hash(password(req.body.password), 12);
    const name = text(req.body.displayName || normalized.split('@')[0], 'Display name', 80);
    await pool.query('INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,$3,$4) ON CONFLICT(email) DO NOTHING', [randomUUID(), normalized, name, passwordHash]);
    await dispatch(req, 'verification');
    res.status(202).json(registrationMessage);
  });
  app.post('/api/auth/resend-verification', async (req, res) => {
    await dispatch(req, 'verification');
    res.json(registrationMessage);
  });
  app.post('/api/auth/verify-email', async (req, res) => {
    const raw = text(req.body.token, 'Token', 200);
    await transaction(pool, async client => {
      const owner = (await client.query('SELECT user_id FROM email_verifications WHERE token_hash=$1', [hash(raw)])).rows[0];
      if (owner) await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [owner.user_id]);
      const token = (await client.query('SELECT * FROM email_verifications WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE', [hash(raw)])).rows[0];
      if (!token) fail(400, 'INVALID_TOKEN', 'Verification link is invalid or expired.');
      await client.query('UPDATE users SET email_verified_at=COALESCE(email_verified_at,now()) WHERE id=$1', [token.user_id]);
      await client.query('UPDATE email_verifications SET used_at=now() WHERE user_id=$1', [token.user_id]);
      await securityAudit('auth.email.verified', 'success', req, token.user_id, client);
      return token.user_id;
    });
    res.json({ message: 'Email verified. Sign in to continue.' });
  });
  const setupAuthorized = req => {
    const supplied = req.get('X-Setup-Token') || req.body.setupToken;
    return typeof config.setupToken === 'string' && config.setupToken.length >= 32 && typeof supplied === 'string' && timingSafeEqual(Buffer.from(hash(supplied)), Buffer.from(hash(config.setupToken)));
  };
  const setupOpen = async (req, client = pool, lock = false, publicStatus = false) => {
    const state = (await client.query(`SELECT completed_at FROM bootstrap_state WHERE singleton${lock ? ' FOR UPDATE' : ''}`)).rows[0];
    if (!(publicStatus ? typeof config.setupToken === 'string' && config.setupToken.length >= 32 : setupAuthorized(req)) || !state || state.completed_at) fail(404, 'NOT_FOUND', 'Not found.');
  };
  app.get('/api/auth/bootstrap/status', async (req, res) => {
    await setupOpen(req, pool, false, true);
    res.json({ available: true });
  });
  app.post('/api/auth/bootstrap/register', async (req, res) => {
    await setupOpen(req);
    const normalized = email(req.body.email), name = text(req.body.displayName, 'Display name', 80);
    const passwordHash = await bcrypt.hash(password(req.body.password), 12);
    const result = await transaction(pool, async client => {
      await client.query('SELECT pg_advisory_xact_lock(721544)');
      await setupOpen(req, client, true);
      const user = (await client.query("INSERT INTO users(id,email,display_name,password_hash,is_admin,app_role,email_verified_at) VALUES($1,$2,$3,$4,true,'super_admin',now()) RETURNING *", [randomUUID(), normalized, name, passwordHash])).rows[0];
      await client.query('UPDATE bootstrap_state SET completed_at=now() WHERE singleton');
      await securityAudit('auth.bootstrap.completed', 'success', req, user.id, client);
      return issue(client, user, res, undefined, req.get('User-Agent') || 'Unknown device');
    });
    res.status(201).json(result);
  });
  app.post('/api/auth/login', async (req, res) => {
    const normalized = email(req.body.email);
    const backoffKey = `${config.authRatePrefix || 'auth'}-backoff:${hash(normalized)}`;
    const failures = config.authRateLimit === false ? 0 : Number(await redis.get(backoffKey) || 0);
    if (failures >= 5) {
      res.set('Retry-After', String(Math.max(1, await redis.ttl(backoffKey))));
      await securityAudit('auth.login', 'throttled', req);
      fail(429, 'RATE_LIMITED', 'Too many sign-in attempts. Try again later.');
    }
    const { rows: [user] } = await pool.query('SELECT * FROM users WHERE email=$1', [normalized]);
    const valid = await bcrypt.compare(typeof req.body.password === 'string' && Buffer.byteLength(req.body.password) <= 72 ? req.body.password : '', user?.password_hash || dummyHash);
    if (!valid || !user) {
      if (config.authRateLimit !== false) {
        await redis.eval("local n=redis.call('INCR',KEYS[1]); redis.call('EXPIRE',KEYS[1],math.min(3600,60*2^math.min(n-1,6))); return n", { keys: [backoffKey], arguments: [] });
      }
      await securityAudit('auth.login', 'failure', req);
      fail(401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
    }
    if (!user.email_verified_at) { await securityAudit('auth.login', 'unverified', req, user.id); fail(403, 'EMAIL_NOT_VERIFIED', 'Verify your email before signing in.'); }
    if (user.suspended_at) { await securityAudit('auth.login', 'suspended', req, user.id); fail(403, 'ACCOUNT_SUSPENDED', 'This account is suspended.'); }
    await redis.del(backoffKey);
    res.json(await transaction(pool, async client => {
      const current = (await client.query('SELECT * FROM users WHERE id=$1 FOR SHARE', [user.id])).rows[0];
      if (!current.email_verified_at) fail(403, 'EMAIL_NOT_VERIFIED', 'Verify your email before signing in.');
      if (current.suspended_at) fail(403, 'ACCOUNT_SUSPENDED', 'This account is suspended.');
      if (current.password_hash !== user.password_hash) fail(401, 'INVALID_CREDENTIALS', 'Credentials changed. Sign in again.');
      await securityAudit('auth.login', 'success', req, current.id, client);
      return issue(client, current, res, undefined, req.get('User-Agent') || 'Unknown device');
    }));
  });
  app.post('/api/auth/renew', csrf, async (req, res) => {
    const raw = req.cookies[cookieName];
    if (!raw) { clear(res); fail(401, 'TOKEN_INVALID', 'Sign in to continue.'); }
    const result = await transaction(pool, async client => {
      const owner = (await client.query('SELECT user_id FROM refresh_tokens WHERE token_hash=$1', [hash(raw)])).rows[0];
      if (owner) await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [owner.user_id]);
      const { rows: [token] } = await client.query('SELECT * FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE', [hash(raw)]);
      if (!token || token.revoked || new Date(token.expires_at) <= new Date()) return { invalid: true };
      if ((await client.query('SELECT 1 FROM refresh_tokens WHERE family_id=$1 AND revoked LIMIT 1', [token.family_id])).rowCount) return { invalid: true };
      if (token.used_at) {
        if (Date.now() - new Date(token.used_at).getTime() < 5000) return { race: true };
        await client.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [token.user_id]);
        await client.query('UPDATE users SET token_version=token_version+1 WHERE id=$1', [token.user_id]);
        await securityAudit('auth.refresh.reuse', 'denied', req, token.user_id, client);
        return { reuse: true };
      }
      await client.query('UPDATE refresh_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL', [hash(raw)]);
      const { rows: [user] } = await client.query('SELECT * FROM users WHERE id=$1 FOR SHARE', [token.user_id]);
      if (!user || !user.email_verified_at || user.suspended_at) return { invalid: true };
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
      if (!user || !user.email_verified_at || user.suspended_at || user.token_version !== payload.tv || await redis.get(`revoked-jti:${payload.jti}`)) fail(401, 'TOKEN_INVALID', 'Sign in to continue.');
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
    await securityAudit('auth.logout', 'success', req, req.user.id);
    res.json({ message: 'Signed out.' });
  });
  app.post('/api/auth/forgot-password', async (req, res) => {
    await dispatch(req, 'reset');
    res.json({ message: 'If the account exists, password-reset instructions will be sent. Check your inbox and spam folder.' });
  });
  app.post('/api/auth/change-password', authenticate, async (req, res) => {
    const candidate = typeof req.body.currentPassword === 'string' && Buffer.byteLength(req.body.currentPassword) <= 72 ? req.body.currentPassword : '';
    if (!await bcrypt.compare(candidate, req.user.password_hash)) {
      await securityAudit('auth.password.change', 'failure', req, req.user.id);
      fail(403, 'REAUTH_REQUIRED', 'Your current password is incorrect.');
    }
    const passwordHash = await bcrypt.hash(password(req.body.newPassword), 12);
    await transaction(pool, async client => {
      const user = (await client.query('SELECT * FROM users WHERE id=$1 FOR UPDATE', [req.user.id])).rows[0];
      if (user.password_hash !== req.user.password_hash || user.token_version !== req.auth.tv) fail(401, 'TOKEN_INVALID', 'Credentials changed. Sign in again.');
      await client.query('UPDATE users SET password_hash=$1,token_version=token_version+1 WHERE id=$2', [passwordHash, user.id]);
      await client.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [user.id]);
      await client.query('UPDATE password_resets SET used_at=now() WHERE user_id=$1 AND used_at IS NULL', [user.id]);
      await securityAudit('auth.password.change', 'success', req, user.id, client);
    });
    clear(res);
    res.json({ message: 'Password updated. Sign in again.' });
  });
  app.post('/api/auth/logout-all', authenticate, async (req, res) => {
    if (req.body.confirm !== true) fail(400, 'CONFIRM_REQUIRED', 'Confirm signing out every session.');
    await transaction(pool, async client => {
      await client.query('UPDATE users SET token_version=token_version+1 WHERE id=$1', [req.user.id]);
      await client.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [req.user.id]);
      await securityAudit('auth.logout.all', 'success', req, req.user.id, client);
    });
    clear(res);
    res.json({ message: 'Signed out of every session.' });
  });
  app.post('/api/auth/reset-password', async (req, res) => {
    const raw = text(req.body.token, 'Token', 200);
    const passwordHash = await bcrypt.hash(password(req.body.newPassword), 12);
    await transaction(pool, async client => {
      const owner = (await client.query('SELECT user_id FROM password_resets WHERE token_hash=$1', [hash(raw)])).rows[0];
      if (owner) await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [owner.user_id]);
      const { rows: [reset] } = await client.query('SELECT * FROM password_resets WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE', [hash(raw)]);
      if (!reset) fail(400, 'INVALID_TOKEN', 'Reset link is invalid or expired.');
      await client.query('UPDATE password_resets SET used_at=now() WHERE user_id=$1', [reset.user_id]);
      await client.query('UPDATE users SET password_hash=$1,token_version=token_version+1 WHERE id=$2', [passwordHash, reset.user_id]);
      await client.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1', [reset.user_id]);
      await securityAudit('auth.password.reset', 'success', req, reset.user_id, client);
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
    await securityAudit('auth.sessions.revoke_others', 'success', req, req.user.id);
    res.json({ ok: true });
  });
  app.delete('/api/auth/sessions/:id', authenticate, async (req, res) => {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(req.params.id)) fail(400, 'VALIDATION_ERROR', 'Invalid session ID.');
    const result = await pool.query('UPDATE refresh_tokens SET revoked=true WHERE user_id=$1 AND family_id=$2 RETURNING family_id', [req.user.id, req.params.id]);
    if (!result.rowCount) fail(404, 'NOT_FOUND', 'Session not found.');
    if (req.params.id === req.auth.sid) clear(res);
    await securityAudit('auth.session.revoked', 'success', req, req.user.id);
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
      if (user.app_role === 'super_admin') {
        const remaining = await client.query("SELECT 1 FROM users WHERE app_role='super_admin' AND suspended_at IS NULL AND id<>$1", [user.id]);
        if (!remaining.rowCount) fail(409, 'LAST_SUPER_ADMIN', 'The last active super administrator cannot delete their account.');
      }
      if (user.is_admin) {
        const admins = await client.query('SELECT count(*)::int AS count FROM users WHERE is_admin AND suspended_at IS NULL AND id<>$1', [user.id]);
        if (!admins.rows[0].count) fail(409, 'LAST_ADMIN', 'The last active administrator cannot delete their account.');
      }
      await client.query('UPDATE cards SET assignee_ids=array_remove(assignee_ids,$1)', [user.id]);
      await client.query('UPDATE admin_audit SET actor_id=NULL WHERE actor_id=$1', [user.id]);
      await client.query('UPDATE invitations SET revoked=true WHERE lower(email)=lower($1) AND accepted_at IS NULL', [user.email]);
      await securityAudit('auth.account.deleted', 'success', req, user.id, client);
      await client.query('DELETE FROM users WHERE id=$1', [user.id]);
    });
    clear(res);
    await redis.set(`revoked-jti:${req.auth.jti}`, '1', { EX: Math.max(1, req.auth.exp - Math.floor(Date.now() / 1000)) });
    res.json({ message: 'Account deleted.' });
  });
  return authenticate;
}
