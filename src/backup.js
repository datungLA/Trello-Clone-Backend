import { randomBytes, randomUUID, createCipheriv, createDecipheriv, createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { access, chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { spawn } from 'node:child_process';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { createGzip } from 'node:zlib';
import { transaction } from './db.js';
import { fail, hash } from './auth.js';
import { audit } from './admin.js';

const googleApi = 'https://www.googleapis.com/drive/v3/files';
const publicRun = row => row && ({ id: row.id, kind: row.kind, status: row.status, startedAt: row.started_at, finishedAt: row.finished_at, sizeBytes: Number(row.size_bytes), checksum: row.checksum, verifiedAt: row.verified_at, error: row.error, remotePath: row.remote_path, scopeDb: row.scope_db, scopeConfigs: row.scope_configs });

export function validateBackupSettings(body) {
  const schedule = body.schedule;
  if (!schedule || !['daily', 'weekly'].includes(schedule.frequency) || !Number.isInteger(schedule.hour) || schedule.hour < 0 || schedule.hour > 23 || !Number.isInteger(schedule.minute) || schedule.minute < 0 || schedule.minute > 59 || !Number.isInteger(schedule.dayOfWeek) || schedule.dayOfWeek < 0 || schedule.dayOfWeek > 6) fail(400, 'VALIDATION_ERROR', 'Choose a valid daily or weekly backup time.');
  try { if (typeof schedule.timezone !== 'string' || schedule.timezone.length > 80) throw Error(); new Intl.DateTimeFormat('en-US', { timeZone: schedule.timezone }).format(); }
  catch { fail(400, 'VALIDATION_ERROR', 'Choose a valid IANA timezone.'); }
  if (!Number.isInteger(body.retentionCount) || body.retentionCount < 1 || body.retentionCount > 30) fail(400, 'VALIDATION_ERROR', 'Keep between 1 and 30 backups.');
  for (const key of ['enabled', 'scopeDb', 'scopeConfigs']) if (typeof body[key] !== 'boolean') fail(400, 'VALIDATION_ERROR', 'Backup options must be true or false.');
  if (!body.scopeDb && !body.scopeConfigs) fail(400, 'VALIDATION_ERROR', 'Select at least one backup scope.');
  if (body.scopeUploads === true) fail(400, 'VALIDATION_ERROR', 'Uploads are not enabled in this installation.');
  if (typeof body.remoteFolder !== 'string' || !/^[\p{L}\p{N} _().-]{1,80}$/u.test(body.remoteFolder) || ['.', '..'].includes(body.remoteFolder.trim())) fail(400, 'VALIDATION_ERROR', 'Use a folder name of 1 to 80 letters, numbers, spaces or simple punctuation.');
  return { ...body, schedule: { frequency: schedule.frequency, hour: schedule.hour, minute: schedule.minute, dayOfWeek: schedule.dayOfWeek, timezone: schedule.timezone }, remoteFolder: body.remoteFolder.trim() };
}

export function scheduleSlot(schedule, now = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: schedule.timezone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', weekday: 'short', hourCycle: 'h23' }).formatToParts(now).map(part => [part.type, part.value]));
  if (Number(parts.hour) !== schedule.hour || Number(parts.minute) !== schedule.minute || (schedule.frequency === 'weekly' && ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(parts.weekday) !== schedule.dayOfWeek)) return null;
  return `${parts.year}-${parts.month}-${parts.day}:${parts.hour}:${parts.minute}:${schedule.timezone}`;
}

function keyBytes(key) {
  if (typeof key !== 'string' || !/^[a-f0-9]{64}$/i.test(key)) fail(503, 'BACKUP_NOT_READY', 'The private backup token encryption key is not configured.');
  return Buffer.from(key, 'hex');
}
export function encryptBackupToken(token, key) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', keyBytes(key), iv);
  cipher.setAAD(Buffer.from('trello-backup-google-v1'));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(token)), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(part => part.toString('base64url')).join('.');
}
export function decryptBackupToken(value, key) {
  const [iv, tag, encrypted] = value.split('.').map(part => Buffer.from(part, 'base64url'));
  const cipher = createDecipheriv('aes-256-gcm', keyBytes(key), iv);
  cipher.setAAD(Buffer.from('trello-backup-google-v1')); cipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([cipher.update(encrypted), cipher.final()]).toString());
}

async function command(name, args, { signal, env = process.env, stdout } = {}) {
  const child = spawn(name, args, { env, signal, stdio: ['ignore', stdout ? 'pipe' : 'ignore', 'pipe'] });
  child.stderr.resume();
  const completed = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', code => code === 0 ? resolve() : reject(new Error('BACKUP_TOOL_FAILED')));
  });
  if (stdout) {
    try { await Promise.all([stdout(child.stdout), completed]); }
    catch (error) { child.kill('SIGTERM'); throw error; }
  } else await completed;
}

export async function createBackupArchive({ config, settings, directory, signal }) {
  await chmod(directory, 0o700);
  const databaseUrl = new URL(config.databaseUrl);
  const entries = [];
  if (settings.scope_db) {
    const output = join(directory, 'database.sql.gz');
    let bytes = 0;
    const limit = new Transform({ transform(chunk, encoding, callback) { bytes += chunk.length; callback(bytes > 256 * 1024 * 1024 ? new Error('BACKUP_TOO_LARGE') : null, chunk); } });
    await command('pg_dump', ['--no-owner', '--no-acl', '--host', databaseUrl.hostname, '--port', databaseUrl.port || '5432', '--username', decodeURIComponent(databaseUrl.username), '--dbname', databaseUrl.pathname.slice(1)], {
      signal, env: { ...process.env, PGPASSWORD: decodeURIComponent(databaseUrl.password), PGCONNECT_TIMEOUT: '15' },
      stdout: stream => pipeline(stream, limit, createGzip(), createWriteStream(output, { mode: 0o600 }), { signal }),
    });
    entries.push('database.sql.gz');
  }
  if (settings.scope_configs) {
    const source = await realpath(config.configDir);
    const destination = join(directory, 'configuration');
    await mkdir(destination, { mode: 0o700 });
    for (const name of ['compose.yaml', 'nginx/default.conf', 'nginx/security-headers.conf']) {
      const resolved = await realpath(join(source, name));
      if (relative(source, resolved).startsWith('..')) throw new Error('BACKUP_CONFIG_PATH');
      const file = await stat(resolved);
      if (!file.isFile() || file.size > 256 * 1024) throw new Error('BACKUP_CONFIG_SIZE');
      await mkdir(join(destination, ...name.split('/').slice(0, -1)), { recursive: true, mode: 0o700 });
      await writeFile(join(destination, name), await readFile(resolved), { mode: 0o600 });
    }
    entries.push('configuration');
  }
  await writeFile(join(directory, 'manifest.json'), JSON.stringify({ format: 'trello-encrypted-backup-v1', createdAt: new Date().toISOString(), environment: config.environment, scopes: { database: settings.scope_db, configuration: settings.scope_configs, uploads: false }, configurationIncludesSecrets: false, recovery: 'Decrypt backup.cms with the separately held recovery private key, then restore database.sql.gz into an isolated PostgreSQL 16 database. Runtime secrets are deliberately excluded.' }), { mode: 0o600 });
  entries.push('manifest.json');
  await command('tar', ['-czf', join(directory, 'archive.tar.gz'), '-C', directory, ...entries], { signal });
  const encrypted = join(directory, 'backup.cms');
  await command('openssl', ['cms', '-encrypt', '-binary', '-aes-256-cbc', '-in', join(directory, 'archive.tar.gz'), '-outform', 'DER', '-out', encrypted, config.recipientCertFile], { signal });
  await chmod(encrypted, 0o600);
  const size = (await stat(encrypted)).size;
  if (size > 256 * 1024 * 1024) throw new Error('BACKUP_TOO_LARGE');
  const checksum = createHash('md5');
  for await (const chunk of createReadStream(encrypted)) checksum.update(chunk);
  return { path: encrypted, size, checksum: checksum.digest('hex') };
}

export function createBackupService({ pool, redis, config: appConfig }) {
  const config = appConfig.backup || {};
  const environment = config.environment || 'dev';
  const redirectUri = `${config.origin || appConfig.origin}/api/backup/oauth/callback`;
  const fetcher = config.fetch || fetch;
  let timer, controller, activePromise, stopped = false, ticking = false;
  const getSettings = async (client = pool) => (await client.query('SELECT * FROM backup_settings WHERE id=true')).rows[0];
  const requireSuper = async (userId, client = pool) => {
    const user = (await client.query("SELECT id FROM users WHERE id=$1 AND app_role='super_admin' AND is_admin AND suspended_at IS NULL AND email_verified_at IS NOT NULL", [userId])).rows[0];
    if (!user) fail(403, 'SUPER_ADMIN_REQUIRED', 'Only a super administrator can manage system backups.');
  };
  async function readiness() {
    const checks = [{ key: 'oauth', label: 'Google OAuth credentials', ok: !!(config.clientId && config.clientSecret) }, { key: 'tokenKey', label: 'Private token encryption key', ok: /^[a-f0-9]{64}$/i.test(config.tokenKey || '') }];
    for (const [key, label, path] of [['certificate', 'Recovery encryption certificate', config.recipientCertFile], ['configuration', 'Allowlisted configuration snapshot', config.configDir], ['staging', 'Private backup staging directory', config.workDir]]) {
      let ok = false;
      try { if (path) { await access(path); ok = true; } } catch {}
      checks.push({ key, label, ok });
    }
    return checks;
  }
  async function publicSettings() {
    const row = await getSettings(), checks = await readiness();
    const lastRun = publicRun((await pool.query('SELECT * FROM backup_runs ORDER BY started_at DESC,id LIMIT 1')).rows[0]);
    return { configured: checks.every(check => check.ok), ready: checks.every(check => check.ok) && !!row.token_ciphertext, credentialConfigured: checks[0].ok, connected: !!row.token_ciphertext, accountEmail: row.account_email, redirectUri, enabled: row.enabled, schedule: row.schedule, retentionCount: row.retention_count, scopeDb: row.scope_db, scopeConfigs: row.scope_configs, scopeUploads: false, uploadsAvailable: false, remoteFolder: row.remote_folder, environment, readiness: checks, lastRun };
  }
  async function request(url, options = {}, timeout = 30000) {
    const response = await fetcher(url, { ...options, signal: options.signal || AbortSignal.timeout(timeout), redirect: 'error' });
    if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? 'GOOGLE_RECONNECT_REQUIRED' : 'GOOGLE_REQUEST_FAILED');
    return response;
  }
  async function accessToken(row) {
    let stored;
    try { stored = decryptBackupToken(row.token_ciphertext, config.tokenKey); } catch { throw new Error('GOOGLE_RECONNECT_REQUIRED'); }
    const response = await request('https://oauth2.googleapis.com/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: stored.refresh_token, client_id: config.clientId, client_secret: config.clientSecret }) });
    const token = await response.json();
    if (!token.access_token) throw new Error('GOOGLE_RECONNECT_REQUIRED');
    return token.access_token;
  }
  function metadata(row) { return { trelloBackup: 'v1', environment, namespace: row.namespace }; }
  async function upload(row, artifact, runId, signal) {
    const token = await accessToken(row), headers = { Authorization: `Bearer ${token}` };
    let folderId = row.folder_id;
    if (folderId) {
      const folder = await (await request(`${googleApi}/${encodeURIComponent(folderId)}?fields=id,trashed,appProperties`, { headers, signal })).json();
      if (folder.trashed || folder.appProperties?.namespace !== row.namespace) throw new Error('GOOGLE_FOLDER_CHANGED');
    } else {
      const folder = await (await request(googleApi + '?fields=id', { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ name: row.remote_folder, mimeType: 'application/vnd.google-apps.folder', appProperties: metadata(row) }), signal })).json();
      folderId = folder.id;
      if (!folderId) throw new Error('GOOGLE_REQUEST_FAILED');
      await pool.query('UPDATE backup_settings SET folder_id=$1 WHERE id=true AND namespace=$2', [folderId, row.namespace]);
    }
    const name = `trello-${environment}-${new Date().toISOString().replace(/[:.]/g, '-')}-${runId}.cms`;
    const response = await request('https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id,size,md5Checksum', { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json', 'X-Upload-Content-Type': 'application/octet-stream', 'X-Upload-Content-Length': String(artifact.size) }, body: JSON.stringify({ name, parents: [folderId], mimeType: 'application/octet-stream', appProperties: { ...metadata(row), runId } }), signal });
    const location = new URL(response.headers.get('location') || 'invalid:', 'https://invalid');
    if (location.protocol !== 'https:' || !['www.googleapis.com', 'content.googleapis.com'].includes(location.hostname) || !location.pathname.startsWith('/upload/drive/')) throw new Error('GOOGLE_UPLOAD_LOCATION');
    const uploaded = await (await request(location.href, { method: 'PUT', headers: { ...headers, 'Content-Type': 'application/octet-stream', 'Content-Length': String(artifact.size) }, body: createReadStream(artifact.path), duplex: 'half', signal }, 600000)).json();
    if (!uploaded.id) throw new Error('GOOGLE_UPLOAD_UNVERIFIED');
    const verified = await (await request(`${googleApi}/${encodeURIComponent(uploaded.id)}?fields=id,size,md5Checksum,trashed`, { headers, signal })).json();
    if (verified.trashed || Number(verified.size) !== artifact.size || verified.md5Checksum !== artifact.checksum) throw new Error('GOOGLE_UPLOAD_UNVERIFIED');
    return { id: uploaded.id, path: `https://drive.google.com/file/d/${uploaded.id}/view`, folderId, headers };
  }
  async function retention(row, uploaded, signal) {
    const params = new URLSearchParams({ q: `'${uploaded.folderId}' in parents and trashed = false and appProperties has { key='namespace' and value='${row.namespace}' } and appProperties has { key='trelloBackup' and value='v1' }`, fields: 'files(id,createdTime,appProperties),nextPageToken', pageSize: '100', orderBy: 'createdTime desc' });
    const response = await (await request(`${googleApi}?${params}`, { headers: uploaded.headers, signal })).json();
    if (response.nextPageToken) throw new Error('BACKUP_RETENTION_LIMIT');
    for (const file of response.files.slice(row.retention_count)) {
      if (!file.appProperties?.runId || file.id === uploaded.id) continue;
      const verified = await pool.query("SELECT 1 FROM backup_runs WHERE id=$1 AND status='success' AND verified_at IS NOT NULL", [file.appProperties.runId]);
      if (verified.rowCount) await request(`${googleApi}/${encodeURIComponent(file.id)}`, { method: 'PATCH', headers: { ...uploaded.headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ trashed: true }), signal });
    }
  }
  async function execute(row) {
    const ownController = new AbortController();
    controller = ownController;
    const signal = AbortSignal.any([ownController.signal, AbortSignal.timeout(30 * 60000)]);
    let directory, heartbeat, status = 'failed', message = '';
    try {
      await pool.query("UPDATE backup_runs SET status='running',heartbeat_at=now() WHERE id=$1", [row.id]);
      heartbeat = setInterval(() => pool.query('UPDATE backup_runs SET heartbeat_at=now() WHERE id=$1', [row.id]).catch(() => ownController.abort()), 15000);
      heartbeat.unref();
      directory = await mkdtemp(join(config.workDir, `run-${row.id}-`));
      const settings = { ...row.settings, token_ciphertext: (await getSettings()).token_ciphertext };
      const artifact = await (config.archive || createBackupArchive)({ config: { ...config, environment }, settings, directory, signal });
      const uploaded = await upload(settings, artifact, row.id, signal);
      await pool.query('UPDATE backup_runs SET verified_at=now(),size_bytes=$2,checksum=$3,remote_path=$4 WHERE id=$1', [row.id, artifact.size, artifact.checksum, uploaded.path]);
      try { await retention(settings, uploaded, signal); } catch { message = 'Backup verified; retention cleanup needs attention.'; }
      await audit(pool, row.triggered_by, 'backup.completed', 'backup', row.id);
      status = 'success';
    } catch (error) {
      message = ['GOOGLE_RECONNECT_REQUIRED', 'GOOGLE_FOLDER_CHANGED'].includes(error.message) ? 'Reconnect Google Drive and try again.' : error.message === 'BACKUP_TOO_LARGE' ? 'Backup exceeds the 256 MB learning-environment limit.' : 'Backup failed or was interrupted. Check connection and server readiness, then retry.';
      await audit(pool, row.triggered_by, 'backup.failed', 'backup', row.id).catch(() => {});
    } finally {
      clearInterval(heartbeat);
      try { if (directory) await rm(directory, { recursive: true, force: true }); }
      catch { status = 'failed'; message = 'Private staging cleanup failed. Ask the server operator to inspect the backup worker.'; }
      if (controller === ownController) controller = null;
      await pool.query('UPDATE backup_runs SET status=$2,finished_at=now(),error=$3 WHERE id=$1', [row.id, status, message]);
    }
  }
  async function enqueue(kind, userId, slot) {
    if (stopped) fail(503, 'BACKUP_STOPPING', 'The backup worker is restarting. Try again shortly.');
    if (activePromise) fail(409, 'BACKUP_BUSY', 'A backup is already running.');
    const run = await transaction(pool, async client => {
      const row = (await client.query('SELECT * FROM backup_settings WHERE id=true FOR UPDATE')).rows[0];
      if (stopped) fail(503, 'BACKUP_STOPPING', 'The backup worker is restarting. Try again shortly.');
      if (kind === 'scheduled' && (!row.enabled || row.last_slot === slot)) return null;
      if (kind === 'manual') await requireSuper(userId, client);
      if ((await readiness()).some(check => !check.ok) || !row.token_ciphertext) fail(503, 'BACKUP_NOT_READY', 'Complete the server setup and connect Google Drive first.');
      if ((await client.query("SELECT 1 FROM backup_runs WHERE status IN('pending','running')")).rowCount) fail(409, 'BACKUP_BUSY', 'A backup is already running.');
      const { token_ciphertext, ...snapshot } = row;
      const result = (await client.query("INSERT INTO backup_runs(id,kind,status,scope_db,scope_configs,triggered_by,settings) VALUES($1,$2,'pending',$3,$4,$5,$6) RETURNING *", [randomUUID(), kind, row.scope_db, row.scope_configs, userId, JSON.stringify(snapshot)])).rows[0];
      if (slot) await client.query('UPDATE backup_settings SET last_slot=$1 WHERE id=true', [slot]);
      await audit(client, userId, 'backup.started', 'backup', result.id, { kind });
      return result;
    });
    if (run && stopped) {
      await pool.query("UPDATE backup_runs SET status='failed',finished_at=now(),error='Worker restarting. Run a new backup.' WHERE id=$1", [run.id]);
      fail(503, 'BACKUP_STOPPING', 'The backup worker is restarting. Try again shortly.');
    }
    if (run) {
      const ownPromise = execute(run).catch(() => {}).finally(() => { if (activePromise === ownPromise) activePromise = null; });
      activePromise = ownPromise;
    }
    return publicRun(run);
  }
  async function tick() {
    if (ticking || stopped) return;
    ticking = true;
    try {
      await pool.query("UPDATE backup_runs SET status='failed',finished_at=now(),error='Worker interrupted. Run a new backup.' WHERE status IN('pending','running') AND heartbeat_at<now()-interval '90 seconds'");
      if (config.workDir) {
        for (const entry of await readdir(config.workDir)) {
          const match = /^run-([a-f0-9-]{36})-[\w-]+$/i.exec(entry);
          if (match && (await pool.query("SELECT 1 FROM backup_runs WHERE id=$1 AND status IN('success','failed')", [match[1]])).rowCount) await rm(join(config.workDir, entry), { recursive: true, force: true });
        }
      }
      if (!activePromise) {
        const row = await getSettings(), slot = row.enabled && scheduleSlot(row.schedule);
        if (slot) await enqueue('scheduled', null, slot);
      }
    } catch {} finally { ticking = false; }
  }
  const cookieOptions = { httpOnly: true, secure: appConfig.secure, sameSite: 'lax', path: '/api/backup/oauth/callback', maxAge: 600000 };
  function installCallback(app) {
    app.get('/api/backup/oauth/callback', async (req, res) => {
      let outcome = 'failed';
      try {
        if (typeof req.query.state !== 'string' || !/^[a-f0-9]{64}$/.test(req.query.state)) throw Error();
        const raw = await redis.getDel(`backup-oauth:${hash(req.query.state)}`);
        if (!raw || req.query.error || typeof req.query.code !== 'string' || req.query.code.length > 4096) throw Error();
        const state = JSON.parse(raw), binding = req.cookies.backup_oauth;
        if (typeof binding !== 'string' || hash(binding) !== state.binding) throw Error();
        await requireSuper(state.userId);
        const live = await pool.query('SELECT 1 FROM refresh_tokens r JOIN users u ON u.id=r.user_id WHERE r.user_id=$1 AND r.family_id=$2 AND NOT r.revoked AND r.expires_at>now() AND u.token_version=$3 AND NOT EXISTS(SELECT 1 FROM refresh_tokens dead WHERE dead.family_id=$2 AND dead.revoked)', [state.userId, state.family, state.version]);
        if (!live.rowCount) throw Error();
        const response = await request('https://oauth2.googleapis.com/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'authorization_code', code: req.query.code, client_id: config.clientId, client_secret: config.clientSecret, redirect_uri: redirectUri, code_verifier: state.verifier }) });
        const token = await response.json();
        if (!token.refresh_token || !token.access_token || !String(token.scope || '').split(' ').includes('https://www.googleapis.com/auth/drive.file')) throw Error();
        const info = await (await request('https://www.googleapis.com/oauth2/v2/userinfo', { headers: { Authorization: `Bearer ${token.access_token}` } })).json();
        await transaction(pool, async client => {
          await client.query('SELECT id FROM backup_settings WHERE id=true FOR UPDATE');
          await requireSuper(state.userId, client);
          const session = await client.query('SELECT 1 FROM refresh_tokens r JOIN users u ON u.id=r.user_id WHERE r.user_id=$1 AND r.family_id=$2 AND NOT r.revoked AND r.expires_at>now() AND u.token_version=$3 AND NOT EXISTS(SELECT 1 FROM refresh_tokens dead WHERE dead.family_id=$2 AND dead.revoked)', [state.userId, state.family, state.version]);
          if (!session.rowCount) fail(401, 'TOKEN_INVALID', 'Sign in to connect Google Drive.');
          const row = await getSettings(client);
          if ((await client.query("SELECT 1 FROM backup_runs WHERE status IN('pending','running')")).rowCount) fail(409, 'BACKUP_BUSY', 'Wait for the running backup.');
          await client.query('UPDATE backup_settings SET token_ciphertext=$1,account_email=$2,folder_id=CASE WHEN account_email=$2 THEN folder_id ELSE NULL END,namespace=CASE WHEN account_email=$2 THEN namespace ELSE gen_random_uuid() END,enabled=false,updated_at=now() WHERE id=true', [encryptBackupToken({ refresh_token: token.refresh_token }, config.tokenKey), typeof info.email === 'string' ? info.email.slice(0, 254) : '']);
          await audit(client, state.userId, 'backup.google.connected', 'backup', row.namespace);
        });
        outcome = 'connected';
      } catch {}
      res.clearCookie('backup_oauth', { ...cookieOptions, maxAge: undefined });
      res.redirect(303, `${config.origin || appConfig.origin}/admin/backup?tab=connect&backupConnection=${outcome}`);
    });
  }
  function installRoutes(app) {
    const prefix = '/api/admin/backup';
    app.use(prefix, async (req, res, next) => { await requireSuper(req.user.id); next(); });
    app.get(`${prefix}/settings`, async (req, res) => res.json(await publicSettings()));
    app.put(`${prefix}/settings`, async (req, res) => {
      const values = validateBackupSettings(req.body);
      await transaction(pool, async client => {
        await requireSuper(req.user.id, client);
        await client.query('SELECT id FROM backup_settings WHERE id=true FOR UPDATE');
        if ((await client.query("SELECT 1 FROM backup_runs WHERE status IN('pending','running')")).rowCount) fail(409, 'BACKUP_BUSY', 'Wait for the running backup before changing settings.');
        if (values.enabled && !(await publicSettings()).ready) fail(503, 'BACKUP_NOT_READY', 'Complete setup and connect Google Drive first.');
        await client.query('UPDATE backup_settings SET enabled=$1,schedule=$2,retention_count=$3,scope_db=$4,scope_configs=$5,remote_folder=$6,folder_id=CASE WHEN remote_folder=$6 THEN folder_id ELSE NULL END,updated_at=now() WHERE id=true', [values.enabled, JSON.stringify(values.schedule), values.retentionCount, values.scopeDb, values.scopeConfigs, values.remoteFolder]);
        await audit(client, req.user.id, 'backup.settings.updated', 'backup', (await getSettings(client)).namespace, { enabled: values.enabled });
      });
      res.json(await publicSettings());
    });
    app.post(`${prefix}/run`, async (req, res) => res.status(202).json(await enqueue('manual', req.user.id)));
    app.get(`${prefix}/runs`, async (req, res) => {
      if (req.query.limit !== undefined && (typeof req.query.limit !== 'string' || !/^[1-9]\d?$/.test(req.query.limit) || Number(req.query.limit) > 50)) fail(400, 'VALIDATION_ERROR', 'Use a history limit between 1 and 50.');
      const limit = Number(req.query.limit || 7), rows = (await pool.query('SELECT * FROM backup_runs ORDER BY started_at DESC,id LIMIT $1', [limit + 1])).rows;
      res.json({ items: rows.slice(0, limit).map(publicRun), hasMore: rows.length > limit });
    });
    app.get(`${prefix}/runs/:id`, async (req, res) => {
      const row = (await pool.query('SELECT * FROM backup_runs WHERE id=$1', [req.params.id])).rows[0];
      if (!row) fail(404, 'NOT_FOUND', 'Backup not found.');
      res.json(publicRun(row));
    });
    app.post(`${prefix}/gdrive/oauth/start`, async (req, res) => {
      keyBytes(config.tokenKey);
      if (!config.clientId || !config.clientSecret) fail(503, 'BACKUP_NOT_READY', 'Google OAuth credentials are not configured.');
      const state = randomBytes(32).toString('hex'), binding = randomBytes(32).toString('hex'), verifier = randomBytes(48).toString('base64url');
      await redis.set(`backup-oauth:${hash(state)}`, JSON.stringify({ userId: req.user.id, family: req.auth.sid, version: req.auth.tv, binding: hash(binding), verifier }), { EX: 600 });
      res.cookie('backup_oauth', binding, cookieOptions);
      const params = new URLSearchParams({ client_id: config.clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.email', access_type: 'offline', prompt: 'consent', state, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' });
      res.json({ authUrl: `https://accounts.google.com/o/oauth2/v2/auth?${params}`, redirectUri });
    });
    app.post(`${prefix}/gdrive/disconnect`, async (req, res) => {
      if (req.body.confirm !== true) fail(400, 'CONFIRM_REQUIRED', 'Confirm disconnecting Google Drive.');
      await transaction(pool, async client => {
        await client.query('SELECT id FROM backup_settings WHERE id=true FOR UPDATE');
        await requireSuper(req.user.id, client);
        if ((await client.query("SELECT 1 FROM backup_runs WHERE status IN('pending','running')")).rowCount) fail(409, 'BACKUP_BUSY', 'Wait for the running backup.');
        await client.query("UPDATE backup_settings SET enabled=false,token_ciphertext=NULL,account_email='',updated_at=now() WHERE id=true");
        await audit(client, req.user.id, 'backup.google.disconnected', 'backup', (await getSettings(client)).namespace);
      });
      res.json(await publicSettings());
    });
  }
  return { installCallback, installRoutes, publicSettings, async start() { stopped = false; await tick(); timer = setInterval(tick, 15000); timer.unref(); }, async stop() { stopped = true; clearInterval(timer); controller?.abort(); if (activePromise) await activePromise; } };
}
