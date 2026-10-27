import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encryptBackupToken, decryptBackupToken, scheduleSlot, validateBackupSettings } from '../src/backup.js';

test('backup refresh tokens are authenticated encrypted and reject corruption or a wrong key', () => {
  const key = '12'.repeat(32), token = { refresh_token: 'private-refresh-token' };
  const sealed = encryptBackupToken(token, key);
  assert.equal(sealed.includes(token.refresh_token), false);
  assert.deepEqual(decryptBackupToken(sealed, key), token);
  assert.notEqual(encryptBackupToken(token, key), sealed);
  assert.throws(() => decryptBackupToken(sealed, '34'.repeat(32)));
  const [iv, tag, payload] = sealed.split('.');
  assert.throws(() => decryptBackupToken([iv, tag, (payload[0] === 'A' ? 'B' : 'A') + payload.slice(1)].join('.'), key));
});

test('backup scheduling uses local wall time and avoids duplicate fall-back slots', () => {
  const schedule = { frequency: 'daily', hour: 1, minute: 30, dayOfWeek: 0, timezone: 'America/Los_Angeles' };
  assert.equal(scheduleSlot(schedule, new Date('2026-11-01T08:30:00Z')), scheduleSlot(schedule, new Date('2026-11-01T09:30:00Z')));
  assert.equal(scheduleSlot(schedule, new Date('2026-11-01T09:31:00Z')), null);
  assert.equal(scheduleSlot({ ...schedule, frequency: 'weekly', dayOfWeek: 1 }, new Date('2026-11-01T08:30:00Z')), null);
  assert.ok(scheduleSlot({ ...schedule, frequency: 'weekly' }, new Date('2026-11-01T08:30:00Z')));
  assert.equal(scheduleSlot({ ...schedule, hour: 2 }, new Date('2026-03-08T10:30:00Z')), null);
});

test('backup settings reject paths, unavailable uploads, empty scope and invalid schedules', () => {
  const valid = { enabled: false, scopeDb: true, scopeConfigs: true, retentionCount: 7, remoteFolder: 'Trello Clone Dev Backups', schedule: { frequency: 'daily', hour: 2, minute: 0, dayOfWeek: 0, timezone: 'America/Los_Angeles' } };
  assert.deepEqual(validateBackupSettings(valid), valid);
  for (const changes of [{ remoteFolder: '../private' }, { remoteFolder: '..' }, { retentionCount: 0 }, { retentionCount: 31 }, { scopeUploads: true }, { scopeDb: false, scopeConfigs: false }, { enabled: 'true' }, { schedule: { ...valid.schedule, minute: 60 } }, { schedule: { ...valid.schedule, timezone: 'Bogus/City' } }]) assert.throws(() => validateBackupSettings({ ...valid, ...changes }));
});
