import { test } from 'node:test';
import assert from 'node:assert/strict';
import { plannerInstant, plannerPayload, plannerRange } from '../src/planner.js';

test('planner instants require explicit offsets and reject calendar, time and UTC-boundary overflow', () => {
  assert.equal(plannerInstant('2026-10-27T08:15:30.5-07:00'), '2026-10-27T15:15:30.500Z');
  assert.equal(plannerInstant('2024-02-29T23:15+01:00'), '2024-02-29T22:15:00.000Z');
  assert.equal(plannerInstant('0001-01-01T00:00:00Z'), '0001-01-01T00:00:00.000Z');
  for (const value of [undefined, null, new Date(), '2026-10-27', '2026-10-27T12:00:00', '2026-02-29T12:00Z', '2024-02-30T12:00Z', '2026-04-31T12:00Z', '2026-00-01T12:00Z', '2026-13-01T12:00Z', '2026-01-00T12:00Z', '2026-01-01T24:00Z', '2026-01-01T12:60Z', '2026-01-01T12:00:60Z', '2026-01-01T12:00+24:00', '2026-01-01T12:00+01:60', '0000-01-01T00:00Z', '0001-01-01T00:00+01:00', '9999-12-31T23:59-01:00', '2026-01-01T12:00:00.0000Z']) assert.throws(() => plannerInstant(value), undefined, String(value));
});

test('focus blocks keep exact notes and enforce one-minute through 24-hour durations', () => {
  const body = { title: '  Plan one thing  ', notes: 'First line\n  Second line  ', startsAt: '2026-10-27T10:00:00Z', endsAt: '2026-10-27T11:00:00Z' };
  assert.deepEqual(plannerPayload(body), { ...body, title: 'Plan one thing', startsAt: '2026-10-27T10:00:00.000Z', endsAt: '2026-10-27T11:00:00.000Z' });
  assert.ok(plannerPayload({ ...body, endsAt: '2026-10-27T10:01:00Z' }));
  assert.ok(plannerPayload({ ...body, endsAt: '2026-10-28T10:00:00Z' }));
  assert.equal(plannerPayload({ ...body, notes: undefined }).notes, '');
  for (const changed of [{ endsAt: body.startsAt }, { endsAt: '2026-10-27T10:00:59.999Z' }, { endsAt: '2026-10-28T10:00:00.001Z' }, { title: '' }, { title: 'x'.repeat(201) }, { notes: null }, { notes: 'x'.repeat(10001) }]) assert.throws(() => plannerPayload({ ...body, ...changed }));
});

test('planner ranges are positive and bound queries to 62 elapsed days', () => {
  assert.deepEqual(plannerRange('2026-01-01T00:00Z', '2026-03-04T00:00Z'), { from: '2026-01-01T00:00:00.000Z', to: '2026-03-04T00:00:00.000Z' });
  assert.throws(() => plannerRange('2026-01-01T00:00Z', '2026-03-04T00:00:00.001Z'));
  assert.throws(() => plannerRange('2026-01-01T00:00Z', '2026-01-01T00:00Z'));
  assert.throws(() => plannerRange('2026-01-02T00:00Z', '2026-01-01T00:00Z'));
  assert.throws(() => plannerRange(undefined, '2026-01-01T00:00Z'));
});
