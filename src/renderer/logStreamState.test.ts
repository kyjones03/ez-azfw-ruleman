import { describe, expect, it } from 'vitest';
import type { FirewallLogRow } from '../shared/fwLogs';
import {
  INITIAL_LOG_STATE,
  logViewReducer,
  type LogViewAction,
  type LogViewState,
} from './logStreamState';

let n = 0;
const row = (s: number) =>
  ({
    id: String(++n),
    time: new Date(Date.UTC(2026, 0, 1, 0, 0, s)).toISOString(),
  }) as FirewallLogRow;
const run = (...actions: LogViewAction[]): LogViewState =>
  actions.reduce(logViewReducer, INITIAL_LOG_STATE);
const batch = (...secs: number[]): LogViewAction => ({
  type: 'batch',
  batch: { rows: secs.map(row), skipped: 0 },
});

describe('logViewReducer', () => {
  it('shows batches immediately while running', () => {
    expect(run(batch(1, 2)).buffer.rows).toHaveLength(2);
  });
  it('holds rows while paused, then merges them on resume', () => {
    const paused = run(batch(1), { type: 'pause' }, batch(5, 3));
    expect(paused.buffer.rows).toHaveLength(1);
    expect(paused.buffer.held).toHaveLength(2);
    const resumed = logViewReducer(paused, { type: 'resume' });
    expect(resumed.paused).toBe(false);
    expect(resumed.buffer.held).toHaveLength(0);
    expect(resumed.buffer.rows.map((r) => r.time.slice(17, 19))).toEqual([
      '05',
      '03',
      '01',
    ]);
  });
  it('pausing twice is a no-op', () => {
    const once = run({ type: 'pause' });
    expect(logViewReducer(once, { type: 'pause' })).toBe(once);
  });
  it('clear empties table and hold list but keeps the pause state', () => {
    const state = run(batch(1), { type: 'pause' }, batch(2), { type: 'clear' });
    expect(state.paused).toBe(true);
    expect(state.buffer.rows).toHaveLength(0);
    expect(state.buffer.held).toHaveLength(0);
  });
});
