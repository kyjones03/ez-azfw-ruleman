import { describe, expect, it } from 'vitest';
import type { FirewallLogRow } from './fwLogs';
import { clear, EMPTY_BUFFER, ingest, MAX_ROWS, release } from './logBuffer';

let n = 0;
const row = (time: string): FirewallLogRow =>
  ({ id: String(++n), time, category: 'NetworkRule' }) as FirewallLogRow;
const t = (s: number) => new Date(Date.UTC(2026, 0, 1, 0, 0, s)).toISOString();
const times = (rows: FirewallLogRow[]) =>
  rows.map((r) => Date.parse(r.time) / 1000 - Date.UTC(2026, 0, 1) / 1000);

describe('logBuffer', () => {
  it('keeps rows newest first across batches, even out of order', () => {
    let b = ingest(EMPTY_BUFFER, [row(t(1)), row(t(5)), row(t(3))], 0, false);
    expect(times(b.rows)).toEqual([5, 3, 1]);
    b = ingest(b, [row(t(4)), row(t(9))], 0, false);
    expect(times(b.rows)).toEqual([9, 5, 4, 3, 1]);
  });
  it('equal timestamps: later arrival first', () => {
    const a = row(t(1));
    const c = row(t(1));
    let b = ingest(EMPTY_BUFFER, [a], 0, false);
    b = ingest(b, [c], 0, false);
    expect(b.rows.map((r) => r.id)).toEqual([c.id, a.id]);
  });
  it('unparseable times sort oldest rather than breaking the merge', () => {
    const b = ingest(EMPTY_BUFFER, [row('garbage'), row(t(2))], 0, false);
    expect(times(b.rows.slice(0, 1))).toEqual([2]);
    expect(b.rows).toHaveLength(2);
  });
  it('counts totals and skips, including skip-only batches', () => {
    let b = ingest(EMPTY_BUFFER, [row(t(1))], 2, false);
    b = ingest(b, [], 3, false);
    expect(b).toMatchObject({ total: 6, skipped: 5 });
    expect(b.rows).toHaveLength(1);
  });
  it('caps the table at MAX_ROWS, dropping the oldest', () => {
    const big = Array.from({ length: MAX_ROWS + 10 }, (_, i) => row(t(i)));
    const b = ingest(EMPTY_BUFFER, big, 0, false);
    expect(b.rows).toHaveLength(MAX_ROWS);
    expect(times(b.rows)[0]).toBe(MAX_ROWS + 9);
    expect(times(b.rows).at(-1)).toBe(10);
  });
  it('while paused, rows go to the hold list and the table does not move', () => {
    let b = ingest(EMPTY_BUFFER, [row(t(1))], 0, false);
    b = ingest(b, [row(t(2)), row(t(3))], 1, true);
    expect(times(b.rows)).toEqual([1]);
    expect(times(b.held)).toEqual([3, 2]);
    expect(b.total).toBe(4);
  });
  it('resume merges held rows in time order, and nothing is lost', () => {
    let b = ingest(EMPTY_BUFFER, [row(t(10))], 0, false);
    b = ingest(b, [row(t(11)), row(t(5))], 0, true);
    b = release(b);
    expect(times(b.rows)).toEqual([11, 10, 5]);
    expect(b.held).toEqual([]);
    expect(b.heldDropped).toBe(0);
  });
  it('a full hold list drops the oldest held rows and says how many', () => {
    const b0 = ingest(
      EMPTY_BUFFER,
      Array.from({ length: MAX_ROWS }, (_, i) => row(t(i + 100))),
      0,
      true,
    );
    const b1 = ingest(b0, [row(t(1)), row(t(2)), row(t(9999))], 0, true);
    expect(b1.held).toHaveLength(MAX_ROWS);
    expect(b1.heldDropped).toBe(3);
    expect(times(b1.held)[0]).toBe(9999);
    const b2 = release(b1);
    expect(b2.rows).toHaveLength(MAX_ROWS);
    expect(b2.heldDropped).toBe(0);
  });
  it('release without held rows returns the same buffer', () => {
    const b = ingest(EMPTY_BUFFER, [row(t(1))], 0, false);
    expect(release(b)).toBe(b);
  });
  it('clear empties the table, hold list and counters', () => {
    const b = ingest(
      ingest(EMPTY_BUFFER, [row(t(1))], 1, false),
      [row(t(2))],
      0,
      true,
    );
    expect(clear()).toEqual(EMPTY_BUFFER);
    expect(b.held).toHaveLength(1);
  });
});
