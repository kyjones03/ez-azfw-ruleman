// The Logs view's row buffer: newest first, capped, with a hold list while paused.
// Pure and immutable so it can be unit tested and used from a reducer.
import type { FirewallLogRow } from './fwLogs';

export const MAX_ROWS = 5000;

export interface LogBuffer {
  /** Visible rows, newest first, at most `MAX_ROWS`. */
  rows: FirewallLogRow[];
  /** Rows that arrived while paused, newest first, at most `MAX_ROWS`. */
  held: FirewallLogRow[];
  /** Held rows discarded because the hold list was full (oldest first); shown as a notice. */
  heldDropped: number;
  /** Records received but not shown (aggregation categories, other resources, junk). */
  skipped: number;
  /** Everything received since the last clear, shown or not. */
  total: number;
}

export const EMPTY_BUFFER: LogBuffer = {
  rows: [],
  held: [],
  heldDropped: 0,
  skipped: 0,
  total: 0,
};

const timeOf = (row: FirewallLogRow): number => {
  const t = Date.parse(row.time);
  return Number.isNaN(t) ? 0 : t;
};

/** Newest first. Stable, so equal timestamps keep arrival order (later arrival first). */
function newestFirst(batch: readonly FirewallLogRow[]): FirewallLogRow[] {
  return batch
    .map((row, i) => ({ row, i, t: timeOf(row) }))
    .sort((a, b) => b.t - a.t || b.i - a.i)
    .map((x) => x.row);
}

/** Merges two newest-first lists in O(n); on a tie, `incoming` goes first (it arrived later). */
function merge(
  incoming: readonly FirewallLogRow[],
  existing: readonly FirewallLogRow[],
  cap: number,
): FirewallLogRow[] {
  const out: FirewallLogRow[] = [];
  let i = 0;
  let j = 0;
  while (out.length < cap && (i < incoming.length || j < existing.length)) {
    if (
      j >= existing.length ||
      (i < incoming.length && timeOf(incoming[i]) >= timeOf(existing[j]))
    )
      out.push(incoming[i++]);
    else out.push(existing[j++]);
  }
  return out;
}

/** Adds a batch from the stream. While paused it goes to the hold list instead of the table. */
export function ingest(
  buf: LogBuffer,
  batch: readonly FirewallLogRow[],
  skipped: number,
  paused: boolean,
): LogBuffer {
  const total = buf.total + batch.length + skipped;
  const skippedTotal = buf.skipped + skipped;
  if (batch.length === 0) return { ...buf, total, skipped: skippedTotal };
  const sorted = newestFirst(batch);
  if (!paused)
    return {
      ...buf,
      rows: merge(sorted, buf.rows, MAX_ROWS),
      total,
      skipped: skippedTotal,
    };
  const combined = buf.held.length + sorted.length;
  return {
    ...buf,
    held: merge(sorted, buf.held, MAX_ROWS),
    heldDropped: buf.heldDropped + Math.max(0, combined - MAX_ROWS),
    total,
    skipped: skippedTotal,
  };
}

/** Resumes: held rows join the table in time order; the notice is cleared. */
export function release(buf: LogBuffer): LogBuffer {
  if (buf.held.length === 0 && buf.heldDropped === 0) return buf;
  return {
    ...buf,
    rows: merge(buf.held, buf.rows, MAX_ROWS),
    held: [],
    heldDropped: 0,
  };
}

/** Clear: empties the table and the hold list; the stream keeps running. */
export const clear = (): LogBuffer => EMPTY_BUFFER;
