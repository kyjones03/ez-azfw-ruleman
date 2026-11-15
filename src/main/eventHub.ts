// Live firewall-log stream session: connects to an Event Hub with the signed-in user's Entra
// identity, parses diagnostic records and hands the renderer one batch about every second.
//
// Reconnect policy (as in az-firewall-watch): the first connection gets three tries (2/5/10 s)
// because a first-time failure is most likely a configuration problem; once connected, drops are
// treated as transient and retried forever with a capped backoff. Authorization and not-found
// errors never fix themselves and stop at once. The SDK is behind `HubClient` so this logic is
// testable without a network; `eventHubClient.ts` is the real implementation.
import {
  displaySafe,
  parseRecord,
  type FirewallLogRow,
} from '../shared/fwLogs';
import {
  IDLE_STATUS,
  LOG_RECEIVER_ROLE,
  type LogBatch,
  type LogErrorKind,
  type LogStreamConfig,
  type LogStreamStatus,
} from '../shared/logStream';
import { MAX_ROWS } from '../shared/logBuffer';

/** Where to start reading one partition. */
export type PartitionStart =
  | 'latest'
  | 'earliest'
  | { afterSequenceNumber: number };

export interface RawEvent {
  /** Bytes (preferred), a string, or an already-parsed value. */
  body: unknown;
  sequenceNumber: number;
}

export interface HubSubscription {
  close(): Promise<void>;
}

export interface HubClient {
  getPartitionIds(signal: AbortSignal): Promise<string[]>;
  subscribe(
    handlers: {
      onEvents(partitionId: string, events: RawEvent[]): void;
      onError(err: unknown): void;
    },
    start: Record<string, PartitionStart>,
  ): HubSubscription;
  close(): Promise<void>;
}

export interface SessionDeps {
  createClient(config: LogStreamConfig): HubClient;
  emitBatch(batch: LogBatch): void;
  emitStatus(status: LogStreamStatus): void;
  /** Resolves after `ms`, or early when the signal aborts. */
  sleep(ms: number, signal: AbortSignal): Promise<void>;
  flushMs?: number;
  probeTimeoutMs?: number;
  closeTimeoutMs?: number;
}

export const INITIAL_BACKOFF_S = [2, 5, 10];
export const MAX_INITIAL_ATTEMPTS = 3;
export const RECONNECT_BACKOFF_S = [2, 5, 10, 30, 60];
/** A connection that lasted this long counts as healthy: the failure counter starts over. */
const HEALTHY_MS = 30_000;
/** After this many failures in a row, stop resuming from remembered offsets and start fresh. */
const DROP_RESUME_AFTER = 3;
const MAX_BODY_BYTES = 4 * 1024 * 1024;

// ── error classification ─────────────────────────────────────────────────────

export interface ErrorKind {
  /** Won't fix itself: stop retrying and show the hint. */
  terminal: boolean;
  hint: string;
  kind: LogErrorKind;
}

const text = (err: unknown): string => {
  const e = err as
    | { name?: string; code?: string; message?: string }
    | undefined;
  return `${e?.name ?? ''} ${e?.code ?? ''} ${e?.message ?? String(err)}`.toLowerCase();
};

export function classifyError(err: unknown): ErrorKind {
  const t = text(err);
  if (
    /signed out|authenticationrequired|sign in again|needs you to sign in/.test(
      t,
    )
  )
    return {
      terminal: true,
      kind: 'signedOut',
      hint: 'Sign in again, then reconnect.',
    };
  if (
    /messagingentitynotfound|entity.*not found|could not be found|not.?found.*hub/.test(
      t,
    )
  )
    return {
      terminal: true,
      kind: 'notFound',
      hint: 'The event hub was not found. Check the namespace and event hub name.',
    };
  if (
    /unauthorized|forbidden|\b401\b|\b403\b|claim\(s\) are required|authorization|invalid signature/.test(
      t,
    )
  )
    return {
      terminal: true,
      kind: 'permission',
      hint:
        `Assign '${LOG_RECEIVER_ROLE}' to your account on the event hub or its namespace ` +
        '(Access control (IAM)). A new role can take several minutes to apply.',
    };
  if (/enotfound|eai_again/.test(t))
    return {
      terminal: false,
      kind: 'network',
      hint: 'The namespace name could not be resolved. Check the name and your network connection.',
    };
  return {
    terminal: false,
    kind: 'network',
    hint: 'The Event Hub could not be reached. Check your network connection (AMQP uses port 5671).',
  };
}

/** Error text for the UI: it may quote server data, so control characters go; line breaks stay. */
export function safeErrorText(err: unknown): string {
  const raw = (err as { message?: string } | undefined)?.message ?? String(err);
  return raw
    .split(/\r?\n/)
    .map((l) => displaySafe(l))
    .join('\n')
    .slice(0, 600);
}

// ── message bodies ───────────────────────────────────────────────────────────

/**
 * Pulls the diagnostic records out of one message. The body is untrusted: anything but the
 * documented {"records": [...]} shape is reported as `undefined`, never thrown, because an
 * exception out of a receive callback stops the receiver.
 */
export function recordsOf(body: unknown): unknown[] | undefined {
  let value = body;
  try {
    if (value instanceof Uint8Array) {
      if (value.byteLength > MAX_BODY_BYTES) return undefined;
      value = new TextDecoder().decode(value);
    }
    if (typeof value === 'string') value = JSON.parse(value);
  } catch {
    return undefined;
  }
  if (!value || typeof value !== 'object') return undefined;
  const records = (value as { records?: unknown }).records;
  return Array.isArray(records) ? records : undefined;
}

// ── session ──────────────────────────────────────────────────────────────────

const withTimeout = <T>(
  p: Promise<T>,
  ms: number,
  message: string,
): Promise<T> =>
  new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    p.then(resolve, reject).finally(() => clearTimeout(timer));
  });

/** Waits for `p`, but never longer than `ms` (and leaves no timer behind). */
async function settleWithin(p: Promise<unknown>, ms: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([
    p,
    new Promise<void>((resolve) => {
      timer = setTimeout(resolve, ms);
    }),
  ]);
  clearTimeout(timer);
}

export class LogStreamSession {
  private ctl?: AbortController;
  private task: Promise<void> = Promise.resolve();
  private _status: LogStreamStatus = IDLE_STATUS;

  constructor(private readonly deps: SessionDeps) {}

  get status(): LogStreamStatus {
    return this._status;
  }

  /** Starts (or restarts) streaming. Returns once started; progress arrives through the deps. */
  async start(config: LogStreamConfig): Promise<void> {
    await this.stop();
    const ctl = new AbortController();
    this.ctl = ctl;
    this.task = this.run(config, ctl.signal).catch((err) => {
      this.setStatus({
        state: 'failed',
        detail: 'unexpected error',
        error: safeErrorText(err),
        hint: '',
        config,
      });
    });
  }

  /** Stops streaming and waits for the connection to close. Safe to call at any time. */
  async stop(): Promise<void> {
    const ctl = this.ctl;
    if (!ctl) return;
    this.ctl = undefined;
    ctl.abort();
    await this.task;
    this.setStatus({
      ...IDLE_STATUS,
      state: 'stopped',
      config: this._status.config,
    });
  }

  private setStatus(next: LogStreamStatus): void {
    this._status = next;
    this.deps.emitStatus(next);
  }

  private async run(
    config: LogStreamConfig,
    signal: AbortSignal,
  ): Promise<void> {
    const { deps } = this;
    const flushMs = deps.flushMs ?? 1000;
    const probeMs = deps.probeTimeoutMs ?? 15_000;
    const closeMs = deps.closeTimeoutMs ?? 5000;
    const status = (s: Omit<LogStreamStatus, 'config'>) =>
      this.setStatus({ ...s, config });

    /** Last sequence number seen per partition, so a reconnect continues where it stopped. */
    const lastSeen = new Map<string, number>();
    let pending: FirewallLogRow[] = [];
    let skipped = 0;
    let failures = 0;
    let everConnected = false;
    let lastError: unknown;
    let lastKind: ErrorKind | undefined;

    const flush = () => {
      if (pending.length === 0 && skipped === 0) return;
      let rows = pending;
      let dropped = 0;
      // A replay can outrun the UI: only the newest MAX_ROWS could ever be shown.
      if (rows.length > MAX_ROWS) {
        dropped = rows.length - MAX_ROWS;
        rows = rows.slice(-MAX_ROWS);
      }
      const batch = { rows, skipped: skipped + dropped };
      pending = [];
      skipped = 0;
      deps.emitBatch(batch);
    };

    while (
      !signal.aborted &&
      (everConnected || failures < MAX_INITIAL_ATTEMPTS)
    ) {
      status({
        state: everConnected ? 'reconnecting' : 'connecting',
        detail: '',
        error: '',
        hint: '',
      });
      let client: HubClient | undefined;
      let subscription: HubSubscription | undefined;
      let timer: ReturnType<typeof setInterval> | undefined;
      let connectedAt = 0;
      let gotEvents = false;
      try {
        client = deps.createClient(config);
        const ids = await withTimeout(
          client.getPartitionIds(signal),
          probeMs,
          'Event Hub did not respond within 15 s. Check the namespace name and your network.',
        );
        if (signal.aborted) return;
        everConnected = true;
        connectedAt = Date.now();
        status({ state: 'connected', detail: '', error: '', hint: '' });

        const start: Record<string, PartitionStart> = {};
        for (const id of ids) {
          const seq = lastSeen.get(id);
          start[id] =
            seq !== undefined && failures < DROP_RESUME_AFTER
              ? { afterSequenceNumber: seq }
              : config.startPosition;
        }

        let fail!: (err: unknown) => void;
        const failed = new Promise<never>((_, reject) => (fail = reject));
        failed.catch(() => undefined); // handled by the race below
        const aborted = new Promise<void>((resolve) =>
          signal.addEventListener('abort', () => resolve(), { once: true }),
        );

        subscription = client.subscribe(
          {
            onEvents: (partitionId, events) => {
              for (const event of events) {
                gotEvents = true;
                lastSeen.set(partitionId, event.sequenceNumber);
                const records = recordsOf(event.body);
                if (!records) {
                  skipped++;
                  continue;
                }
                for (const rec of records) {
                  const parsed = parseRecord(rec);
                  if (parsed.kind === 'row') pending.push(parsed.row);
                  else skipped++;
                }
              }
            },
            onError: (err) => fail(err),
          },
          start,
        );
        timer = setInterval(flush, flushMs);
        await Promise.race([failed, aborted]);
        if (signal.aborted) return;
      } catch (err) {
        if (signal.aborted) return;
        lastError = err;
        lastKind = classifyError(err);
      } finally {
        if (timer) clearInterval(timer);
        flush();
        const closing = Promise.allSettled([
          subscription?.close() ?? Promise.resolve(),
          client?.close() ?? Promise.resolve(),
        ]);
        // A dead connection can make close() hang; don't let that block stopping or retrying.
        await settleWithin(closing, closeMs);
      }
      if (signal.aborted) return;

      if (connectedAt && (gotEvents || Date.now() - connectedAt >= HEALTHY_MS))
        failures = 0;
      failures++;
      const kind = lastKind ?? classifyError(lastError);
      const error = safeErrorText(lastError);
      if (kind.terminal) {
        status({
          state: 'failed',
          detail: 'configuration error',
          error,
          hint: kind.hint,
          errorKind: kind.kind,
        });
        return;
      }
      if (!everConnected && failures >= MAX_INITIAL_ATTEMPTS) break;

      const backoff = everConnected ? RECONNECT_BACKOFF_S : INITIAL_BACKOFF_S;
      const delay = backoff[Math.min(failures, backoff.length) - 1];
      for (
        let remaining = delay;
        remaining > 0 && !signal.aborted;
        remaining--
      ) {
        status({
          state: everConnected ? 'reconnecting' : 'retrying',
          detail: everConnected
            ? `attempt ${failures} in ${remaining}s`
            : `attempt ${failures}/${MAX_INITIAL_ATTEMPTS} in ${remaining}s`,
          error,
          hint: kind.hint,
          errorKind: kind.kind,
        });
        await deps.sleep(1000, signal);
      }
    }

    if (!signal.aborted)
      status({
        state: 'failed',
        detail: `after ${MAX_INITIAL_ATTEMPTS} attempts`,
        error: safeErrorText(lastError),
        hint: (lastKind ?? classifyError(lastError)).hint,
        errorKind: (lastKind ?? classifyError(lastError)).kind,
      });
  }
}
