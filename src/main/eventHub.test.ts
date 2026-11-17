import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  LogBatch,
  LogStreamConfig,
  LogStreamStatus,
} from '../shared/logStream';
import {
  classifyError,
  LogStreamSession,
  recordsOf,
  safeErrorText,
  type HubClient,
  type PartitionStart,
  type RawEvent,
} from './eventHub';

const FW =
  '/SUBSCRIPTIONS/0/RESOURCEGROUPS/rg/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/FW';
const CONFIG: LogStreamConfig = {
  namespace: 'contoso-fw.servicebus.windows.net',
  eventHub: 'firewall-logs',
  consumerGroup: '$Default',
  startPosition: 'latest',
};
const record = (n: number, category = 'AZFWNetworkRule') => ({
  time: new Date(Date.UTC(2026, 0, 1, 0, 0, n)).toISOString(),
  resourceId: FW,
  category,
  properties: {
    Protocol: 'TCP',
    SourceIp: '10.0.0.1',
    DestinationIp: '10.0.0.2',
    Action: 'Allow',
  },
});
const bytes = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value));
const message = (records: unknown[], seq: number): RawEvent => ({
  body: bytes({ records }),
  sequenceNumber: seq,
});

/** A scriptable client: each createClient() call takes the next behaviour from the queue. */
class FakeHub implements HubClient {
  static instances: FakeHub[] = [];
  starts: Record<string, PartitionStart> = {};
  handlers!: Parameters<HubClient['subscribe']>[0];
  closed = false;
  subClosed = false;
  constructor(readonly probe: () => Promise<string[]>) {
    FakeHub.instances.push(this);
  }
  getPartitionIds() {
    return this.probe();
  }
  subscribe(
    handlers: Parameters<HubClient['subscribe']>[0],
    start: Record<string, PartitionStart>,
  ) {
    this.handlers = handlers;
    this.starts = start;
    return {
      close: async () => {
        this.subClosed = true;
      },
    };
  }
  async close() {
    this.closed = true;
  }
}

function setup(probes: (() => Promise<string[]>)[]) {
  FakeHub.instances = [];
  const queue = [...probes];
  const batches: LogBatch[] = [];
  const statuses: LogStreamStatus[] = [];
  const session = new LogStreamSession({
    createClient: () =>
      new FakeHub(queue.shift() ?? (() => Promise.resolve(['0', '1']))),
    emitBatch: (b) => batches.push(b),
    emitStatus: (s) => statuses.push(s),
    sleep: (ms, signal) =>
      new Promise<void>((resolve) => {
        const t = setTimeout(resolve, ms);
        signal.addEventListener('abort', () => (clearTimeout(t), resolve()), {
          once: true,
        });
      }),
  });
  const last = () => statuses.at(-1)!;
  const hub = (i = FakeHub.instances.length - 1) => FakeHub.instances[i];
  return { session, batches, statuses, last, hub };
}

const ok = () => Promise.resolve(['0', '1']);
const fail =
  (message: string, name = 'Error') =>
  () =>
    Promise.reject(Object.assign(new Error(message), { name }));
const tick = (ms: number) => vi.advanceTimersByTimeAsync(ms);

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => (resolve = done));
  return { promise, resolve };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('recordsOf', () => {
  it('reads bytes, strings and parsed objects', () => {
    const body = { records: [{ a: 1 }] };
    expect(recordsOf(bytes(body))).toEqual([{ a: 1 }]);
    expect(recordsOf(JSON.stringify(body))).toEqual([{ a: 1 }]);
    expect(recordsOf(body)).toEqual([{ a: 1 }]);
  });
  it('rejects everything that is not {records: [...]}, without throwing', () => {
    for (const bad of [
      null,
      undefined,
      5,
      'not json',
      bytes([1, 2]),
      bytes({ records: {} }),
      {},
      new Uint8Array([0xff, 0xfe, 0x7b]),
      new Uint8Array(5 * 1024 * 1024),
    ])
      expect(recordsOf(bad)).toBeUndefined();
  });
});

describe('classifyError', () => {
  it('separates configuration errors from transient ones', () => {
    expect(
      classifyError(
        Object.assign(
          new Error("Unauthorized access. 'Listen' claim(s) are required"),
          { name: 'UnauthorizedError' },
        ),
      ),
    ).toMatchObject({ terminal: true });
    expect(classifyError(new Error('401 Unauthorized')).hint).toContain(
      'Azure Event Hubs Data Receiver',
    );
    expect(
      classifyError(
        Object.assign(new Error('x'), { name: 'MessagingEntityNotFoundError' }),
      ),
    ).toMatchObject({ terminal: true });
    expect(
      classifyError(
        new Error('You are signed out. Sign in to Azure to continue.'),
      ),
    ).toMatchObject({ terminal: true });
    expect(
      classifyError(
        new Error('getaddrinfo ENOTFOUND x.servicebus.windows.net'),
      ),
    ).toMatchObject({ terminal: false });
    expect(classifyError(new Error('connection reset'))).toMatchObject({
      terminal: false,
    });
  });
  it('safeErrorText strips control characters but keeps line breaks', () => {
    expect(safeErrorText(new Error('a\u001b[2Jb\nc'))).toBe('a\uFFFD[2Jb\nc');
  });
});

describe('LogStreamSession', () => {
  it('connects, batches parsed rows about once a second, and counts skips', async () => {
    const t = setup([ok]);
    await t.session.start(CONFIG);
    await tick(0);
    expect(t.last()).toMatchObject({ state: 'connected', config: CONFIG });
    expect(t.hub().starts).toEqual({ '0': 'latest', '1': 'latest' });

    t.hub().handlers.onEvents('0', [
      message(
        [record(1), record(2), record(3, 'AZFWNetworkRuleAggregation')],
        10,
      ),
      { body: 'garbage', sequenceNumber: 11 },
    ]);
    expect(t.batches).toHaveLength(0); // nothing until the flush
    await tick(1000);
    expect(t.batches).toHaveLength(1);
    expect(t.batches[0].rows.map((r) => r.category)).toEqual([
      'NetworkRule',
      'NetworkRule',
    ]);
    expect(t.batches[0].skipped).toBe(2);
    await tick(3000);
    expect(t.batches).toHaveLength(1); // quiet periods emit nothing
    await t.session.stop();
  });

  it('start position earliest is passed to every partition', async () => {
    const t = setup([ok]);
    await t.session.start({ ...CONFIG, startPosition: 'earliest' });
    await tick(0);
    expect(t.hub().starts).toEqual({ '0': 'earliest', '1': 'earliest' });
    await t.session.stop();
  });

  it('stop closes the subscription and client, discards buffered data, and reports stopped', async () => {
    const t = setup([ok]);
    await t.session.start(CONFIG);
    await tick(0);
    t.hub().handlers.onEvents('0', [message([record(1)], 1)]);
    await t.session.stop();
    expect(t.hub().subClosed && t.hub().closed).toBe(true);
    expect(t.batches).toHaveLength(0);
    expect(t.last().state).toBe('stopped');
    await t.session.stop(); // idempotent
  });

  it('serializes concurrent starts and stop closes every receiver', async () => {
    const t = setup([ok, ok]);
    const other = { ...CONFIG, eventHub: 'other' };
    await Promise.all([t.session.start(CONFIG), t.session.start(other)]);
    await tick(0);

    expect(FakeHub.instances).toHaveLength(2);
    expect(t.hub(0).subClosed && t.hub(0).closed).toBe(true);
    expect(t.hub(1).subClosed || t.hub(1).closed).toBe(false);
    expect(t.last()).toMatchObject({ state: 'connected', config: other });

    await t.session.stop();
    expect(FakeHub.instances.every((h) => h.subClosed && h.closed)).toBe(true);
    expect(t.last()).toMatchObject({ state: 'stopped', config: other });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('orders a start immediately followed by concurrent stops without reviving it', async () => {
    const t = setup([ok]);
    await Promise.all([
      t.session.start(CONFIG),
      t.session.stop(),
      t.session.stop(),
    ]);
    const statuses = [...t.statuses];
    await tick(30_000);

    expect(FakeHub.instances).toHaveLength(1);
    expect(t.hub().closed).toBe(true);
    expect(t.last().state).toBe('stopped');
    expect(t.statuses).toEqual(statuses);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('waits for an overlapping stop to finish closing before the next start', async () => {
    const t = setup([ok, ok]);
    await t.session.start(CONFIG);
    await tick(0);
    const closing = deferred<void>();
    const close = vi.spyOn(t.hub(), 'close').mockImplementation(async () => {
      await closing.promise;
      t.hub(0).closed = true;
    });

    const stopping = t.session.stop();
    const starting = t.session.start({ ...CONFIG, eventHub: 'other' });
    await tick(0);
    expect(close).toHaveBeenCalledOnce();
    expect(FakeHub.instances).toHaveLength(1);

    closing.resolve();
    await Promise.all([stopping, starting]);
    await tick(0);
    expect(t.hub(0).subClosed && t.hub(0).closed).toBe(true);
    expect(t.last()).toMatchObject({
      state: 'connected',
      config: { eventHub: 'other' },
    });
    await t.session.stop();
  });

  it('does not subscribe or report connected when a probe resolves after stop', async () => {
    const probe = deferred<string[]>();
    const t = setup([() => probe.promise, ok]);
    await t.session.start(CONFIG);
    const stopping = t.session.stop();
    const starting = t.session.start({ ...CONFIG, eventHub: 'other' });
    await tick(0);
    probe.resolve(['0']);
    await Promise.all([stopping, starting]);
    await tick(0);

    expect(t.hub(0).handlers).toBeUndefined();
    expect(t.hub(0).closed).toBe(true);
    expect(
      t.statuses
        .filter((s) => s.config?.eventHub === CONFIG.eventHub)
        .map((s) => s.state),
    ).toEqual(['connecting', 'stopped']);
    expect(t.last()).toMatchObject({
      state: 'connected',
      config: { eventHub: 'other' },
    });
    await t.session.stop();
  });

  it('ignores events and errors during abort cleanup and after stop/sign-out', async () => {
    const t = setup([ok]);
    await t.session.start(CONFIG);
    await tick(0);
    const hub = t.hub();
    hub.handlers.onEvents('0', [message([record(1)], 1)]);
    const lateCallbacks = () => {
      hub.handlers.onEvents('0', [message([record(2)], 2)]);
      hub.handlers.onError(new Error('You are signed out'));
    };
    const closing = deferred<void>();
    hub.close = async () => {
      lateCallbacks();
      await closing.promise;
      hub.closed = true;
    };
    const stopping = t.session.stop();
    await tick(0);
    lateCallbacks();
    expect(t.batches).toHaveLength(0);
    closing.resolve();
    await stopping;
    const statuses = [...t.statuses];
    lateCallbacks();
    await tick(30_000);

    expect(t.batches).toHaveLength(0);
    expect(t.statuses).toEqual(statuses);
    expect(t.last().state).toBe('stopped');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ignores retired callbacks after replacement, even when close timed out', async () => {
    const t = setup([ok, ok]);
    await t.session.start(CONFIG);
    await tick(0);
    const old = t.hub();
    old.close = () => new Promise(() => undefined);
    const starting = t.session.start({ ...CONFIG, eventHub: 'other' });
    await tick(5000);
    await starting;
    const statuses = [...t.statuses];
    old.handlers.onEvents('0', [message([record(1)], 1)]);
    old.handlers.onError(new Error('late unauthorized'));
    t.hub().handlers.onEvents('0', [message([record(2)], 2)]);
    await tick(1000);

    expect(t.statuses).toEqual(statuses);
    expect(t.batches.flatMap((b) => b.rows).map((r) => r.time)).toEqual([
      record(2).time,
    ]);
    await t.session.stop();
  });

  it('retries the first connection three times with 2/5/10 s countdowns, then fails with a hint', async () => {
    const t = setup([
      fail('connection reset'),
      fail('connection reset'),
      fail('connection reset'),
    ]);
    await t.session.start(CONFIG);
    await tick(0);
    expect(t.last()).toMatchObject({
      state: 'retrying',
      detail: 'attempt 1/3 in 2s',
    });
    await tick(1000);
    expect(t.last().detail).toBe('attempt 1/3 in 1s');
    await tick(1000); // second attempt fails
    expect(t.last()).toMatchObject({
      state: 'retrying',
      detail: 'attempt 2/3 in 5s',
    });
    await tick(5000); // third attempt fails
    expect(t.last()).toMatchObject({
      state: 'failed',
      detail: 'after 3 attempts',
    });
    expect(t.last().error).toContain('connection reset');
    expect(t.last().hint).toContain('5671');
    expect(t.last().errorKind).toBe('network');
    expect(FakeHub.instances).toHaveLength(3);
    expect(FakeHub.instances.every((h) => h.closed)).toBe(true);
    await tick(60_000);
    expect(FakeHub.instances).toHaveLength(3); // no further tries
  });

  it('a missing role fails at once, with the role named', async () => {
    const t = setup([
      fail(
        "Unauthorized access. 'Listen' claim(s) are required",
        'UnauthorizedError',
      ),
    ]);
    await t.session.start(CONFIG);
    await tick(0);
    expect(t.last()).toMatchObject({
      state: 'failed',
      detail: 'configuration error',
    });
    expect(t.last().hint).toContain('Azure Event Hubs Data Receiver');
    expect(t.last().errorKind).toBe('permission');
    expect(FakeHub.instances).toHaveLength(1);
  });

  it('a probe that never answers times out after 15 s', async () => {
    const t = setup([() => new Promise(() => undefined), ok]);
    await t.session.start(CONFIG);
    await tick(15_000);
    expect(t.last().state).toBe('retrying');
    expect(t.last().error).toContain('did not respond within 15 s');
    await t.session.stop();
  });

  it('after the first success, a drop reconnects forever with capped backoff and resumes after the last event', async () => {
    const t = setup([
      ok,
      fail('reset'),
      fail('reset'),
      fail('reset'),
      fail('reset'),
      fail('reset'),
      ok,
    ]);
    await t.session.start(CONFIG);
    await tick(0);
    t.hub(0).handlers.onEvents('0', [message([record(1)], 41)]);
    t.hub(0).handlers.onEvents('1', [message([record(2)], 7)]);
    t.hub(0).handlers.onError(new Error('link detached'));
    await tick(0);
    expect(t.last()).toMatchObject({
      state: 'reconnecting',
      detail: 'attempt 1 in 2s',
    });
    expect(t.hub(0).closed).toBe(true);
    // Delays: 2, 5, 10, 30, 60, 60 … never gives up.
    await tick(2000);
    expect(t.last().detail).toBe('attempt 2 in 5s');
    await tick(5000);
    expect(t.last().detail).toBe('attempt 3 in 10s');
    await tick(10_000);
    expect(t.last().detail).toBe('attempt 4 in 30s');
    await tick(30_000);
    expect(t.last().detail).toBe('attempt 5 in 60s');
    await tick(60_000);
    expect(t.last().detail).toBe('attempt 6 in 60s');
    await tick(60_000);
    expect(t.last().state).toBe('connected');
    // 6 attempts in a row: remembered offsets are dropped, back to the configured position.
    expect(t.hub().starts).toEqual({ '0': 'latest', '1': 'latest' });
    await t.session.stop();
  });

  it('a quick reconnect continues after the last sequence number of each partition', async () => {
    const t = setup([ok, ok]);
    await t.session.start(CONFIG);
    await tick(0);
    t.hub(0).handlers.onEvents('0', [message([record(1)], 41)]);
    t.hub(0).handlers.onEvents('0', [message([record(2)], 42)]);
    t.hub(0).handlers.onError(new Error('link detached'));
    await tick(2000);
    expect(t.last().state).toBe('connected');
    expect(t.hub().starts).toEqual({
      '0': { afterSequenceNumber: 42 },
      '1': 'latest',
    });
    // Nothing received before the drop is lost: the flush in `finally` delivered it.
    expect(t.batches.flatMap((b) => b.rows)).toHaveLength(2);
    await t.session.stop();
  });

  it('ignores a retired retry receiver without changing rows or resume offsets', async () => {
    const t = setup([ok, ok]);
    await t.session.start(CONFIG);
    await tick(0);
    const old = t.hub();
    old.handlers.onEvents('0', [message([record(1)], 41)]);
    old.handlers.onError(new Error('link detached'));
    await tick(0);
    old.handlers.onEvents('0', [message([record(2)], 999)]);
    old.handlers.onError(new Error('late unauthorized'));
    await tick(2000);

    expect(t.hub().starts['0']).toEqual({ afterSequenceNumber: 41 });
    expect(t.last().state).toBe('connected');
    const statuses = [...t.statuses];
    old.handlers.onEvents('0', [message([record(3)], 1000)]);
    old.handlers.onError(new Error('late unauthorized'));
    await tick(1000);
    expect(t.statuses).toEqual(statuses);
    expect(t.batches.flatMap((b) => b.rows)).toHaveLength(1);
    await t.session.stop();
  });

  it('a long healthy connection resets the failure counter', async () => {
    const t = setup([ok, ok, ok]);
    await t.session.start(CONFIG);
    await tick(0);
    for (let i = 0; i < 2; i++) {
      await tick(31_000);
      t.hub().handlers.onError(new Error('reset'));
      await tick(0);
      expect(t.last().detail).toBe('attempt 1 in 2s');
      await tick(2000);
    }
    await t.session.stop();
  });

  it('a hung close() does not block retrying', async () => {
    const t = setup([ok, ok]);
    await t.session.start(CONFIG);
    await tick(0);
    t.hub(0).close = () => new Promise(() => undefined);
    t.hub(0).handlers.onError(new Error('reset'));
    await tick(5000 + 2000);
    expect(t.last().state).toBe('connected');
    await t.session.stop();
  });

  it('start() while running stops the old stream first', async () => {
    const t = setup([ok, ok]);
    await t.session.start(CONFIG);
    await tick(0);
    await t.session.start({ ...CONFIG, eventHub: 'other' });
    await tick(0);
    expect(FakeHub.instances).toHaveLength(2);
    expect(FakeHub.instances[0].closed).toBe(true);
    expect(t.last()).toMatchObject({
      state: 'connected',
      config: { eventHub: 'other' },
    });
    await t.session.stop();
  });

  it('caps a flush at the newest MAX_ROWS rows and counts the rest as skipped', async () => {
    const t = setup([ok]);
    await t.session.start(CONFIG);
    await tick(0);
    const many = Array.from({ length: 6000 }, (_, i) => record(i));
    t.hub().handlers.onEvents('0', [message(many, 1)]);
    await tick(1000);
    expect(t.batches[0].rows).toHaveLength(5000);
    expect(t.batches[0].skipped).toBe(1000);
    await t.session.stop();
  });

  it('a throwing probe after stop() does not revive the session', async () => {
    const t = setup([
      () =>
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('late')), 500),
        ),
    ]);
    await t.session.start(CONFIG);
    const stopping = t.session.stop();
    await tick(1000);
    await stopping;
    expect(t.last().state).toBe('stopped');
    expect(FakeHub.instances).toHaveLength(1);
  });
});

describe('LogStreamSession: waiting for a freshly assigned role', () => {
  const denied = () =>
    fail(
      "Unauthorized access. 'Listen' claim(s) are required",
      'UnauthorizedError',
    );

  it('retries a missing role during the grace period, then connects', async () => {
    const t = setup([denied(), denied(), ok].map((f) => f));
    await t.session.start(CONFIG, { permissionGraceMs: 120_000 });
    await tick(0);
    expect(t.last()).toMatchObject({
      state: 'retrying',
      errorKind: 'permission',
    });
    expect(t.last().detail).toMatch(
      /waiting for the new role to apply, trying again in 15s \(giving up in 12\ds\)/,
    );
    await tick(15_000);
    expect(t.last().detail).toMatch(/waiting for the new role/);
    await tick(15_000);
    expect(t.last().state).toBe('connected');
    await t.session.stop();
  });

  it('does not count the waiting as failed attempts', async () => {
    // Six denied probes would exhaust the three first-connection attempts if they counted.
    const t = setup([
      denied(),
      denied(),
      denied(),
      denied(),
      denied(),
      denied(),
      ok,
    ]);
    await t.session.start(CONFIG, { permissionGraceMs: 300_000 });
    await tick(6 * 15_000 + 100);
    expect(t.last().state).toBe('connected');
    await t.session.stop();
  });

  it('gives up with the normal permission error once the grace period is over', async () => {
    const t = setup([
      denied(),
      denied(),
      denied(),
      denied(),
      denied(),
      denied(),
    ]);
    await t.session.start(CONFIG, { permissionGraceMs: 30_000 });
    await tick(31_000);
    expect(t.last()).toMatchObject({
      state: 'failed',
      errorKind: 'permission',
    });
    expect(t.last().hint).toContain('Azure Event Hubs Data Receiver');
  });

  it('without a grace period a missing role fails at once, as before', async () => {
    const t = setup([denied()]);
    await t.session.start(CONFIG);
    await tick(0);
    expect(t.last().state).toBe('failed');
  });

  it('other errors during the grace period still follow the normal retry rules', async () => {
    const t = setup([fail('connection reset'), ok]);
    await t.session.start(CONFIG, { permissionGraceMs: 120_000 });
    await tick(0);
    expect(t.last()).toMatchObject({
      state: 'retrying',
      detail: 'attempt 1/3 in 2s',
    });
    await t.session.stop();
  });
});
