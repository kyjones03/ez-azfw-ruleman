import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  armRequest: vi.fn(),
  discoverFirewalls: vi.fn(),
  getAccount: vi.fn(),
  managed: [] as string[],
}));
vi.mock('./auth', () => ({ getAccount: mocks.getAccount }));
vi.mock('./arm', () => ({ armRequest: mocks.armRequest }));
vi.mock('./azure', () => ({
  discoverFirewalls: mocks.discoverFirewalls,
  describeAzureError: (e: unknown) => `described: ${(e as Error).message}`,
}));
vi.mock('./store', () => ({
  loadState: () => ({ managedFirewallIds: mocks.managed }),
}));

import {
  applyCleanup,
  findDanglingSettings,
  isGone,
  reviewCleanup,
} from './logCleanup';
import type { FirewallLogging } from '../shared/logSources';

const SUB = '00000000-0000-0000-0000-000000000000';
const FW = `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw-hub-eus2`;
const NS = `/subscriptions/${SUB}/resourceGroups/rg-scratch/providers/Microsoft.EventHub/namespaces/scratch-logs-namespace`;
const RULE = `${NS}/authorizationrules/RootManageSharedAccessKey`;

const armError = (statusCode: number, code: string) =>
  Object.assign(new Error(code), { statusCode, code });

const summary = (name: string, namespaceId?: string) => ({
  name,
  eventHubNamespaceId: namespaceId,
  categories: [],
  allLogs: false,
  logAnalytics: false,
  storage: false,
});
const firewall = (
  ...settings: ReturnType<typeof summary>[]
): FirewallLogging => ({
  firewallId: FW,
  firewallName: 'fw-hub-eus2',
  settings,
});

beforeEach(() => {
  vi.resetAllMocks();
  mocks.getAccount.mockReturnValue({
    method: 'cli',
    username: 'reviewer@example.com',
    tenantId: SUB,
  });
  mocks.managed = [];
  mocks.discoverFirewalls.mockResolvedValue([
    { id: FW, name: 'fw-hub-eus2', location: 'eastus2' },
  ]);
});

describe('isGone', () => {
  it('is true only for 404 with an explicit not-found code', () => {
    expect(isGone(armError(404, 'ResourceNotFound'))).toBe(true);
    expect(isGone(armError(404, 'ResourceGroupNotFound'))).toBe(true);
    expect(isGone(armError(404, 'SubscriptionNotFound'))).toBe(false);
    expect(isGone(armError(403, 'AuthorizationFailed'))).toBe(false);
    expect(isGone(new Error('network'))).toBe(false);
    expect(isGone(undefined)).toBe(false);
  });
});

describe('findDanglingSettings', () => {
  it('offers a setting whose namespace is confirmed deleted', async () => {
    mocks.armRequest.mockRejectedValue(armError(404, 'ResourceNotFound'));
    const found = await findDanglingSettings(
      [firewall(summary('old', NS))],
      [],
    );
    expect(found.map((d) => d.settingName)).toEqual(['old']);
  });

  it.each([
    ['no permission', armError(403, 'AuthorizationFailed')],
    ['a subscription we cannot see', armError(404, 'SubscriptionNotFound')],
    ['a network error', new Error('offline')],
  ])('offers nothing when the check fails with %s', async (_n, err) => {
    mocks.armRequest.mockRejectedValue(err);
    expect(
      await findDanglingSettings([firewall(summary('old', NS))], []),
    ).toEqual([]);
  });

  it('offers nothing when the namespace still exists', async () => {
    mocks.armRequest.mockResolvedValue({ status: 200, data: {} });
    expect(
      await findDanglingSettings([firewall(summary('old', NS))], []),
    ).toEqual([]);
  });

  it('does not ask about namespaces discovery already found, and asks once per namespace', async () => {
    mocks.armRequest.mockRejectedValue(armError(404, 'ResourceNotFound'));
    const other = NS.replace('scratch-logs-namespace', 'live');
    const found = await findDanglingSettings(
      [firewall(summary('a', NS), summary('b', NS), summary('c', other))],
      [{ id: other.toUpperCase() } as never],
    );
    expect(mocks.armRequest).toHaveBeenCalledTimes(1);
    expect(found.map((d) => d.settingName)).toEqual(['a', 'b']);
  });
});

const setting = (props: Record<string, unknown>) => ({
  data: {
    name: 'old',
    properties: {
      eventHubAuthorizationRuleId: RULE,
      eventHubName: 'hub',
      ...props,
    },
  },
});

/** GET setting, then GET namespace (gone), in the order prepare() asks. */
function arrange(props: Record<string, unknown>, nsGone = true) {
  mocks.armRequest.mockImplementation(
    async (path: string, init?: { method?: string }) => {
      if (init?.method) return { status: 200, data: {} };
      if (path.includes('diagnosticSettings')) return setting(props);
      if (nsGone) throw armError(404, 'ResourceNotFound');
      return { status: 200, data: {} };
    },
  );
}
const writes = () =>
  mocks.armRequest.mock.calls.filter(([, init]) => init?.method);

describe('reviewCleanup', () => {
  it('describes a trim and changes nothing', async () => {
    arrange({ storageAccountId: '/s/st' });
    const review = await reviewCleanup(FW, 'old');
    expect(review.action).toBe('trim');
    expect(review.lines[0]).toContain('keeps Storage');
    expect(writes()).toEqual([]);
  });

  it('describes a delete when the event hub was the only destination', async () => {
    arrange({});
    expect((await reviewCleanup(FW, 'old')).action).toBe('delete');
  });

  it('refuses when the namespace is not confirmed gone', async () => {
    arrange({}, false);
    await expect(reviewCleanup(FW, 'old')).rejects.toThrow(
      'Nothing to clean up',
    );
  });

  it('refuses a firewall the app does not list', async () => {
    arrange({});
    mocks.managed = [
      '/subscriptions/x/resourceGroups/r/providers/Microsoft.Network/azureFirewalls/other',
    ];
    await expect(reviewCleanup(FW, 'old')).rejects.toThrow(
      'not one this app lists',
    );
    expect(mocks.armRequest).not.toHaveBeenCalled();
  });

  it('rejects malformed input before calling Azure', async () => {
    await expect(reviewCleanup(1, 'old')).rejects.toThrow('Invalid');
    await expect(reviewCleanup(FW, '  ')).rejects.toThrow('Invalid');
    expect(mocks.armRequest).not.toHaveBeenCalled();
  });
});

describe('applyCleanup', () => {
  it('PUTs the trimmed setting without the event hub fields', async () => {
    arrange({ storageAccountId: '/s/st' });
    const { hash } = await reviewCleanup(FW, 'old');
    expect(await applyCleanup(FW, 'old', hash)).toEqual({ action: 'trim' });
    const [path, init] = writes()[0];
    expect(path).toContain('/diagnosticSettings/old?');
    expect(init.method).toBe('PUT');
    const sent = JSON.parse(init.body);
    expect(sent.properties.storageAccountId).toBe('/s/st');
    expect(sent.properties.eventHubName).toBeUndefined();
    expect(sent.properties.eventHubAuthorizationRuleId).toBeUndefined();
  });

  it('DELETEs a setting that only sent to the deleted namespace', async () => {
    arrange({});
    const { hash } = await reviewCleanup(FW, 'old');
    expect(await applyCleanup(FW, 'old', hash)).toEqual({ action: 'delete' });
    expect(writes()[0][1].method).toBe('DELETE');
  });

  it('writes nothing when Azure changed since the review', async () => {
    arrange({});
    const { hash } = await reviewCleanup(FW, 'old');
    arrange({ storageAccountId: '/s/st' });
    await expect(applyCleanup(FW, 'old', hash)).rejects.toThrow(
      'Azure changed',
    );
    expect(writes()).toEqual([]);
  });

  it.each([
    ['storageAccountId', '/s/other'],
    ['workspaceId', '/w/other'],
    ['logs', [{ category: 'AZFWNetworkRule', enabled: true }]],
    ['metrics', [{ category: 'AllMetrics', enabled: true }]],
    ['customProperty', { preserved: true }],
  ])(
    'rejects changes to preserved cleanup property %s with unchanged prose',
    async (key, value) => {
      const props = { storageAccountId: '/s/st', workspaceId: '/w/logs' };
      arrange(props);
      const review = await reviewCleanup(FW, 'old');
      arrange({ ...props, [key]: value });
      expect((await reviewCleanup(FW, 'old')).lines).toEqual(review.lines);
      await expect(applyCleanup(FW, 'old', review.hash)).rejects.toThrow(
        'Azure changed',
      );
      expect(writes()).toEqual([]);
    },
  );

  it.each([{}, { storageAccountId: '/s/st' }])(
    'rejects a changed deleted destination even with the same namespace name and action %j',
    async (props) => {
      arrange(props);
      const review = await reviewCleanup(FW, 'old');
      arrange({
        ...props,
        eventHubAuthorizationRuleId: RULE.replace(
          SUB,
          '11111111-1111-1111-1111-111111111111',
        ),
      });
      expect((await reviewCleanup(FW, 'old')).lines).toEqual(review.lines);
      await expect(applyCleanup(FW, 'old', review.hash)).rejects.toThrow(
        'Azure changed',
      );
      expect(writes()).toEqual([]);
    },
  );

  it.each(['firewall', 'setting'])(
    'rejects a changed cleanup %s target with unchanged prose',
    async (target) => {
      arrange({});
      const review = await reviewCleanup(FW, 'old');
      const otherFw = FW.replace(SUB, '11111111-1111-1111-1111-111111111111');
      mocks.discoverFirewalls.mockResolvedValue([
        { id: FW, name: 'fw-hub-eus2', location: 'eastus2' },
        { id: otherFw, name: 'fw-hub-eus2', location: 'eastus2' },
      ]);
      await expect(
        applyCleanup(
          target === 'firewall' ? otherFw : FW,
          target === 'setting' ? 'other' : 'old',
          review.hash,
        ),
      ).rejects.toThrow('Azure changed');
      expect(writes()).toEqual([]);
    },
  );

  it.each([
    { tenantId: 'other-tenant' },
    { username: 'other@example.com' },
    { method: 'browser' },
    null,
  ])('rejects a changed active cleanup account context %j', async (change) => {
    arrange({});
    const { hash } = await reviewCleanup(FW, 'old');
    mocks.getAccount.mockReturnValue(
      change === null ? null : { ...mocks.getAccount(), ...change },
    );
    await expect(applyCleanup(FW, 'old', hash)).rejects.toThrow(
      'Azure changed',
    );
    expect(writes()).toEqual([]);
  });

  it('turns a missing permission into a plain message', async () => {
    arrange({});
    const { hash } = await reviewCleanup(FW, 'old');
    mocks.armRequest.mockImplementation(
      async (path: string, init?: { method?: string }) => {
        if (init?.method) throw armError(403, 'AuthorizationFailed');
        if (path.includes('diagnosticSettings')) return setting({});
        throw armError(404, 'ResourceNotFound');
      },
    );
    await expect(applyCleanup(FW, 'old', hash)).rejects.toThrow(
      /permission.*Nothing was changed/,
    );
  });
});
