import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  armRequest: vi.fn(),
  armList: vi.fn(),
  graphQuery: vi.fn(),
  discoverFirewalls: vi.fn(),
  grantRole: vi.fn(),
  managed: [] as string[],
}));
vi.mock('./arm', () => ({
  armRequest: mocks.armRequest,
  armList: mocks.armList,
}));
vi.mock('./azure', () => ({
  graphQuery: mocks.graphQuery,
  discoverFirewalls: mocks.discoverFirewalls,
  describeAzureError: (e: unknown) => `described: ${(e as Error).message}`,
}));
vi.mock('./roleAssignments', () => ({ grantRole: mocks.grantRole }));
vi.mock('./store', () => ({
  loadState: () => ({ managedFirewallIds: mocks.managed }),
}));

import {
  discoverLogSources,
  grantReceiver,
  listConsumerGroups,
  listEventHubs,
} from './logSources';

const SUB = '00000000-0000-0000-0000-000000000000';
const fwId = (n: string) =>
  `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/${n}`;
const NS_ID = `/subscriptions/${SUB}/resourceGroups/rg-logs/providers/Microsoft.EventHub/namespaces/contoso-fw`;
const settings = {
  value: [
    {
      name: 'to-eh',
      properties: {
        eventHubAuthorizationRuleId: `${NS_ID}/authorizationrules/Root`,
        eventHubName: 'firewall-logs',
        logs: [{ category: 'AZFWNetworkRule', enabled: true }],
      },
    },
  ],
};

beforeEach(() => {
  vi.resetAllMocks();
  mocks.managed = [];
});

describe('discoverLogSources', () => {
  const firewalls = ['fw1', 'fw2', 'fw3'].map((n) => ({
    id: fwId(n),
    name: n,
    skuTier: 'Premium',
  }));
  const namespaces = [
    {
      id: NS_ID,
      name: 'Contoso-FW',
      subscriptionId: SUB,
      subscriptionName: 'Prod',
      resourceGroup: 'rg-logs',
      location: 'westeurope',
      skuTier: 'Standard',
    },
  ];
  const wire = () => {
    mocks.discoverFirewalls.mockResolvedValue(firewalls);
    mocks.graphQuery.mockResolvedValue(namespaces);
  };

  it('maps namespaces and reads settings only for the managed firewalls', async () => {
    wire();
    mocks.managed = [fwId('FW2')]; // IDs are case-insensitive
    mocks.armRequest.mockResolvedValue({ data: settings });
    const result = await discoverLogSources();
    expect(result.namespaces[0]).toMatchObject({
      name: 'Contoso-FW',
      fqdn: 'contoso-fw.servicebus.windows.net',
      skuTier: 'Standard',
    });
    expect(result.firewalls.map((f) => f.firewallName)).toEqual(['fw2']);
    expect(mocks.armRequest).toHaveBeenCalledTimes(1);
    expect(mocks.armRequest.mock.calls[0][0]).toContain(
      `${fwId('fw2')}/providers/Microsoft.Insights/diagnosticSettings`,
    );
    expect(result.firewalls[0].settings[0]).toMatchObject({
      eventHubName: 'firewall-logs',
      categories: ['AZFWNetworkRule'],
    });
    expect(result.firewalls[0].skuTier).toBe('Premium');
  });
  it('falls back to every firewall when none is managed', async () => {
    wire();
    mocks.armRequest.mockResolvedValue({ data: { value: [] } });
    expect((await discoverLogSources()).firewalls).toHaveLength(3);
  });
  it('a firewall whose settings cannot be read is reported, not fatal', async () => {
    wire();
    mocks.armRequest
      .mockResolvedValueOnce({ data: settings })
      .mockRejectedValueOnce(new Error('AuthorizationFailed'))
      .mockResolvedValueOnce({ data: settings });
    const result = await discoverLogSources();
    expect(result.firewalls.map((f) => !!f.readError)).toEqual([
      false,
      true,
      false,
    ]);
    expect(result.firewalls[1].readError).toContain('AuthorizationFailed');
  });
});

describe('listEventHubs / listConsumerGroups', () => {
  it('maps hubs, with retention in hours, sorted by name', async () => {
    mocks.armList.mockResolvedValue([
      {
        name: 'zeta',
        properties: { partitionCount: 2, messageRetentionInDays: 1 },
      },
      {
        name: 'alpha',
        properties: { retentionDescription: { retentionTimeInHours: 72 } },
      },
      { properties: {} },
    ]);
    expect(await listEventHubs(NS_ID)).toEqual([
      { name: 'alpha', partitionCount: undefined, retentionHours: 72 },
      { name: 'zeta', partitionCount: 2, retentionHours: 24 },
    ]);
    expect(mocks.armList.mock.calls[0][0]).toContain(
      `${NS_ID}/eventhubs?api-version=`,
    );
  });
  it('lists consumer groups of one hub', async () => {
    mocks.armList.mockResolvedValue([
      { name: 'viewer' },
      { name: '$Default' },
      {},
    ]);
    expect(await listConsumerGroups(NS_ID, 'firewall-logs')).toEqual([
      '$Default',
      'viewer',
    ]);
    expect(mocks.armList.mock.calls[0][0]).toContain(
      '/eventhubs/firewall-logs/consumergroups',
    );
  });
});

describe('grantReceiver', () => {
  const config = {
    namespace: 'Contoso-FW',
    eventHub: 'firewall-logs',
    consumerGroup: '$Default',
    startPosition: 'latest' as const,
  };
  it('assigns the Data Receiver role at hub scope, not namespace scope', async () => {
    mocks.graphQuery.mockResolvedValue([{ id: NS_ID }]);
    expect(await grantReceiver(config)).toBe(
      `${NS_ID}/eventhubs/firewall-logs`,
    );
    expect(mocks.grantRole).toHaveBeenCalledWith(
      `${NS_ID}/eventhubs/firewall-logs`,
      'a638d3c7-ab3a-418d-83e6-5f17a39d4fde',
    );
    expect(mocks.graphQuery.mock.calls[0][0]).toContain("name =~ 'contoso-fw'");
  });
  it("refuses when the namespace is not in the user's subscriptions", async () => {
    mocks.graphQuery.mockResolvedValue([]);
    await expect(grantReceiver(config)).rejects.toThrow(
      /Couldn't find the namespace contoso-fw/,
    );
    expect(mocks.grantRole).not.toHaveBeenCalled();
  });
  it('never lets a hostile namespace reach the query', async () => {
    await expect(
      grantReceiver({ ...config, namespace: "x' | take 1 //" }),
    ).rejects.toThrow(/Invalid Event Hubs namespace/);
    expect(mocks.graphQuery).not.toHaveBeenCalled();
  });
});
