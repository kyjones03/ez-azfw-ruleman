import { describe, it, expect, vi } from 'vitest';
import { LogStreamSession, type HubClient } from '../src/main/eventHub';
import {
  buildProvisionPlan,
  reviewLines,
  type ProvisionRequest,
} from '../src/shared/logProvision';

const azure = vi.hoisted(() => ({
  armRequest: vi.fn(),
  discoverFirewalls: vi.fn(),
  grantRole: vi.fn(),
}));
vi.mock('../src/main/arm', () => ({ armRequest: azure.armRequest }));
vi.mock('../src/main/azure', () => ({
  discoverFirewalls: azure.discoverFirewalls,
  describeAzureError: (e: Error) => e.message,
}));
vi.mock('../src/main/roleAssignments', () => ({ grantRole: azure.grantRole }));
import { reviewSetup, applySetup } from '../src/main/logProvision';

const config = {
  namespace: 'contoso-logs.servicebus.windows.net',
  eventHub: 'firewall-logs',
  consumerGroup: '$Default',
  startPosition: 'latest' as const,
};

describe('Independent PR23 regression checks', () => {
  it('concurrent starts leave only one live client and stop closes every client', async () => {
    const clients: {
      closed: boolean;
      abort: () => void;
      handlers?: Parameters<HubClient['subscribe']>[0];
    }[] = [];
    const batches: unknown[] = [];
    const session = new LogStreamSession({
      createClient: () => {
        const state: (typeof clients)[number] = {
          closed: false,
          abort: () => {},
        };
        clients.push(state);
        const client: HubClient = {
          getPartitionIds: async (signal) => {
            state.abort = () => {
              Object.defineProperty(signal, 'aborted', {
                value: true,
                configurable: true,
              });
              signal.dispatchEvent(new Event('abort'));
            };
            return ['0'];
          },
          subscribe: (handlers) => {
            state.handlers = handlers;
            return { close: async () => {} };
          },
          close: async () => {
            state.closed = true;
          },
        };
        return client;
      },
      emitBatch: (batch) => batches.push(batch),
      emitStatus: () => {},
      sleep: async () => {},
    });
    await Promise.all([
      session.start(config),
      session.start({ ...config, eventHub: 'second-hub' }),
    ]);
    await new Promise((resolve) => setImmediate(resolve));
    await session.stop();
    const remaining = clients.filter((c) => !c.closed).length;
    const before = batches.length;
    for (const c of clients.filter((c) => !c.closed))
      c.handlers!.onEvents('0', [
        {
          sequenceNumber: 1,
          body: {
            records: [
              {
                category: 'AZFWNetworkRule',
                resourceId:
                  '/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/old-firewall',
                properties: { Action: 'Allow' },
              },
            ],
          },
        },
      ]);
    // Clean up any orphan's event loop handles even when the assertion fails.
    for (const c of clients) c.abort();
    await new Promise((resolve) => setImmediate(resolve));
    expect({
      remaining,
      batchesEmittedAfterStop: batches.length - before,
    }).toEqual({ remaining: 0, batchesEmittedAfterStop: 0 });
  });

  it('the confirmation material differs for different Azure write scopes', () => {
    const request = (sub: string): ProvisionRequest => ({
      firewalls: [
        {
          id: `/subscriptions/${sub}/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw`,
          name: 'fw',
          location: 'eastus',
        },
      ],
      destination: {
        kind: 'new',
        subscriptionId: sub,
        resourceGroup: 'logs',
        createResourceGroup: true,
        namespaceName: 'contoso-logs',
        tier: 'Basic',
        eventHub: 'logs',
        retentionHours: 24,
      },
      categories: ['AZFWNetworkRule'],
      settingName: 'ez-azfw-logs',
      grantRole: true,
    });
    const first = buildProvisionPlan(
      request('11111111-1111-1111-1111-111111111111'),
      { firewalls: [] },
    );
    const second = buildProvisionPlan(
      request('22222222-2222-2222-2222-222222222222'),
      { firewalls: [] },
    );
    expect(first.steps).not.toEqual(second.steps);
    // main/logProvision.ts hashes only these lines for review AND apply.
    expect(reviewLines(first)).not.toEqual(reviewLines(second));
  });

  it('apply rejects a reviewed hash when destination subscription has changed', async () => {
    const sub = '11111111-1111-1111-1111-111111111111';
    const otherSub = '22222222-2222-2222-2222-222222222222';
    const firewall = {
      id: `/subscriptions/${sub}/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw`,
      name: 'fw',
      location: 'eastus',
    };
    azure.discoverFirewalls.mockResolvedValue([firewall]);
    const writes: string[] = [];
    azure.armRequest.mockImplementation(
      async (path: string, init?: RequestInit) => {
        if (init?.method && init.method !== 'GET') writes.push(path);
        let data: unknown = {};
        if (path.includes('diagnosticSettingsCategories'))
          data = {
            value: [
              { name: 'AZFWNetworkRule', properties: { categoryType: 'Logs' } },
            ],
          };
        else if (path.includes('diagnosticSettings?')) data = { value: [] };
        else if (path.includes('/deployments/'))
          data = { properties: { provisioningState: 'Succeeded' } };
        else data = { registrationState: 'Registered' };
        return { data };
      },
    );
    const request: ProvisionRequest = {
      firewalls: [firewall],
      destination: {
        kind: 'new',
        subscriptionId: sub,
        resourceGroup: 'logs',
        createResourceGroup: true,
        namespaceName: 'contoso-logs',
        tier: 'Basic',
        eventHub: 'logs',
        retentionHours: 24,
      },
      categories: ['AZFWNetworkRule'],
      settingName: 'ez-azfw-logs',
      grantRole: false,
    };
    const review = await reviewSetup(request);
    const changed: ProvisionRequest = {
      ...request,
      destination: {
        ...request.destination,
        subscriptionId: otherSub,
      } as ProvisionRequest['destination'],
    };
    let rejected = false;
    try {
      await applySetup(changed, review.hash, () => {}, {
        now: () => 0,
        sleep: async () => {},
      });
    } catch {
      rejected = true;
    }
    expect({
      rejected,
      writesToOtherSubscription: writes.filter((path) =>
        path.includes(otherSub),
      ).length,
    }).toEqual({ rejected: true, writesToOtherSubscription: 0 });
  });
});
