import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  armRequest: vi.fn(),
  discoverFirewalls: vi.fn(),
  grantRole: vi.fn(),
}));
vi.mock('./arm', () => ({ armRequest: mocks.armRequest }));
vi.mock('./azure', () => ({
  discoverFirewalls: mocks.discoverFirewalls,
  describeAzureError: (e: unknown) => (e as Error).message,
}));
vi.mock('./roleAssignments', () => ({ grantRole: mocks.grantRole }));

import {
  applySetup,
  checkNamespaceName,
  getSetupContext,
  reviewSetup,
} from './logProvision';
import type { ProvisionProgress } from '../shared/logProvision';

const SUB = '00000000-0000-0000-0000-000000000000';
const FW1 = `/subscriptions/${SUB}/resourceGroups/rg-fw/providers/Microsoft.Network/azureFirewalls/fw1`;
const NS_ID = `/subscriptions/${SUB}/resourceGroups/rg-logs/providers/Microsoft.EventHub/namespaces/contoso-logs`;
const OFFERED = [
  'AZFWNetworkRule',
  'AZFWApplicationRule',
  'AZFWNatRule',
  'AZFWThreatIntel',
  'AZFWIdpsSignature',
  'AZFWDnsQuery',
  'AZFWFqdnResolveFailure',
  'AZFWFlowTrace',
  'AZFWFatFlow',
  'AZFWDnsAdditional',
];

interface World {
  settings: unknown[];
  providers: Record<string, string>;
  deployment: string[];
  failOn?: RegExp;
  /** publicNetworkAccess of the existing destination namespace, as Azure reports it. */
  namespaceAccess?: string;
  failWith?: { statusCode?: number; message: string };
  calls: { method: string; url: string; body?: any }[];
}
let world: World;

function route(path: string, init: RequestInit = {}) {
  const method = init.method ?? 'GET';
  const body = init.body ? JSON.parse(String(init.body)) : undefined;
  world.calls.push({ method, url: path, body });
  if (world.failOn?.test(`${method} ${path}`)) {
    throw Object.assign(new Error(world.failWith?.message ?? 'boom'), {
      statusCode: world.failWith?.statusCode,
    });
  }
  const ok = (data: unknown) =>
    Promise.resolve({ status: 200, headers: new Headers(), data });
  if (/diagnosticSettingsCategories/.test(path))
    return ok({
      value: [
        ...OFFERED.map((name) => ({
          name,
          properties: { categoryType: 'Logs' },
        })),
        { name: 'AllMetrics', properties: { categoryType: 'Metrics' } },
      ],
    });
  if (/diagnosticSettings\?/.test(path)) return ok({ value: world.settings });
  if (method === 'GET' && /\/namespaces\/[^/?]+\?api-version/.test(path))
    return ok({ properties: { publicNetworkAccess: world.namespaceAccess } });
  if (/diagnosticSettings\/[^?]+\?/.test(path) && method === 'PUT')
    return ok({});
  const provider = /\/providers\/(Microsoft\.\w+)(\/register)?\?/.exec(path);
  if (
    provider &&
    !path.includes('/deployments/') &&
    !path.includes('checkName')
  ) {
    if (provider[2]) {
      world.providers[provider[1]] = 'Registered';
      return ok({});
    }
    return ok({
      registrationState: world.providers[provider[1]] ?? 'Registered',
    });
  }
  if (/checkNameAvailability/.test(path))
    return ok({ nameAvailable: false, message: 'The name is not available.' });
  if (/\/deployments\//.test(path)) {
    if (method === 'PUT') return ok({});
    const next = world.deployment.shift() ?? 'Succeeded';
    return ok({
      properties: {
        provisioningState: next,
        error:
          next === 'Failed'
            ? {
                code: 'InvalidTemplateDeployment',
                message: 'The template failed',
                details: [
                  {
                    code: 'NamespaceAlreadyExists',
                    message: 'The namespace name is not available',
                  },
                ],
              }
            : undefined,
      },
    });
  }
  return ok({});
}

const request = (
  over: Record<string, unknown> = {},
  dest: Record<string, unknown> = {},
) => ({
  firewalls: [
    {
      id: FW1,
      name: 'renderer says fw9',
      location: 'westus',
      skuTier: 'Basic',
    },
  ],
  destination: {
    kind: 'new',
    subscriptionId: SUB,
    resourceGroup: 'rg-logs',
    createResourceGroup: true,
    namespaceName: 'contoso-logs',
    tier: 'Basic',
    eventHub: 'firewall-logs',
    retentionHours: 24,
    ...dest,
  },
  categories: ['AZFWNetworkRule', 'AZFWApplicationRule', 'AZFWNatRule'],
  settingName: 'ez-azfw-logs',
  grantRole: true,
  ...over,
});

const deps = {
  sleep: vi.fn(async () => undefined),
  now: () => 1_700_000_000_000,
};
const writes = () =>
  world.calls
    .filter((c) => c.method !== 'GET' && !/checkNameAvailability/.test(c.url))
    .map(
      (c) =>
        `${c.method} ${c.url.replace(/\?.*/, '').replace(/^.*\/providers\//, '')}`,
    );

beforeEach(() => {
  vi.resetAllMocks();
  deps.sleep.mockClear();
  world = { settings: [], providers: {}, deployment: [], calls: [] };
  mocks.armRequest.mockImplementation((path: string, init?: RequestInit) =>
    route(path, init),
  );
  mocks.discoverFirewalls.mockResolvedValue([
    { id: FW1, name: 'fw1', location: 'eastus2', skuTier: 'Premium' },
  ]);
  mocks.grantRole.mockResolvedValue(undefined);
});

describe('getSetupContext', () => {
  it('takes name, region and tier from discovery, never from the caller; reads Log categories and settings', async () => {
    const ctx = await getSetupContext([FW1.toUpperCase()], SUB);
    expect(ctx.firewalls[0].firewall).toEqual({
      id: FW1,
      name: 'fw1',
      location: 'eastus2',
      skuTier: 'Premium',
    });
    expect(ctx.firewalls[0].state?.offeredCategories).toEqual(OFFERED);
    expect(ctx.providers).toEqual([
      {
        subscriptionId: SUB,
        namespace: 'Microsoft.Insights',
        registered: true,
      },
      {
        subscriptionId: SUB,
        namespace: 'Microsoft.EventHub',
        registered: true,
      },
    ]);
  });
  it('reports an unknown firewall', async () => {
    await expect(getSetupContext([FW1.replace('fw1', 'nope')])).rejects.toThrow(
      /could not be found/,
    );
  });
  it('a firewall whose settings cannot be read is reported, not fatal', async () => {
    world.failOn = /diagnosticSettingsCategories/;
    world.failWith = { message: 'AuthorizationFailed' };
    const ctx = await getSetupContext([FW1]);
    expect(ctx.firewalls[0]).toMatchObject({
      readError: 'AuthorizationFailed',
    });
    expect(ctx.firewalls[0].state).toBeUndefined();
  });
  it('treats a provider it cannot read as registered rather than inventing a step', async () => {
    world.failOn = /\/providers\/Microsoft\.EventHub\?/;
    expect(
      (await getSetupContext([FW1], SUB)).providers.at(-1)?.registered,
    ).toBe(true);
  });
});

describe('checkNamespaceName', () => {
  it('asks Azure and returns its message', async () => {
    expect(await checkNamespaceName(SUB, 'taken-name')).toEqual({
      available: false,
      message: 'The name is not available.',
    });
    expect(world.calls[0]).toMatchObject({
      method: 'POST',
      body: { name: 'taken-name' },
    });
  });
});

describe('reviewSetup: namespace network access', () => {
  const existing = {
    kind: 'existing',
    namespaceId: NS_ID,
    namespaceLocation: 'eastus2',
    tier: 'Basic',
    eventHub: 'firewall-logs',
    createEventHub: false,
    retentionHours: 24,
  };
  const review = () =>
    reviewSetup({
      ...request({ grantRole: false }),
      destination: existing,
    } as unknown as ReturnType<typeof request>);
  const namespaceReads = () =>
    world.calls.filter(
      (c) => c.method === 'GET' && /\/namespaces\/contoso-logs\?/.test(c.url),
    );

  it('warns, and still lets the review go ahead, when Azure says public access is disabled', async () => {
    world.namespaceAccess = 'Disabled';
    const result = await review();
    expect(result.errors).toEqual([]);
    expect(result.warnings.join(' ')).toMatch(/public network access disabled/);
    expect(namespaceReads()).toHaveLength(1);
  });
  it('does not warn when public access is enabled', async () => {
    world.namespaceAccess = 'Enabled';
    expect((await review()).warnings).toEqual([]);
  });
  it('does not warn when the namespace cannot be read', async () => {
    world.failOn = /GET .*\/namespaces\/contoso-logs\?/;
    world.failWith = { statusCode: 403, message: 'forbidden' };
    const result = await review();
    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([]);
  });
  it('does not read a namespace when a new one is created', async () => {
    world.namespaceAccess = 'Disabled';
    await reviewSetup(request());
    expect(namespaceReads()).toEqual([]);
  });
});

describe('reviewSetup', () => {
  it("lists the changes, the permissions and the cost, and uses Azure's facts for the firewall", async () => {
    const review = await reviewSetup(request());
    expect(review.errors).toEqual([]);
    expect(review.lines[0]).toBe('Create resource group rg-logs in eastus2'); // region from Azure, not the "westus" the caller sent
    expect(review.lines.join('\n')).toContain(
      'fw1: create diagnostic setting "ez-azfw-logs"',
    );
    expect(review.lines.join('\n')).not.toContain('fw9');
    expect(review.cost).toMatch(/about \$11 per month/);
    expect(review.permissions.map((p) => p.what)).toContain(
      'Assign the Data Receiver role',
    );
    expect(review.labels).toHaveLength(4);
    expect(writes()).toEqual([]); // reviewing changes nothing
  });
  it('is stable for the same state and changes when the plan changes', async () => {
    const a = await reviewSetup(request());
    expect((await reviewSetup(request())).hash).toBe(a.hash);
    expect((await reviewSetup(request({ grantRole: false }))).hash).not.toBe(
      a.hash,
    );
  });
  it('reports rule violations instead of throwing', async () => {
    const review = await reviewSetup(request({ settingName: 'a/b' }));
    expect(review.errors.join(' ')).toMatch(
      /Diagnostic setting name can't contain/,
    );
  });
  it('refuses a firewall whose settings could not be read', async () => {
    world.failOn = /diagnosticSettings\?/;
    world.failWith = { message: 'AuthorizationFailed' };
    await expect(reviewSetup(request())).rejects.toThrow(
      /Couldn't read the diagnostic settings of fw1: AuthorizationFailed/,
    );
  });
  it('rejects a malformed request', async () => {
    await expect(reviewSetup({ firewalls: [] })).rejects.toThrow(
      /at least one firewall/,
    );
  });
  it('plans provider registration when a provider is not registered', async () => {
    world.providers['Microsoft.EventHub'] = 'NotRegistered';
    expect((await reviewSetup(request())).lines[0]).toMatch(
      /^Register Microsoft.EventHub/,
    );
  });
});

describe('applySetup', () => {
  const run = async (raw = request(), hash?: string) => {
    const emitted: ProvisionProgress[] = [];
    const h = hash ?? (await reviewSetup(raw)).hash;
    world.calls = [];
    const result = await applySetup(raw, h, (p) => emitted.push(p), deps);
    return { result, emitted };
  };

  it('runs the steps in order and reports each one', async () => {
    world.deployment = ['Running', 'Succeeded'];
    const { result, emitted } = await run();
    expect(writes()).toEqual([
      expect.stringMatching(
        /^PUT \/subscriptions\/.*\/resourcegroups\/rg-logs$/,
      ),
      'PUT Microsoft.Resources/deployments/ezazfw-logs-1700000000000',
      'PUT Microsoft.Insights/diagnosticSettings/ez-azfw-logs',
    ]);
    expect(mocks.grantRole).toHaveBeenCalledWith(
      `${NS_ID}/eventhubs/firewall-logs`,
      'a638d3c7-ab3a-418d-83e6-5f17a39d4fde',
    );
    expect(result.phase).toBe('succeeded');
    expect(result.steps.map((s) => s.state)).toEqual([
      'done',
      'done',
      'done',
      'done',
    ]);
    expect(result.connect).toMatchObject({
      namespace: 'contoso-logs.servicebus.windows.net',
      eventHub: 'firewall-logs',
      consumerGroup: '$Default',
    });
    // Progress was reported as it went: first all pending, then each step running and done.
    expect(emitted[0].steps.every((s) => s.state === 'pending')).toBe(true);
    expect(emitted.some((e) => e.steps[1].state === 'running')).toBe(true);
    expect(emitted.at(-1)?.phase).toBe('succeeded');
    expect(deps.sleep).toHaveBeenCalled(); // polled the running deployment
  });

  it('sends the template and the merged diagnostic setting body to Azure', async () => {
    await run();
    const deployment = world.calls.find(
      (c) => c.method === 'PUT' && /deployments/.test(c.url),
    )!;
    expect(deployment.body.properties.mode).toBe('Incremental');
    expect(
      deployment.body.properties.template.resources[0].properties
        .disableLocalAuth,
    ).toBe(true);
    const setting = world.calls.find(
      (c) => c.method === 'PUT' && /diagnosticSettings\//.test(c.url),
    )!;
    expect(setting.url).toContain(
      `${FW1}/providers/Microsoft.Insights/diagnosticSettings/ez-azfw-logs?api-version=2021-05-01-preview`,
    );
    expect(setting.body.properties.eventHubAuthorizationRuleId).toBe(
      `${NS_ID}/authorizationRules/ez-azfw-logs-send`,
    );
    expect(setting.body.properties.logs.map((l: any) => l.category)).toEqual([
      'AZFWNetworkRule',
      'AZFWApplicationRule',
      'AZFWNatRule',
    ]);
  });

  it('refuses to run when the plan changed since the review, and writes nothing', async () => {
    await expect(
      applySetup(request(), 'stale-hash', () => undefined, deps),
    ).rejects.toThrow(/changed since you reviewed/);
    expect(writes()).toEqual([]);
    expect(mocks.grantRole).not.toHaveBeenCalled();
  });

  it('refuses a request that breaks the rules, even with a matching hash', async () => {
    const raw = request({ settingName: 'a/b' });
    const { hash } = await reviewSetup(raw);
    await expect(applySetup(raw, hash, () => undefined, deps)).rejects.toThrow(
      /Diagnostic setting name/,
    );
    expect(writes()).toEqual([]);
  });

  it('stops at the first failure, skips the rest, and explains the Azure error', async () => {
    world.failOn = /^PUT .*diagnosticSettings\//;
    world.failWith = {
      message:
        "Resources should be in the same region. Resource 'a' is in region 'x'",
    };
    const { result } = await run();
    expect(result.phase).toBe('failed');
    expect(result.steps.map((s) => s.state)).toEqual([
      'done',
      'done',
      'failed',
      'skipped',
    ]);
    expect(result.error).toMatch(/same region as the firewall/);
    expect(mocks.grantRole).not.toHaveBeenCalled();
  });

  it('reports why a deployment failed', async () => {
    world.deployment = ['Failed'];
    const { result } = await run();
    expect(result.phase).toBe('failed');
    expect(result.steps[1]).toMatchObject({ state: 'failed' });
    // Azure's NamespaceAlreadyExists detail is turned into plain advice.
    expect(result.error).toMatch(/namespace name is already taken/);
    expect(result.steps[2].state).toBe('skipped');
  });

  it('a missing role-assignment permission becomes a manual step, not a failure', async () => {
    mocks.grantRole.mockRejectedValue(
      Object.assign(new Error('AuthorizationFailed'), { statusCode: 403 }),
    );
    const { result } = await run();
    expect(result.phase).toBe('succeeded');
    expect(result.steps.at(-1)?.state).toBe('manual');
    expect(result.manual[0]).toMatch(
      /Assign yourself the "Azure Event Hubs Data Receiver" role on the event hub firewall-logs/,
    );
    expect(result.connect).toBeDefined();
  });

  it('any other role-assignment error is a failure', async () => {
    mocks.grantRole.mockRejectedValue(
      Object.assign(new Error('Service unavailable'), { statusCode: 503 }),
    );
    const { result } = await run();
    expect(result.phase).toBe('failed');
    expect(result.error).toBe('Service unavailable');
  });

  it('does not write a diagnostic setting that is already as wanted', async () => {
    const dest = {
      kind: 'existing',
      namespaceId: NS_ID,
      namespaceLocation: 'eastus2',
      tier: 'Basic',
      eventHub: 'firewall-logs',
      createEventHub: false,
      retentionHours: 24,
    };
    world.settings = [
      {
        name: 'mine',
        properties: {
          eventHubAuthorizationRuleId: `${NS_ID}/authorizationRules/ez-azfw-logs-send`,
          eventHubName: 'firewall-logs',
          logs: ['AZFWNetworkRule', 'AZFWApplicationRule', 'AZFWNatRule'].map(
            (category) => ({ category, enabled: true }),
          ),
        },
      },
    ];
    const raw = { ...request({ grantRole: false }), destination: dest };
    const { result } = await run(raw as unknown as ReturnType<typeof request>);
    expect(result.phase).toBe('succeeded');
    expect(writes().filter((w) => /diagnosticSettings/.test(w))).toEqual([]);
    expect(result.steps.at(-1)?.label).toMatch(/already set up/);
  });

  it('registers a provider first and waits until Azure reports it registered', async () => {
    world.providers['Microsoft.EventHub'] = 'NotRegistered';
    const { result } = await run();
    expect(result.steps[0].label).toBe('Register Microsoft.EventHub');
    expect(writes()[0]).toMatch(/^POST Microsoft\.EventHub\/register$/);
    expect(result.phase).toBe('succeeded');
  });

  it('allows only one setup at a time', async () => {
    const raw = request();
    const { hash } = await reviewSetup(raw);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    mocks.grantRole.mockImplementation(() => gate);
    const first = applySetup(raw, hash, () => undefined, deps);
    await vi.waitFor(() => expect(mocks.grantRole).toHaveBeenCalled());
    await expect(applySetup(raw, hash, () => undefined, deps)).rejects.toThrow(
      /already running/,
    );
    release();
    await first;
    // And it can run again afterwards.
    await expect(
      applySetup(raw, hash, () => undefined, deps),
    ).resolves.toBeDefined();
  });
});
