import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { FirewallAllocation } from '../shared/resourceSettings';

interface FixtureResource {
  id: string;
  name: string;
  location: string;
  etag?: string;
  properties: Record<string, unknown>;
  [key: string]: unknown;
}
const mocks = vi.hoisted(() => ({
  resources: new Map<string, FixtureResource>(),
  assignments: [] as {
    id: string;
    name: string;
    properties: { maintenanceConfigurationId: string };
  }[],
  state: { firewallAllocations: {} as Record<string, FirewallAllocation> },
  request: vi.fn(),
  list: vi.fn(),
  write: vi.fn(),
  graph: vi.fn(),
  learned: vi.fn(),
  validateMode: vi.fn(),
}));
vi.mock('./arm', () => ({
  armRequest: mocks.request,
  armList: mocks.list,
  armWrite: mocks.write,
}));
vi.mock('./store', () => ({
  loadState: () => mocks.state,
  updateState: (fn: (s: typeof mocks.state) => void) => {
    fn(mocks.state);
    return true;
  },
}));
vi.mock('./azure', () => ({
  graphQuery: mocks.graph,
  describeAzureError: (e: Error) => e.message,
  network: () => ({ azureFirewalls: { listLearnedPrefixes: mocks.learned } }),
  validatePolicyMode: mocks.validateMode,
}));
const settings = await import('./resourceSettings');
const ROOT =
  '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg';
const NET = `${ROOT}/providers/Microsoft.Network`;
const FW = `${NET}/azureFirewalls/fw`;
const POLICY = `${NET}/firewallPolicies/fp`;
const VNET = `${NET}/virtualNetworks/vnet`;
const PIP = `${NET}/publicIPAddresses/pip`;
const HUB = `${NET}/virtualHubs/hub`;
const RS = `${NET}/virtualHubs/route-server`;
const MAINT = `${ROOT}/providers/Microsoft.Maintenance/maintenanceConfigurations/daily`;
const IDENTITY = `${ROOT}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/tls-identity`;
const put = (
  id: string,
  properties: Record<string, unknown>,
  extra: Record<string, unknown> = {},
) => {
  const raw: FixtureResource = {
    id,
    name: id.slice(id.lastIndexOf('/') + 1),
    location: 'eastus',
    etag: 'etag-current',
    properties,
    ...extra,
  };
  mocks.resources.set(id, raw);
  return raw;
};
async function applyWrite(path: string, method: string, body?: unknown) {
  const id = path.split('?')[0];
  if (id.includes('/configurationAssignments/')) {
    if (method === 'DELETE')
      mocks.assignments = mocks.assignments.filter((a) => a.id !== id);
    else {
      const value = body as {
        properties: { maintenanceConfigurationId: string };
      };
      mocks.assignments.push({
        id,
        name: id.slice(id.lastIndexOf('/') + 1),
        properties: value.properties,
      });
    }
    return;
  }
  const value = body as FixtureResource;
  const { properties: _properties, ...extra } = structuredClone(value);
  put(
    id,
    { ...structuredClone(value.properties), provisioningState: 'Succeeded' },
    { ...extra, id },
  );
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.resources.clear();
  mocks.assignments = [];
  mocks.state.firewallAllocations = {};
  put(
    FW,
    {
      provisioningState: 'Succeeded',
      sku: { name: 'AZFW_VNet', tier: 'Standard' },
      firewallPolicy: { id: POLICY },
      additionalProperties: { 'Keep.This': 'unchanged' },
      ipConfigurations: [
        {
          name: 'data',
          properties: {
            subnet: { id: `${VNET}/subnets/AzureFirewallSubnet` },
            publicIPAddress: { id: PIP },
            privateIPAddress: '10.0.0.4',
          },
        },
      ],
    },
    { tags: { env: 'prod' }, zones: ['1', '2'] },
  );
  put(
    POLICY,
    {
      provisioningState: 'Succeeded',
      sku: { tier: 'Premium' },
      threatIntelMode: 'Alert',
      firewalls: [{ id: FW }],
      snat: {
        privateRanges: ['10.0.0.0/8'],
        autoLearnPrivateRanges: 'Disabled',
      },
      intrusionDetection: { mode: 'Deny' },
    },
    { tags: { env: 'prod' } },
  );
  put(VNET, {
    subnets: [
      {
        id: `${VNET}/subnets/AzureFirewallSubnet`,
        name: 'AzureFirewallSubnet',
      },
    ],
  });
  put(
    PIP,
    { publicIPAllocationMethod: 'Static' },
    { sku: { name: 'Standard' } },
  );
  put(HUB, { virtualWan: { id: `${NET}/virtualWans/wan` } });
  put(RS, {});
  put(MAINT, {
    maintenanceScope: 'Resource',
    extensionProperties: { maintenanceSubScope: 'NetworkSecurity' },
    maintenanceWindow: {
      duration: '05:00',
      recurEvery: 'Day',
      timeZone: 'UTC',
      startDateTime: '2026-01-01 01:00',
    },
  });
  put(IDENTITY, { clientId: 'identity-client-id' });
  mocks.request.mockImplementation(async (path: string) => {
    const raw = mocks.resources.get(path.split('?')[0]);
    if (!raw)
      throw Object.assign(new Error(`Missing resource: ${path}`), {
        statusCode: 404,
      });
    return { data: structuredClone(raw), status: 200, headers: new Headers() };
  });
  mocks.list.mockImplementation(async (path: string) => {
    if (path.includes('/configurationAssignments'))
      return structuredClone(mocks.assignments);
    if (path.startsWith(`${RS}/ipConfigurations`))
      return [
        { properties: { subnet: { id: `${VNET}/subnets/RouteServerSubnet` } } },
      ];
    return [];
  });
  mocks.write.mockImplementation(applyWrite);
  mocks.graph.mockResolvedValue([]);
  mocks.validateMode.mockResolvedValue(undefined);
  mocks.learned.mockResolvedValue({
    ipPrefixes: ['10.0.0.0/8', '198.51.100.0/24'],
  });
});

describe('advanced firewall operations', () => {
  it('updates scaling and Route Server without replacing unrelated properties', async () => {
    const before = await settings.getFirewallConfiguration(FW);
    await settings.putFirewallConfiguration(FW, before, {
      ...before,
      minCapacity: 4,
      maxCapacity: 8,
      routeServerId: RS,
    });
    expect(mocks.write).toHaveBeenCalledWith(
      expect.stringContaining(FW),
      'PUT',
      expect.objectContaining({
        tags: { env: 'prod' },
        zones: ['1', '2'],
        properties: expect.objectContaining({
          firewallPolicy: { id: POLICY },
          autoscaleConfiguration: { minCapacity: 4, maxCapacity: 8 },
          additionalProperties: {
            'Keep.This': 'unchanged',
            'Network.RouteServerInfo.RouteServerID': RS,
          },
        }),
      }),
    );
    expect(
      mocks.write.mock.calls[0][2].properties.ipConfigurations[0].properties
        .privateIPAddress,
    ).toBeUndefined();
  });

  it('uses explicit nulls when resetting prescaling to service defaults', async () => {
    const raw = mocks.resources.get(FW);
    if (!raw) throw new Error('Fixture missing');
    raw.properties.autoscaleConfiguration = { minCapacity: 4, maxCapacity: 8 };
    const before = await settings.getFirewallConfiguration(FW);
    await settings.putFirewallConfiguration(FW, before, {
      ...before,
      minCapacity: null,
      maxCapacity: null,
    });
    expect(
      mocks.write.mock.calls[0][2].properties.autoscaleConfiguration,
    ).toEqual({ minCapacity: null, maxCapacity: null });
  });

  it('saves allocation before stopping and restarts without applying the firewall ETag to its subnet', async () => {
    const before = await settings.getFirewallConfiguration(FW);
    mocks.write.mockImplementation(
      async (path: string, method: string, body?: unknown, etag?: string) => {
        const properties = (body as FixtureResource).properties;
        if (
          etag &&
          Array.isArray(properties.ipConfigurations) &&
          properties.ipConfigurations.length &&
          etag !== 'subnet-etag'
        )
          throw Object.assign(
            new Error(
              'Firewall If-Match did not match the linked subnet ETag.',
            ),
            { code: 'PreconditionFailedEtagMismatch' },
          );
        expect(mocks.state.firewallAllocations[FW.toLowerCase()]).toBeDefined();
        await applyWrite(path, method, body);
      },
    );
    await settings.putFirewallConfiguration(FW, before, {
      ...before,
      powerState: 'Stopped',
    });
    const stopped = await settings.getFirewallConfiguration(FW);
    expect(stopped.powerState).toBe('Stopped');
    expect(stopped.allocation?.ipConfigurations[0]).toEqual({
      name: 'data',
      subnet: { id: `${VNET}/subnets/AzureFirewallSubnet` },
      publicIPAddress: { id: PIP },
    });
    await settings.putFirewallConfiguration(FW, stopped, {
      ...stopped,
      powerState: 'Running',
    });
    expect((await settings.getFirewallConfiguration(FW)).powerState).toBe(
      'Running',
    );
    expect(
      mocks.write.mock.calls[1][2].properties.ipConfigurations[0].properties,
    ).toEqual({
      subnet: { id: `${VNET}/subnets/AzureFirewallSubnet` },
      publicIPAddress: { id: PIP },
    });
  });

  it('restores secured-hub attachment and its explicit service-managed public-IP count', async () => {
    put(FW, {
      provisioningState: 'Succeeded',
      sku: { name: 'AZFW_Hub', tier: 'Standard' },
      virtualHub: { id: HUB },
      hubIPAddresses: { privateIPAddress: '10.0.0.4', publicIPs: { count: 4 } },
    });
    const before = await settings.getFirewallConfiguration(FW);
    await settings.putFirewallConfiguration(FW, before, {
      ...before,
      powerState: 'Stopped',
    });
    const stopped = await settings.getFirewallConfiguration(FW);
    await settings.putFirewallConfiguration(FW, stopped, {
      ...stopped,
      powerState: 'Running',
    });
    expect(mocks.write.mock.calls[1][2].properties).toMatchObject({
      virtualHub: { id: HUB },
      hubIPAddresses: { publicIPs: { count: 4 } },
    });
  });

  it('blocks private-IP DNAT stops and concurrent edited-field changes before writing', async () => {
    const before = await settings.getFirewallConfiguration(FW);
    mocks.list.mockResolvedValueOnce([
      {
        properties: {
          ruleCollections: [
            {
              rules: [
                { ruleType: 'NatRule', destinationAddresses: ['10.0.0.4'] },
              ],
            },
          ],
        },
      },
    ]);
    await expect(
      settings.putFirewallConfiguration(FW, before, {
        ...before,
        powerState: 'Stopped',
      }),
    ).rejects.toThrow('private-IP DNAT');
    expect(mocks.write).not.toHaveBeenCalled();
    const raw = mocks.resources.get(FW);
    if (!raw) throw new Error('Fixture missing');
    raw.properties.autoscaleConfiguration = { minCapacity: 4, maxCapacity: 8 };
    await expect(
      settings.putFirewallConfiguration(FW, before, {
        ...before,
        minCapacity: 6,
        maxCapacity: 10,
      }),
    ).rejects.toMatchObject({ code: 'ResourceSettingsConflict' });
    expect(mocks.write).not.toHaveBeenCalled();
  });

  it('does not remove a maintenance assignment created while the firewall resource was updating', async () => {
    const before = await settings.getFirewallConfigurationForDraft(FW, true);
    const other = MAINT.replace('/daily', '/external');
    mocks.write.mockImplementation(
      async (path: string, method: string, body?: unknown) => {
        await applyWrite(path, method, body);
        if (path.startsWith(`${FW}?`))
          mocks.assignments.push({
            id: `${FW}/providers/Microsoft.Maintenance/configurationAssignments/external`,
            name: 'external',
            properties: { maintenanceConfigurationId: other },
          });
      },
    );
    await expect(
      settings.putFirewallConfiguration(FW, before, {
        ...before,
        minCapacity: 4,
        maxCapacity: 8,
        maintenanceConfigurationIds: [MAINT],
      }),
    ).rejects.toMatchObject({ code: 'ResourceSettingsConflict' });
    expect(
      mocks.assignments.map((a) => a.properties.maintenanceConfigurationId),
    ).toEqual([other]);
    expect(
      mocks.write.mock.calls.some(([, method]) => method === 'DELETE'),
    ).toBe(false);
    expect((await settings.getFirewallConfiguration(FW)).minCapacity).toBe(4);
  });

  it('assigns/removes existing maintenance resources and rejects invalid schedules', async () => {
    const before = await settings.getFirewallConfigurationForDraft(FW, true);
    await settings.putFirewallConfiguration(FW, before, {
      ...before,
      maintenanceConfigurationIds: [MAINT],
    });
    expect(mocks.assignments[0].properties.maintenanceConfigurationId).toBe(
      MAINT,
    );
    const assigned = await settings.getFirewallConfigurationForDraft(FW, true);
    await settings.putFirewallConfiguration(FW, assigned, {
      ...assigned,
      maintenanceConfigurationIds: [],
    });
    expect(mocks.assignments).toEqual([]);
    const config = mocks.resources.get(MAINT);
    if (!config) throw new Error('Fixture missing');
    config.properties.maintenanceWindow = {
      duration: '04:59',
      recurEvery: 'Day',
    };
    mocks.write.mockClear();
    await expect(
      settings.putFirewallConfiguration(FW, before, {
        ...before,
        maintenanceConfigurationIds: [MAINT],
      }),
    ).rejects.toThrow('at least 5 hours');
    expect(mocks.write).not.toHaveBeenCalled();
  });

  it('surfaces maintenance permissions independently and returns learned prefixes read-only', async () => {
    mocks.list.mockRejectedValueOnce(new Error('Maintenance read denied'));
    const view = await settings.getFirewallSettings(FW);
    expect(view.running.maintenanceConfigurationIds).toBeUndefined();
    expect(view.errors.join(' ')).toContain('Maintenance read denied');
    expect(view.running.powerState).toBe('Running');
    await expect(settings.getLearnedPrefixes(FW)).resolves.toEqual([
      '10.0.0.0/8',
      '198.51.100.0/24',
    ]);
    expect(mocks.write).not.toHaveBeenCalled();
  });
});

describe('hub allocation recovery', () => {
  it('retains customer-provided public IP hints for a hub stopped outside this device', async () => {
    put(FW, {
      provisioningState: 'Succeeded',
      sku: { name: 'AZFW_Hub', tier: 'Standard' },
      virtualHub: null,
      hubIPAddresses: null,
      ipConfigurations: [
        { name: 'byopip', properties: { publicIPAddress: { id: PIP } } },
      ],
    });
    const before = await settings.getFirewallConfiguration(FW);
    expect(before.powerState).toBe('Stopped');
    expect(before.allocation?.ipConfigurations[0].publicIPAddress?.id).toBe(
      PIP,
    );
    if (!before.allocation) throw new Error('Allocation hint missing');
    await settings.putFirewallConfiguration(FW, before, {
      ...before,
      powerState: 'Running',
      allocation: { ...before.allocation, virtualHubId: HUB },
    });
    expect(mocks.write.mock.calls[0][2].properties).toMatchObject({
      virtualHub: { id: HUB },
      hubIPAddresses: null,
      ipConfigurations: [
        { name: 'byopip', properties: { publicIPAddress: { id: PIP } } },
      ],
    });
  });
});

describe('advanced policy operations', () => {
  it('updates mode and advanced policy fields in one conditional resource write', async () => {
    const before = await settings.getPolicyConfiguration(POLICY);
    const desired = { ...before.settings, allowlistIps: ['192.0.2.1'] };
    await settings.putPolicyConfiguration(POLICY, before.settings, desired, {
      before: 'Alert',
      after: 'Deny',
    });
    expect(mocks.write).toHaveBeenCalledTimes(1);
    expect(mocks.write.mock.calls[0][2].properties).toMatchObject({
      threatIntelMode: 'Deny',
      threatIntelWhitelist: { ipAddresses: ['192.0.2.1'] },
    });
    expect(mocks.validateMode).toHaveBeenCalled();
  });

  it('preserves concurrent mode and unrelated policy settings when editing DNS and allowlists', async () => {
    const before = await settings.getPolicyConfiguration(POLICY);
    const desired = structuredClone(before.settings);
    desired.dns = { inherit: false, enableProxy: true, servers: ['10.0.0.4'] };
    desired.allowlistIps = ['192.0.2.1'];
    const raw = mocks.resources.get(POLICY);
    if (!raw) throw new Error('Fixture missing');
    raw.properties.threatIntelMode = 'Deny';
    await settings.putPolicyConfiguration(POLICY, before.settings, desired);
    expect(mocks.write.mock.calls[0][2].properties).toMatchObject({
      threatIntelMode: 'Deny',
      intrusionDetection: { mode: 'Deny' },
      dnsSettings: { enableProxy: true, servers: ['10.0.0.4'] },
      threatIntelWhitelist: { ipAddresses: ['192.0.2.1'], fqdns: [] },
    });
  });

  it('requires a committed Route Server association before enabling VNet SNAT auto-learning', async () => {
    const before = await settings.getPolicyConfiguration(POLICY);
    const desired = { ...before.settings, autoLearnSnat: true };
    await expect(
      settings.putPolicyConfiguration(POLICY, before.settings, desired),
    ).rejects.toThrow('commit that association');
    expect(mocks.write).not.toHaveBeenCalled();
    const fw = mocks.resources.get(FW);
    if (!fw) throw new Error('Fixture missing');
    fw.properties.additionalProperties = {
      'Network.RouteServerInfo.RouteServerID': RS,
    };
    await settings.putPolicyConfiguration(POLICY, before.settings, desired);
    expect(mocks.write.mock.calls[0][2].properties.snat).toEqual({
      privateRanges: ['10.0.0.0/8'],
      autoLearnPrivateRanges: 'Enabled',
    });
  });

  it('configures Premium TLS using references only, without retrieving certificates or granting permissions', async () => {
    const fw = mocks.resources.get(FW);
    if (!fw) throw new Error('Fixture missing');
    fw.properties.sku = { name: 'AZFW_VNet', tier: 'Premium' };
    const before = await settings.getPolicyConfiguration(POLICY);
    const desired = {
      ...before.settings,
      tls: {
        enabled: true,
        certificateName: 'intermediate-ca',
        secretId: 'https://demo-vault.vault.azure.net/secrets/intermediate-ca',
        identityIds: [IDENTITY],
      },
    };
    await settings.putPolicyConfiguration(POLICY, before.settings, desired);
    const body = mocks.write.mock.calls[0][2];
    expect(body.properties.transportSecurity.certificateAuthority).toEqual({
      name: 'intermediate-ca',
      keyVaultSecretId: desired.tls.secretId,
    });
    expect(body.identity.userAssignedIdentities).toEqual({ [IDENTITY]: {} });
    expect(body.properties.intrusionDetection).toEqual({ mode: 'Deny' });
    expect(
      mocks.request.mock.calls.some(([path]) =>
        String(path).includes('vault.azure.net'),
      ),
    ).toBe(false);
    expect(mocks.write.mock.calls).toHaveLength(1);
    expect(mocks.write.mock.calls[0][0]).toContain(POLICY);
  });
});
