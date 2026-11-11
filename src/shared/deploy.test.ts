import { describe, it, expect } from 'vitest';
import {
  buildFirewallTemplate,
  validateDeployRequest,
  type DeployContext,
  type DeployRequest,
} from './deploy';

const SUB = '00000000-1111-2222-3333-444444444444';
const RG = `/subscriptions/${SUB}/resourceGroups`;
const VNET = `${RG}/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub`;
const HUB = `${RG}/rg-wan/providers/Microsoft.Network/virtualHubs/hub-eus`;
const SECURED_HUB = `${RG}/rg-wan/providers/Microsoft.Network/virtualHubs/hub-weu`;
const STD_POLICY = `${RG}/rg-pol/providers/Microsoft.Network/firewallPolicies/fp-std`;
const PREM_POLICY = `${RG}/rg-pol/providers/Microsoft.Network/firewallPolicies/fp-prem`;

const ctx: DeployContext = {
  subscriptionId: SUB,
  network: { state: 'registered' },
  resourceGroups: [
    { name: 'rg-hub', location: 'eastus' },
    { name: 'rg-pol', location: 'eastus' },
  ],
  locations: ['eastus', 'westeurope'],
  vnets: [
    {
      id: VNET,
      name: 'vnet-hub',
      resourceGroup: 'rg-hub',
      location: 'eastus',
      addressPrefixes: ['10.0.0.0/16'],
      subnets: [{ name: 'GatewaySubnet', prefix: '10.0.0.0/27' }],
    },
  ],
  hubs: [
    { id: HUB, name: 'hub-eus', resourceGroup: 'rg-wan', location: 'eastus' },
    {
      id: SECURED_HUB,
      name: 'hub-weu',
      resourceGroup: 'rg-wan',
      location: 'westeurope',
      firewallId: 'x',
    },
  ],
  policies: [
    {
      id: STD_POLICY,
      name: 'fp-std',
      resourceGroup: 'rg-pol',
      location: 'eastus',
      tier: 'Standard',
    },
    {
      id: PREM_POLICY,
      name: 'fp-prem',
      resourceGroup: 'rg-pol',
      location: 'eastus',
      tier: 'Premium',
    },
  ],
};

function request(overrides: Partial<DeployRequest> = {}): DeployRequest {
  return {
    subscriptionId: SUB,
    name: 'fw-hub',
    tier: 'Standard',
    resourceGroup: 'rg-hub',
    createResourceGroup: false,
    location: 'eastus',
    zones: [],
    tags: {},
    managementNic: false,
    target: {
      kind: 'vnet-existing',
      vnetId: VNET,
      subnetPrefix: '10.0.1.0/26',
    },
    policy: { kind: 'existing', policyId: STD_POLICY },
    addToManaged: true,
    ...overrides,
  };
}

type Res = {
  type: string;
  name: string;
  dependsOn?: string[];
  properties: Record<string, any>;
  zones?: string[];
};
const resources = (r: DeployRequest) =>
  buildFirewallTemplate(r, ctx).template.resources as Res[];
const firewallOf = (r: DeployRequest) =>
  resources(r).find((x) => x.type === 'Microsoft.Network/azureFirewalls')!;
const newPolicy = (
  extra: Partial<Extract<DeployRequest['policy'], { kind: 'new' }>> = {},
): DeployRequest['policy'] => ({
  kind: 'new',
  name: 'fp-new',
  threatIntelMode: 'Alert',
  resourceGroup: 'rg-hub',
  createResourceGroup: false,
  ...extra,
});
const newVnet = (
  extra: Partial<Extract<DeployRequest['target'], { kind: 'vnet-new' }>> = {},
): DeployRequest['target'] => ({
  kind: 'vnet-new',
  resourceGroup: 'rg-hub',
  createResourceGroup: false,
  vnetName: 'vnet-hub-x',
  addressSpace: '10.50.0.0/16',
  subnetPrefix: '10.50.0.0/26',
  ...extra,
});

describe('validateDeployRequest', () => {
  it('accepts a valid existing-VNet request', () => {
    expect(validateDeployRequest(request(), ctx)).toEqual([]);
  });

  it('refuses when the subscription cannot use Azure networking', () => {
    const blocked: DeployContext = {
      ...ctx,
      network: {
        state: 'blocked',
        message: "This subscription's offer doesn't allow networking.",
      },
    };
    expect(validateDeployRequest(request(), blocked)).toContain(
      "This subscription's offer doesn't allow networking.",
    );
  });

  it('rejects bad names and zones', () => {
    const errors = validateDeployRequest(
      request({ name: '-bad', zones: ['4'] }),
      ctx,
    );
    expect(errors.some((e) => e.includes('Firewall name'))).toBe(true);
    expect(errors.some((e) => e.includes('zones'))).toBe(true);
  });

  it('rejects subnets that are too small, outside the VNet or overlapping', () => {
    const tooSmall = request({
      target: {
        kind: 'vnet-existing',
        vnetId: VNET,
        subnetPrefix: '10.0.1.0/27',
      },
    });
    expect(
      validateDeployRequest(tooSmall, ctx).some((e) =>
        e.includes('/26 or larger'),
      ),
    ).toBe(true);

    const outside = request({
      target: {
        kind: 'vnet-existing',
        vnetId: VNET,
        subnetPrefix: '10.9.0.0/26',
      },
    });
    expect(
      validateDeployRequest(outside, ctx).some((e) =>
        e.includes("doesn't fit inside the VNet address space"),
      ),
    ).toBe(true);

    const overlap = request({
      target: {
        kind: 'vnet-existing',
        vnetId: VNET,
        subnetPrefix: '10.0.0.0/26',
      },
    });
    expect(
      validateDeployRequest(overlap, ctx).some((e) =>
        e.includes('overlaps GatewaySubnet (10.0.0.0/27)'),
      ),
    ).toBe(true);
  });

  it('limits the firewall name so derived public IP names fit 80 characters', () => {
    const errors = validateDeployRequest(
      request({ name: 'f'.repeat(77) }),
      ctx,
    );
    expect(errors).toContain(
      'Firewall name must be at most 76 characters: its public IP is named "<name>-pip" and Azure allows 80.',
    );
    // Hub firewalls have no public IP resources, so the full 80 is allowed.
    expect(
      validateDeployRequest(
        request({
          name: 'f'.repeat(80),
          target: { kind: 'hub', hubId: HUB, publicIpCount: 1 },
        }),
        ctx,
      ),
    ).toEqual([]);
  });

  it('rejects names with spaces or bad endings', () => {
    const errors = validateDeployRequest(
      request({
        name: 'fw hub',
        target: newVnet({ vnetName: 'vnet-' }),
        policy: newPolicy({ name: 'fp.', resourceGroup: 'rg.' }),
      }),
      ctx,
    );
    expect(errors).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^Firewall name can't contain spaces/),
        'VNet name must end with a letter, digit or underscore.',
        'Policy name must end with a letter, digit or underscore.',
        "Policy resource group can't end with a period.",
      ]),
    );
  });

  it('requires a new VNet address space big enough for the firewall subnets', () => {
    expect(
      validateDeployRequest(
        request({
          target: newVnet({
            addressSpace: '10.50.0.0/27',
            subnetPrefix: '10.50.0.0/27',
          }),
        }),
        ctx,
      ),
    ).toContain(
      'VNet address space: /27 is too small. AzureFirewallSubnet needs a /26, so use /26 or larger.',
    );
    const withMgmt = validateDeployRequest(
      request({
        managementNic: true,
        target: newVnet({
          addressSpace: '10.50.0.0/26',
          managementSubnetPrefix: '10.50.0.64/26',
        }),
      }),
      ctx,
    );
    expect(withMgmt.some((e) => e.includes('use /25 or larger'))).toBe(true);
  });

  it('explains host bits and overlapping firewall subnets in a new VNet', () => {
    const errors = validateDeployRequest(
      request({
        managementNic: true,
        target: newVnet({
          addressSpace: '10.50.0.0/16',
          subnetPrefix: '10.50.0.0/26',
          managementSubnetPrefix: '10.50.0.0/26',
        }),
      }),
      ctx,
    );
    expect(errors).toContain(
      'AzureFirewallManagementSubnet: 10.50.0.0/26 overlaps AzureFirewallSubnet (10.50.0.0/26).',
    );
    expect(
      validateDeployRequest(
        request({ target: newVnet({ addressSpace: '10.50.1.0/16' }) }),
        ctx,
      ),
    ).toContain(
      "VNet address space: 10.50.1.0/16 isn't a valid network address for /16 (host bits are set). Did you mean 10.50.0.0/16?",
    );
  });

  it('requires a management NIC for Basic VNet firewalls', () => {
    const errors = validateDeployRequest(
      request({
        tier: 'Basic',
        policy: newPolicy({ name: 'fp-basic' }),
      }),
      ctx,
    );
    expect(errors.some((e) => e.includes('management NIC'))).toBe(true);
  });

  it('requires the policy tier to match the firewall tier', () => {
    const errors = validateDeployRequest(request({ tier: 'Premium' }), ctx);
    expect(errors.some((e) => e.includes('needs a Premium policy'))).toBe(true);
  });

  it('rejects a parent policy of a different tier', () => {
    const errors = validateDeployRequest(
      request({
        policy: newPolicy({ name: 'fp-child', basePolicyId: PREM_POLICY }),
      }),
      ctx,
    );
    expect(errors.some((e) => e.includes('Parent policy'))).toBe(true);
  });

  it('rejects a parent policy in another region (Azure requires the same region)', () => {
    const child = newPolicy({ name: 'fp-child', basePolicyId: STD_POLICY });
    expect(
      validateDeployRequest(request({ policy: child }), ctx).filter((e) =>
        e.includes('Parent policy'),
      ),
    ).toEqual([]);
    const errors = validateDeployRequest(
      request({
        location: 'westeurope',
        target: { kind: 'hub', hubId: HUB, publicIpCount: 1 },
        policy: child,
      }),
      ctx,
    );
    expect(errors).toContain(
      'Parent policy fp-std is in eastus; a child policy must be in the same region as its parent (westeurope).',
    );
  });

  it('rejects hubs that already have a firewall', () => {
    const errors = validateDeployRequest(
      request({
        target: { kind: 'hub', hubId: SECURED_HUB, publicIpCount: 1 },
      }),
      ctx,
    );
    expect(errors.some((e) => e.includes('already has a firewall'))).toBe(true);
  });

  it('validates new-VNet requests against the resource group list', () => {
    const errors = validateDeployRequest(
      request({
        target: newVnet({ createResourceGroup: true, vnetName: 'vnet-new' }),
      }),
      ctx,
    );
    expect(errors).toContain('Resource group "rg-hub" already exists.');
  });

  it('rejects an existing VNet or hub in a different region than the firewall', () => {
    const vnetErrors = validateDeployRequest(
      request({ location: 'westeurope' }),
      ctx,
    );
    expect(vnetErrors.some((e) => e.includes('same region as its VNet'))).toBe(
      true,
    );

    const hubErrors = validateDeployRequest(
      request({
        location: 'westeurope',
        target: { kind: 'hub', hubId: HUB, publicIpCount: 1 },
      }),
      ctx,
    );
    expect(hubErrors.some((e) => e.includes('same region as its hub'))).toBe(
      true,
    );
  });

  it('rejects a firewall region where Azure Firewall is unavailable', () => {
    expect(validateDeployRequest(request({ location: 'mars' }), ctx)).toContain(
      'Choose a region where Azure Firewall is available.',
    );
  });

  it('lets the VNet and policy reuse a resource group the firewall creates', () => {
    const r = request({
      resourceGroup: 'rg-new',
      createResourceGroup: true,
      target: newVnet({ resourceGroup: 'RG-NEW', createResourceGroup: true }),
      policy: newPolicy({ resourceGroup: 'rg-new' }),
    });
    expect(validateDeployRequest(r, ctx)).toEqual([]);
    expect(buildFirewallTemplate(r, ctx).newResourceGroups).toEqual(['rg-new']);
  });

  it('reports a missing resource group for the policy', () => {
    const errors = validateDeployRequest(
      request({ policy: newPolicy({ resourceGroup: 'rg-missing' }) }),
      ctx,
    );
    expect(errors).toContain('Resource group "rg-missing" was not found.');
  });

  it('rejects a new policy name already used in its resource group', () => {
    const errors = validateDeployRequest(
      request({
        policy: newPolicy({ name: 'FP-STD', resourceGroup: 'rg-pol' }),
      }),
      ctx,
    );
    expect(errors).toContain(
      'A policy named "FP-STD" already exists in rg-pol.',
    );
  });
});

describe('availability zones and names', () => {
  const zoned: DeployContext = {
    ...ctx,
    locationNames: { eastus: 'East US', northcentralus: 'North Central US' },
    locationZones: { eastus: ['1', '2', '3'] },
  };

  it('accepts zones the region supports', () => {
    expect(
      validateDeployRequest(request({ zones: ['1', '3'] }), zoned),
    ).toEqual([]);
  });

  it('rejects zones in a region without availability zones', () => {
    const errors = validateDeployRequest(
      request({
        zones: ['1'],
        location: 'northcentralus',
        target: newVnet(),
      }),
      { ...zoned, locations: ['eastus', 'northcentralus'] },
    );
    expect(errors).toContain(
      'North Central US has no availability zones. Clear the zone selection or choose a region with zones.',
    );
  });

  it('does not check zones when Azure gave no zone data', () => {
    expect(validateDeployRequest(request({ zones: ['1'] }), ctx)).toEqual([]);
  });

  it('rejects a new VNet name that already exists in the resource group', () => {
    const errors = validateDeployRequest(
      request({ target: newVnet({ vnetName: 'VNET-HUB' }) }),
      ctx,
    );
    expect(errors.some((e) => e.includes('already exists in rg-hub'))).toBe(
      true,
    );
  });
});

describe('buildFirewallTemplate', () => {
  it('creates the missing subnet, a public IP and a VNet-mode firewall in the VNet resource group', () => {
    const plan = buildFirewallTemplate(request({ zones: ['1', '2'] }), ctx);
    expect(plan.resourceGroup).toBe('rg-hub');
    expect(plan.location).toBe('eastus');
    expect(plan.firewallId).toBe(
      `${RG}/rg-hub/providers/Microsoft.Network/azureFirewalls/fw-hub`,
    );

    const res = plan.template.resources as Res[];
    expect(res.map((r) => r.type)).toEqual([
      'Microsoft.Network/virtualNetworks/subnets',
      'Microsoft.Network/publicIPAddresses',
      'Microsoft.Network/azureFirewalls',
    ]);
    const fw = res[2];
    expect(fw.properties.sku).toEqual({ name: 'AZFW_VNet', tier: 'Standard' });
    expect(fw.properties.firewallPolicy.id).toBe(STD_POLICY);
    expect(fw.zones).toEqual(['1', '2']);
    expect(fw.dependsOn).toHaveLength(2);
    expect(fw.properties.managementIpConfiguration).toBeUndefined();
  });

  it('adds a management subnet, IP and configuration when requested', () => {
    const r = request({
      managementNic: true,
      target: {
        kind: 'vnet-existing',
        vnetId: VNET,
        subnetPrefix: '10.0.1.0/26',
        managementSubnetPrefix: '10.0.1.64/26',
      },
    });
    const res = resources(r);
    const mgmtSubnet = res.find(
      (x) => x.name === 'vnet-hub/AzureFirewallManagementSubnet',
    )!;
    expect(mgmtSubnet.dependsOn).toEqual([
      expect.stringContaining('/subnets/AzureFirewallSubnet'),
    ]);
    expect(res.some((x) => x.name === 'fw-hub-mgmt-pip')).toBe(true);
    expect(firewallOf(r).properties.managementIpConfiguration).toBeDefined();
  });

  it('creates a new policy that inherits a parent policy', () => {
    const r = request({
      policy: newPolicy({
        name: 'fp-child',
        threatIntelMode: 'Deny',
        basePolicyId: STD_POLICY,
      }),
    });
    const policy = resources(r).find(
      (x) => x.type === 'Microsoft.Network/firewallPolicies',
    )!;
    expect(policy.properties).toEqual({
      sku: { tier: 'Standard' },
      threatIntelMode: 'Deny',
      basePolicy: { id: STD_POLICY },
    });
    expect(firewallOf(r).properties.firewallPolicy.id).toBe(
      `${RG}/rg-hub/providers/Microsoft.Network/firewallPolicies/fp-child`,
    );
  });

  it('builds a hub firewall without VNet resources', () => {
    const r = request({
      target: { kind: 'hub', hubId: HUB, publicIpCount: 2 },
    });
    const res = resources(r);
    expect(res.map((x) => x.type)).toEqual([
      'Microsoft.Network/azureFirewalls',
    ]);
    expect(res[0].properties).toMatchObject({
      sku: { name: 'AZFW_Hub', tier: 'Standard' },
      virtualHub: { id: HUB },
      hubIPAddresses: { publicIPs: { count: 2 } },
    });
    expect(buildFirewallTemplate(r, ctx).resourceGroup).toBe('rg-hub');
  });

  it('creates a new VNet with the firewall subnet inline in the firewall resource group', () => {
    const r = request({ target: newVnet() });
    const vnet = resources(r).find(
      (x) => x.type === 'Microsoft.Network/virtualNetworks',
    )!;
    expect(vnet.properties.subnets).toEqual([
      {
        name: 'AzureFirewallSubnet',
        properties: { addressPrefix: '10.50.0.0/26' },
      },
    ]);
    expect(buildFirewallTemplate(r, ctx).location).toBe('eastus');
  });

  it('puts a VNet and policy in other resource groups via nested deployments', () => {
    const r = request({
      location: 'westeurope',
      target: newVnet({ resourceGroup: 'rg-net', createResourceGroup: true }),
      policy: newPolicy({ resourceGroup: 'rg-pol' }),
    });
    expect(validateDeployRequest(r, ctx)).toEqual([]);
    const plan = buildFirewallTemplate(r, ctx, 'ezazfw-fw-hub-1');
    expect(plan.newResourceGroups).toEqual(['rg-net']);
    const res = plan.template.resources as (Res & {
      resourceGroup?: string;
      location?: string;
    })[];
    const nested = res.filter(
      (x) => x.type === 'Microsoft.Resources/deployments',
    );
    expect(nested.map((x) => [x.name, x.resourceGroup])).toEqual([
      ['ezazfw-fw-hub-1-vnet', 'rg-net'],
      ['ezazfw-fw-hub-1-policy', 'rg-pol'],
    ]);
    const innerVnet = nested[0].properties.template.resources[0];
    expect(innerVnet.type).toBe('Microsoft.Network/virtualNetworks');
    expect(innerVnet.location).toBe('westeurope');

    const fw = res.find((x) => x.type === 'Microsoft.Network/azureFirewalls')!;
    expect(fw.dependsOn).toEqual(
      expect.arrayContaining([
        `${RG}/rg-net/providers/Microsoft.Resources/deployments/ezazfw-fw-hub-1-vnet`,
        `${RG}/rg-pol/providers/Microsoft.Resources/deployments/ezazfw-fw-hub-1-policy`,
      ]),
    );
    expect(fw.properties.ipConfigurations[0].properties.subnet.id).toBe(
      `${RG}/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-hub-x/subnets/AzureFirewallSubnet`,
    );
    expect(fw.properties.firewallPolicy.id).toBe(
      `${RG}/rg-pol/providers/Microsoft.Network/firewallPolicies/fp-new`,
    );
    expect(plan.firewallId).toBe(
      `${RG}/rg-hub/providers/Microsoft.Network/azureFirewalls/fw-hub`,
    );
  });

  it("creates missing subnets in an existing VNet's own resource group", () => {
    const r = request({ resourceGroup: 'rg-pol' });
    const res = resources(r);
    const nested = res.find(
      (x) => x.type === 'Microsoft.Resources/deployments',
    ) as Res & { resourceGroup: string };
    expect(nested.resourceGroup).toBe('rg-hub');
    expect(nested.properties.template.resources[0].name).toBe(
      'vnet-hub/AzureFirewallSubnet',
    );
    expect(
      res.some((x) => x.type === 'Microsoft.Network/virtualNetworks/subnets'),
    ).toBe(false);
  });

  it('always tags resources with createdBy tag, keeping user tags', () => {
    const fw = firewallOf(request({ tags: { env: 'prod' } })) as Res & {
      tags: Record<string, string>;
    };
    expect(fw.tags).toEqual({ createdBy: 'EZ AzFW Manager', env: 'prod' });
  });
});
