import { cidrContains, cidrError, cidrOverlaps, parseCidr } from './cidr';
import { MAX_TAGS, NAME_RULES, nameError, tagError } from './naming';
import { parseResourceId, sameResourceId } from './resourceId';

export type FirewallTier = 'Basic' | 'Standard' | 'Premium';
export type ThreatIntelMode = 'Off' | 'Alert' | 'Deny';

/** createdBy tag value on resources the deploy wizard creates. */
export const APP_TAG = 'EZ AzFW Manager';
export const FIREWALL_SUBNET = 'AzureFirewallSubnet';
export const MANAGEMENT_SUBNET = 'AzureFirewallManagementSubnet';
export const NETWORK_API_VERSION = '2024-05-01';
const DEPLOYMENTS_API_VERSION = '2022-09-01';
const TEMPLATE_SCHEMA =
  'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#';
/** Azure requires firewall subnets to be at least /26. */
export const MIN_SUBNET_BITS = 26;

export interface SubscriptionInfo {
  subscriptionId: string;
  name: string;
}

export interface VnetInfo {
  id: string;
  name: string;
  resourceGroup: string;
  location: string;
  addressPrefixes: string[];
  subnets: { name: string; prefix?: string }[];
}

export interface HubInfo {
  id: string;
  name: string;
  resourceGroup: string;
  location: string;
  virtualWanName?: string;
  firewallId?: string;
}

export interface PolicyInfo {
  id: string;
  name: string;
  resourceGroup: string;
  location: string;
  tier: FirewallTier;
}

export interface NetworkAvailability {
  /** Whether the subscription can use Microsoft.Network (Azure networking) at all. */
  state:
    | 'registered'
    | 'registering'
    | 'not-registered'
    | 'blocked'
    | 'unknown';
  message?: string;
}

export interface DeployContext {
  subscriptionId: string;
  network: NetworkAvailability;
  resourceGroups: { name: string; location: string }[];
  vnets: VnetInfo[];
  hubs: HubInfo[];
  policies: PolicyInfo[];
  /** Regions where Azure Firewall is available, e.g. "eastus". */
  locations: string[];
  /** Display names for regions, e.g. { eastus: "East US" }. */
  locationNames?: Record<string, string>;
  /**
   * Availability zones Azure Firewall supports per region, e.g. { eastus: ["1","2","3"] }.
   * A region missing from the map has no zones.
   */
  locationZones?: Record<string, string[]>;
}

export type DeployTarget =
  | {
      kind: 'vnet-existing';
      vnetId: string;
      subnetPrefix?: string;
      managementSubnetPrefix?: string;
    }
  | {
      kind: 'vnet-new';
      /** Defaults to the firewall's resource group; the VNet always uses the firewall's region. */
      resourceGroup: string;
      createResourceGroup: boolean;
      vnetName: string;
      addressSpace: string;
      subnetPrefix: string;
      managementSubnetPrefix?: string;
    }
  | { kind: 'hub'; hubId: string; publicIpCount: number };

export type DeployPolicy =
  | { kind: 'existing'; policyId: string }
  | {
      kind: 'new';
      name: string;
      threatIntelMode: ThreatIntelMode;
      basePolicyId?: string;
      /** Defaults to the firewall's resource group; the policy uses the firewall's region. */
      resourceGroup: string;
      createResourceGroup: boolean;
    };

export interface DeployRequest {
  subscriptionId: string;
  name: string;
  tier: FirewallTier;
  /** Resource group for the firewall and its public IPs. */
  resourceGroup: string;
  createResourceGroup: boolean;
  /** Region for the firewall and everything created with it, e.g. "eastus". */
  location: string;
  zones: string[];
  tags: Record<string, string>;
  /** Adds a management NIC (required for Basic and forced tunneling). VNet targets only. */
  managementNic: boolean;
  target: DeployTarget;
  policy: DeployPolicy;
  addToManaged: boolean;
}

export interface DeployOperation {
  resourceType: string;
  resourceName: string;
  state: string;
  error?: string;
}

export type DeployPhase =
  | 'preparing'
  | 'validating'
  | 'deploying'
  | 'succeeded'
  | 'failed';

export interface DeployProgress {
  firewallName: string;
  phase: DeployPhase;
  message: string;
  startedAt: string;
  operations: DeployOperation[];
  deploymentId?: string;
  firewallId?: string;
  error?: string;
}

export const TIERS: FirewallTier[] = ['Basic', 'Standard', 'Premium'];

/** Public IP names the wizard derives from the firewall name (VNet firewalls only). */
export const publicIpNames = (name: string, managementNic: boolean) =>
  managementNic ? [`${name}-pip`, `${name}-mgmt-pip`] : [`${name}-pip`];

/** Problems with the firewall name, including the public IP names derived from it. */
export function firewallNameError(
  name: string,
  isVnet: boolean,
  managementNic: boolean,
): string | undefined {
  const own = nameError('firewall', name);
  if (own || !isVnet) return own;
  for (const pip of publicIpNames(name, managementNic)) {
    if (nameError('publicIp', pip)) {
      const suffix = pip.slice(name.length);
      const max = NAME_RULES.publicIp.max - suffix.length;
      return `Firewall name must be at most ${max} characters: its public IP is named "<name>${suffix}" and Azure allows ${NAME_RULES.publicIp.max}.`;
    }
  }
  return undefined;
}

/** Problems with a new VNet's address space, including room for the firewall subnets. */
export function addressSpaceError(
  space: string,
  managementNic: boolean,
): string | undefined {
  const invalid = cidrError(space, 'VNet address space');
  if (invalid) return invalid;
  const need = managementNic ? MIN_SUBNET_BITS - 1 : MIN_SUBNET_BITS;
  const bits = parseCidr(space)!.bits;
  if (bits > need) {
    return `VNet address space: /${bits} is too small. ${FIREWALL_SUBNET} needs a /${MIN_SUBNET_BITS}${managementNic ? ` and ${MANAGEMENT_SUBNET} another /${MIN_SUBNET_BITS}` : ''}, so use /${need} or larger.`;
  }
  return undefined;
}

/** Region names compare case- and space-insensitively ("East US" equals "eastus"). */
export const sameLocation = (a?: string, b?: string) =>
  !!a && !!b && normalizeLocation(a) === normalizeLocation(b);

export const normalizeLocation = (l: string) =>
  l.toLowerCase().replace(/\s+/g, '');

const sameName = (a?: string, b?: string) =>
  !!a && !!b && a.toLowerCase() === b.toLowerCase();

/** Every resource group the request places resources in, and whether the wizard creates it. */
function groupChoices(req: DeployRequest, ctx: DeployContext) {
  const choices: { label: string; name: string; create: boolean }[] = [
    {
      label: 'Firewall resource group',
      name: req.resourceGroup,
      create: req.createResourceGroup,
    },
  ];
  if (req.target?.kind === 'vnet-new') {
    choices.push({
      label: 'VNet resource group',
      name: req.target.resourceGroup,
      create: req.target.createResourceGroup,
    });
  }
  if (req.policy?.kind === 'new') {
    choices.push({
      label: 'Policy resource group',
      name: req.policy.resourceGroup,
      create: req.policy.createResourceGroup,
    });
  }
  return choices.map((c) => ({
    ...c,
    exists: ctx.resourceGroups.some((g) => sameName(g.name, c.name)),
  }));
}

/** Resource groups that must be created before deploying (deduplicated). */
export function newResourceGroups(
  req: DeployRequest,
  ctx: DeployContext,
): string[] {
  const out: string[] = [];
  for (const c of groupChoices(req, ctx)) {
    if (c.create && !c.exists && !out.some((n) => sameName(n, c.name)))
      out.push(c.name);
  }
  return out;
}

/** Resolves the network the firewall attaches to (existing VNet or hub). */
export function resolveNetwork(req: DeployRequest, ctx: DeployContext) {
  const t = req.target;
  if (t?.kind === 'vnet-existing')
    return { vnet: ctx.vnets.find((v) => sameResourceId(v.id, t.vnetId)) };
  if (t?.kind === 'hub')
    return { hub: ctx.hubs.find((h) => sameResourceId(h.id, t.hubId)) };
  return {};
}

/** Every problem with a firewall subnet prefix; empty when it's valid. */
export function subnetErrors(
  label: string,
  prefix: string | undefined,
  addressSpaces: string[],
  others: { name: string; prefix: string }[] = [],
): string[] {
  const errors: string[] = [];
  checkSubnet(label, prefix, addressSpaces, others, errors);
  return errors;
}

function checkSubnet(
  label: string,
  prefix: string | undefined,
  addressSpaces: string[],
  others: { name: string; prefix: string }[],
  errors: string[],
) {
  const invalid = cidrError(prefix ?? '', label);
  if (invalid) {
    errors.push(invalid);
    return;
  }
  const p = prefix!.trim();
  const bits = parseCidr(p)!.bits;
  if (bits > MIN_SUBNET_BITS)
    errors.push(
      `${label}: /${bits} is too small. Azure Firewall needs /${MIN_SUBNET_BITS} or larger.`,
    );
  if (!addressSpaces.some((s) => cidrContains(s, p))) {
    errors.push(
      `${label}: ${p} doesn't fit inside the VNet address space (${addressSpaces.join(', ')}).`,
    );
  }
  const clash = others.find((o) => cidrOverlaps(o.prefix, p));
  if (clash)
    errors.push(`${label}: ${p} overlaps ${clash.name} (${clash.prefix}).`);
}

/** Zones Azure Firewall supports in a region; undefined when the app couldn't find out. */
export function supportedZones(
  location: string | undefined,
  ctx: DeployContext,
): string[] | undefined {
  if (!location || !ctx.locationZones) return undefined;
  return ctx.locationZones[normalizeLocation(location)] ?? [];
}

function checkZones(
  zones: string[],
  location: string | undefined,
  ctx: DeployContext,
): string | undefined {
  if (!zones?.length) return undefined;
  const supported = supportedZones(location, ctx);
  if (!supported) return undefined;
  const unsupported = zones.filter((z) => !supported.includes(z));
  if (!unsupported.length) return undefined;
  const region = ctx.locationNames?.[normalizeLocation(location!)] ?? location;
  return supported.length
    ? `${region} supports availability zones ${supported.join(', ')} for Azure Firewall, not ${unsupported.join(', ')}.`
    : `${region} has no availability zones. Clear the zone selection or choose a region with zones.`;
}

export function validateDeployRequest(
  req: DeployRequest,
  ctx: DeployContext,
): string[] {
  const errors: string[] = [];
  if (ctx.network.state !== 'registered') {
    errors.push(
      ctx.network.message ??
        "Azure networking (Microsoft.Network) isn't available in this subscription.",
    );
  }
  const firewallError = firewallNameError(
    req.name ?? '',
    req.target?.kind !== 'hub',
    !!req.managementNic,
  );
  if (firewallError) errors.push(firewallError);
  if (!TIERS.includes(req.tier)) errors.push('Choose a firewall tier.');
  if (
    !Array.isArray(req.zones) ||
    req.zones.some((z) => !['1', '2', '3'].includes(z))
  ) {
    errors.push('Availability zones must be 1, 2 and/or 3.');
  }

  const tagEntries = Object.entries(req.tags ?? {});
  if (tagEntries.length > MAX_TAGS)
    errors.push(`At most ${MAX_TAGS} tags are allowed.`);
  for (const [k, v] of tagEntries) {
    const tagProblem = tagError(k, typeof v === 'string' ? v : '');
    if (tagProblem) errors.push(tagProblem);
  }

  const regionName = (l: string) =>
    ctx.locationNames?.[normalizeLocation(l)] ?? l;
  const location = req.location ?? '';
  const locationValid = ctx.locations.some((l) => sameLocation(l, location));
  if (!locationValid)
    errors.push('Choose a region where Azure Firewall is available.');

  const groups = groupChoices(req, ctx);
  for (const g of groups) {
    const rgProblem = nameError('resourceGroup', g.name, g.label);
    if (rgProblem) {
      errors.push(rgProblem);
      continue;
    }
    // A group created for one resource can be reused by the others in the same deployment.
    const createdHere = groups.some(
      (o) => o.create && sameName(o.name, g.name),
    );
    if (g.create && g.exists)
      errors.push(`Resource group "${g.name}" already exists.`);
    else if (!g.create && !g.exists && !createdHere)
      errors.push(`Resource group "${g.name}" was not found.`);
  }

  const zoneError = locationValid
    ? checkZones(req.zones, location, ctx)
    : undefined;
  if (zoneError) errors.push(zoneError);
  const network = resolveNetwork(req, ctx);
  const t = req.target;
  if (t?.kind === 'vnet-existing') {
    const vnet = network.vnet;
    if (!vnet) {
      errors.push('Select a virtual network.');
    } else {
      if (locationValid && !sameLocation(vnet.location, location)) {
        errors.push(
          `VNet ${vnet.name} is in ${regionName(vnet.location)}; the firewall must be in the same region as its VNet (${regionName(location)}).`,
        );
      }
      const used = vnet.subnets
        .filter((s) => s.prefix)
        .map((s) => ({ name: s.name, prefix: s.prefix! }));
      const fw = vnet.subnets.find((s) => s.name === FIREWALL_SUBNET);
      if (fw) {
        const bits = fw.prefix ? parseCidr(fw.prefix)?.bits : undefined;
        if (bits && bits > MIN_SUBNET_BITS)
          errors.push(
            `${FIREWALL_SUBNET} in ${vnet.name} is smaller than /${MIN_SUBNET_BITS}.`,
          );
      } else {
        checkSubnet(
          FIREWALL_SUBNET,
          t.subnetPrefix,
          vnet.addressPrefixes,
          used,
          errors,
        );
      }
      if (
        req.managementNic &&
        !vnet.subnets.some((s) => s.name === MANAGEMENT_SUBNET)
      ) {
        checkSubnet(
          MANAGEMENT_SUBNET,
          t.managementSubnetPrefix,
          vnet.addressPrefixes,
          [
            ...used,
            ...(fw || !t.subnetPrefix
              ? []
              : [{ name: FIREWALL_SUBNET, prefix: t.subnetPrefix }]),
          ],
          errors,
        );
      }
    }
  } else if (t?.kind === 'vnet-new') {
    const vnetProblem = nameError('vnet', t.vnetName);
    if (vnetProblem) errors.push(vnetProblem);
    if (
      ctx.vnets.some(
        (v) =>
          v.name.toLowerCase() === t.vnetName?.toLowerCase() &&
          v.resourceGroup.toLowerCase() === t.resourceGroup?.toLowerCase(),
      )
    ) {
      errors.push(
        `A virtual network named "${t.vnetName}" already exists in ${t.resourceGroup}. Choose another name, or use "Existing hub VNet".`,
      );
    }
    const spaceProblem = addressSpaceError(
      t.addressSpace ?? '',
      !!req.managementNic,
    );
    if (spaceProblem) {
      errors.push(spaceProblem);
    } else {
      const space = t.addressSpace.trim();
      checkSubnet(FIREWALL_SUBNET, t.subnetPrefix, [space], [], errors);
      if (req.managementNic) {
        checkSubnet(
          MANAGEMENT_SUBNET,
          t.managementSubnetPrefix,
          [space],
          t.subnetPrefix
            ? [{ name: FIREWALL_SUBNET, prefix: t.subnetPrefix }]
            : [],
          errors,
        );
      }
    }
  } else if (t?.kind === 'hub') {
    const hub = network.hub;
    if (!hub) errors.push('Select a virtual hub.');
    else if (hub.firewallId)
      errors.push(`Virtual hub ${hub.name} already has a firewall.`);
    else if (locationValid && !sameLocation(hub.location, location)) {
      errors.push(
        `Virtual hub ${hub.name} is in ${regionName(hub.location)}; the firewall must be in the same region as its hub (${regionName(location)}).`,
      );
    }
    if (
      !Number.isInteger(t.publicIpCount) ||
      t.publicIpCount < 1 ||
      t.publicIpCount > 250
    ) {
      errors.push('Public IP count must be between 1 and 250.');
    }
  } else {
    errors.push('Choose where to deploy the firewall.');
  }

  if (req.tier === 'Basic' && t?.kind !== 'hub' && !req.managementNic) {
    errors.push('Basic firewalls in a VNet require a management NIC.');
  }

  const p = req.policy;
  if (p?.kind === 'existing') {
    const policy = ctx.policies.find((x) => sameResourceId(x.id, p.policyId));
    if (!policy) errors.push('Select a firewall policy.');
    else if (policy.tier !== req.tier) {
      errors.push(
        `Policy ${policy.name} is ${policy.tier}; a ${req.tier} firewall needs a ${req.tier} policy.`,
      );
    }
  } else if (p?.kind === 'new') {
    const policyProblem = nameError('policy', p.name);
    if (policyProblem) errors.push(policyProblem);
    if (!['Off', 'Alert', 'Deny'].includes(p.threatIntelMode))
      errors.push('Choose a threat intelligence mode.');
    if (req.tier === 'Basic' && p.threatIntelMode !== 'Alert') {
      errors.push(
        'Basic policies support threat intelligence in Alert mode only.',
      );
    }
    if (p.basePolicyId) {
      const base = ctx.policies.find((x) =>
        sameResourceId(x.id, p.basePolicyId),
      );
      if (!base) errors.push('The selected parent policy was not found.');
      else if (base.tier !== req.tier)
        errors.push(`Parent policy ${base.name} must also be ${req.tier}.`);
      // The new policy is created in the firewall's region, and a parent must share its region.
      else if (locationValid && !sameLocation(base.location, location))
        errors.push(
          `Parent policy ${base.name} is in ${regionName(base.location)}; a child policy must be in the same region as its parent (${regionName(location)}).`,
        );
    }
    if (
      ctx.policies.some(
        (x) =>
          sameName(x.name, p.name) &&
          sameName(x.resourceGroup, p.resourceGroup),
      )
    ) {
      errors.push(
        `A policy named "${p.name}" already exists in ${p.resourceGroup}.`,
      );
    }
  } else {
    errors.push('Choose a firewall policy option.');
  }
  return errors;
}

/**
 * Builds an ARM template scoped to the firewall's resource group. Resources that belong in another
 * resource group (a new VNet, subnets on an existing VNet elsewhere, or a new policy) go into
 * nested deployments targeting that group.
 */
export function buildFirewallTemplate(
  req: DeployRequest,
  ctx: DeployContext,
  deploymentName = 'ezazfw',
) {
  const { resourceGroup, location } = req;
  const sub = req.subscriptionId;
  const rgId = (rg: string) => `/subscriptions/${sub}/resourceGroups/${rg}`;
  const net = (rg: string, type: string, ...names: string[]) =>
    `${rgId(rg)}/providers/Microsoft.Network/${type}/${names.join('/')}`;

  const tags = { createdBy: APP_TAG, ...req.tags };
  const zones = req.zones.length ? req.zones : undefined;
  const resources: Record<string, unknown>[] = [];
  const firewallDependsOn: string[] = [];
  const t = req.target;
  const network = resolveNetwork(req, ctx);

  /** Adds resources to `rg`: directly when it's the firewall's group, else via a nested deployment. */
  const place = (
    rg: string,
    suffix: string,
    inner: Record<string, unknown>[],
    innerIds: string[],
  ) => {
    if (!inner.length) return;
    if (sameName(rg, resourceGroup)) {
      resources.push(...inner);
      firewallDependsOn.push(...innerIds);
      return;
    }
    const name = `${deploymentName.slice(0, 56)}-${suffix}`;
    resources.push({
      type: 'Microsoft.Resources/deployments',
      apiVersion: DEPLOYMENTS_API_VERSION,
      name,
      resourceGroup: rg,
      properties: {
        mode: 'Incremental',
        template: {
          $schema: TEMPLATE_SCHEMA,
          contentVersion: '1.0.0.0',
          resources: inner,
        },
      },
    });
    firewallDependsOn.push(
      `${rgId(rg)}/providers/Microsoft.Resources/deployments/${name}`,
    );
  };

  let firewallSubnetId: string | undefined;
  let managementSubnetId: string | undefined;

  if (t.kind === 'vnet-new') {
    const subnets = [
      { name: FIREWALL_SUBNET, properties: { addressPrefix: t.subnetPrefix } },
    ];
    if (req.managementNic) {
      subnets.push({
        name: MANAGEMENT_SUBNET,
        properties: { addressPrefix: t.managementSubnetPrefix! },
      });
    }
    const vnetId = net(t.resourceGroup, 'virtualNetworks', t.vnetName);
    place(
      t.resourceGroup,
      'vnet',
      [
        {
          type: 'Microsoft.Network/virtualNetworks',
          apiVersion: NETWORK_API_VERSION,
          name: t.vnetName,
          location,
          tags,
          properties: {
            addressSpace: { addressPrefixes: [t.addressSpace] },
            subnets,
          },
        },
      ],
      [vnetId],
    );
    firewallSubnetId = `${vnetId}/subnets/${FIREWALL_SUBNET}`;
    managementSubnetId = `${vnetId}/subnets/${MANAGEMENT_SUBNET}`;
  } else if (t.kind === 'vnet-existing') {
    const vnet = network.vnet;
    const vnetName = parseResourceId(t.vnetId).name;
    const vnetRg =
      vnet?.resourceGroup ?? parseResourceId(t.vnetId).resourceGroup;
    const vnetId = net(vnetRg, 'virtualNetworks', vnetName);
    firewallSubnetId = `${vnetId}/subnets/${FIREWALL_SUBNET}`;
    managementSubnetId = `${vnetId}/subnets/${MANAGEMENT_SUBNET}`;
    const inner: Record<string, unknown>[] = [];
    const innerIds: string[] = [];
    let previousSubnet: string | undefined;
    if (!vnet?.subnets.some((s) => s.name === FIREWALL_SUBNET)) {
      inner.push({
        type: 'Microsoft.Network/virtualNetworks/subnets',
        apiVersion: NETWORK_API_VERSION,
        name: `${vnetName}/${FIREWALL_SUBNET}`,
        properties: { addressPrefix: t.subnetPrefix },
      });
      innerIds.push(firewallSubnetId);
      previousSubnet = firewallSubnetId;
    }
    if (
      req.managementNic &&
      !vnet?.subnets.some((s) => s.name === MANAGEMENT_SUBNET)
    ) {
      // Subnets on one VNet must be created one after another.
      inner.push({
        type: 'Microsoft.Network/virtualNetworks/subnets',
        apiVersion: NETWORK_API_VERSION,
        name: `${vnetName}/${MANAGEMENT_SUBNET}`,
        dependsOn: previousSubnet ? [previousSubnet] : [],
        properties: { addressPrefix: t.managementSubnetPrefix },
      });
      innerIds.push(managementSubnetId);
    }
    place(vnetRg, 'subnets', inner, innerIds);
  }

  const publicIp = (name: string) => {
    resources.push({
      type: 'Microsoft.Network/publicIPAddresses',
      apiVersion: NETWORK_API_VERSION,
      name,
      location,
      tags,
      zones,
      sku: { name: 'Standard', tier: 'Regional' },
      properties: {
        publicIPAllocationMethod: 'Static',
        publicIPAddressVersion: 'IPv4',
      },
    });
    const id = net(resourceGroup, 'publicIPAddresses', name);
    firewallDependsOn.push(id);
    return id;
  };

  let policyId: string;
  if (req.policy.kind === 'new') {
    const p = req.policy;
    policyId = net(p.resourceGroup, 'firewallPolicies', p.name);
    place(
      p.resourceGroup,
      'policy',
      [
        {
          type: 'Microsoft.Network/firewallPolicies',
          apiVersion: NETWORK_API_VERSION,
          name: p.name,
          location,
          tags,
          properties: {
            sku: { tier: req.tier },
            threatIntelMode: p.threatIntelMode,
            ...(p.basePolicyId ? { basePolicy: { id: p.basePolicyId } } : {}),
          },
        },
      ],
      [policyId],
    );
  } else {
    policyId = req.policy.policyId;
  }

  const firewallProps: Record<string, unknown> = {
    sku: { name: t.kind === 'hub' ? 'AZFW_Hub' : 'AZFW_VNet', tier: req.tier },
    firewallPolicy: { id: policyId },
  };
  if (t.kind === 'hub') {
    firewallProps.virtualHub = { id: t.hubId };
    firewallProps.hubIPAddresses = { publicIPs: { count: t.publicIpCount } };
  } else {
    firewallProps.ipConfigurations = [
      {
        name: 'ipconfig1',
        properties: {
          subnet: { id: firewallSubnetId },
          publicIPAddress: { id: publicIp(`${req.name}-pip`) },
        },
      },
    ];
    if (req.managementNic) {
      firewallProps.managementIpConfiguration = {
        name: 'mgmt-ipconfig',
        properties: {
          subnet: { id: managementSubnetId },
          publicIPAddress: { id: publicIp(`${req.name}-mgmt-pip`) },
        },
      };
    }
  }

  resources.push({
    type: 'Microsoft.Network/azureFirewalls',
    apiVersion: NETWORK_API_VERSION,
    name: req.name,
    location,
    tags,
    zones,
    dependsOn: firewallDependsOn,
    properties: firewallProps,
  });

  return {
    resourceGroup,
    location,
    newResourceGroups: newResourceGroups(req, ctx),
    firewallId: net(resourceGroup, 'azureFirewalls', req.name),
    template: {
      $schema: TEMPLATE_SCHEMA,
      contentVersion: '1.0.0.0',
      resources,
    },
  };
}
