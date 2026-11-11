import {
  graphQuery,
  network,
  describeAzureError,
  validatePolicyMode,
} from './azure';
import type { ThreatIntelMode } from '../shared/deploy';
import { armList, armRequest, armWrite } from './arm';
import { addressContains } from '../shared/search';
import { loadState, updateState } from './store';
import { parseResourceId, sameResourceId } from '../shared/resourceId';
import { isThreatIntelMode } from '../shared/policyMode';
import {
  allocationErrors,
  allocationSignature,
  firewallSettingsErrors,
  mergeSettings,
  policySettingsErrors,
  readPolicySettings,
  settingsObject,
  FIREWALL_SETTING_KEYS,
  POLICY_SETTING_KEYS,
  type AllocationIpConfiguration,
  type FirewallAllocation,
  type FirewallConfiguration,
  type FirewallSettingsView,
  type PolicyAdvancedSettings,
  type PolicySettingsView,
  type ResourceOption,
} from '../shared/resourceSettings';

const NETWORK_API = '2026-03-01';
const MAINTENANCE_API = '2023-09-01-preview';
const ROUTE_SERVER_KEY = 'Network.RouteServerInfo.RouteServerID';
const normalize = (value: string) => value.toLowerCase().replace(/\s/g, '');

interface ArmResource {
  id: string;
  name: string;
  location: string;
  properties: Record<string, unknown>;
  etag?: string;
  [key: string]: unknown;
}

function objectOrEmpty(value: unknown, label: string) {
  return value == null ? {} : settingsObject(value, label);
}
function string(value: unknown, label: string, empty = ''): string {
  if (value == null) return empty;
  if (typeof value !== 'string')
    throw new Error(`Invalid ${label} returned by Azure.`);
  return value;
}
function array(value: unknown, label: string): unknown[] {
  if (value == null) return [];
  if (!Array.isArray(value))
    throw new Error(`Invalid ${label} returned by Azure.`);
  return value;
}
function ref(value: unknown, label: string): string {
  return string(objectOrEmpty(value, label).id, label);
}

async function resource(
  id: string,
  version = NETWORK_API,
): Promise<ArmResource> {
  const { data } = await armRequest<unknown>(`${id}?api-version=${version}`);
  const raw = settingsObject(data, 'resource');
  if (
    typeof raw.id !== 'string' ||
    !sameResourceId(raw.id, id) ||
    typeof raw.name !== 'string' ||
    typeof raw.location !== 'string'
  )
    throw new Error('Azure returned an incomplete or unexpected resource.');
  return {
    ...raw,
    id: raw.id,
    name: raw.name,
    location: raw.location,
    properties: settingsObject(raw.properties, 'resource properties'),
    etag: typeof raw.etag === 'string' ? raw.etag : undefined,
  };
}

function writable(raw: ArmResource): Record<string, unknown> {
  const result = structuredClone(raw);
  for (const key of ['id', 'type', 'etag', 'systemData']) delete result[key];
  for (const key of [
    'provisioningState',
    'firewalls',
    'childPolicies',
    'ruleCollectionGroups',
    'kubeSelectorGroups',
    'size',
    'ipGroups',
    'afcConfiguration',
    'afcManaged',
  ])
    delete result.properties[key];
  const configs = [
    ...(Array.isArray(result.properties.ipConfigurations)
      ? result.properties.ipConfigurations
      : []),
    ...(result.properties.managementIpConfiguration
      ? [result.properties.managementIpConfiguration]
      : []),
  ];
  for (const config of configs) {
    const item = settingsObject(config, 'IP configuration');
    delete item.etag;
    const properties = settingsObject(
      item.properties,
      'IP configuration properties',
    );
    delete properties.provisioningState;
    delete properties.privateIPAddress;
  }
  if (result.properties.hubIPAddresses) {
    const hub = settingsObject(
      result.properties.hubIPAddresses,
      'hub addresses',
    );
    delete hub.privateIPAddress;
    if (hub.publicIPs)
      delete settingsObject(hub.publicIPs, 'hub public IPs').addresses;
  }
  return result;
}

function ipConfiguration(value: unknown): AllocationIpConfiguration {
  const item = settingsObject(value, 'IP configuration');
  const p = settingsObject(item.properties, 'IP configuration properties');
  const subnetId = ref(p.subnet, 'subnet');
  const publicId = ref(p.publicIPAddress, 'public IP');
  return {
    name: string(item.name, 'IP configuration name'),
    ...(subnetId ? { subnet: { id: subnetId } } : {}),
    ...(publicId ? { publicIPAddress: { id: publicId } } : {}),
  };
}

function allocation(
  raw: ArmResource,
  partial = false,
): FirewallAllocation | undefined {
  const p = raw.properties;
  const sku = string(objectOrEmpty(p.sku, 'firewall SKU').name, 'firewall SKU');
  if (sku !== 'AZFW_VNet' && sku !== 'AZFW_Hub') return undefined;
  const configs = array(p.ipConfigurations, 'IP configurations').map(
    ipConfiguration,
  );
  const hubId = ref(p.virtualHub, 'virtual hub');
  const count = objectOrEmpty(
    objectOrEmpty(p.hubIPAddresses, 'hub addresses').publicIPs,
    'hub public IPs',
  ).count;
  if (
    (sku === 'AZFW_Hub' ? !hubId : !configs.length) &&
    (!partial ||
      sku !== 'AZFW_Hub' ||
      (!configs.some((c) => c.publicIPAddress) && typeof count !== 'number'))
  )
    return undefined;
  return {
    skuName: sku,
    ipConfigurations: configs,
    ...(p.managementIpConfiguration
      ? {
          managementIpConfiguration: ipConfiguration(
            p.managementIpConfiguration,
          ),
        }
      : {}),
    ...(hubId ? { virtualHubId: hubId } : {}),
    ...(typeof count === 'number' ? { publicIpCount: count } : {}),
  };
}

function firewallConfig(raw: ArmResource): FirewallConfiguration {
  const p = raw.properties;
  const sku = string(objectOrEmpty(p.sku, 'firewall SKU').name, 'firewall SKU');
  const state = string(p.provisioningState, 'provisioning state');
  const scale = objectOrEmpty(p.autoscaleConfiguration, 'autoscaling');
  const capacity = (value: unknown) => {
    if (value == null) return null;
    if (typeof value !== 'number' || !Number.isFinite(value))
      throw new Error('Azure returned an invalid capacity.');
    return value;
  };
  const saved = loadState().firewallAllocations?.[raw.id.toLowerCase()];
  const current = allocation(raw);
  const power =
    state.toLowerCase() !== 'succeeded'
      ? 'Unknown'
      : sku === 'AZFW_Hub'
        ? ref(p.virtualHub, 'virtual hub')
          ? 'Running'
          : 'Stopped'
        : sku === 'AZFW_VNet'
          ? array(p.ipConfigurations, 'IP configurations').length
            ? 'Running'
            : 'Stopped'
          : 'Unknown';
  return {
    name: raw.name,
    provisioningState: state,
    privateIp:
      power === 'Running'
        ? string(
            objectOrEmpty(p.hubIPAddresses, 'hub addresses').privateIPAddress,
            'hub private IP',
          ) ||
          array(p.ipConfigurations, 'IP configurations')
            .map((c) =>
              string(
                settingsObject(
                  settingsObject(c, 'IP configuration').properties,
                  'IP properties',
                ).privateIPAddress,
                'private IP',
              ),
            )
            .find(Boolean)
        : undefined,
    routeServerId: string(
      objectOrEmpty(p.additionalProperties, 'additional properties')[
        ROUTE_SERVER_KEY
      ],
      'Route Server association',
    ),
    minCapacity: capacity(scale.minCapacity),
    maxCapacity: capacity(scale.maxCapacity),
    powerState: power,
    allocation: current ?? saved ?? allocation(raw, true),
  };
}

export async function getFirewallConfiguration(
  id: string,
): Promise<FirewallConfiguration> {
  return firewallConfig(await resource(id));
}

async function assignments(id: string) {
  return armList<{
    id: string;
    name: string;
    properties?: { maintenanceConfigurationId?: string };
  }>(
    `${id}/providers/Microsoft.Maintenance/configurationAssignments?api-version=${MAINTENANCE_API}`,
  );
}

export async function getFirewallConfigurationForDraft(
  id: string,
  withMaintenance: boolean,
): Promise<FirewallConfiguration> {
  return (await getFirewallDraftContext(id, withMaintenance)).configuration;
}

export async function getFirewallDraftContext(
  id: string,
  withMaintenance: boolean,
) {
  const raw = await resource(id);
  const value = firewallConfig(raw);
  if (withMaintenance)
    value.maintenanceConfigurationIds = [
      ...new Set(
        (await assignments(id)).map((a) => {
          if (!a.properties?.maintenanceConfigurationId)
            throw new Error(
              'Azure returned an incomplete maintenance assignment.',
            );
          return a.properties.maintenanceConfigurationId;
        }),
      ),
    ].sort();
  return {
    configuration: value,
    policyId: ref(raw.properties.firewallPolicy, 'associated policy'),
  };
}

async function lookup<T>(
  label: string,
  errors: string[],
  load: () => Promise<T>,
  empty: T,
): Promise<T> {
  try {
    return await load();
  } catch (err) {
    errors.push(`${label}: ${describeAzureError(err)}`);
    return empty;
  }
}

interface GraphResource extends ResourceOption {
  properties?: Record<string, unknown>;
  kind?: string;
}
function listResources(type: string, sub?: string) {
  return graphQuery<GraphResource>(
    `resources | where type =~ '${type}' | project id, name, subscriptionId, resourceGroup, location, properties, kind | order by name asc`,
    sub,
  );
}

export async function getFirewallSettings(
  id: string,
): Promise<FirewallSettingsView> {
  const raw = await resource(id);
  const { subscriptionId } = parseResourceId(id);
  const p = raw.properties;
  const sku = objectOrEmpty(p.sku, 'firewall SKU');
  const errors: string[] = [];
  const [maintenance, configs, allHubs, vnets, publicIps] = await Promise.all([
    lookup(
      'Maintenance assignments could not be loaded',
      errors,
      () => assignments(id),
      undefined,
    ),
    lookup(
      'Maintenance configurations could not be loaded',
      errors,
      () =>
        listResources(
          'microsoft.maintenance/maintenanceconfigurations',
          subscriptionId,
        ),
      [],
    ),
    lookup(
      'Hubs and Route Servers could not be loaded',
      errors,
      () => listResources('microsoft.network/virtualhubs', subscriptionId),
      [],
    ),
    lookup(
      'Virtual networks could not be loaded',
      errors,
      () => listResources('microsoft.network/virtualnetworks', subscriptionId),
      [],
    ),
    lookup(
      'Public IPs could not be loaded',
      errors,
      () =>
        listResources('microsoft.network/publicipaddresses', subscriptionId),
      [],
    ),
  ]);
  const local = (r: ResourceOption) =>
    normalize(r.location) === normalize(raw.location);
  const running = firewallConfig(raw);
  if (maintenance)
    running.maintenanceConfigurationIds = [
      ...new Set(
        maintenance.map((a) => {
          if (!a.properties?.maintenanceConfigurationId)
            throw new Error(
              'Azure returned an incomplete maintenance assignment.',
            );
          return a.properties.maintenanceConfigurationId;
        }),
      ),
    ].sort();
  return {
    id,
    policyId: ref(p.firewallPolicy, 'firewall policy') || undefined,
    location: raw.location,
    tier: string(sku.tier, 'firewall tier'),
    skuName: string(sku.name, 'firewall SKU'),
    provisioningState: string(p.provisioningState, 'provisioning state'),
    running,
    errors,
    maintenanceConfigurations: configs
      .filter(
        (r) =>
          local(r) &&
          r.properties?.maintenanceScope === 'Resource' &&
          objectOrEmpty(
            r.properties?.extensionProperties,
            'maintenance extension',
          ).maintenanceSubScope === 'NetworkSecurity',
      )
      .map((r) => {
        const window = objectOrEmpty(
          r.properties?.maintenanceWindow,
          'maintenance window',
        );
        return {
          ...r,
          schedule: `${String(window.recurEvery ?? '')} ${String(window.startDateTime ?? '')}, ${String(window.duration ?? '')} (${String(window.timeZone ?? '')})`,
        };
      }),
    routeServers: allHubs.filter(
      (r) => local(r) && !ref(r.properties?.virtualWan, 'virtual WAN'),
    ),
    hubs: allHubs.filter(
      (r) => local(r) && !!ref(r.properties?.virtualWan, 'virtual WAN'),
    ),
    publicIps: publicIps.filter(local),
    vnets: vnets.filter(local).map((r) => {
      const subnets = array(
        r.properties?.subnets,
        'virtual network subnets',
      ).map((s) => settingsObject(s, 'subnet'));
      return {
        ...r,
        subnetId:
          string(
            subnets.find((s) => s.name === 'AzureFirewallSubnet')?.id,
            'firewall subnet',
          ) || undefined,
        managementSubnetId:
          string(
            subnets.find((s) => s.name === 'AzureFirewallManagementSubnet')?.id,
            'management subnet',
          ) || undefined,
      };
    }),
  };
}

export async function getLearnedPrefixes(id: string): Promise<string[]> {
  const { subscriptionId, resourceGroup, name } = parseResourceId(id);
  const result = await network(
    subscriptionId,
  ).azureFirewalls.listLearnedPrefixes(resourceGroup, name, {
    abortSignal: AbortSignal.timeout(120_000),
  });
  if (!Array.isArray(result.ipPrefixes))
    throw new Error('Azure did not return a learned-prefix list.');
  return result.ipPrefixes;
}

export async function getPolicyConfiguration(id: string) {
  const raw = await resource(id);
  if (!isThreatIntelMode(raw.properties.threatIntelMode))
    throw new Error('Azure returned an unsupported threat-intelligence mode.');
  return {
    name: raw.name,
    threatIntelMode: raw.properties.threatIntelMode,
    settings: readPolicySettings(raw.properties, raw.identity),
    provisioningState: string(raw.properties.provisioningState, 'policy state'),
  };
}

export async function getPolicySettings(
  id: string,
): Promise<PolicySettingsView> {
  const raw = await resource(id);
  const errors: string[] = [];
  if (!isThreatIntelMode(raw.properties.threatIntelMode))
    throw new Error('Azure returned an unsupported threat-intelligence mode.');
  const identities = await lookup(
    'Managed identities could not be loaded',
    errors,
    () => listResources('microsoft.managedidentity/userassignedidentities'),
    [],
  );
  return {
    id,
    name: raw.name,
    tier: string(
      objectOrEmpty(raw.properties.sku, 'policy SKU').tier,
      'policy tier',
    ),
    threatIntelMode: raw.properties.threatIntelMode,
    running: readPolicySettings(raw.properties, raw.identity),
    identities,
    errors,
  };
}

async function validateRouteServer(
  raw: ArmResource,
  id: string,
  requestedAllocation?: FirewallAllocation,
) {
  if (!id) return;
  const rs = await resource(id);
  if (ref(rs.properties.virtualWan, 'virtual WAN'))
    throw new Error(
      'The selected resource is a Virtual WAN hub, not an Azure Route Server.',
    );
  const subnetId = (
    allocation(raw) ?? requestedAllocation
  )?.ipConfigurations.find((c) => c.subnet)?.subnet?.id;
  if (!subnetId)
    throw new Error(
      'The firewall VNet allocation is required before associating a Route Server.',
    );
  const configs = await armList<{ properties?: { subnet?: { id?: string } } }>(
    `${id}/ipConfigurations?api-version=${NETWORK_API}`,
  );
  const vnetId = subnetId.replace(/\/subnets\/[^/]+$/i, '');
  if (
    !configs.some((c) =>
      c.properties?.subnet?.id
        ?.toLowerCase()
        .startsWith(`${vnetId.toLowerCase()}/subnets/`),
    )
  )
    throw new Error(
      'Azure Route Server must be in the same virtual network as the firewall.',
    );
}

async function validateMaintenance(raw: ArmResource, ids: string[]) {
  for (const id of ids) {
    const config = await resource(id, MAINTENANCE_API);
    const p = config.properties;
    const extension = objectOrEmpty(
      p.extensionProperties,
      'maintenance extension',
    );
    const window = objectOrEmpty(p.maintenanceWindow, 'maintenance window');
    const duration = /^(\d{1,2}):([0-5]\d)$/.exec(
      String(window.duration ?? ''),
    );
    if (
      normalize(config.location) !== normalize(raw.location) ||
      p.maintenanceScope !== 'Resource' ||
      extension.maintenanceSubScope !== 'NetworkSecurity' ||
      !/^(?:1)?Day$/i.test(String(window.recurEvery)) ||
      !duration ||
      Number(duration[1]) * 60 + Number(duration[2]) < 300
    )
      throw new Error(
        `Maintenance configuration "${config.name}" must be in the firewall's region, use Resource / NetworkSecurity scope, and recur daily for at least 5 hours.`,
      );
  }
}

async function validateAllocation(raw: ArmResource, value: FirewallAllocation) {
  const tier = string(
    objectOrEmpty(raw.properties.sku, 'firewall SKU').tier,
    'firewall tier',
  );
  const errors = allocationErrors(value, tier);
  if (errors.length) throw new Error(errors.join('\n'));
  if (value.skuName === 'AZFW_VNet') {
    const dataSubnets = value.ipConfigurations.flatMap((c) =>
      c.subnet ? [c.subnet.id] : [],
    );
    if (!dataSubnets.every((id) => /\/subnets\/AzureFirewallSubnet$/i.test(id)))
      throw new Error('The data interface must use AzureFirewallSubnet.');
    if (
      value.managementIpConfiguration?.subnet &&
      !/\/subnets\/AzureFirewallManagementSubnet$/i.test(
        value.managementIpConfiguration.subnet.id,
      )
    )
      throw new Error(
        'The management interface must use AzureFirewallManagementSubnet.',
      );
  }
  const sub = parseResourceId(raw.id).subscriptionId;
  const refs = [
    ...(value.virtualHubId ? [value.virtualHubId] : []),
    ...value.ipConfigurations.flatMap((c) =>
      [c.subnet?.id, c.publicIPAddress?.id].filter((v): v is string => !!v),
    ),
    ...(value.managementIpConfiguration
      ? [
          value.managementIpConfiguration.subnet?.id,
          value.managementIpConfiguration.publicIPAddress?.id,
        ].filter((v): v is string => !!v)
      : []),
  ];
  for (const id of new Set(refs)) {
    if (parseResourceId(id).subscriptionId.toLowerCase() !== sub.toLowerCase())
      throw new Error(
        'Allocation resources must be in the firewall subscription.',
      );
    const subnet = /\/subnets\/[^/]+$/i.test(id);
    const target = await resource(
      subnet ? id.replace(/\/subnets\/[^/]+$/i, '') : id,
    );
    if (
      subnet &&
      !array(target.properties.subnets, 'VNet subnets').some((s) =>
        sameResourceId(string(settingsObject(s, 'subnet').id, 'subnet ID'), id),
      )
    )
      throw new Error(
        'The selected subnet no longer exists in the virtual network.',
      );
    if (normalize(target.location) !== normalize(raw.location))
      throw new Error('Allocation resources must be in the firewall region.');
    if (
      value.skuName === 'AZFW_Hub' &&
      sameResourceId(id, value.virtualHubId)
    ) {
      const owner = ref(target.properties.azureFirewall, 'hub firewall');
      if (owner && !sameResourceId(owner, raw.id))
        throw new Error(
          'The selected virtual hub already has a different firewall.',
        );
    }
    if (/\/publicIPAddresses\//i.test(id)) {
      if (
        objectOrEmpty(target.sku, 'public IP SKU').name !== 'Standard' ||
        target.properties.publicIPAllocationMethod !== 'Static'
      )
        throw new Error(
          `Public IP "${target.name}" must use Standard SKU and Static allocation.`,
        );
      const owner = ref(
        target.properties.ipConfiguration,
        'public IP assignment',
      );
      if (owner && !owner.toLowerCase().startsWith(`${raw.id.toLowerCase()}/`))
        throw new Error(
          `Public IP "${target.name}" is already assigned to another resource.`,
        );
    }
  }
}

export async function validateFirewallConfiguration(
  id: string,
  desired: FirewallConfiguration,
  before?: FirewallConfiguration,
): Promise<void> {
  const raw = await resource(id);
  const current = firewallConfig(raw);
  const sku = objectOrEmpty(raw.properties.sku, 'firewall SKU');
  const errors = firewallSettingsErrors(
    { ...desired, allocation: desired.allocation ?? current.allocation },
    string(sku.tier, 'tier'),
    string(sku.name, 'SKU'),
    before ?? current,
  );
  if (errors.length) throw new Error(errors.join('\n'));
  if (raw.properties.afcConfiguration)
    throw new Error('AFC-managed firewalls cannot be edited here.');
  if (desired.routeServerId !== (before ?? current).routeServerId)
    await validateRouteServer(raw, desired.routeServerId, desired.allocation);
  if (
    desired.maintenanceConfigurationIds !== undefined &&
    JSON.stringify(desired.maintenanceConfigurationIds) !==
      JSON.stringify(before?.maintenanceConfigurationIds)
  )
    await validateMaintenance(raw, desired.maintenanceConfigurationIds);
  if (desired.powerState !== (before ?? current).powerState) {
    if (desired.powerState === 'Unknown' || current.powerState === 'Unknown')
      throw new Error(
        'Wait for a settled, known firewall power state before starting or stopping it.',
      );
    if (desired.powerState === 'Running') {
      if (!desired.allocation)
        throw new Error(
          'Select the existing allocation resources before starting this firewall.',
        );
      if (desired.allocation.skuName !== sku.name)
        throw new Error(
          'The allocation type does not match the firewall deployment type.',
        );
      await validateAllocation(raw, desired.allocation);
    } else {
      const profile = allocation(raw);
      if (!profile)
        throw new Error(
          'The current allocation could not be read; stopping would lose the restart configuration.',
        );
      const problems = allocationErrors(profile, string(sku.tier, 'tier'));
      if (problems.length) throw new Error(problems.join('\n'));
      // Private-IP DNAT can prevent later reallocation; don't offer a stop that strands it.
      const policyId = ref(raw.properties.firewallPolicy, 'policy');
      const groups = policyId
        ? await armList<{
            properties?: {
              ruleCollections?: {
                rules?: {
                  ruleType?: string;
                  destinationAddresses?: string[];
                }[];
              }[];
            };
          }>(`${policyId}/ruleCollectionGroups?api-version=${NETWORK_API}`)
        : [];
      const classicNat = array(
        raw.properties.natRuleCollections,
        'classic NAT collections',
      ).flatMap((c) => {
        const collection = settingsObject(c, 'NAT collection');
        return array(
          objectOrEmpty(collection.properties, 'NAT properties').rules,
          'NAT rules',
        ).map((r) => {
          const rule = settingsObject(r, 'NAT rule');
          return {
            destinationAddresses: array(
              rule.destinationAddresses,
              'DNAT destinations',
            ).map((v) => string(v, 'DNAT address')),
          };
        });
      });
      const privateIps = [
        ...array(raw.properties.ipConfigurations, 'IP configurations').map(
          (config) =>
            string(
              settingsObject(
                settingsObject(config, 'IP configuration').properties,
                'IP properties',
              ).privateIPAddress,
              'private IP',
            ),
        ),
        string(
          objectOrEmpty(raw.properties.hubIPAddresses, 'hub addresses')
            .privateIPAddress,
          'hub private IP',
        ),
      ].filter(Boolean);
      const nat = [
        ...groups
          .flatMap((g) => g.properties?.ruleCollections ?? [])
          .flatMap((c) => c.rules ?? [])
          .filter((r) => r.ruleType === 'NatRule'),
        ...classicNat,
      ];
      if (nat.length && !privateIps.length)
        throw new Error(
          'The firewall private addresses could not be verified against its DNAT rules. Refresh before attempting to stop it.',
        );
      if (
        nat.some((r) =>
          r.destinationAddresses?.some(
            (ip) =>
              privateIps.some((privateIp) => addressContains(ip, privateIp)) ||
              /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip),
          ),
        )
      )
        throw new Error(
          'Stopping/reallocation is not supported with private-IP DNAT rules. Remove or migrate those rules first.',
        );
    }
  }
}

function serializeAllocation(config: AllocationIpConfiguration) {
  return {
    name: config.name,
    properties: {
      ...(config.subnet ? { subnet: config.subnet } : {}),
      ...(config.publicIPAddress
        ? { publicIPAddress: config.publicIPAddress }
        : {}),
    },
  };
}

async function applyMaintenance(
  raw: ArmResource,
  wanted: string[],
  expected: string[] | undefined,
) {
  const current = await assignments(raw.id);
  if (!expected)
    throw new Error('Current maintenance assignments could not be verified.');
  const ids = current.map((a) => {
    if (!a.properties?.maintenanceConfigurationId)
      throw new Error('Azure returned an invalid maintenance assignment.');
    return a.properties.maintenanceConfigurationId;
  });
  const signature = (values: string[]) =>
    [...new Set(values.map((id) => id.toLowerCase()))].sort().join('\n');
  if (
    signature(ids) !== signature(expected) &&
    signature(ids) !== signature(wanted)
  )
    throw Object.assign(
      new Error(
        'Maintenance assignments changed in Azure while the firewall update was applying. Refresh and review the draft before retrying.',
      ),
      { code: 'ResourceSettingsConflict' },
    );
  for (const assignment of current) {
    const config = assignment.properties?.maintenanceConfigurationId;
    if (!config)
      throw new Error('Azure returned an invalid maintenance assignment.');
    if (!wanted.some((id) => sameResourceId(id, config))) {
      const prefix =
        `${raw.id}/providers/Microsoft.Maintenance/configurationAssignments/`.toLowerCase();
      if (!assignment.id.toLowerCase().startsWith(prefix))
        throw new Error('Azure returned an assignment for another resource.');
      await armWrite(
        `${assignment.id}?api-version=${MAINTENANCE_API}`,
        'DELETE',
      );
    }
  }
  for (const id of wanted) {
    if (
      current.some((a) =>
        sameResourceId(a.properties?.maintenanceConfigurationId, id),
      )
    )
      continue;
    const { createHash } = await import('node:crypto');
    const name = `ezazfw-${createHash('sha256').update(id.toLowerCase()).digest('hex').slice(0, 20)}`;
    if (current.some((a) => a.name === name))
      throw new Error(
        'A maintenance assignment with this generated name already exists. Review assignments in Azure before retrying.',
      );
    await armWrite(
      `${raw.id}/providers/Microsoft.Maintenance/configurationAssignments/${name}?api-version=${MAINTENANCE_API}`,
      'PUT',
      {
        location: raw.location,
        properties: { resourceId: raw.id, maintenanceConfigurationId: id },
      },
    );
  }
}

export async function putFirewallConfiguration(
  id: string,
  baseline: FirewallConfiguration,
  desired: FirewallConfiguration,
): Promise<void> {
  const raw = await resource(id);
  const current = firewallConfig(raw);
  if (desired.maintenanceConfigurationIds !== undefined)
    current.maintenanceConfigurationIds = (
      await getFirewallConfigurationForDraft(id, true)
    ).maintenanceConfigurationIds;
  if (
    baseline.powerState === 'Stopped' &&
    desired.powerState === 'Running' &&
    current.powerState === 'Running' &&
    allocationSignature(current.allocation) !==
      allocationSignature(desired.allocation)
  )
    throw Object.assign(
      new Error(
        'The firewall was started with a different allocation after this draft began. Refresh and review the network resources again.',
      ),
      { code: 'ResourceSettingsConflict' },
    );
  const merged = mergeSettings(
    baseline,
    desired,
    current,
    FIREWALL_SETTING_KEYS,
  );
  merged.allocation = desired.allocation ?? current.allocation;
  await validateFirewallConfiguration(id, merged, current);
  const body = writable(raw);
  const p = settingsObject(body.properties, 'firewall properties');
  let write = false;
  if (merged.routeServerId !== current.routeServerId) {
    const additional = {
      ...objectOrEmpty(p.additionalProperties, 'additional properties'),
    };
    if (merged.routeServerId)
      additional[ROUTE_SERVER_KEY] = merged.routeServerId;
    else delete additional[ROUTE_SERVER_KEY];
    p.additionalProperties = additional;
    write = true;
  }
  if (
    merged.minCapacity !== current.minCapacity ||
    merged.maxCapacity !== current.maxCapacity
  ) {
    p.autoscaleConfiguration = {
      ...objectOrEmpty(p.autoscaleConfiguration, 'autoscaling'),
      minCapacity: merged.minCapacity,
      maxCapacity: merged.maxCapacity,
    };
    write = true;
  }
  if (merged.powerState !== current.powerState) {
    if (merged.powerState === 'Stopped') {
      const saved = allocation(raw);
      if (!saved) throw new Error('The restart allocation could not be saved.');
      const savedToDisk = updateState((state) => {
        state.firewallAllocations ??= {};
        state.firewallAllocations[id.toLowerCase()] = saved;
      });
      if (!savedToDisk)
        throw new Error(
          'The restart allocation could not be saved to disk. The firewall was not stopped.',
        );
      if (saved.skuName === 'AZFW_Hub') p.virtualHub = null;
      else {
        p.ipConfigurations = [];
        p.managementIpConfiguration = null;
      }
    } else if (merged.powerState === 'Running' && merged.allocation) {
      const saved = merged.allocation;
      if (saved.skuName === 'AZFW_Hub') {
        p.virtualHub = { id: saved.virtualHubId };
        if (saved.ipConfigurations.some((c) => c.publicIPAddress)) {
          p.ipConfigurations = saved.ipConfigurations.map(serializeAllocation);
          p.hubIPAddresses = null;
        } else {
          p.ipConfigurations = [];
          p.hubIPAddresses = { publicIPs: { count: saved.publicIpCount } };
        }
      } else {
        p.ipConfigurations = saved.ipConfigurations.map(serializeAllocation);
        p.managementIpConfiguration = saved.managementIpConfiguration
          ? serializeAllocation(saved.managementIpConfiguration)
          : null;
      }
    }
    write = true;
  }
  if (write) {
    // Network RP can apply If-Match to the linked subnet, whose ETag differs from the firewall's.
    await armWrite(`${id}?api-version=${NETWORK_API}`, 'PUT', body);
  }
  if (
    merged.maintenanceConfigurationIds !== undefined &&
    JSON.stringify(merged.maintenanceConfigurationIds) !==
      JSON.stringify(current.maintenanceConfigurationIds)
  ) {
    try {
      await applyMaintenance(
        raw,
        merged.maintenanceConfigurationIds,
        current.maintenanceConfigurationIds,
      );
    } catch (err) {
      if (!write) throw err;
      const details = err as { code?: string; statusCode?: number } | null;
      throw Object.assign(
        new Error(
          `The firewall resource update was applied, but maintenance assignment failed. The draft is retained; refresh before retrying. ${describeAzureError(err)}`,
        ),
        { code: details?.code, statusCode: details?.statusCode },
      );
    }
  }
}

export async function validatePolicyConfiguration(
  id: string,
  desired: PolicyAdvancedSettings,
  before?: PolicyAdvancedSettings,
): Promise<void> {
  const raw = await resource(id);
  const current = readPolicySettings(raw.properties, raw.identity);
  const tier = string(
    objectOrEmpty(raw.properties.sku, 'policy SKU').tier,
    'policy tier',
  );
  const errors = policySettingsErrors(desired, tier, before ?? current);
  if (errors.length) throw new Error(errors.join('\n'));
  if (raw.properties.afcManaged === true)
    throw new Error('AFC-managed policies are read-only.');
  const firewalls = array(raw.properties.firewalls, 'associated firewalls').map(
    (f) => ref(f, 'associated firewall'),
  );
  for (const firewallId of firewalls) {
    const fw = await resource(firewallId);
    const config = firewallConfig(fw);
    if (
      desired.autoLearnSnat &&
      !current.autoLearnSnat &&
      string(objectOrEmpty(fw.properties.sku, 'firewall SKU').name, 'SKU') !==
        'AZFW_Hub' &&
      !config.routeServerId
    )
      throw new Error(
        `Associate Azure Route Server with "${fw.name}" and commit that association before enabling policy SNAT auto-learning.`,
      );
    if (
      desired.autoLearnSnat &&
      !current.autoLearnSnat &&
      string(objectOrEmpty(fw.properties.sku, 'firewall SKU').name, 'SKU') !==
        'AZFW_Hub'
    )
      await validateRouteServer(fw, config.routeServerId, config.allocation);
    if (
      desired.tls.enabled &&
      string(objectOrEmpty(fw.properties.sku, 'firewall SKU').tier, 'tier') !==
        'Premium'
    )
      throw new Error(`TLS inspection requires Premium firewall "${fw.name}".`);
  }
  if (
    desired.tls.enabled &&
    JSON.stringify(desired.tls) !== JSON.stringify(current.tls)
  ) {
    for (const identityId of desired.tls.identityIds)
      await resource(identityId, '2023-01-31');
  }
}

export async function putPolicyConfiguration(
  id: string,
  baseline: PolicyAdvancedSettings,
  desired: PolicyAdvancedSettings,
  mode?: { before: ThreatIntelMode; after: ThreatIntelMode },
): Promise<void> {
  const raw = await resource(id);
  const current = readPolicySettings(raw.properties, raw.identity);
  const merged = mergeSettings(baseline, desired, current, POLICY_SETTING_KEYS);
  await validatePolicyConfiguration(id, merged, current);
  const body = writable(raw);
  const p = settingsObject(body.properties, 'policy properties');
  const modeChanged =
    !!mode &&
    mode.before !== mode.after &&
    raw.properties.threatIntelMode !== mode.after;
  if (mode && mode.before !== mode.after) {
    if (!isThreatIntelMode(mode.after))
      throw new Error('Unsupported threat-intelligence mode.');
    if (
      raw.properties.threatIntelMode !== mode.before &&
      raw.properties.threatIntelMode !== mode.after
    )
      throw Object.assign(
        new Error(
          'Threat intelligence changed in Azure after this draft started. Refresh and review the policy settings.',
        ),
        { code: 'ResourceSettingsConflict' },
      );
    const parsed = parseResourceId(id);
    await validatePolicyMode(
      {
        id,
        name: raw.name,
        subscriptionId: parsed.subscriptionId,
        resourceGroup: parsed.resourceGroup,
        tier: string(
          objectOrEmpty(raw.properties.sku, 'policy SKU').tier,
          'policy tier',
        ),
        basePolicyId:
          ref(raw.properties.basePolicy, 'parent policy') || undefined,
        firewallIds: [],
        childPolicyIds: [],
      },
      mode.after,
    );
    p.threatIntelMode = mode.after;
  }
  if (JSON.stringify(merged.dns) !== JSON.stringify(current.dns))
    p.dnsSettings = merged.dns.inherit
      ? null
      : {
          ...objectOrEmpty(p.dnsSettings, 'DNS settings'),
          enableProxy: merged.dns.enableProxy,
          servers: merged.dns.servers,
        };
  if (
    JSON.stringify(merged.allowlistIps) !==
      JSON.stringify(current.allowlistIps) ||
    JSON.stringify(merged.allowlistFqdns) !==
      JSON.stringify(current.allowlistFqdns)
  )
    p.threatIntelWhitelist = {
      ...objectOrEmpty(p.threatIntelWhitelist, 'allowlist'),
      ipAddresses: merged.allowlistIps,
      fqdns: merged.allowlistFqdns,
    };
  if (merged.autoLearnSnat !== current.autoLearnSnat)
    p.snat = {
      ...objectOrEmpty(p.snat, 'SNAT'),
      autoLearnPrivateRanges: merged.autoLearnSnat ? 'Enabled' : 'Disabled',
    };
  if (JSON.stringify(merged.tls) !== JSON.stringify(current.tls)) {
    p.transportSecurity = merged.tls.enabled
      ? {
          ...objectOrEmpty(p.transportSecurity, 'TLS'),
          certificateAuthority: {
            name: merged.tls.certificateName,
            keyVaultSecretId: merged.tls.secretId,
          },
        }
      : null;
    if (merged.tls.enabled) {
      const identity = objectOrEmpty(body.identity, 'policy identity');
      body.identity = {
        ...identity,
        type: String(identity.type ?? '').includes('SystemAssigned')
          ? 'SystemAssigned, UserAssigned'
          : 'UserAssigned',
        userAssignedIdentities: Object.fromEntries(
          merged.tls.identityIds.map((id) => [id, {}]),
        ),
      };
    }
  }
  if (
    modeChanged ||
    POLICY_SETTING_KEYS.some(
      (key) => JSON.stringify(merged[key]) !== JSON.stringify(current[key]),
    )
  )
    await armWrite(`${id}?api-version=${NETWORK_API}`, 'PUT', body, raw.etag);
}
