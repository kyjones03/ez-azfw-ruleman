import { addressEntryError } from './cidr';
import { FQDN, stableStringify } from './rules';
import {
  isResourceIdOfType,
  RESOURCE_TYPES,
  sameResourceId,
} from './resourceId';
import type { ChangeItem } from './types';
import type { ThreatIntelMode } from './deploy';

export interface PolicyAdvancedSettings {
  dns: { inherit: boolean; enableProxy: boolean; servers: string[] };
  allowlistIps: string[];
  allowlistFqdns: string[];
  autoLearnSnat: boolean;
  tls: {
    enabled: boolean;
    certificateName: string;
    secretId: string;
    identityIds: string[];
  };
}

export interface AllocationIpConfiguration {
  name: string;
  subnet?: { id: string };
  publicIPAddress?: { id: string };
}

export interface FirewallAllocation {
  skuName: 'AZFW_VNet' | 'AZFW_Hub';
  ipConfigurations: AllocationIpConfiguration[];
  managementIpConfiguration?: AllocationIpConfiguration;
  virtualHubId?: string;
  publicIpCount?: number;
}

export type FirewallPowerState = 'Running' | 'Stopped' | 'Unknown';

export interface FirewallConfiguration {
  name: string;
  provisioningState?: string;
  privateIp?: string;
  routeServerId: string;
  minCapacity: number | null;
  maxCapacity: number | null;
  powerState: FirewallPowerState;
  /** Omitted when maintenance assignments could not be read; never interpreted as an empty list. */
  maintenanceConfigurationIds?: string[];
  allocation?: FirewallAllocation;
}

export interface ResourceOption {
  id: string;
  name: string;
  resourceGroup: string;
  location: string;
  subscriptionId?: string;
}

export interface FirewallSettingsView {
  id: string;
  policyId?: string;
  location: string;
  tier: string;
  skuName: string;
  provisioningState?: string;
  running: FirewallConfiguration;
  draft?: FirewallConfiguration;
  routeServers: ResourceOption[];
  maintenanceConfigurations: (ResourceOption & { schedule: string })[];
  vnets: (ResourceOption & {
    subnetId?: string;
    managementSubnetId?: string;
  })[];
  hubs: ResourceOption[];
  publicIps: ResourceOption[];
  errors: string[];
}

export interface PolicySettingsView {
  id: string;
  name: string;
  tier: string;
  threatIntelMode: ThreatIntelMode;
  running: PolicyAdvancedSettings;
  draft?: PolicyAdvancedSettings;
  identities: ResourceOption[];
  errors: string[];
}

const REFERENCE_ID =
  /^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/resourceGroups\/[^/?#\\]+\/providers\/Microsoft\.ManagedIdentity\/userAssignedIdentities\/[A-Za-z0-9_-]{1,128}$/i;
export const isIdentityId = (id: string) => REFERENCE_ID.test(id);

export function keyVaultSecretError(value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'Enter the HTTPS Key Vault secret identifier, not the certificate contents.';
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.port ||
    url.search ||
    url.hash ||
    !/^[a-z][a-z0-9-]{1,22}[a-z0-9]\.vault\.azure\.net$/i.test(url.hostname) ||
    !/^\/secrets\/[a-z0-9-]{1,127}(?:\/[0-9a-f]{32})?$/i.test(url.pathname)
  )
    return 'Use a Key Vault secret URI such as https://vault-name.vault.azure.net/secrets/ca-certificate (optionally with its version).';
  return undefined;
}

function ipError(value: string, single = false): string | undefined {
  if (value.trim() === '*') return 'Wildcards are not allowed.';
  if (single && /[/-]/.test(value))
    return 'Enter one IPv4 address, not a CIDR or range.';
  return addressEntryError(value);
}

export function policySettingsErrors(
  value: PolicyAdvancedSettings,
  tier: string,
  before?: PolicyAdvancedSettings,
): string[] {
  const errors: string[] = [];
  const changed = (key: keyof PolicyAdvancedSettings) =>
    !before || stableStringify(value[key]) !== stableStringify(before[key]);
  if (changed('dns') && tier === 'Basic' && !value.dns.inherit)
    errors.push(
      'Custom DNS and DNS proxy require a Standard or Premium policy.',
    );
  if (changed('dns') && value.dns.servers.length > 15)
    errors.push('Custom DNS supports at most 15 servers.');
  for (const ip of changed('dns') ? value.dns.servers : []) {
    const error = ipError(ip, true);
    if (error) errors.push(`DNS server ${ip}: ${error}`);
  }
  for (const ip of changed('allowlistIps') ? value.allowlistIps : []) {
    const error = ipError(ip);
    if (error) errors.push(`Allowlist ${ip}: ${error}`);
  }
  for (const fqdn of changed('allowlistFqdns') ? value.allowlistFqdns : [])
    if (
      !FQDN.test(fqdn) ||
      fqdn === '*' ||
      /^[a-z]+:\/\//i.test(fqdn) ||
      fqdn.includes('/')
    )
      errors.push(
        `Allowlist "${fqdn}" must be a valid FQDN without a scheme or path.`,
      );
  if (changed('autoLearnSnat') && value.autoLearnSnat && tier === 'Basic')
    errors.push('SNAT auto-learning requires a Standard or Premium policy.');
  if (changed('tls') && value.tls.enabled) {
    if (tier !== 'Premium')
      errors.push(
        'TLS inspection requires a Premium policy and Premium firewalls.',
      );
    const secretError = keyVaultSecretError(value.tls.secretId);
    if (secretError) errors.push(secretError);
    if (
      !value.tls.certificateName.trim() ||
      value.tls.certificateName.length > 512 ||
      [...value.tls.certificateName].some((char) => char.charCodeAt(0) < 32)
    )
      errors.push(
        'Enter a readable CA certificate name (up to 512 characters, without control characters).',
      );
    if (
      value.tls.identityIds.length !== 1 ||
      !value.tls.identityIds.every(isIdentityId)
    )
      errors.push(
        'Select one existing user-assigned managed identity for TLS inspection.',
      );
  }
  return errors;
}

export function firewallSettingsErrors(
  value: FirewallConfiguration,
  tier: string,
  skuName: string,
  before?: FirewallConfiguration,
): string[] {
  const errors: string[] = [];
  if (
    (!before || value.routeServerId !== before.routeServerId) &&
    value.routeServerId &&
    !isResourceIdOfType(value.routeServerId, RESOURCE_TYPES.virtualHub)
  )
    errors.push('Select an existing Azure Route Server.');
  if (
    (!before || value.routeServerId !== before.routeServerId) &&
    skuName === 'AZFW_Hub' &&
    (value.routeServerId || before?.routeServerId)
  )
    errors.push(
      'Secured hub firewalls use their built-in Route Server; do not assign another one.',
    );
  if (
    (!before || value.routeServerId !== before.routeServerId) &&
    tier === 'Basic' &&
    value.routeServerId
  )
    errors.push(
      'Route Server association for SNAT auto-learning requires a Standard or Premium firewall.',
    );
  const min = value.minCapacity;
  const max = value.maxCapacity;
  const scalingChanged =
    !before || min !== before.minCapacity || max !== before.maxCapacity;
  if (scalingChanged && (min === null) !== (max === null))
    errors.push('Set both capacity limits, or reset both to service defaults.');
  if (scalingChanged && min !== null && max !== null) {
    if (tier === 'Basic')
      errors.push('Prescaling requires a Standard or Premium firewall.');
    if (
      !Number.isInteger(min) ||
      !Number.isInteger(max) ||
      min < 2 ||
      max > 50 ||
      min > max
    )
      errors.push(
        'Capacity limits must be whole numbers from 2 to 50, with minimum no greater than maximum.',
      );
    else if (max - min === 1)
      errors.push('Capacity limits must be equal, or differ by at least 2.');
  }
  const changesAllocation =
    value.powerState === 'Running' &&
    (!before ||
      before.powerState !== 'Running' ||
      allocationSignature(value.allocation) !==
        allocationSignature(before.allocation));
  if (
    (scalingChanged || changesAllocation) &&
    min !== null &&
    skuName === 'AZFW_Hub' &&
    value.allocation?.ipConfigurations.some((c) => c.publicIPAddress)
  )
    errors.push(
      'Prescaling is not supported on secured hubs with customer-provided public IPs. Reset scaling to service defaults first.',
    );
  for (const id of value.maintenanceConfigurationIds ?? [])
    if (!isResourceIdOfType(id, RESOURCE_TYPES.maintenanceConfiguration))
      errors.push('Select an existing maintenance configuration.');
  return errors;
}

export function allocationErrors(
  value: FirewallAllocation,
  tier: string,
): string[] {
  const errors: string[] = [];
  if (value.skuName === 'AZFW_Hub') {
    if (!isResourceIdOfType(value.virtualHubId, RESOURCE_TYPES.virtualHub))
      errors.push(
        'Select the existing virtual hub used to start this firewall.',
      );
    if (
      value.publicIpCount !== undefined &&
      (!Number.isInteger(value.publicIpCount) ||
        value.publicIpCount < 1 ||
        value.publicIpCount > 250)
    )
      errors.push('Hub public IP count must be between 1 and 250.');
    if (
      !value.ipConfigurations.some((c) => c.publicIPAddress) &&
      value.publicIpCount === undefined
    )
      errors.push(
        'The hub public IP count is required to preserve its allocation.',
      );
  } else {
    if (
      !value.ipConfigurations.length ||
      !value.ipConfigurations.some((c) =>
        isResourceIdOfType(c.subnet?.id, RESOURCE_TYPES.subnet),
      )
    )
      errors.push(
        'Select an existing virtual network with AzureFirewallSubnet.',
      );
    if (
      !value.ipConfigurations.some((c) => c.publicIPAddress?.id) &&
      !value.managementIpConfiguration?.publicIPAddress?.id
    )
      errors.push(
        'Select an existing public IP, or a management public IP for forced tunneling.',
      );
    if (tier === 'Basic' && !value.managementIpConfiguration)
      errors.push(
        'Basic firewalls require a management public IP and AzureFirewallManagementSubnet.',
      );
  }
  for (const config of [
    ...value.ipConfigurations,
    ...(value.managementIpConfiguration
      ? [value.managementIpConfiguration]
      : []),
  ]) {
    if (!config.name || /[/\\?#]/.test(config.name))
      errors.push('An allocation IP configuration has an invalid name.');
    if (
      config.publicIPAddress &&
      !isResourceIdOfType(config.publicIPAddress.id, RESOURCE_TYPES.publicIp)
    )
      errors.push('Select a valid existing public IP.');
    if (
      config.subnet &&
      !isResourceIdOfType(config.subnet.id, RESOURCE_TYPES.subnet)
    )
      errors.push('Select a valid existing subnet.');
  }
  if (
    value.managementIpConfiguration &&
    (!value.managementIpConfiguration.subnet ||
      !value.managementIpConfiguration.publicIPAddress)
  )
    errors.push(
      'A management IP configuration needs both AzureFirewallManagementSubnet and an existing public IP.',
    );
  const dataVnet = value.ipConfigurations
    .find((c) => c.subnet)
    ?.subnet?.id.replace(/\/subnets\/[^/]+$/i, '');
  const managementVnet = value.managementIpConfiguration?.subnet?.id.replace(
    /\/subnets\/[^/]+$/i,
    '',
  );
  if (dataVnet && managementVnet && !sameResourceId(dataVnet, managementVnet))
    errors.push(
      'Data and management subnets must belong to the same virtual network.',
    );
  return errors;
}

export const POLICY_SETTING_KEYS = [
  'dns',
  'allowlistIps',
  'allowlistFqdns',
  'autoLearnSnat',
  'tls',
] as const;
export function allocationSignature(
  value: FirewallAllocation | undefined,
): string {
  if (!value) return '';
  const refs = value.ipConfigurations
    .filter((c) => c.subnet || c.publicIPAddress)
    .map((c) => ({
      subnet: c.subnet?.id.toLowerCase(),
      publicIp: c.publicIPAddress?.id.toLowerCase(),
    }))
    .sort((a, b) => stableStringify(a).localeCompare(stableStringify(b)));
  return stableStringify({
    sku: value.skuName,
    hub: value.virtualHubId?.toLowerCase(),
    refs,
    managementSubnet: value.managementIpConfiguration?.subnet?.id.toLowerCase(),
    managementPublicIp:
      value.managementIpConfiguration?.publicIPAddress?.id.toLowerCase(),
    publicIpCount: value.ipConfigurations.some((c) => c.publicIPAddress)
      ? undefined
      : value.publicIpCount,
  });
}

export const FIREWALL_SETTING_KEYS = [
  'routeServerId',
  'minCapacity',
  'maxCapacity',
  'maintenanceConfigurationIds',
  'powerState',
] as const;

const labels: Record<string, string> = {
  dns: 'DNS settings (inherit / proxy / servers)',
  allowlistIps: 'Threat-intelligence allowlist IPs',
  allowlistFqdns: 'Threat-intelligence allowlist FQDNs',
  autoLearnSnat: 'SNAT auto-learning',
  tls: 'TLS inspection / CA / managed identity',
  routeServerId: 'Route Server association',
  minCapacity: 'Minimum capacity',
  maxCapacity: 'Maximum capacity',
  maintenanceConfigurationIds: 'Maintenance configurations',
  powerState: 'Firewall power',
};
const describe = (value: unknown) =>
  value === null
    ? 'service default'
    : typeof value === 'boolean'
      ? value
        ? 'Enabled'
        : 'Disabled'
      : Array.isArray(value)
        ? value.join('; ') || '(none)'
        : typeof value === 'object'
          ? JSON.stringify(value)
          : String(value || '(none)');

export function settingsChanges<T extends object>(
  before: T,
  after: T,
  keys: readonly (keyof T)[],
  target: 'policy' | 'firewall',
): ChangeItem[] {
  return keys
    .filter(
      (key) =>
        after[key] !== undefined &&
        stableStringify(before[key]) !== stableStringify(after[key]),
    )
    .map((key) => ({
      target,
      kind: 'modified',
      detail: `${labels[String(key)] ?? String(key)}: ${describe(before[key])} -> ${describe(after[key])}`,
    }));
}

/** Rebase only the fields this draft edits; never overwrite a concurrent change to those fields. */
export function mergeSettings<T extends object>(
  before: T,
  desired: T,
  current: T,
  keys: readonly (keyof T)[],
): T {
  const result = structuredClone(current);
  for (const key of keys) {
    if (
      desired[key] === undefined ||
      stableStringify(before[key]) === stableStringify(desired[key])
    )
      continue;
    if (
      stableStringify(current[key]) !== stableStringify(before[key]) &&
      stableStringify(current[key]) !== stableStringify(desired[key])
    )
      throw Object.assign(
        new Error(
          `${labels[String(key)] ?? String(key)} changed in Azure after this draft started. Refresh and review it again.`,
        ),
        { code: 'ResourceSettingsConflict' },
      );
    result[key] = structuredClone(desired[key]);
  }
  return result;
}

export function draftBaseline<T extends object>(
  before: T,
  desired: T,
  current: T,
  keys: readonly (keyof T)[],
): T {
  const baseline = structuredClone(current);
  for (const key of keys)
    if (
      desired[key] !== undefined &&
      stableStringify(before[key]) !== stableStringify(desired[key])
    )
      baseline[key] = structuredClone(before[key]);
  return baseline;
}

export function settingsApplied<T extends object>(
  before: T,
  desired: T,
  current: T,
  keys: readonly (keyof T)[],
): boolean {
  return keys.every(
    (key) =>
      desired[key] === undefined ||
      stableStringify(before[key]) === stableStringify(desired[key]) ||
      stableStringify(desired[key]) === stableStringify(current[key]),
  );
}

export function firewallConfigurationChanges(
  before: FirewallConfiguration,
  after: FirewallConfiguration,
): ChangeItem[] {
  const changes = settingsChanges(
    before,
    after,
    FIREWALL_SETTING_KEYS,
    'firewall',
  );
  if (
    before.powerState !== after.powerState &&
    after.powerState === 'Running' &&
    after.allocation
  )
    changes.push({
      target: 'firewall',
      kind: 'modified',
      detail: `Start allocation: ${JSON.stringify(after.allocation)}`,
    });
  return changes;
}

export function firewallConfigurationWarnings(
  before: FirewallConfiguration,
  after: FirewallConfiguration,
): string[] {
  const changes = firewallConfigurationChanges(before, after);
  const warnings: string[] = [];
  if (changes.some((c) => c.detail?.startsWith('Firewall power')))
    warnings.push(
      after.powerState === 'Stopped'
        ? 'Stopping deallocates the firewall and interrupts all traffic through it. Regional capacity constraints can prevent a later restart. Public IP and other resource charges can continue.'
        : 'Starting allocates the firewall and can take several minutes. Its private IP can change; verify routes, DNS and downstream dependencies.',
    );
  if (changes.some((c) => /capacity:/.test(c.detail ?? '')))
    warnings.push(
      'Prescaling changes provisioned capacity and cost. Equal minimum and maximum values disable autoscaling.',
    );
  if (changes.some((c) => c.detail?.startsWith('Route Server')))
    warnings.push(
      'Route Server changes affect which prefixes are learned for SNAT. The associated policy must separately enable auto-learning.',
    );
  if (changes.some((c) => c.detail?.startsWith('Maintenance')))
    warnings.push(
      'Maintenance assignments affect future update windows and can take up to 24 hours to take effect.',
    );
  return warnings;
}

export function settingsObject(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`Invalid ${label} returned by Azure.`);
  return value as Record<string, unknown>;
}

export function settingsStrings(value: unknown, label: string): string[] {
  if (value === undefined || value === null) return [];
  if (
    !Array.isArray(value) ||
    !value.every((item): item is string => typeof item === 'string')
  )
    throw new Error(`Invalid ${label} returned by Azure.`);
  return value;
}

function requiredStrings(value: unknown, label: string): string[] {
  if (
    !Array.isArray(value) ||
    value.length > 50000 ||
    !value.every((s): s is string => typeof s === 'string' && s.length <= 2048)
  )
    throw new Error(`Invalid ${label}.`);
  return [...new Set(value.map((item) => item.trim()))];
}

export function sanitizePolicySettings(value: unknown): PolicyAdvancedSettings {
  const p = settingsObject(value, 'policy settings payload');
  const dns = settingsObject(p.dns, 'DNS settings payload');
  const tls = settingsObject(p.tls, 'TLS settings payload');
  if (
    typeof dns.inherit !== 'boolean' ||
    typeof dns.enableProxy !== 'boolean' ||
    typeof p.autoLearnSnat !== 'boolean' ||
    typeof tls.enabled !== 'boolean' ||
    typeof tls.certificateName !== 'string' ||
    typeof tls.secretId !== 'string' ||
    tls.certificateName.length > 512 ||
    tls.secretId.length > 2048
  )
    throw new Error('Invalid policy settings payload.');
  return {
    dns: {
      inherit: dns.inherit,
      enableProxy: dns.enableProxy,
      servers: requiredStrings(dns.servers, 'DNS servers'),
    },
    allowlistIps: requiredStrings(p.allowlistIps, 'allowlist IPs'),
    allowlistFqdns: requiredStrings(p.allowlistFqdns, 'allowlist FQDNs'),
    autoLearnSnat: p.autoLearnSnat,
    tls: {
      enabled: tls.enabled,
      certificateName: tls.certificateName,
      secretId: tls.secretId,
      identityIds: requiredStrings(
        tls.identityIds,
        'managed identities',
      ).sort(),
    },
  };
}

export function sanitizeAllocation(value: unknown): FirewallAllocation {
  const p = settingsObject(value, 'allocation payload');
  if (p.skuName !== 'AZFW_VNet' && p.skuName !== 'AZFW_Hub')
    throw new Error('Invalid allocation deployment type.');
  if (!Array.isArray(p.ipConfigurations) || p.ipConfigurations.length > 250)
    throw new Error('Invalid allocation IP configurations.');
  const config = (value: unknown): AllocationIpConfiguration => {
    const c = settingsObject(value, 'allocation IP configuration');
    if (typeof c.name !== 'string' || c.name.length > 80)
      throw new Error('Invalid IP configuration name.');
    const resourceRef = (v: unknown) => {
      const r = settingsObject(v, 'allocation resource reference');
      if (typeof r.id !== 'string' || r.id.length > 2048)
        throw new Error('Invalid allocation resource ID.');
      return { id: r.id };
    };
    return {
      name: c.name,
      ...(c.subnet ? { subnet: resourceRef(c.subnet) } : {}),
      ...(c.publicIPAddress
        ? { publicIPAddress: resourceRef(c.publicIPAddress) }
        : {}),
    };
  };
  if (
    p.virtualHubId !== undefined &&
    (typeof p.virtualHubId !== 'string' || p.virtualHubId.length > 2048)
  )
    throw new Error('Invalid hub ID.');
  if (p.publicIpCount !== undefined && typeof p.publicIpCount !== 'number')
    throw new Error('Invalid hub public IP count.');
  return {
    skuName: p.skuName,
    ipConfigurations: p.ipConfigurations.map(config),
    ...(p.managementIpConfiguration
      ? { managementIpConfiguration: config(p.managementIpConfiguration) }
      : {}),
    ...(typeof p.virtualHubId === 'string'
      ? { virtualHubId: p.virtualHubId }
      : {}),
    ...(typeof p.publicIpCount === 'number'
      ? { publicIpCount: p.publicIpCount }
      : {}),
  };
}

export function sanitizeFirewallConfiguration(
  value: unknown,
): FirewallConfiguration {
  const p = settingsObject(value, 'firewall settings payload');
  if (
    typeof p.name !== 'string' ||
    p.name.length > 80 ||
    typeof p.routeServerId !== 'string' ||
    p.routeServerId.length > 2048 ||
    (p.minCapacity !== null && typeof p.minCapacity !== 'number') ||
    (p.maxCapacity !== null && typeof p.maxCapacity !== 'number') ||
    (p.powerState !== 'Running' &&
      p.powerState !== 'Stopped' &&
      p.powerState !== 'Unknown')
  )
    throw new Error('Invalid firewall settings payload.');
  return {
    name: p.name,
    routeServerId: p.routeServerId,
    minCapacity: p.minCapacity,
    maxCapacity: p.maxCapacity,
    powerState: p.powerState,
    ...(p.maintenanceConfigurationIds !== undefined
      ? {
          maintenanceConfigurationIds: requiredStrings(
            p.maintenanceConfigurationIds,
            'maintenance configurations',
          ).sort(),
        }
      : {}),
    ...(p.allocation !== undefined
      ? { allocation: sanitizeAllocation(p.allocation) }
      : {}),
  };
}

export function readPolicySettings(
  properties: unknown,
  identity?: unknown,
): PolicyAdvancedSettings {
  const p = settingsObject(properties, 'policy');
  const dns =
    p.dnsSettings == null
      ? undefined
      : settingsObject(p.dnsSettings, 'DNS settings');
  const allow =
    p.threatIntelWhitelist == null
      ? {}
      : settingsObject(p.threatIntelWhitelist, 'threat-intelligence allowlist');
  const snat = p.snat == null ? {} : settingsObject(p.snat, 'SNAT settings');
  const transport =
    p.transportSecurity == null
      ? {}
      : settingsObject(p.transportSecurity, 'TLS settings');
  const ca =
    transport.certificateAuthority == null
      ? undefined
      : settingsObject(transport.certificateAuthority, 'TLS CA');
  const id =
    identity == null ? {} : settingsObject(identity, 'policy identity');
  const assigned =
    id.userAssignedIdentities == null
      ? {}
      : settingsObject(id.userAssignedIdentities, 'managed identities');
  if (dns?.enableProxy !== undefined && typeof dns.enableProxy !== 'boolean')
    throw new Error('Invalid DNS proxy state returned by Azure.');
  if (
    snat.autoLearnPrivateRanges !== undefined &&
    !['Enabled', 'Disabled'].includes(String(snat.autoLearnPrivateRanges))
  )
    throw new Error('Unsupported SNAT auto-learning state returned by Azure.');
  if (
    ca &&
    ((ca.name != null && typeof ca.name !== 'string') ||
      (ca.keyVaultSecretId != null && typeof ca.keyVaultSecretId !== 'string'))
  )
    throw new Error('Azure returned an invalid TLS CA configuration.');
  const secretId =
    typeof ca?.keyVaultSecretId === 'string' ? ca.keyVaultSecretId : '';
  const certificateName =
    typeof ca?.name === 'string'
      ? ca.name
      : (secretId.split('/secrets/')[1]?.split('/')[0] ?? '');
  return {
    dns: {
      inherit: !dns,
      enableProxy: dns?.enableProxy === true,
      servers: settingsStrings(dns?.servers, 'DNS servers'),
    },
    allowlistIps: settingsStrings(allow.ipAddresses, 'allowlist IPs'),
    allowlistFqdns: settingsStrings(allow.fqdns, 'allowlist FQDNs'),
    autoLearnSnat: snat.autoLearnPrivateRanges === 'Enabled',
    tls: {
      enabled: !!secretId,
      certificateName,
      secretId,
      identityIds: Object.keys(assigned),
    },
  };
}
