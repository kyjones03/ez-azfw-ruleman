export interface ParsedResourceId {
  subscriptionId: string;
  resourceGroup: string;
  provider: string;
  /** Full type, e.g. Microsoft.Network/firewallPolicies/ruleCollectionGroups */
  type: string;
  /** Name of the top-level resource. */
  name: string;
  /** Name of the child resource, when present. */
  childName?: string;
}

const RESOURCE_ID =
  /^\/subscriptions\/([0-9a-f-]{36})\/resourceGroups\/([-\w.()]{1,90})\/providers\/([\w.]+)\/(\w+)\/([-\w.]{1,80})(?:\/(\w+)\/([-\w.]{1,80}))?$/i;

export function parseResourceId(id: string): ParsedResourceId {
  const m = RESOURCE_ID.exec(id);
  if (!m) {
    throw new Error(`Invalid Azure resource ID: ${id}`);
  }
  const [
    ,
    subscriptionId,
    resourceGroup,
    provider,
    type,
    name,
    childType,
    childName,
  ] = m;
  return {
    subscriptionId,
    resourceGroup,
    provider,
    type: childType
      ? `${provider}/${type}/${childType}`
      : `${provider}/${type}`,
    name,
    childName,
  };
}

export const RESOURCE_TYPES = {
  firewall: 'Microsoft.Network/azureFirewalls',
  ipGroup: 'Microsoft.Network/ipGroups',
  policy: 'Microsoft.Network/firewallPolicies',
  ruleCollectionGroup:
    'Microsoft.Network/firewallPolicies/ruleCollectionGroups',
  virtualNetwork: 'Microsoft.Network/virtualNetworks',
  virtualHub: 'Microsoft.Network/virtualHubs',
  deployment: 'Microsoft.Resources/deployments',
  storageAccount: 'Microsoft.Storage/storageAccounts',
  maintenanceConfiguration: 'Microsoft.Maintenance/maintenanceConfigurations',
  publicIp: 'Microsoft.Network/publicIPAddresses',
  subnet: 'Microsoft.Network/virtualNetworks/subnets',
} as const;

export function isResourceIdOfType(id: unknown, type: string): id is string {
  if (typeof id !== 'string') return false;
  try {
    return parseResourceId(id).type.toLowerCase() === type.toLowerCase();
  } catch {
    return false;
  }
}

export function resourceName(id: string): string {
  return id.split('/').filter(Boolean).at(-1) ?? id;
}

/** Case-insensitive resource ID comparison (Azure IDs are case-insensitive). */
export function sameResourceId(a?: string, b?: string): boolean {
  return !!a && !!b && a.toLowerCase() === b.toLowerCase();
}

export function portalUrl(id: string): string {
  return `https://portal.azure.com/#resource${id}`;
}
