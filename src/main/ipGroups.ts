import { ResourceManagementClient } from '@azure/arm-resources';
import { getCredential, onSignOut } from './auth';
import { graphQuery, network } from './azure';
import {
  ipGroupErrors,
  type CreateIpGroupRequest,
  type IpGroupContext,
} from '../shared/ipGroups';
import type { IpGroupInfo } from '../shared/types';

// Keep new groups visible in both the list and rule pickers while Resource Graph catches up.
const recentGroups = new Map<string, IpGroupInfo>();
let sessionGeneration = 0;
onSignOut(() => {
  recentGroups.clear();
  sessionGeneration++;
});

export async function discoverIpGroups(): Promise<IpGroupInfo[]> {
  const generation = sessionGeneration;
  const rows = await graphQuery<
    Omit<IpGroupInfo, 'addresses'> & { addresses?: string[] }
  >(
    `resources
     | where type =~ 'microsoft.network/ipgroups'
     | join kind=leftouter (
         resourcecontainers
         | where type =~ 'microsoft.resources/subscriptions'
         | project subscriptionId, subscriptionName = name
       ) on subscriptionId
     | project id, name, resourceGroup, subscriptionId, subscriptionName, location, tags,
               provisioningState = tostring(properties.provisioningState),
               addresses = properties.ipAddresses
     | order by subscriptionName asc, name asc`,
  );
  if (generation !== sessionGeneration)
    throw new Error(
      'The directory changed while loading IP groups. Refresh to try again.',
    );
  const groups = new Map(
    rows.map((g) => [
      g.id.toLowerCase(),
      { ...g, addresses: g.addresses ?? [] },
    ]),
  );
  for (const [id, group] of recentGroups) {
    if (groups.has(id)) recentGroups.delete(id);
    else groups.set(id, group);
  }
  return [...groups.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export async function getIpGroupContext(
  subscriptionId: string,
): Promise<IpGroupContext> {
  const client = new ResourceManagementClient(getCredential(), subscriptionId);
  const [resourceGroups, provider] = await Promise.all([
    (async () => {
      const names: string[] = [];
      for await (const group of client.resourceGroups.list())
        if (group.name) names.push(group.name);
      return names.sort((a, b) => a.localeCompare(b));
    })(),
    client.providers.get('Microsoft.Network'),
  ]);
  const type = provider.resourceTypes?.find(
    (t) => t.resourceType?.toLowerCase() === 'ipgroups',
  );
  const locations = (type?.locations ?? []).map((displayName) => ({
    name: displayName.toLowerCase().replace(/\s+/g, ''),
    displayName,
  }));
  if (!locations.length)
    throw new Error(
      'Azure did not return any locations for IP groups in this subscription. Check that Microsoft.Network is registered.',
    );
  return {
    resourceGroups,
    locations: locations.sort((a, b) =>
      a.displayName.localeCompare(b.displayName),
    ),
  };
}

export async function createIpGroup(
  request: CreateIpGroupRequest,
): Promise<IpGroupInfo> {
  const generation = sessionGeneration;
  const errors = Object.values(ipGroupErrors(request));
  if (errors.length) throw new Error(errors.join('\n'));
  const { subscriptionId, resourceGroup, location, name, addresses } = request;
  const client = network(subscriptionId).ipGroups;
  let exists = false;
  try {
    await client.get(resourceGroup, name);
    exists = true;
  } catch (err) {
    if ((err as { statusCode?: number }).statusCode !== 404) throw err;
  }
  if (exists)
    throw new Error(
      `An IP group named "${name}" already exists in ${resourceGroup}. Choose a different name.`,
    );
  const result = await client.createOrUpdate(resourceGroup, name, {
    location,
    ipAddresses: addresses,
  });
  if (result.provisioningState !== 'Succeeded')
    throw new Error(
      `IP group "${name}" did not finish provisioning (state: ${result.provisioningState ?? 'unknown'}). Refresh to check its status before trying again.`,
    );
  if (!result.id)
    throw new Error(
      'Azure did not return an ID for the created IP group. Refresh to check its status.',
    );
  const group: IpGroupInfo = {
    id: result.id,
    name: result.name ?? name,
    subscriptionId,
    resourceGroup,
    location: result.location ?? location,
    addresses: result.ipAddresses ?? addresses,
    provisioningState: result.provisioningState,
    tags: result.tags,
  };
  if (generation === sessionGeneration)
    recentGroups.set(group.id.toLowerCase(), group);
  return group;
}
