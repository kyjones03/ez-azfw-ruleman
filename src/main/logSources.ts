// Finds where firewall logs can be read from: Event Hubs namespaces and hubs, and what each
// firewall's diagnostic settings send where. Read-only except for grantReceiver, which the user
// confirms explicitly in the UI.
import { armList, armRequest } from './arm';
import { discoverFirewalls, graphQuery } from './azure';
import { grantRole } from './roleAssignments';
import { loadState } from './store';
import { sameResourceId } from '../shared/resourceId';
import {
  DATA_RECEIVER_ROLE_ID,
  parseDiagnosticSettings,
  type EventHubInfo,
  type EventHubNamespaceInfo,
  type FirewallLogging,
  type LogSources,
} from '../shared/logSources';
import { normaliseNamespace, type LogStreamConfig } from '../shared/logStream';
import { describeAzureError } from './azure';

const EVENTHUB_API_VERSION = '2024-01-01';
const DIAGNOSTICS_API_VERSION = '2021-05-01-preview';
const CONCURRENCY = 4;

const NAMESPACE_QUERY = `
resources
| where type =~ 'microsoft.eventhub/namespaces'
| extend skuTier = tostring(sku.tier)
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
  ) on subscriptionId
| project id, name, subscriptionId, subscriptionName, resourceGroup, location, skuTier
| order by subscriptionName asc, name asc`;

export async function discoverNamespaces(): Promise<EventHubNamespaceInfo[]> {
  const rows = await graphQuery<Record<string, unknown>>(NAMESPACE_QUERY);
  return rows.map((r) => ({
    id: String(r.id),
    name: String(r.name),
    fqdn: `${String(r.name).toLowerCase()}.servicebus.windows.net`,
    subscriptionId: String(r.subscriptionId),
    subscriptionName:
      typeof r.subscriptionName === 'string' ? r.subscriptionName : undefined,
    resourceGroup: String(r.resourceGroup),
    location: String(r.location),
    skuTier: typeof r.skuTier === 'string' && r.skuTier ? r.skuTier : undefined,
  }));
}

/** Runs `fn` over `items` with at most `limit` in flight, keeping the order of results. */
async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out: R[] = Array.from({ length: items.length });
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    }),
  );
  return out;
}

/** What the managed firewalls (or every firewall, when none are chosen) send to Event Hubs. */
async function readFirewallLogging(): Promise<FirewallLogging[]> {
  const all = await discoverFirewalls();
  const managed = loadState().managedFirewallIds;
  const chosen = managed.length
    ? all.filter((f) => managed.some((id) => sameResourceId(id, f.id)))
    : all;
  return mapLimit(chosen, CONCURRENCY, async (fw): Promise<FirewallLogging> => {
    const base = {
      firewallId: fw.id,
      firewallName: fw.name,
      location: fw.location,
      skuTier: fw.skuTier,
    };
    try {
      const { data } = await armRequest<unknown>(
        `${fw.id}/providers/Microsoft.Insights/diagnosticSettings?api-version=${DIAGNOSTICS_API_VERSION}`,
      );
      return { ...base, settings: parseDiagnosticSettings(data) };
    } catch (err) {
      return { ...base, settings: [], readError: describeAzureError(err) };
    }
  });
}

/** Resource groups of one subscription, for choosing where a new namespace goes. */
export async function listResourceGroups(
  subscriptionId: string,
): Promise<{ name: string; location: string }[]> {
  const rows = await graphQuery<{ name: string; location: string }>(
    `resourcecontainers
     | where type =~ 'microsoft.resources/subscriptions/resourcegroups'
     | project name, location
     | order by name asc`,
    subscriptionId,
  );
  return rows.map((r) => ({
    name: String(r.name),
    location: String(r.location),
  }));
}

export async function discoverLogSources(): Promise<LogSources> {
  const [namespaces, firewalls] = await Promise.all([
    discoverNamespaces(),
    readFirewallLogging(),
  ]);
  return { namespaces, firewalls };
}

interface ArmEventHub {
  name?: string;
  properties?: {
    partitionCount?: number;
    retentionDescription?: { retentionTimeInHours?: number };
    messageRetentionInDays?: number;
  };
}

export async function listEventHubs(
  namespaceId: string,
): Promise<EventHubInfo[]> {
  const hubs = await armList<ArmEventHub>(
    `${namespaceId}/eventhubs?api-version=${EVENTHUB_API_VERSION}`,
  );
  return hubs
    .filter(
      (h): h is ArmEventHub & { name: string } => typeof h.name === 'string',
    )
    .map((h) => ({
      name: h.name,
      partitionCount: h.properties?.partitionCount,
      retentionHours:
        h.properties?.retentionDescription?.retentionTimeInHours ??
        (h.properties?.messageRetentionInDays
          ? h.properties.messageRetentionInDays * 24
          : undefined),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export async function listConsumerGroups(
  namespaceId: string,
  eventHub: string,
): Promise<string[]> {
  const groups = await armList<{ name?: string }>(
    `${namespaceId}/eventhubs/${encodeURIComponent(eventHub)}/consumergroups?api-version=${EVENTHUB_API_VERSION}`,
  );
  return groups
    .map((g) => g.name)
    .filter((n): n is string => typeof n === 'string')
    .sort((a, b) => a.localeCompare(b));
}

/**
 * Assigns the signed-in user "Azure Event Hubs Data Receiver" on one event hub (least privilege:
 * not the namespace). Writes to Azure, so the UI asks first. Returns the scope that was used.
 */
export async function grantReceiver(config: LogStreamConfig): Promise<string> {
  const fqdn = normaliseNamespace(config.namespace);
  if (!fqdn) throw new Error('Invalid Event Hubs namespace.');
  const name = fqdn.split('.')[0]; // validated: [a-z0-9-] only, safe to put in a query
  const rows = await graphQuery<{ id: string }>(
    `resources | where type =~ 'microsoft.eventhub/namespaces' | where name =~ '${name}' | project id | limit 1`,
  );
  const namespaceId = rows[0]?.id;
  if (!namespaceId)
    throw new Error(
      `Couldn't find the namespace ${name} in your subscriptions, so the role can't be assigned from here.`,
    );
  const scope = `${namespaceId}/eventhubs/${config.eventHub}`;
  await grantRole(scope, DATA_RECEIVER_ROLE_ID);
  return scope;
}
