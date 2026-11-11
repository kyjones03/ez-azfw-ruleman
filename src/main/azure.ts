import { ResourceGraphClient } from '@azure/arm-resourcegraph';
import { NetworkManagementClient } from '@azure/arm-network';
import { getCredential, onSignOut } from './auth';
import { parseResourceId } from '../shared/resourceId';
import { explainAzureError } from '../shared/azureErrors';
import {
  isThreatIntelMode,
  policyModeError,
  type PolicyModeConfig,
} from '../shared/policyMode';
import type { ThreatIntelMode } from '../shared/deploy';
import { readPolicySettings } from '../shared/resourceSettings';
import type {
  FirewallSummary,
  PolicySummary,
  RuleCollectionGroup,
} from '../shared/types';

const FIREWALL_QUERY = `
resources
| where type =~ 'microsoft.network/azurefirewalls'
| extend skuName = tostring(properties.sku.name),
         skuTier = tostring(properties.sku.tier),
         policyId = tostring(properties.firewallPolicy.id),
         provisioningState = tostring(properties.provisioningState),
         threatIntelMode = tostring(properties.threatIntelMode),
         privateIp = tostring(coalesce(properties.ipConfigurations[0].properties.privateIPAddress,
                                       properties.hubIPAddresses.privateIPAddress)),
         hubId = tostring(properties.virtualHub.id),
         classicRuleCollectionCount = coalesce(array_length(properties.networkRuleCollections), 0)
                                    + coalesce(array_length(properties.applicationRuleCollections), 0)
                                    + coalesce(array_length(properties.natRuleCollections), 0)
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
  ) on subscriptionId
| project id, name, subscriptionId, subscriptionName, resourceGroup, location, skuName, skuTier,
          policyId, provisioningState, threatIntelMode, privateIp, hubId, classicRuleCollectionCount, tags
| order by subscriptionName asc, name asc`;

const clients = new Map<string, NetworkManagementClient>();
onSignOut(() => clients.clear());

export function network(subscriptionId: string): NetworkManagementClient {
  let client = clients.get(subscriptionId);
  if (!client) {
    client = new NetworkManagementClient(getCredential(), subscriptionId);
    clients.set(subscriptionId, client);
  }
  return client;
}

/** Converts SDK objects (with possible prototypes/undefined fields) into plain JSON. */
function plain<T>(value: unknown): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

const emptyToUndefined = (v: unknown) =>
  typeof v === 'string' && v.length > 0 ? v : undefined;

const QUERY_TIMEOUT_MS = 60_000;

/** Runs a Resource Graph query (all pages). Each page is bounded so a stuck call can't hang the UI. */
export async function graphQuery<T>(
  kql: string,
  subscriptionId?: string,
): Promise<T[]> {
  const client = new ResourceGraphClient(getCredential());
  const rows: T[] = [];
  let skipToken: string | undefined;
  do {
    const page = await client.resources(
      {
        query: kql,
        subscriptions: subscriptionId ? [subscriptionId] : undefined,
        options: { resultFormat: 'objectArray', top: 1000, skipToken },
      },
      { abortSignal: AbortSignal.timeout(QUERY_TIMEOUT_MS) },
    );
    rows.push(...((page.data ?? []) as T[]));
    skipToken = page.skipToken;
  } while (skipToken);
  return rows;
}

export async function discoverFirewalls(): Promise<FirewallSummary[]> {
  const rows = await graphQuery<Record<string, unknown>>(FIREWALL_QUERY);
  return rows.map((row) => ({
    id: String(row.id),
    name: String(row.name),
    subscriptionId: String(row.subscriptionId),
    subscriptionName: emptyToUndefined(row.subscriptionName),
    resourceGroup: String(row.resourceGroup),
    location: String(row.location),
    skuName: emptyToUndefined(row.skuName),
    skuTier: emptyToUndefined(row.skuTier),
    policyId: emptyToUndefined(row.policyId),
    provisioningState: emptyToUndefined(row.provisioningState),
    threatIntelMode: emptyToUndefined(row.threatIntelMode),
    privateIp: emptyToUndefined(row.privateIp),
    hubId: emptyToUndefined(row.hubId),
    classicRuleCollectionCount: Number(row.classicRuleCollectionCount ?? 0),
    tags: toTags(row.tags),
  }));
}

/** Resource Graph returns tags as an object (or null); keep only string values. */
function toTags(v: unknown): Record<string, string> | undefined {
  if (!v || typeof v !== 'object') return undefined;
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v))
    if (val != null) out[k] = String(val);
  return Object.keys(out).length ? out : undefined;
}

export async function getPolicy(policyId: string): Promise<PolicySummary> {
  const { subscriptionId, resourceGroup, name } = parseResourceId(policyId);
  const p = await network(subscriptionId).firewallPolicies.get(
    resourceGroup,
    name,
  );
  return {
    id: p.id ?? policyId,
    name: p.name ?? name,
    subscriptionId,
    resourceGroup,
    location: p.location,
    tier: p.sku?.tier,
    threatIntelMode: p.threatIntelMode,
    settings: readPolicySettings(p, p.identity),
    basePolicyId: p.basePolicy?.id,
    provisioningState: p.provisioningState,
    firewallIds: (p.firewalls ?? [])
      .map((f) => f.id)
      .filter((id): id is string => !!id),
    childPolicyIds: (p.childPolicies ?? [])
      .map((f) => f.id)
      .filter((id): id is string => !!id),
    tags: toTags(p.tags),
  };
}

export async function getPolicyMode(
  policyId: string,
): Promise<PolicyModeConfig & { provisioningState?: string }> {
  const policy = await getPolicy(policyId);
  if (!isThreatIntelMode(policy.threatIntelMode))
    throw new Error(
      `Azure did not return a supported threat-intelligence mode for "${policy.name}".`,
    );
  return {
    name: policy.name,
    threatIntelMode: policy.threatIntelMode,
    provisioningState: policy.provisioningState,
    settings: policy.settings,
  };
}

export async function validatePolicyMode(
  policy: PolicySummary,
  mode: ThreatIntelMode,
): Promise<void> {
  let parentMode: ThreatIntelMode | undefined;
  if (policy.basePolicyId)
    parentMode = (await getPolicyMode(policy.basePolicyId)).threatIntelMode;
  const error = policyModeError(mode, policy.tier, parentMode);
  if (error) throw new Error(error);
}

/** Re-read the full resource so unrelated settings survive a policy update. */
export async function putPolicyMode(
  policyId: string,
  baseline: ThreatIntelMode,
  mode: ThreatIntelMode,
): Promise<void> {
  const { subscriptionId, resourceGroup, name } = parseResourceId(policyId);
  const client = network(subscriptionId).firewallPolicies;
  const current = await client.get(resourceGroup, name);
  if (!isThreatIntelMode(current.threatIntelMode))
    throw new Error(
      'Azure did not return a supported threat-intelligence mode.',
    );
  if (current.threatIntelMode !== baseline && current.threatIntelMode !== mode)
    throw Object.assign(
      new Error(
        'Threat intelligence changed in Azure after this draft started. Discard the policy-settings draft, refresh, and make the change again.',
      ),
      { code: 'PolicyModeConflict' },
    );
  if (current.threatIntelMode === mode) return;
  await validatePolicyMode(
    {
      id: policyId,
      name,
      subscriptionId,
      resourceGroup,
      tier: current.sku?.tier,
      basePolicyId: current.basePolicy?.id,
      firewallIds: [],
      childPolicyIds: [],
    },
    mode,
  );
  await client.createOrUpdate(
    resourceGroup,
    name,
    {
      ...current,
      threatIntelMode: mode,
    },
    current.etag
      ? { requestOptions: { headers: { 'If-Match': current.etag } } }
      : {},
  );
}

function toGroup(raw: unknown): RuleCollectionGroup {
  const g = plain<RuleCollectionGroup>(raw);
  return {
    ...g,
    ruleCollections: (g.ruleCollections ?? []).map((c) => ({
      ...c,
      rules: c.rules ?? [],
    })),
  } as RuleCollectionGroup;
}

export async function listRuleCollectionGroups(
  policyId: string,
): Promise<RuleCollectionGroup[]> {
  const { subscriptionId, resourceGroup, name } = parseResourceId(policyId);
  const groups: RuleCollectionGroup[] = [];
  for await (const g of network(
    subscriptionId,
  ).firewallPolicyRuleCollectionGroups.list(resourceGroup, name)) {
    groups.push(toGroup(g));
  }
  return groups.sort((a, b) => a.priority - b.priority);
}

export async function getRuleCollectionGroup(
  groupId: string,
): Promise<RuleCollectionGroup> {
  const { subscriptionId, resourceGroup, name, childName } =
    parseResourceId(groupId);
  const g = await network(
    subscriptionId,
  ).firewallPolicyRuleCollectionGroups.get(resourceGroup, name, childName!);
  return toGroup(g);
}

export async function putRuleCollectionGroup(
  group: RuleCollectionGroup,
): Promise<RuleCollectionGroup> {
  const { subscriptionId, resourceGroup, name, childName } = parseResourceId(
    group.id,
  );
  const result = await network(
    subscriptionId,
  ).firewallPolicyRuleCollectionGroups.createOrUpdate(
    resourceGroup,
    name,
    childName!,
    // Our types mirror the SDK model; only editable fields are sent.
    {
      priority: group.priority,
      ruleCollections: group.ruleCollections,
    } as never,
  );
  return toGroup(result);
}

/** Turns Azure SDK errors into short, user-facing messages. */
export function describeAzureError(err: unknown): string {
  const e = err as {
    statusCode?: number;
    code?: string;
    message?: string;
    name?: string;
  };
  const explained = explainAzureError(e?.code, e?.message);
  if (explained) return explained;
  if (e?.code === 'PassthroughTokenValidationFailed') {
    return "Azure rejected the sign-in for this directory. Pick the directory that holds your subscriptions from the Directory menu, or sign in again and enter that directory's domain or ID.";
  }
  if (e?.statusCode === 401) {
    const detail = [e.code, e.message].filter(Boolean).join(': ');
    return `Azure rejected the sign-in token.${detail ? ` ${detail}` : ''}`;
  }
  if (e?.statusCode === 403 || e?.code === 'AuthorizationFailed') {
    return `You don't have permission for this operation. ${e.message ?? ''}`.trim();
  }
  if (e?.name === 'AuthenticationRequiredError') {
    return 'Your Azure sign-in needs to be renewed. Sign in again.';
  }
  if (e?.name === 'CredentialUnavailableError') {
    return e.message ?? 'Azure sign-in is required.';
  }
  if (e?.name === 'AbortError' || e?.name === 'TimeoutError') {
    return "Azure didn't answer within a minute. Check your network connection, then try again.";
  }
  const prefix = e?.code && e.code !== 'Error' ? `${e.code}: ` : '';
  return `${prefix}${e?.message ?? String(err)}`;
}
