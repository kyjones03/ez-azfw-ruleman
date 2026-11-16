// Where the firewall logs go: Event Hub discovery results and what a firewall's diagnostic
// settings say about a hub. Pure functions over untrusted Azure JSON, so they are testable.
import type { LogStreamConfig } from './logStream';

export interface EventHubNamespaceInfo {
  id: string;
  name: string;
  /** contoso-fw.servicebus.windows.net */
  fqdn: string;
  subscriptionId: string;
  subscriptionName?: string;
  resourceGroup: string;
  location: string;
  /** Basic, Standard, Premium. Basic only has the $Default consumer group. */
  skuTier?: string;
}

export interface EventHubInfo {
  name: string;
  partitionCount?: number;
  retentionHours?: number;
}

/** One diagnostic setting of a firewall, reduced to what the Logs view needs. */
export interface DiagnosticSettingSummary {
  name: string;
  /** Namespace resource ID taken from the authorization rule ID; absent when no Event Hub target. */
  eventHubNamespaceId?: string;
  /** Empty means Azure creates one hub per category (insights-logs-*), which we cannot read. */
  eventHubName?: string;
  /** Enabled log categories. */
  categories: string[];
  /** "allLogs" category group: every category, including the Policy Analytics aggregation ones. */
  allLogs: boolean;
  logAnalytics: boolean;
  storage: boolean;
}

export interface FirewallLogging {
  firewallId: string;
  firewallName: string;
  /** Azure region, e.g. "eastus2". */
  location?: string;
  skuTier?: string;
  settings: DiagnosticSettingSummary[];
  /** Set when the settings could not be read (no Reader/Monitoring Reader on the firewall). */
  readError?: string;
}

export interface LogSources {
  namespaces: EventHubNamespaceInfo[];
  firewalls: FirewallLogging[];
}

// ── categories ───────────────────────────────────────────────────────────────

interface CategoryDef {
  label: string;
  /** Structured (resource-specific) and legacy diagnostic category names; either one counts. */
  names: string[];
  tier: 'core' | 'recommended' | 'troubleshooting';
  premiumOnly?: boolean;
}

export const CATEGORY_DEFS: readonly CategoryDef[] = [
  {
    label: 'NetworkRule',
    names: ['AZFWNetworkRule', 'AzureFirewallNetworkRule'],
    tier: 'core',
  },
  {
    label: 'AppRule',
    names: ['AZFWApplicationRule', 'AzureFirewallApplicationRule'],
    tier: 'core',
  },
  {
    label: 'NATRule',
    // Azure offers no legacy NAT category (spike 4a), so only the structured one can carry it.
    names: ['AZFWNatRule'],
    tier: 'core',
  },
  { label: 'ThreatIntel', names: ['AZFWThreatIntel'], tier: 'recommended' },
  {
    label: 'IDPS',
    names: ['AZFWIdpsSignature'],
    tier: 'recommended',
    premiumOnly: true,
  },
  {
    label: 'DnsQuery',
    names: ['AZFWDnsQuery', 'AzureFirewallDnsProxy'],
    tier: 'recommended',
  },
  {
    label: 'DnsFailure',
    names: ['AZFWFqdnResolveFailure', 'AZFWInternalFqdnResolutionFailure'],
    tier: 'recommended',
  },
  // Both need extra switches on the firewall and add real volume: never reported as missing.
  { label: 'FlowTrace', names: ['AZFWFlowTrace'], tier: 'troubleshooting' },
  { label: 'FatFlow', names: ['AZFWFatFlow'], tier: 'troubleshooting' },
];

export type CoverageState = 'none' | 'incomplete' | 'complete';

export interface Coverage {
  /** none: no diagnostic setting sends this firewall's logs to the hub. */
  state: CoverageState;
  /** Rule categories the hub does not carry: the Logs view would miss decisions. */
  missingCore: string[];
  missingRecommended: string[];
  /** The hub carries every category (allLogs), including ones that are not displayed. */
  allLogs: boolean;
  /** A setting sends to this namespace without naming a hub (one hub per category). */
  perCategoryHubs: boolean;
}

const lower = (v: string | undefined) => (v ?? '').toLowerCase();

/** "contoso-fw" from "contoso-fw.servicebus.windows.net", or the name itself. */
export const namespaceShortName = (namespace: string): string =>
  lower(namespace).split('.')[0];

/**
 * Which log categories reach `namespace`/`eventHub`, judged from the firewall's diagnostic
 * settings. A setting counts when it targets that namespace and names that hub.
 */
export function eventHubCoverage(
  settings: readonly DiagnosticSettingSummary[],
  namespace: string,
  eventHub: string,
  skuTier?: string,
): Coverage {
  const short = namespaceShortName(namespace);
  const toNamespace = settings.filter(
    (s) =>
      s.eventHubNamespaceId &&
      lower(s.eventHubNamespaceId.split('/').pop()) === short,
  );
  const matching = toNamespace.filter(
    (s) => lower(s.eventHubName) === lower(eventHub),
  );
  const perCategoryHubs = toNamespace.some((s) => !s.eventHubName);
  if (matching.length === 0)
    return {
      state: 'none',
      missingCore: [],
      missingRecommended: [],
      allLogs: false,
      perCategoryHubs,
    };

  const allLogs = matching.some((s) => s.allLogs);
  const enabled = new Set(matching.flatMap((s) => s.categories.map(lower)));
  const carried = (d: CategoryDef) =>
    allLogs || d.names.some((n) => enabled.has(lower(n)));
  const premium = lower(skuTier) === 'premium';
  const missing = (tier: CategoryDef['tier']) =>
    CATEGORY_DEFS.filter(
      (d) =>
        d.tier === tier &&
        !carried(d) &&
        (!d.premiumOnly || premium || skuTier === undefined),
    ).map((d) => d.label);
  const missingCore = missing('core');
  return {
    state: missingCore.length ? 'incomplete' : 'complete',
    missingCore,
    missingRecommended: missing('recommended'),
    allLogs,
    perCategoryHubs,
  };
}

// ── diagnostic settings ──────────────────────────────────────────────────────

const NAMESPACE_OF_RULE =
  /^(\/subscriptions\/[^/]+\/resourceGroups\/[^/]+\/providers\/Microsoft\.EventHub\/namespaces\/[^/]+)\/authorizationrules\/[^/]+$/i;

const obj = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
const str = (v: unknown): string => (typeof v === 'string' ? v : '');

/** Reads the `value` array of a diagnosticSettings list response; ignores anything malformed. */
export function parseDiagnosticSettings(
  response: unknown,
): DiagnosticSettingSummary[] {
  const value = obj(response).value;
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry): DiagnosticSettingSummary[] => {
    const e = obj(entry);
    const props = obj(e.properties);
    const ruleId = str(props.eventHubAuthorizationRuleId);
    const namespaceId = NAMESPACE_OF_RULE.exec(ruleId)?.[1];
    const logs = Array.isArray(props.logs) ? props.logs.map(obj) : [];
    const on = logs.filter((l) => l.enabled === true);
    return [
      {
        name: str(e.name),
        eventHubNamespaceId: namespaceId,
        eventHubName: namespaceId ? str(props.eventHubName) : undefined,
        categories: on.map((l) => str(l.category)).filter(Boolean),
        allLogs: on.some((l) => lower(str(l.categoryGroup)) === 'alllogs'),
        logAnalytics: !!str(props.workspaceId),
        storage: !!str(props.storageAccountId),
      },
    ];
  });
}

// ── detected hubs ────────────────────────────────────────────────────────────

export interface DetectedHub {
  firewallId: string;
  firewallName: string;
  namespaceId: string;
  namespaceName: string;
  /** Empty when the setting sends to per-category hubs. */
  eventHub: string;
  coverage: Coverage;
}

/** Every (firewall → hub) pair found in diagnostic settings, one per distinct namespace/hub. */
export function detectedHubs(
  firewalls: readonly FirewallLogging[],
): DetectedHub[] {
  const out: DetectedHub[] = [];
  for (const fw of firewalls) {
    const seen = new Set<string>();
    for (const s of fw.settings) {
      if (!s.eventHubNamespaceId) continue;
      const namespaceName = s.eventHubNamespaceId.split('/').pop() ?? '';
      const key = `${lower(namespaceName)}/${lower(s.eventHubName)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        firewallId: fw.firewallId,
        firewallName: fw.firewallName,
        namespaceId: s.eventHubNamespaceId,
        namespaceName,
        eventHub: s.eventHubName ?? '',
        coverage: eventHubCoverage(
          fw.settings,
          namespaceName,
          s.eventHubName ?? '',
          fw.skuTier,
        ),
      });
    }
  }
  return out;
}

/** Fills a config from a detected hub (the consumer group and position keep their defaults). */
export function configFromDetected(
  hub: DetectedHub,
  base: Pick<LogStreamConfig, 'consumerGroup' | 'startPosition'>,
): Pick<
  LogStreamConfig,
  'namespace' | 'eventHub' | 'consumerGroup' | 'startPosition'
> {
  return {
    namespace: `${hub.namespaceName.toLowerCase()}.servicebus.windows.net`,
    eventHub: hub.eventHub,
    ...base,
  };
}

/** The Event Hub data role the Logs view needs, assignable at hub scope. */
export const DATA_RECEIVER_ROLE_ID = 'a638d3c7-ab3a-418d-83e6-5f17a39d4fde';
