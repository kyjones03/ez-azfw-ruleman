// Cleaning up diagnostic settings that send to an Event Hubs namespace which no longer exists.
//
// Azure keeps such a setting after the namespace is deleted (it still names the deleted rule), and it
// still counts towards the limit of five settings per firewall. Pure planning code; the main process
// decides which namespaces are really gone (only a "not found" answer counts) and applies the plan.
import type { FirewallLogging } from './logSources';

type Json = Record<string, unknown>;
const obj = (v: unknown): Json =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {};
const lower = (v: unknown) => (typeof v === 'string' ? v.toLowerCase() : '');
const filled = (v: unknown) => typeof v === 'string' && v.trim() !== '';

/** The namespace resource ID inside an authorization rule ID, lower-cased for comparison. */
export function namespaceIdOfRule(ruleId: unknown): string | undefined {
  if (typeof ruleId !== 'string') return undefined;
  const at = ruleId.toLowerCase().indexOf('/authorizationrules/');
  return at > 0 ? ruleId.slice(0, at) : undefined;
}

/** A setting that sends to a namespace that was confirmed gone. */
export interface DanglingSetting {
  firewallId: string;
  firewallName: string;
  settingName: string;
  namespaceId: string;
  eventHubName?: string;
}

/**
 * Settings whose Event Hub target is in `goneNamespaceIds`. Namespaces that could not be checked are
 * simply not in that set, so an unreadable namespace never produces a candidate.
 */
export function danglingSettings(
  firewalls: readonly FirewallLogging[],
  goneNamespaceIds: ReadonlySet<string>,
): DanglingSetting[] {
  const gone = new Set([...goneNamespaceIds].map(lower));
  const out: DanglingSetting[] = [];
  for (const fw of firewalls)
    for (const s of fw.settings)
      if (s.eventHubNamespaceId && gone.has(lower(s.eventHubNamespaceId)))
        out.push({
          firewallId: fw.firewallId,
          firewallName: fw.firewallName,
          settingName: s.name,
          namespaceId: s.eventHubNamespaceId,
          eventHubName: s.eventHubName,
        });
  return out;
}

/** Destinations other than an Event Hub that a setting can have. */
const OTHER_DESTINATIONS: { key: string; label: string }[] = [
  { key: 'workspaceId', label: 'Log Analytics' },
  { key: 'storageAccountId', label: 'Storage' },
  { key: 'serviceBusRuleId', label: 'Service Bus' },
  { key: 'marketplacePartnerId', label: 'a partner solution' },
];

export type CleanupPlan =
  | {
      /** Remove only the Event Hub destination; the setting keeps its other destinations. */
      action: 'trim';
      body: { properties: Json };
      kept: string[];
      lines: string[];
    }
  | {
      /** The Event Hub was the only destination, so nothing useful is left to keep. */
      action: 'delete';
      kept: [];
      lines: string[];
    }
  | { action: 'noop'; kept: []; lines: [] };

function withoutNulls<T>(value: T): T {
  if (Array.isArray(value)) return value.map(withoutNulls) as T;
  if (value && typeof value === 'object') {
    const out: Json = {};
    for (const [k, v] of Object.entries(value as Json))
      if (v !== null && v !== undefined) out[k] = withoutNulls(v);
    return out as T;
  }
  return value;
}

/**
 * What to do with `existing` (a diagnostic setting as Azure returned it) whose Event Hub namespace
 * is gone. Trims when another destination remains, deletes when the Event Hub was the only one, and
 * does nothing when the setting no longer points at that namespace (it changed since discovery).
 */
export function planCleanup(
  existing: unknown,
  firewallName: string,
  namespaceId: string,
): CleanupPlan {
  const name = String(obj(existing).name ?? '');
  const props: Json = JSON.parse(JSON.stringify(obj(obj(existing).properties)));
  if (
    lower(namespaceIdOfRule(props.eventHubAuthorizationRuleId)) !==
    lower(namespaceId)
  )
    return { action: 'noop', kept: [], lines: [] };

  const hub = filled(props.eventHubName)
    ? ` (event hub ${props.eventHubName})`
    : '';
  const gone = `namespace ${namespaceId.split('/').pop()}${hub}, which no longer exists`;
  const kept = OTHER_DESTINATIONS.filter((d) => filled(props[d.key])).map(
    (d) => d.label,
  );

  if (kept.length === 0)
    return {
      action: 'delete',
      kept: [],
      lines: [
        `${firewallName}: delete diagnostic setting "${name}". It only sent to ${gone}.`,
      ],
    };

  delete props.eventHubName;
  delete props.eventHubAuthorizationRuleId;
  return {
    action: 'trim',
    body: { properties: withoutNulls(props) },
    kept,
    lines: [
      `${firewallName}: diagnostic setting "${name}": stop sending to ${gone}. It keeps ${kept.join(' and ')} and its categories.`,
    ],
  };
}

/** Permission needed, shown in the review. */
export const CLEANUP_PERMISSION =
  'Change the diagnostic setting: Monitoring Contributor on the firewall';

/** What the review shows before a cleanup is applied. */
export interface CleanupReview {
  action: 'trim' | 'delete';
  /** Every change, one line each. */
  lines: string[];
  permission: string;
  /** Changes when the plan would change; sent back on apply so a stale review cannot run. */
  hash: string;
}
