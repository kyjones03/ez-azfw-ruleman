// Setting up firewall logging: creating the Event Hub and the firewall's diagnostic setting.
//
// Pure planning code. The wizard builds a ProvisionRequest, `buildProvisionPlan` turns it into an
// ordered list of steps, and the review screen and the executor both read that same plan, so what
// the user confirms is what runs. Rules here come from the Azure documentation and from running
// the calls against a scratch resource group.
import { APP_TAG, normalizeLocation } from './deploy';
import {
  CATEGORY_DEFS,
  DATA_RECEIVER_ROLE_ID,
  namespaceShortName,
} from './logSources';
import { DEFAULT_CONSUMER_GROUP, type LogStreamConfig } from './logStream';
import { nameError } from './naming';
import {
  isResourceIdOfType,
  parseResourceId,
  RESOURCE_TYPES,
} from './resourceId';

export const SEND_RULE_NAME = 'ez-azfw-logs-send';
export const DEFAULT_HUB_NAME = 'firewall-logs';
export const DEFAULT_SETTING_NAME = 'ez-azfw-logs';
/** Standard and above only; Basic has no consumer groups besides $Default. */
export const STANDARD_CONSUMER_GROUP = 'ruleman';
/** Azure allows at most five diagnostic settings on a resource. */
export const MAX_DIAGNOSTIC_SETTINGS = 5;
export const EVENTHUB_API_VERSION = '2024-01-01';
export const DIAGNOSTIC_SETTINGS_API_VERSION = '2021-05-01-preview';
export const DATA_RECEIVER_ROLE_NAME = 'Azure Event Hubs Data Receiver';
const TEMPLATE_SCHEMA =
  'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#';

export type HubTier = 'Basic' | 'Standard';
export const HUB_TIERS: HubTier[] = ['Basic', 'Standard'];
/** Basic keeps events for one day at most; Standard for up to seven. */
export const MAX_RETENTION_HOURS: Record<HubTier, number> = {
  Basic: 24,
  Standard: 168,
};
export const DEFAULT_RETENTION_HOURS = 24;

/** Rough monthly prices from Microsoft's Event Hubs pricing page (US list prices, one throughput unit). */
export const COST_NOTE: Record<HubTier, string> = {
  Basic:
    'about $11 per month plus about $0.03 per million events (approximate; varies by region and agreement)',
  Standard:
    'about $22 per month plus about $0.03 per million events (approximate; varies by region and agreement)',
};

// ── request ──────────────────────────────────────────────────────────────────

export interface ProvisionFirewall {
  id: string;
  name: string;
  /** Azure region, e.g. "eastus2". */
  location: string;
  skuTier?: string;
}

export type ProvisionDestination =
  | {
      kind: 'new';
      subscriptionId: string;
      resourceGroup: string;
      createResourceGroup: boolean;
      namespaceName: string;
      tier: HubTier;
      eventHub: string;
      retentionHours: number;
    }
  | {
      kind: 'existing';
      namespaceId: string;
      namespaceLocation: string;
      /** Basic, Standard or Premium, when known. */
      tier?: string;
      eventHub: string;
      /** False when the hub is already there. */
      createEventHub: boolean;
      retentionHours: number;
    };

export interface ProvisionRequest {
  firewalls: ProvisionFirewall[];
  destination: ProvisionDestination;
  /** Category names to send, exactly as the firewalls offer them. */
  categories: string[];
  settingName: string;
  /** Also give the signed-in user the Data Receiver role on the hub. */
  grantRole: boolean;
}

/** What Azure says about one firewall right now. */
export interface FirewallLoggingState {
  firewallId: string;
  /** Log categories the firewall offers (`diagnosticSettingsCategories`). */
  offeredCategories: string[];
  /** The `value` entries of the diagnostic settings list, as returned by Azure. */
  existingSettings: unknown[];
}

/** Resource providers the steps depend on, and whether the subscription has them registered. */
export interface ProviderState {
  subscriptionId: string;
  namespace: 'Microsoft.EventHub' | 'Microsoft.Insights';
  registered: boolean;
}

export interface ProvisionContext {
  firewalls: FirewallLoggingState[];
  /** Left out when not checked; a missing entry is treated as registered. */
  providers?: ProviderState[];
}

// ── names and categories ─────────────────────────────────────────────────────

const lower = (v: unknown) => (typeof v === 'string' ? v.toLowerCase() : '');
const sameText = (a: unknown, b: unknown) =>
  !!lower(a) && lower(a) === lower(b);

/** The name the log view uses for a category: NetworkRule, AppRule, NATRule … */
export const labelOf = (category: string): string =>
  CATEGORY_DEFS.find((d) => d.names.some((n) => sameText(n, category)))
    ?.label ?? category;

const tierOfCategory = (category: string) =>
  CATEGORY_DEFS.find((d) => d.names.some((n) => sameText(n, category)))?.tier;

/**
 * The categories to offer in the wizard, in display order, as the firewall names them. Structured
 * names win over legacy ones. `allLogs` is never used: it adds the Policy Analytics aggregation
 * categories, which the view does not show.
 */
export function selectableCategories(offered: readonly string[]): {
  core: string[];
  recommended: string[];
  troubleshooting: string[];
} {
  const out = {
    core: [] as string[],
    recommended: [] as string[],
    troubleshooting: [] as string[],
  };
  for (const def of CATEGORY_DEFS) {
    const name = def.names
      .map((n) => offered.find((o) => sameText(o, n)))
      .find((n): n is string => !!n);
    if (name) out[def.tier].push(name);
  }
  return out;
}

/** Core and recommended categories; the noisy troubleshooting ones are opt-in. */
export function defaultCategories(offered: readonly string[]): string[] {
  const s = selectableCategories(offered);
  return [...s.core, ...s.recommended];
}

export function eventHubNamespaceError(name: string): string | undefined {
  return nameError('eventHubNamespace', name);
}

// ── destination facts derived from the request ───────────────────────────────

export interface DestinationInfo {
  subscriptionId: string;
  resourceGroup: string;
  namespaceName: string;
  namespaceId: string;
  /** The rule diagnostic settings use to send. Azure treats it as the data sink. */
  ruleId: string;
  hubId: string;
  eventHub: string;
  location: string;
  tier: string | undefined;
  createsNamespace: boolean;
  createsHub: boolean;
  consumerGroup: string;
  /** Whether a consumer group is created (Standard and above). */
  createsConsumerGroup: boolean;
  retentionHours: number;
}

export function destinationInfo(req: ProvisionRequest): DestinationInfo {
  const d = req.destination;
  if (d.kind === 'new') {
    const namespaceId = `/subscriptions/${d.subscriptionId}/resourceGroups/${d.resourceGroup}/providers/Microsoft.EventHub/namespaces/${d.namespaceName}`;
    const standard = d.tier !== 'Basic';
    return {
      subscriptionId: d.subscriptionId,
      resourceGroup: d.resourceGroup,
      namespaceName: d.namespaceName,
      namespaceId,
      ruleId: `${namespaceId}/authorizationRules/${SEND_RULE_NAME}`,
      hubId: `${namespaceId}/eventhubs/${d.eventHub}`,
      eventHub: d.eventHub,
      location: normalizeLocation(req.firewalls[0]?.location ?? ''),
      tier: d.tier,
      createsNamespace: true,
      createsHub: true,
      consumerGroup: standard
        ? STANDARD_CONSUMER_GROUP
        : DEFAULT_CONSUMER_GROUP,
      createsConsumerGroup: standard,
      retentionHours: d.retentionHours,
    };
  }
  const parsed = parseResourceId(d.namespaceId);
  const standard = !!d.tier && d.tier.toLowerCase() !== 'basic';
  return {
    subscriptionId: parsed.subscriptionId,
    resourceGroup: parsed.resourceGroup,
    namespaceName: parsed.name,
    namespaceId: d.namespaceId,
    ruleId: `${d.namespaceId}/authorizationRules/${SEND_RULE_NAME}`,
    hubId: `${d.namespaceId}/eventhubs/${d.eventHub}`,
    eventHub: d.eventHub,
    location: normalizeLocation(d.namespaceLocation),
    tier: d.tier,
    createsNamespace: false,
    createsHub: d.createEventHub,
    consumerGroup: standard ? STANDARD_CONSUMER_GROUP : DEFAULT_CONSUMER_GROUP,
    createsConsumerGroup: standard,
    retentionHours: d.retentionHours,
  };
}

// ── the Event Hubs template ──────────────────────────────────────────────────

/**
 * Resource-group-scope template for what has to exist before a diagnostic setting can send:
 * the namespace and hub when they are new, always the Send-only rule, and a consumer group on
 * Standard and above. Local authentication is disabled on new namespaces: diagnostic settings
 * still deliver (checked against Azure), and logs are read with Entra ID only.
 *
 * An existing namespace is never redeclared, so its settings are left alone.
 */
export function buildEventHubTemplate(req: ProvisionRequest) {
  const info = destinationInfo(req);
  const ns = info.namespaceName;
  const nsRef = `[resourceId('Microsoft.EventHub/namespaces', '${ns}')]`;
  const hubRef = `[resourceId('Microsoft.EventHub/namespaces/eventhubs', '${ns}', '${info.eventHub}')]`;
  const resources: Record<string, unknown>[] = [];

  if (info.createsNamespace) {
    const tier = (req.destination as { tier: HubTier }).tier;
    resources.push({
      type: 'Microsoft.EventHub/namespaces',
      apiVersion: EVENTHUB_API_VERSION,
      name: ns,
      location: info.location,
      tags: { createdBy: APP_TAG },
      sku: { name: tier, tier, capacity: 1 },
      properties: {
        minimumTlsVersion: '1.2',
        disableLocalAuth: true,
      },
    });
  }
  const dependsOnNamespace = info.createsNamespace ? [nsRef] : undefined;
  if (info.createsHub) {
    resources.push({
      type: 'Microsoft.EventHub/namespaces/eventhubs',
      apiVersion: EVENTHUB_API_VERSION,
      name: `${ns}/${info.eventHub}`,
      dependsOn: dependsOnNamespace,
      properties: {
        partitionCount: 1,
        // Always spelled out: a default above what Basic allows makes the create fail.
        retentionDescription: {
          cleanupPolicy: 'Delete',
          retentionTimeInHours: info.retentionHours,
        },
      },
    });
  }
  resources.push({
    type: 'Microsoft.EventHub/namespaces/authorizationRules',
    apiVersion: EVENTHUB_API_VERSION,
    name: `${ns}/${SEND_RULE_NAME}`,
    dependsOn: dependsOnNamespace,
    properties: { rights: ['Send'] },
  });
  if (info.createsConsumerGroup) {
    resources.push({
      type: 'Microsoft.EventHub/namespaces/eventhubs/consumergroups',
      apiVersion: EVENTHUB_API_VERSION,
      name: `${ns}/${info.eventHub}/${STANDARD_CONSUMER_GROUP}`,
      dependsOn: info.createsHub ? [hubRef] : dependsOnNamespace,
      properties: {},
    });
  }
  return {
    $schema: TEMPLATE_SCHEMA,
    contentVersion: '1.0.0.0',
    resources: resources.map((r) => JSON.parse(JSON.stringify(r))) as Record<
      string,
      unknown
    >[],
  };
}

// ── diagnostic settings ──────────────────────────────────────────────────────

type Json = Record<string, unknown>;
const obj = (v: unknown): Json =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {};

/** Drops `null` values (Azure returns them for unset properties) at every depth. */
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

export interface DiagnosticSettingBody {
  properties: Json;
}

export interface MergeResult {
  body: DiagnosticSettingBody;
  /** Plain-language list of what changes; empty when nothing does. */
  changes: string[];
  noop: boolean;
}

const isAllLogsOn = (log: Json) =>
  lower(log.categoryGroup) === 'alllogs' && log.enabled === true;

/**
 * The body to PUT for a diagnostic setting that must send `categories` to `target`.
 *
 * A PUT replaces the whole setting, so this starts from what Azure returned and changes only what
 * it has to: the event hub destination and the `enabled` flag of the wanted categories. Other
 * destinations (Log Analytics, Storage), other categories, metrics and the `allLogs` group stay
 * exactly as they were. With `allLogs` on, categories are already covered and are not added.
 */
export function mergeDiagnosticSetting(
  existing: unknown,
  target: { ruleId: string; eventHub: string },
  categories: readonly string[],
): MergeResult {
  const props: Json = JSON.parse(JSON.stringify(obj(obj(existing).properties)));
  const logs: Json[] = Array.isArray(props.logs) ? props.logs.map(obj) : [];
  const changes: string[] = [];

  const allLogs = logs.some(isAllLogsOn);
  for (const category of new Set(categories)) {
    const entry = logs.find((l) => sameText(l.category, category));
    if (entry) {
      if (entry.enabled !== true && !allLogs) {
        entry.enabled = true;
        changes.push(`Turn on ${labelOf(category)}`);
      }
    } else if (!allLogs) {
      logs.push({ category, enabled: true });
      changes.push(`Turn on ${labelOf(category)}`);
    }
  }
  props.logs = logs;
  if (!Array.isArray(props.metrics)) props.metrics = [];

  const sameSink =
    sameText(props.eventHubAuthorizationRuleId, target.ruleId) &&
    sameText(props.eventHubName, target.eventHub);
  if (!sameSink) {
    const was =
      typeof props.eventHubName === 'string' ? props.eventHubName : '';
    changes.unshift(
      was
        ? `Change the event hub from ${was} to ${target.eventHub}`
        : `Send to event hub ${target.eventHub}`,
    );
    props.eventHubAuthorizationRuleId = target.ruleId;
    props.eventHubName = target.eventHub;
  }
  return {
    body: { properties: withoutNulls(props) },
    changes,
    noop: changes.length === 0,
  };
}

export type SettingPlan =
  | {
      action: 'create' | 'update' | 'noop';
      settingName: string;
      body: DiagnosticSettingBody;
      changes: string[];
    }
  | { action: 'blocked'; settingName: string; reason: string };

const settingsOf = (list: unknown[]) =>
  list.map((s) => ({
    raw: s,
    name: String(obj(s).name ?? ''),
    props: obj(obj(s).properties),
  }));

const enabledCategories = (props: Json): string[] =>
  (Array.isArray(props.logs) ? props.logs.map(obj) : [])
    .filter((l) => l.enabled === true && typeof l.category === 'string')
    .map((l) => l.category as string);

/** "name", then "name-2", "name-3" … the first one no existing setting uses. */
export function uniqueSettingName(
  base: string,
  taken: readonly string[],
): string {
  const used = new Set(taken.map((t) => t.toLowerCase()));
  if (!used.has(base.toLowerCase())) return base;
  for (let i = 2; ; i++) {
    const candidate = `${base}-${i}`;
    if (!used.has(candidate.toLowerCase())) return candidate;
  }
}

/**
 * Decides how to get one firewall to send `categories` to the hub:
 *
 * - A setting that already uses the same rule is the sink's owner (Azure allows a sink once per
 *   category on a resource). On the same hub it is updated in place; on another hub, with
 *   categories that overlap, it is blocked, because changing it would redirect logs someone else
 *   set up.
 * - Otherwise a new setting is created, under a name no existing setting uses, unless the
 *   firewall already has five.
 */
export function planDiagnosticSetting(
  existingSettings: unknown[],
  desired: {
    settingName: string;
    ruleId: string;
    eventHub: string;
    categories: readonly string[];
  },
): SettingPlan {
  const settings = settingsOf(existingSettings);
  const owner = settings.find((s) =>
    sameText(s.props.eventHubAuthorizationRuleId, desired.ruleId),
  );

  if (owner) {
    if (sameText(owner.props.eventHubName, desired.eventHub)) {
      const merged = mergeDiagnosticSetting(
        owner.raw,
        { ruleId: desired.ruleId, eventHub: desired.eventHub },
        desired.categories,
      );
      return {
        action: merged.noop ? 'noop' : 'update',
        settingName: owner.name,
        body: merged.body,
        changes: merged.changes,
      };
    }
    const taken = new Set(
      enabledCategories(owner.props).map((c) => c.toLowerCase()),
    );
    const allLogs = (
      Array.isArray(owner.props.logs) ? owner.props.logs.map(obj) : []
    ).some(isAllLogsOn);
    const overlap =
      allLogs || desired.categories.some((c) => taken.has(c.toLowerCase()));
    if (overlap) {
      return {
        action: 'blocked',
        settingName: owner.name,
        reason: `The diagnostic setting "${owner.name}" already sends some of these categories to the event hub "${String(owner.props.eventHubName ?? '')}" through the same access rule, and Azure allows that only once. Use a different namespace, or change that setting in the Azure portal.`,
      };
    }
  }

  if (settings.length >= MAX_DIAGNOSTIC_SETTINGS) {
    return {
      action: 'blocked',
      settingName: desired.settingName,
      reason: `This firewall already has ${MAX_DIAGNOSTIC_SETTINGS} diagnostic settings, the most Azure allows. Delete one you no longer need in the Azure portal, then try again.`,
    };
  }
  const settingName = uniqueSettingName(
    desired.settingName,
    settings.map((s) => s.name),
  );
  const merged = mergeDiagnosticSetting(
    undefined,
    { ruleId: desired.ruleId, eventHub: desired.eventHub },
    desired.categories,
  );
  return {
    action: 'create',
    settingName,
    body: merged.body,
    changes: merged.changes,
  };
}

// ── validation ───────────────────────────────────────────────────────────────

const SUBSCRIPTION_ID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;

export interface ProvisionCheck {
  errors: string[];
  warnings: string[];
}

export function validateProvisionRequest(
  req: ProvisionRequest,
  ctx: ProvisionContext,
): ProvisionCheck {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Firewalls: at least one, one region (the hub must be in it).
  if (!Array.isArray(req.firewalls) || req.firewalls.length === 0) {
    errors.push('Choose at least one firewall.');
    return { errors, warnings };
  }
  for (const fw of req.firewalls)
    if (!isResourceIdOfType(fw.id, RESOURCE_TYPES.firewall))
      errors.push(`"${fw.name}" is not a firewall resource ID.`);
  const regions = new Set(
    req.firewalls.map((f) => normalizeLocation(f.location)),
  );
  if (regions.size > 1)
    errors.push(
      `These firewalls are in different regions (${[...regions].join(', ')}). An event hub must be in the same region as the firewall that sends to it, so set them up one region at a time.`,
    );
  const location = normalizeLocation(req.firewalls[0].location);

  // Destination.
  const d = req.destination;
  if (d?.kind === 'new') {
    if (!SUBSCRIPTION_ID.test(d.subscriptionId ?? ''))
      errors.push('Choose a subscription.');
    const rg = nameError('resourceGroup', d.resourceGroup);
    if (rg) errors.push(rg);
    const ns = nameError('eventHubNamespace', d.namespaceName);
    if (ns) errors.push(ns);
    if (!HUB_TIERS.includes(d.tier))
      errors.push('Choose the Basic or Standard tier.');
  } else if (d?.kind === 'existing') {
    if (!isResourceIdOfType(d.namespaceId, RESOURCE_TYPES.eventHubNamespace))
      errors.push('Choose an Event Hubs namespace.');
    else if (normalizeLocation(d.namespaceLocation ?? '') !== location)
      errors.push(
        `This namespace is in ${normalizeLocation(d.namespaceLocation ?? '') || 'an unknown region'}, but the firewall is in ${location}. An event hub must be in the same region as the firewall that sends to it.`,
      );
  } else {
    errors.push('Choose where the logs should go.');
    return { errors, warnings };
  }
  const hub = nameError('eventHub', d.eventHub);
  if (hub) errors.push(hub);
  if (d.kind === 'new' || d.createEventHub) {
    const tier =
      d.kind === 'new'
        ? d.tier
        : d.tier?.toLowerCase() === 'basic'
          ? 'Basic'
          : 'Standard';
    const max =
      MAX_RETENTION_HOURS[tier as HubTier] ?? MAX_RETENTION_HOURS.Standard;
    if (
      !Number.isInteger(d.retentionHours) ||
      d.retentionHours < 1 ||
      d.retentionHours > max
    )
      errors.push(
        `Retention must be 1 to ${max} hours${tier === 'Basic' ? ' on the Basic tier' : ''}.`,
      );
  }
  const setting = nameError('diagnosticSetting', req.settingName);
  if (setting) errors.push(setting);

  // Categories.
  const categories = [...new Set(req.categories ?? [])];
  if (categories.length === 0) errors.push('Choose at least one log category.');
  for (const fw of req.firewalls) {
    const state = ctx.firewalls.find((s) => sameText(s.firewallId, fw.id));
    if (!state) continue;
    const missing = categories.filter(
      (c) => !state.offeredCategories.some((o) => sameText(o, c)),
    );
    if (missing.length)
      errors.push(
        `${fw.name} doesn't offer ${missing.map(labelOf).join(', ')}.`,
      );
  }
  if (categories.length && errors.length === 0) {
    const core = categories.filter((c) => tierOfCategory(c) === 'core');
    if (core.length < CATEGORY_DEFS.filter((d) => d.tier === 'core').length)
      warnings.push(
        'Some rule categories (NetworkRule, AppRule, NATRule) are not selected. The log view will miss those decisions.',
      );
    const noisy = categories
      .filter((c) => tierOfCategory(c) === 'troubleshooting')
      .map(labelOf);
    if (noisy.length)
      warnings.push(
        `${noisy.join(' and ')} can produce a lot of data and need an extra switch on the firewall. Turn them on for troubleshooting, not permanently.`,
      );
  }

  // Things only the current state of the firewalls can tell: blocked settings.
  if (errors.length === 0) {
    for (const p of buildProvisionPlan(req, ctx).blocked) errors.push(p);
  }
  return { errors, warnings };
}

// ── plan ─────────────────────────────────────────────────────────────────────

export type ProvisionStep =
  | {
      kind: 'registerProvider';
      subscriptionId: string;
      namespace: ProviderState['namespace'];
    }
  | {
      kind: 'resourceGroup';
      subscriptionId: string;
      name: string;
      location: string;
    }
  | {
      kind: 'eventHubs';
      subscriptionId: string;
      resourceGroup: string;
      template: ReturnType<typeof buildEventHubTemplate>;
      /** What the template creates, for the review. */
      creates: string[];
    }
  | {
      kind: 'diagnosticSetting';
      firewallId: string;
      firewallName: string;
      action: 'create' | 'update' | 'noop';
      settingName: string;
      body: DiagnosticSettingBody;
      changes: string[];
    }
  | { kind: 'role'; scope: string; roleId: string; roleName: string };

export interface ProvisionPlan {
  steps: ProvisionStep[];
  /** Problems that stop the plan (a setting that cannot be created). Empty when it can run. */
  blocked: string[];
  /** The Logs view settings to connect with afterwards. */
  connect: LogStreamConfig;
  info: DestinationInfo;
}

export function buildProvisionPlan(
  req: ProvisionRequest,
  ctx: ProvisionContext,
): ProvisionPlan {
  const info = destinationInfo(req);
  const steps: ProvisionStep[] = [];
  const blocked: string[] = [];

  const unregistered = (
    subscriptionId: string,
    namespace: ProviderState['namespace'],
  ) =>
    (ctx.providers ?? []).some(
      (p) =>
        p.namespace === namespace &&
        sameText(p.subscriptionId, subscriptionId) &&
        !p.registered,
    );
  if (unregistered(info.subscriptionId, 'Microsoft.EventHub'))
    steps.push({
      kind: 'registerProvider',
      subscriptionId: info.subscriptionId,
      namespace: 'Microsoft.EventHub',
    });
  const insightsSubs = new Set<string>();
  for (const fw of req.firewalls) {
    try {
      const sub = parseResourceId(fw.id).subscriptionId.toLowerCase();
      if (!insightsSubs.has(sub) && unregistered(sub, 'Microsoft.Insights')) {
        insightsSubs.add(sub);
        steps.push({
          kind: 'registerProvider',
          subscriptionId: sub,
          namespace: 'Microsoft.Insights',
        });
      }
    } catch {
      // An invalid firewall ID is reported by validation.
    }
  }

  if (req.destination.kind === 'new' && req.destination.createResourceGroup)
    steps.push({
      kind: 'resourceGroup',
      subscriptionId: info.subscriptionId,
      name: info.resourceGroup,
      location: info.location,
    });

  const creates: string[] = [];
  if (info.createsNamespace) {
    const tier = (req.destination as { tier: HubTier }).tier;
    creates.push(
      `Event Hubs namespace ${info.namespaceName} (${tier} tier, ${info.location}, local authentication disabled)`,
    );
  }
  if (info.createsHub)
    creates.push(
      `Event hub ${info.eventHub} (1 partition, ${info.retentionHours} hours retention)`,
    );
  creates.push(
    `Access rule ${SEND_RULE_NAME} on ${info.namespaceName}, with the Send right only`,
  );
  if (info.createsConsumerGroup)
    creates.push(
      `Consumer group ${STANDARD_CONSUMER_GROUP} on ${info.eventHub}`,
    );
  steps.push({
    kind: 'eventHubs',
    subscriptionId: info.subscriptionId,
    resourceGroup: info.resourceGroup,
    template: buildEventHubTemplate(req),
    creates,
  });

  for (const fw of req.firewalls) {
    const state = ctx.firewalls.find((s) => sameText(s.firewallId, fw.id));
    const plan = planDiagnosticSetting(state?.existingSettings ?? [], {
      settingName: req.settingName,
      ruleId: info.ruleId,
      eventHub: info.eventHub,
      categories: req.categories,
    });
    if (plan.action === 'blocked') {
      blocked.push(`${fw.name}: ${plan.reason}`);
      continue;
    }
    steps.push({
      kind: 'diagnosticSetting',
      firewallId: fw.id,
      firewallName: fw.name,
      action: plan.action,
      settingName: plan.settingName,
      body: plan.body,
      changes: plan.changes,
    });
  }

  if (req.grantRole)
    steps.push({
      kind: 'role',
      scope: info.hubId,
      roleId: DATA_RECEIVER_ROLE_ID,
      roleName: DATA_RECEIVER_ROLE_NAME,
    });

  return {
    steps,
    blocked,
    info,
    connect: {
      namespace: `${namespaceShortName(info.namespaceName)}.servicebus.windows.net`,
      eventHub: info.eventHub,
      consumerGroup: info.consumerGroup,
      startPosition: 'latest',
    },
  };
}

// ── review text ──────────────────────────────────────────────────────────────

/** Every change the plan makes in Azure, one plain line each. The executor runs these same steps. */
export function reviewLines(plan: ProvisionPlan): string[] {
  const lines: string[] = [];
  for (const step of plan.steps) {
    switch (step.kind) {
      case 'registerProvider':
        lines.push(
          `Register ${step.namespace} in subscription ${step.subscriptionId} (needed once per subscription)`,
        );
        break;
      case 'resourceGroup':
        lines.push(`Create resource group ${step.name} in ${step.location}`);
        break;
      case 'eventHubs':
        lines.push(...step.creates.map((c) => `Create ${c}`));
        break;
      case 'diagnosticSetting':
        lines.push(
          step.action === 'noop'
            ? `${step.firewallName}: diagnostic setting "${step.settingName}" already sends these logs; no change`
            : `${step.firewallName}: ${step.action === 'create' ? 'create' : 'update'} diagnostic setting "${step.settingName}": ${step.changes.join('; ')}`,
        );
        break;
      case 'role':
        lines.push(
          `Give you the ${step.roleName} role on event hub ${step.scope.split('/').pop()} (this hub only)`,
        );
        break;
    }
  }
  return lines;
}

/** The permissions the steps need, so the review can say what to expect. */
export function requiredPermissions(
  plan: ProvisionPlan,
): { what: string; permission: string }[] {
  const out: { what: string; permission: string }[] = [];
  const needsProvider = plan.steps.some((s) => s.kind === 'registerProvider');
  if (needsProvider)
    out.push({
      what: 'Register a resource provider',
      permission: 'Contributor on the subscription',
    });
  const has = (k: ProvisionStep['kind']) =>
    plan.steps.some((s) => s.kind === k);
  if (has('resourceGroup') || has('eventHubs'))
    out.push({
      what: 'Create the Event Hub resources',
      permission:
        'Contributor on the resource group (on the subscription to create a resource group)',
    });
  if (
    plan.steps.some(
      (s) => s.kind === 'diagnosticSetting' && s.action !== 'noop',
    )
  )
    out.push({
      what: 'Write the diagnostic settings',
      permission:
        'Monitoring Contributor on each firewall, and permission to use the access rule (Contributor)',
    });
  if (has('role'))
    out.push({
      what: 'Assign the Data Receiver role',
      permission: 'Owner or User Access Administrator on the event hub',
    });
  return out;
}

// ── progress ─────────────────────────────────────────────────────────────────

export type ProvisionStepState =
  | 'pending'
  | 'running'
  | 'done'
  | 'failed'
  /** Not run because an earlier step failed. */
  | 'skipped'
  /** Could not be done with the user's permissions; the text says how to do it by hand. */
  | 'manual';

export interface ProvisionStepStatus {
  label: string;
  state: ProvisionStepState;
  detail?: string;
}

export interface ProvisionProgress {
  phase: 'running' | 'succeeded' | 'failed';
  steps: ProvisionStepStatus[];
  startedAt: string;
  error?: string;
  /** Steps left for the user to do by hand. */
  manual: string[];
  /** Where to connect once it succeeded. */
  connect?: LogStreamConfig;
}

/** One short row per step, for the progress list. */
export function stepLabels(plan: ProvisionPlan): string[] {
  return plan.steps.map((step) => {
    switch (step.kind) {
      case 'registerProvider':
        return `Register ${step.namespace}`;
      case 'resourceGroup':
        return `Create resource group ${step.name}`;
      case 'eventHubs':
        return `Create Event Hub resources in ${step.resourceGroup}`;
      case 'diagnosticSetting':
        return step.action === 'noop'
          ? `${step.firewallName}: diagnostic setting already set up`
          : `${step.firewallName}: ${step.action === 'create' ? 'create' : 'update'} diagnostic setting "${step.settingName}"`;
      case 'role':
        return `Assign ${step.roleName}`;
    }
  });
}

// ── untrusted input ──────────────────────────────────────────────────────────

const text = (v: unknown, label: string, max: number): string => {
  if (typeof v !== 'string' || v.length > max)
    throw new Error(`Invalid ${label}.`);
  return v.trim();
};
const int = (v: unknown, label: string): number => {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 100000)
    throw new Error(`Invalid ${label}.`);
  return v;
};

/**
 * Rebuilds a request from untrusted input (it arrives over IPC), keeping only known, correctly
 * typed fields. This checks shape only; `validateProvisionRequest` checks the rules.
 */
export function parseProvisionRequest(raw: unknown): ProvisionRequest {
  const r = obj(raw);
  if (
    !Array.isArray(r.firewalls) ||
    r.firewalls.length === 0 ||
    r.firewalls.length > 50
  )
    throw new Error('Choose at least one firewall.');
  const firewalls = r.firewalls.map((f): ProvisionFirewall => {
    const o = obj(f);
    return {
      id: text(o.id, 'firewall ID', 512),
      name: text(o.name, 'firewall name', 80),
      location: text(o.location, 'firewall region', 40),
      skuTier:
        o.skuTier === undefined
          ? undefined
          : text(o.skuTier, 'firewall tier', 20),
    };
  });
  const d = obj(r.destination);
  let destination: ProvisionDestination;
  if (d.kind === 'new') {
    if (d.tier !== 'Basic' && d.tier !== 'Standard')
      throw new Error('Choose the Basic or Standard tier.');
    destination = {
      kind: 'new',
      subscriptionId: text(d.subscriptionId, 'subscription', 64),
      resourceGroup: text(d.resourceGroup, 'resource group', 90),
      createResourceGroup: d.createResourceGroup === true,
      namespaceName: text(d.namespaceName, 'namespace name', 64),
      tier: d.tier,
      eventHub: text(d.eventHub, 'event hub name', 256),
      retentionHours: int(d.retentionHours, 'retention'),
    };
  } else if (d.kind === 'existing') {
    destination = {
      kind: 'existing',
      namespaceId: text(d.namespaceId, 'namespace ID', 512),
      namespaceLocation: text(d.namespaceLocation, 'namespace region', 40),
      tier:
        d.tier === undefined ? undefined : text(d.tier, 'namespace tier', 20),
      eventHub: text(d.eventHub, 'event hub name', 256),
      createEventHub: d.createEventHub === true,
      retentionHours: int(d.retentionHours, 'retention'),
    };
  } else {
    throw new Error('Choose where the logs should go.');
  }
  if (!Array.isArray(r.categories) || r.categories.length > 40)
    throw new Error('Invalid log categories.');
  return {
    firewalls,
    destination,
    categories: r.categories.map((c) => text(c, 'log category', 100)),
    settingName: text(r.settingName, 'diagnostic setting name', 260),
    grantRole: r.grantRole === true,
  };
}

// ── Azure error messages ─────────────────────────────────────────────────────

/**
 * Plain advice for the errors Azure is known to return while setting up logging, or undefined
 * for anything else (the caller then shows Azure's own text).
 */
export function explainProvisionError(message: string): string | undefined {
  const m = message ?? '';
  if (/Resources should be in the same region/i.test(m))
    return "The event hub must be in the same region as the firewall. Use a namespace in the firewall's region.";
  if (/is already used in diagnostic setting '([^']+)' for category/i.test(m)) {
    const name = /diagnostic setting '([^']+)'/i.exec(m)?.[1];
    return `The firewall already sends some of these categories through the same access rule${name ? ` in the diagnostic setting "${name}"` : ''}. Azure allows that only once per category. Update that setting instead, or use a different namespace.`;
  }
  if (/limit of \d+ diagnostic settings/i.test(m))
    return 'The firewall already has the maximum of 5 diagnostic settings. Delete one you no longer need, then try again.';
  if (/ConsumerGroup.*Basic|Basic.*ConsumerGroup/i.test(m))
    return 'The Basic tier has no consumer groups besides $Default. Use $Default, or choose the Standard tier.';
  if (/MessagingGatewayBadRequest/i.test(m) && /retention/i.test(m))
    return 'That retention is more than this tier allows. Basic keeps events for at most 24 hours.';
  if (
    /NamespaceAlreadyExists|name.*(is|already).*(not available|in use|taken|exists)/i.test(
      m,
    )
  )
    return 'That namespace name is already taken. Event Hubs namespace names are unique across Azure; choose another.';
  return undefined;
}

// ── what the wizard and the main process exchange ────────────────────────────

/** One firewall as read from Azure for the wizard. */
export interface SetupFirewall {
  firewall: ProvisionFirewall;
  /** Missing when the firewall's diagnostic settings could not be read. */
  state?: FirewallLoggingState;
  readError?: string;
}

export interface SetupContext {
  firewalls: SetupFirewall[];
  providers: ProviderState[];
}

export function toProvisionContext(ctx: SetupContext): ProvisionContext {
  return {
    firewalls: ctx.firewalls.flatMap((f) => (f.state ? [f.state] : [])),
    providers: ctx.providers,
  };
}

/** What the review screen shows before anything is changed. */
export interface SetupReview {
  errors: string[];
  warnings: string[];
  /** Every change, one line each. */
  lines: string[];
  permissions: { what: string; permission: string }[];
  /** Cost of a new namespace; absent when none is created. */
  cost?: string;
  /** Changes when the plan would change; sent back on apply so a stale review cannot run. */
  hash: string;
  /** One row per step, for the progress list. */
  labels: string[];
}
