// Cleans up diagnostic settings that send to an Event Hubs namespace that was deleted.
//
// A namespace counts as gone only when Azure says so explicitly (404 ResourceNotFound or
// ResourceGroupNotFound). A 403, a subscription we cannot see, or any other failure means "could
// not check", and no cleanup is offered. The review and the apply both rebuild the plan from fresh
// Azure state, and apply refuses to run if it differs from what was reviewed.
import { createHash } from 'node:crypto';
import { armRequest } from './arm';
import { describeAzureError, discoverFirewalls } from './azure';
import { loadState } from './store';
import {
  CLEANUP_PERMISSION,
  danglingSettings,
  namespaceIdOfRule,
  planCleanup,
  type CleanupPlan,
  type CleanupReview,
  type DanglingSetting,
} from '../shared/logCleanup';
import type {
  EventHubNamespaceInfo,
  FirewallLogging,
} from '../shared/logSources';
import {
  DIAGNOSTIC_SETTINGS_API_VERSION,
  EVENTHUB_API_VERSION,
} from '../shared/logProvision';
import { sameResourceId } from '../shared/resourceId';

const CONCURRENCY = 4;

type Json = Record<string, unknown>;
const obj = (v: unknown): Json =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {};

/** True only for an explicit "this does not exist" answer. */
export function isGone(err: unknown): boolean {
  const e = err as { statusCode?: number; code?: string };
  return (
    e?.statusCode === 404 &&
    (e.code === 'ResourceNotFound' || e.code === 'ResourceGroupNotFound')
  );
}

/** Whether a namespace is confirmed deleted. Any other outcome, including errors, is "not gone". */
async function namespaceIsGone(namespaceId: string): Promise<boolean> {
  try {
    await armRequest(`${namespaceId}?api-version=${EVENTHUB_API_VERSION}`);
    return false;
  } catch (err) {
    return isGone(err);
  }
}

async function goneNamespaces(ids: string[]): Promise<Set<string>> {
  const gone = new Set<string>();
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, ids.length) }, async () => {
      while (next < ids.length) {
        const id = ids[next++];
        if (await namespaceIsGone(id)) gone.add(id);
      }
    }),
  );
  return gone;
}

/**
 * Settings of the listed firewalls that send to a namespace confirmed deleted. Namespaces that
 * discovery already found exist and are not asked about again.
 */
export async function findDanglingSettings(
  firewalls: FirewallLogging[],
  known: EventHubNamespaceInfo[],
): Promise<DanglingSetting[]> {
  const exists = new Set(known.map((n) => n.id.toLowerCase()));
  const unknown = new Map<string, string>();
  for (const fw of firewalls)
    for (const s of fw.settings) {
      const id = s.eventHubNamespaceId;
      if (id && !exists.has(id.toLowerCase()))
        unknown.set(id.toLowerCase(), id);
    }
  if (unknown.size === 0) return [];
  const gone = await goneNamespaces([...unknown.values()]);
  return danglingSettings(firewalls, gone);
}

// ── review and apply ─────────────────────────────────────────────────────────

const hashOf = (lines: string[]) =>
  createHash('sha256').update(lines.join('\n')).digest('hex').slice(0, 16);

const settingUrl = (firewallId: string, name: string) =>
  `${firewallId}/providers/Microsoft.Insights/diagnosticSettings/${encodeURIComponent(name)}?api-version=${DIAGNOSTIC_SETTINGS_API_VERSION}`;

/** Fresh state for one setting: the firewall must be one the app lists, the namespace still gone. */
async function prepare(
  firewallId: unknown,
  settingName: unknown,
): Promise<{
  firewallId: string;
  settingName: string;
  plan: CleanupPlan;
}> {
  if (typeof firewallId !== 'string' || typeof settingName !== 'string')
    throw new Error('Invalid cleanup request.');
  if (!settingName.trim() || settingName.length > 260)
    throw new Error('Invalid setting name.');

  const all = await discoverFirewalls();
  const managed = loadState().managedFirewallIds;
  const fw = all.find(
    (f) =>
      sameResourceId(f.id, firewallId) &&
      (managed.length === 0 || managed.some((id) => sameResourceId(id, f.id))),
  );
  if (!fw) throw new Error('That firewall is not one this app lists.');

  let existing: unknown;
  try {
    ({ data: existing } = await armRequest<unknown>(
      settingUrl(fw.id, settingName),
    ));
  } catch (err) {
    throw new Error(
      `Couldn't read diagnostic setting "${settingName}": ${describeAzureError(err)}`,
    );
  }
  const namespaceId = namespaceIdOfRule(
    obj(obj(existing).properties).eventHubAuthorizationRuleId,
  );
  if (!namespaceId || !(await namespaceIsGone(namespaceId)))
    return {
      firewallId: fw.id,
      settingName,
      plan: { action: 'noop', kept: [], lines: [] },
    };
  return {
    firewallId: fw.id,
    settingName,
    plan: planCleanup(existing, fw.name, namespaceId),
  };
}

/** What a cleanup would change. Changes nothing in Azure. */
export async function reviewCleanup(
  firewallId: unknown,
  settingName: unknown,
): Promise<CleanupReview> {
  const { plan } = await prepare(firewallId, settingName);
  if (plan.action === 'noop')
    throw new Error(
      'Nothing to clean up: the setting changed, or its namespace could not be confirmed as deleted.',
    );
  return {
    action: plan.action,
    lines: plan.lines,
    permission: CLEANUP_PERMISSION,
    hash: hashOf(plan.lines),
  };
}

/** Runs the reviewed cleanup, but only if it is still exactly what was reviewed. */
export async function applyCleanup(
  firewallId: unknown,
  settingName: unknown,
  reviewHash: string,
): Promise<{ action: 'trim' | 'delete' }> {
  const {
    firewallId: id,
    settingName: name,
    plan,
  } = await prepare(firewallId, settingName);
  if (plan.action === 'noop')
    throw new Error(
      'Nothing to clean up: the setting changed, or its namespace could not be confirmed as deleted.',
    );
  if (hashOf(plan.lines) !== reviewHash)
    throw new Error(
      'Azure changed since the review. Review the cleanup again before applying it.',
    );
  try {
    if (plan.action === 'trim')
      await armRequest(settingUrl(id, name), {
        method: 'PUT',
        body: JSON.stringify(plan.body),
      });
    else await armRequest(settingUrl(id, name), { method: 'DELETE' });
  } catch (err) {
    const status = (err as { statusCode?: number }).statusCode;
    if (status === 401 || status === 403)
      throw new Error(
        `You don't have permission to change this diagnostic setting (${CLEANUP_PERMISSION}). Nothing was changed.`,
      );
    throw new Error(
      `Couldn't change the diagnostic setting: ${describeAzureError(err)}`,
    );
  }
  return { action: plan.action };
}
