// Sets up firewall logging in Azure: Event Hub resources, the firewalls' diagnostic settings and
// the Data Receiver role. Everything that changes Azure comes from one plan (see
// src/shared/logProvision.ts); the review screen shows it and `applySetup` runs it.
import { createHash } from 'node:crypto';
import { armRequest } from './arm';
import { describeAzureError, discoverFirewalls } from './azure';
import { grantRole } from './roleAssignments';
import {
  buildProvisionPlan,
  COST_NOTE,
  DIAGNOSTIC_SETTINGS_API_VERSION,
  explainProvisionError,
  parseProvisionRequest,
  requiredPermissions,
  reviewLines,
  stepLabels,
  toProvisionContext,
  validateProvisionRequest,
  type FirewallLoggingState,
  type ProviderState,
  type ProvisionPlan,
  type ProvisionProgress,
  type ProvisionRequest,
  type ProvisionStep,
  type SetupContext,
  type SetupFirewall,
  type SetupReview,
} from '../shared/logProvision';
import { APP_TAG } from '../shared/deploy';
import { parseResourceId, sameResourceId } from '../shared/resourceId';

const EVENTHUB_API_VERSION = '2024-01-01';
const PROVIDERS_API_VERSION = '2021-04-01';
const DEPLOYMENTS_API_VERSION = '2022-09-01';
const GROUPS_API_VERSION = '2021-04-01';
const PROVIDER_POLL_MS = 5000;
const PROVIDER_POLLS = 36;
const DEPLOYMENT_POLL_MS = 3000;
const DEPLOYMENT_POLLS = 200;

export interface SetupDeps {
  sleep(ms: number): Promise<void>;
  now(): number;
}
const realDeps: SetupDeps = {
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now: () => Date.now(),
};

type Json = Record<string, unknown>;
const obj = (v: unknown): Json =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {};

// ── reading Azure ────────────────────────────────────────────────────────────

async function providerState(
  subscriptionId: string,
  namespace: ProviderState['namespace'],
): Promise<ProviderState> {
  try {
    const { data } = await armRequest<Json>(
      `/subscriptions/${subscriptionId}/providers/${namespace}?api-version=${PROVIDERS_API_VERSION}`,
    );
    return {
      subscriptionId,
      namespace,
      registered:
        String(data.registrationState ?? '').toLowerCase() === 'registered',
    };
  } catch {
    // Cannot tell (no read access to the subscription): do not invent a registration step.
    return { subscriptionId, namespace, registered: true };
  }
}

async function readFirewall(
  fw: SetupFirewall['firewall'],
): Promise<SetupFirewall> {
  const base = `${fw.id}/providers/Microsoft.Insights`;
  try {
    const [categories, settings] = await Promise.all([
      armRequest<Json>(
        `${base}/diagnosticSettingsCategories?api-version=${DIAGNOSTIC_SETTINGS_API_VERSION}`,
      ),
      armRequest<Json>(
        `${base}/diagnosticSettings?api-version=${DIAGNOSTIC_SETTINGS_API_VERSION}`,
      ),
    ]);
    const offered = (
      Array.isArray(categories.data.value) ? categories.data.value : []
    )
      .map(obj)
      .filter((c) => String(obj(c.properties).categoryType) === 'Logs')
      .map((c) => String(c.name));
    const state: FirewallLoggingState = {
      firewallId: fw.id,
      offeredCategories: offered,
      existingSettings: Array.isArray(settings.data.value)
        ? settings.data.value
        : [],
    };
    return { firewall: fw, state };
  } catch (err) {
    return { firewall: fw, readError: describeAzureError(err) };
  }
}

/**
 * What the wizard needs about the chosen firewalls: region and tier from discovery (never from the
 * renderer), the categories each offers, their current diagnostic settings, and whether the
 * resource providers are registered in the subscriptions involved.
 */
export async function getSetupContext(
  firewallIds: string[],
  destinationSubscriptionId?: string,
): Promise<SetupContext> {
  const all = await discoverFirewalls();
  const chosen = firewallIds.map((id) => {
    const found = all.find((f) => sameResourceId(f.id, id));
    if (!found) throw new Error('One of the firewalls could not be found.');
    return {
      id: found.id,
      name: found.name,
      location: found.location,
      skuTier: found.skuTier,
    };
  });
  const firewalls = await Promise.all(chosen.map(readFirewall));

  const subs = new Set<string>(
    chosen.map((f) => parseResourceId(f.id).subscriptionId.toLowerCase()),
  );
  const providers = await Promise.all([
    ...[...subs].map((s) => providerState(s, 'Microsoft.Insights')),
    ...(destinationSubscriptionId
      ? [
          providerState(
            destinationSubscriptionId.toLowerCase(),
            'Microsoft.EventHub',
          ),
        ]
      : []),
  ]);
  return { firewalls, providers };
}

/** Whether an Event Hubs namespace name is free (names are unique across Azure). */
export async function checkNamespaceName(
  subscriptionId: string,
  name: string,
): Promise<{ available: boolean; message?: string }> {
  const { data } = await armRequest<Json>(
    `/subscriptions/${subscriptionId}/providers/Microsoft.EventHub/checkNameAvailability?api-version=${EVENTHUB_API_VERSION}`,
    { method: 'POST', body: JSON.stringify({ name }) },
  );
  return {
    available: data.nameAvailable === true,
    message: typeof data.message === 'string' ? data.message : undefined,
  };
}

// ── review ───────────────────────────────────────────────────────────────────

/** Rebuilds the request from the renderer's data, with facts about the firewalls from Azure. */
async function prepare(raw: unknown): Promise<{
  req: ProvisionRequest;
  setup: SetupContext;
  plan: ProvisionPlan;
}> {
  const parsed = parseProvisionRequest(raw);
  const destinationSubscription =
    parsed.destination.kind === 'new'
      ? parsed.destination.subscriptionId
      : parseResourceId(parsed.destination.namespaceId).subscriptionId;
  const setup = await getSetupContext(
    parsed.firewalls.map((f) => f.id),
    destinationSubscription,
  );
  const req: ProvisionRequest = {
    ...parsed,
    firewalls: setup.firewalls.map((f) => f.firewall),
  };
  const unreadable = setup.firewalls.find((f) => !f.state);
  if (unreadable)
    throw new Error(
      `Couldn't read the diagnostic settings of ${unreadable.firewall.name}: ${unreadable.readError ?? 'unknown error'}`,
    );
  return {
    req,
    setup,
    plan: buildProvisionPlan(req, toProvisionContext(setup)),
  };
}

const hashOf = (lines: string[]) =>
  createHash('sha256').update(lines.join('\n')).digest('hex').slice(0, 16);

export async function reviewSetup(raw: unknown): Promise<SetupReview> {
  const { req, setup, plan } = await prepare(raw);
  const check = validateProvisionRequest(req, toProvisionContext(setup));
  const lines = reviewLines(plan);
  const d = req.destination;
  return {
    errors: check.errors,
    warnings: check.warnings,
    lines,
    permissions: requiredPermissions(plan),
    cost: d.kind === 'new' ? COST_NOTE[d.tier] : undefined,
    hash: hashOf(lines),
    labels: stepLabels(plan),
  };
}

// ── applying ─────────────────────────────────────────────────────────────────

function flattenError(error: unknown): string {
  const e = obj(error);
  const parts = [
    [e.code, e.message].filter((x) => typeof x === 'string').join(': '),
  ];
  if (Array.isArray(e.details)) parts.push(...e.details.map(flattenError));
  return parts.filter(Boolean).join(' ');
}

async function registerProvider(
  step: Extract<ProvisionStep, { kind: 'registerProvider' }>,
  deps: SetupDeps,
): Promise<void> {
  const base = `/subscriptions/${step.subscriptionId}/providers/${step.namespace}`;
  await armRequest(`${base}/register?api-version=${PROVIDERS_API_VERSION}`, {
    method: 'POST',
  });
  for (let i = 0; i < PROVIDER_POLLS; i++) {
    const { data } = await armRequest<Json>(
      `${base}?api-version=${PROVIDERS_API_VERSION}`,
    );
    if (String(data.registrationState).toLowerCase() === 'registered') return;
    await deps.sleep(PROVIDER_POLL_MS);
  }
  throw new Error(
    `Azure is still registering ${step.namespace}. Try again in a minute.`,
  );
}

async function deployEventHubs(
  step: Extract<ProvisionStep, { kind: 'eventHubs' }>,
  deps: SetupDeps,
): Promise<void> {
  const name = `ezazfw-logs-${deps.now()}`;
  const path = `/subscriptions/${step.subscriptionId}/resourcegroups/${step.resourceGroup}/providers/Microsoft.Resources/deployments/${name}?api-version=${DEPLOYMENTS_API_VERSION}`;
  await armRequest(path, {
    method: 'PUT',
    body: JSON.stringify({
      properties: { mode: 'Incremental', template: step.template },
      tags: { createdBy: APP_TAG },
    }),
  });
  for (let i = 0; i < DEPLOYMENT_POLLS; i++) {
    const { data } = await armRequest<Json>(path);
    const props = obj(data.properties);
    const state = String(props.provisioningState);
    if (state === 'Succeeded') return;
    if (state === 'Failed' || state === 'Canceled')
      throw new Error(
        flattenError(props.error) || `The deployment ${state.toLowerCase()}.`,
      );
    await deps.sleep(DEPLOYMENT_POLL_MS);
  }
  throw new Error(
    'The deployment is taking longer than expected. Check it in the Azure portal.',
  );
}

const manualRoleSteps = (scope: string, roleName: string) =>
  `Assign yourself the "${roleName}" role on the event hub ${scope.split('/').pop()}: Azure portal, the event hub, Access control (IAM), Add role assignment.`;

async function runStep(
  step: ProvisionStep,
  deps: SetupDeps,
): Promise<'done' | 'manual'> {
  switch (step.kind) {
    case 'registerProvider':
      await registerProvider(step, deps);
      return 'done';
    case 'resourceGroup':
      await armRequest(
        `/subscriptions/${step.subscriptionId}/resourcegroups/${step.name}?api-version=${GROUPS_API_VERSION}`,
        {
          method: 'PUT',
          body: JSON.stringify({
            location: step.location,
            tags: { createdBy: APP_TAG },
          }),
        },
      );
      return 'done';
    case 'eventHubs':
      await deployEventHubs(step, deps);
      return 'done';
    case 'diagnosticSetting':
      if (step.action === 'noop') return 'done';
      await armRequest(
        `${step.firewallId}/providers/Microsoft.Insights/diagnosticSettings/${encodeURIComponent(step.settingName)}?api-version=${DIAGNOSTIC_SETTINGS_API_VERSION}`,
        { method: 'PUT', body: JSON.stringify(step.body) },
      );
      return 'done';
    case 'role':
      try {
        await grantRole(step.scope, step.roleId);
        return 'done';
      } catch (err) {
        const status = (err as { statusCode?: number }).statusCode;
        // Without permission to assign roles, the rest still works; the user does this by hand.
        if (status === 401 || status === 403) return 'manual';
        throw err;
      }
  }
}

let running = false;

/**
 * Runs the plan, one step at a time, reporting progress. The first failure stops the run and the
 * later steps are skipped; running it again is safe (resources that exist are left alone).
 * `expectedHash` is the hash from the review: if Azure changed since, nothing is run.
 */
export async function applySetup(
  raw: unknown,
  expectedHash: string,
  emit: (progress: ProvisionProgress) => void,
  deps: SetupDeps = realDeps,
): Promise<ProvisionProgress> {
  if (running) throw new Error('Another logging setup is already running.');
  running = true;
  try {
    const { req, setup, plan } = await prepare(raw);
    const check = validateProvisionRequest(req, toProvisionContext(setup));
    if (check.errors.length) throw new Error(check.errors.join(' '));
    if (hashOf(reviewLines(plan)) !== expectedHash)
      throw new Error(
        'Something in Azure changed since you reviewed this. Go back and review the changes again.',
      );

    const progress: ProvisionProgress = {
      phase: 'running',
      startedAt: new Date(deps.now()).toISOString(),
      manual: [],
      steps: stepLabels(plan).map((label) => ({
        label,
        state: 'pending' as const,
      })),
    };
    emit(structuredClone(progress));

    for (let i = 0; i < plan.steps.length; i++) {
      progress.steps[i].state = 'running';
      emit(structuredClone(progress));
      try {
        const result = await runStep(plan.steps[i], deps);
        progress.steps[i].state = result;
        if (result === 'manual') {
          const role = plan.steps[i] as Extract<
            ProvisionStep,
            { kind: 'role' }
          >;
          progress.steps[i].detail =
            "You don't have permission to assign roles.";
          progress.manual.push(manualRoleSteps(role.scope, role.roleName));
        }
      } catch (err) {
        const text = describeAzureError(err);
        const message = explainProvisionError(text) ?? text;
        progress.steps[i].state = 'failed';
        progress.steps[i].detail = message;
        for (let j = i + 1; j < progress.steps.length; j++)
          progress.steps[j].state = 'skipped';
        progress.phase = 'failed';
        progress.error = message;
        emit(structuredClone(progress));
        return progress;
      }
      emit(structuredClone(progress));
    }
    progress.phase = 'succeeded';
    progress.connect = plan.connect;
    emit(structuredClone(progress));
    return progress;
  } finally {
    running = false;
  }
}
