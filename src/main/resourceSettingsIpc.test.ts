import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PersistedState } from './store';
import type { IpcResult } from '../shared/ipc';
import { IPC } from '../shared/ipc';
import {
  readPolicySettings,
  type FirewallConfiguration,
} from '../shared/resourceSettings';

type Handler = (
  event: unknown,
  ...args: unknown[]
) => Promise<IpcResult<unknown>>;
const mocks = vi.hoisted(() => ({
  handlers: new Map<string, Handler>(),
  state: {
    version: 1,
    candidate: [],
    history: [],
    activeCommits: [],
    managedFirewallIds: [],
  } as PersistedState,
  policy: vi.fn(),
  firewall: vi.fn(),
  validate: vi.fn(),
}));
vi.mock('electron', () => ({
  app: {},
  BrowserWindow: {},
  dialog: {},
  shell: {},
  ipcMain: {
    handle: (name: string, handler: Handler) =>
      mocks.handlers.set(name, handler),
  },
}));
vi.mock('./auth', () => ({ onSignOut: () => {} }));
vi.mock('./appProtocol', () => ({ isAppUrl: () => true }));
vi.mock('./store', () => ({
  loadState: () => mocks.state,
  updateState: (fn: (s: PersistedState) => void) => {
    fn(mocks.state);
    return true;
  },
}));
vi.mock('./azure', () => ({
  getPolicy: mocks.policy,
  validatePolicyMode: mocks.validate,
  describeAzureError: (e: Error) => e.message,
}));
vi.mock('./resourceSettings', () => ({
  getPolicyConfiguration: async () => {
    const policy = await mocks.policy();
    return {
      name: policy.name,
      threatIntelMode: policy.threatIntelMode,
      settings: policy.settings,
    };
  },
  getFirewallDraftContext: async (_id: string, maintenance: boolean) => {
    const config: FirewallConfiguration = structuredClone(
      await mocks.firewall(),
    );
    if (!maintenance) delete config.maintenanceConfigurationIds;
    return { configuration: config, policyId: POLICY };
  },
  validatePolicyConfiguration: mocks.validate,
  validateFirewallConfiguration: mocks.validate,
}));
vi.mock('./snapshotStorage', () => ({}));
vi.mock('./lookups', () => ({ clearLookupCache: () => {} }));
vi.mock('./deploy', () => ({}));
const POLICY =
  '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/fp';
const FW = POLICY.replace('/firewallPolicies/fp', '/azureFirewalls/fw');
const MAINT =
  '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Maintenance/maintenanceConfigurations/daily';
const frame: { url: string; top?: unknown } = { url: 'app://bundle' };
frame.top = frame;
const event = { senderFrame: frame };

beforeEach(async () => {
  vi.resetModules();
  vi.clearAllMocks();
  mocks.handlers.clear();
  mocks.state = {
    version: 1,
    candidate: [],
    policyCandidate: [],
    firewallCandidate: [],
    history: [],
    activeCommits: [],
    managedFirewallIds: [],
  };
  mocks.policy.mockResolvedValue({
    id: POLICY,
    name: 'fp',
    threatIntelMode: 'Alert',
    settings: readPolicySettings({}),
  });
  mocks.firewall.mockResolvedValue({
    name: 'fw',
    provisioningState: 'Succeeded',
    routeServerId: '',
    minCapacity: null,
    maxCapacity: null,
    powerState: 'Running',
    maintenanceConfigurationIds: [],
  });
  mocks.validate.mockResolvedValue(undefined);
  const { registerIpc } = await import('./ipc');
  registerIpc(() => undefined);
});

async function invoke(name: string, ...args: unknown[]) {
  const handler = mocks.handlers.get(name);
  if (!handler) throw new Error(`Missing IPC handler ${name}`);
  return handler(event, ...args);
}

describe('settings IPC and candidate integration', () => {
  it('does not drop staged DNS settings when the existing mode slider is used', async () => {
    const policy = await mocks.policy();
    const desired = structuredClone(policy.settings);
    desired.dns = { inherit: false, enableProxy: true, servers: ['10.0.0.4'] };
    expect(
      await invoke(IPC.stagePolicySettings, POLICY, policy.settings, desired),
    ).toMatchObject({ ok: true });
    const mode = await invoke(IPC.stagePolicyMode, POLICY, 'Deny');
    expect(mode).toMatchObject({
      ok: true,
      data: {
        pending: [
          {
            target: 'policy',
            policyMode: { after: 'Deny' },
            changes: expect.arrayContaining([
              expect.objectContaining({
                detail: expect.stringContaining('DNS'),
              }),
              expect.objectContaining({
                detail: 'Threat intelligence: Alert -> Deny',
              }),
            ]),
          },
        ],
      },
    });
  });

  it('preserves scaling and maintenance drafts when the start/stop slider reads only core firewall state', async () => {
    const before = await mocks.firewall();
    const desired = {
      ...before,
      minCapacity: 4,
      maxCapacity: 8,
      maintenanceConfigurationIds: [MAINT],
    };
    expect(
      await invoke(IPC.stageFirewallSettings, FW, before, desired),
    ).toMatchObject({ ok: true });
    const stop = await invoke(IPC.stageFirewallPower, FW, 'Stopped', undefined);
    expect(stop).toMatchObject({
      ok: true,
      data: {
        pending: [
          {
            target: 'firewall',
            firewallConfiguration: {
              after: {
                minCapacity: 4,
                maxCapacity: 8,
                maintenanceConfigurationIds: [MAINT],
                powerState: 'Stopped',
              },
            },
          },
        ],
      },
    });
    expect(mocks.state.firewallCandidate).toEqual([]);
    expect(await invoke(IPC.save)).toMatchObject({ ok: true });
    expect(
      mocks.state.firewallCandidate?.[0].candidate.maintenanceConfigurationIds,
    ).toEqual([MAINT]);
  });

  it('rejects malformed configuration payloads with the normal logged IPC error envelope', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const before = readPolicySettings({});
      expect(
        await invoke(IPC.stagePolicySettings, POLICY, before, {
          ...before,
          allowlistIps: '10.0.0.1',
        }),
      ).toMatchObject({
        ok: false,
        error: expect.stringContaining('allowlist'),
      });
      expect(logged).toHaveBeenCalled();
      expect(mocks.state.policyCandidate).toEqual([]);
    } finally {
      logged.mockRestore();
    }
  });
});
