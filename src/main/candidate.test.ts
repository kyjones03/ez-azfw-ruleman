import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  CommitProgress,
  FirewallRule,
  RuleCollectionGroup,
} from '../shared/types';
import { csvCell } from '../shared/csv';
import { planRuleImport, RULE_IMPORT_COLUMNS } from '../shared/ruleImport';
import type {
  FirewallConfiguration,
  PolicyAdvancedSettings,
} from '../shared/resourceSettings';

// The candidate module touches disk (store) and Azure (azure); stub both.
const azure = vi.hoisted(() => ({
  getRuleCollectionGroup: vi.fn(),
  listRuleCollectionGroups: vi.fn(),
  putRuleCollectionGroup: vi.fn(),
  getPolicyMode: vi.fn(),
  putPolicyMode: vi.fn(),
}));
const resourceOperations = vi.hoisted(() => ({
  getFirewallConfigurationForDraft: vi.fn(),
  putFirewallConfiguration: vi.fn(),
  putPolicyConfiguration: vi.fn(),
}));
vi.mock('./resourceSettings', () => resourceOperations);
const snapshotStorage = vi.hoisted(() => ({
  requireSnapshotStorageConfigured: vi.fn(),
  saveSnapshotToCentralStorage: vi.fn(),
  saveCommitToCentralHistory: vi.fn(),
}));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const store = vi.hoisted(() => ({ state: {} as any, writable: true }));
vi.mock('./store', () => ({
  loadState: () => store.state,
  updateState: (mutate: (s: unknown) => void) => {
    mutate(store.state);
    return store.writable;
  },
}));
vi.mock('./snapshotStorage', () => snapshotStorage);
beforeEach(() => {
  store.writable = true;
  store.state = {
    candidate: [],
    history: [],
    activeCommits: [],
  };
  azure.listRuleCollectionGroups.mockReset();
  resourceOperations.getFirewallConfigurationForDraft.mockReset();
  resourceOperations.putFirewallConfiguration
    .mockReset()
    .mockImplementation(
      async (
        _id: string,
        _before: FirewallConfiguration,
        after: FirewallConfiguration,
      ) => {
        resourceOperations.getFirewallConfigurationForDraft.mockResolvedValue({
          ...after,
          provisioningState: 'Succeeded',
        });
      },
    );
  resourceOperations.putPolicyConfiguration
    .mockReset()
    .mockImplementation(
      async (
        _id: string,
        _before: PolicyAdvancedSettings,
        after: PolicyAdvancedSettings,
        mode?: { before: string; after: string },
      ) => {
        const current = await azure.getPolicyMode();
        azure.getPolicyMode.mockResolvedValue({
          ...current,
          settings: after,
          threatIntelMode:
            mode && mode.before !== mode.after
              ? mode.after
              : current.threatIntelMode,
        });
      },
    );
  azure.listRuleCollectionGroups.mockResolvedValue([]);
  azure.getPolicyMode.mockReset().mockResolvedValue({
    name: 'fp',
    threatIntelMode: 'Alert',
    provisioningState: 'Succeeded',
  });
  azure.putPolicyMode
    .mockReset()
    .mockImplementation(
      async (_id: string, _baseline: string, mode: string) => {
        azure.getPolicyMode.mockResolvedValue({
          name: 'fp',
          threatIntelMode: mode,
          provisioningState: 'Succeeded',
        });
      },
    );
  snapshotStorage.requireSnapshotStorageConfigured.mockReset();
  snapshotStorage.requireSnapshotStorageConfigured.mockResolvedValue({
    storageAccountId:
      '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stsnap',
    storageAccountName: 'stsnap',
    containerName: 'ez-azfw-snapshots',
    configuredAt: '2026-01-01T00:00:00.000Z',
  });
  snapshotStorage.saveSnapshotToCentralStorage.mockReset();
  snapshotStorage.saveSnapshotToCentralStorage.mockResolvedValue(undefined);
  snapshotStorage.saveCommitToCentralHistory.mockReset();
  snapshotStorage.saveCommitToCentralHistory.mockResolvedValue(undefined);
});
vi.mock('./azure', () => ({
  ...azure,
  describeAzureError: (e: Error) => e.message,
}));

const POLICY =
  '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/fp';
const running: RuleCollectionGroup[] = [
  {
    id: `${POLICY}/ruleCollectionGroups/Platform`,
    name: 'Platform',
    priority: 100,
    etag: 'e1',
    ruleCollections: [],
  },
];
const NEW_ID = `${POLICY}/ruleCollectionGroups/rcg-new`;
const notFound = Object.assign(new Error('Not found'), { statusCode: 404 });

async function freshCandidate() {
  vi.resetModules();
  const mod = await import('./candidate');
  mod.Candidate.pollMs = 1;
  return mod.candidate;
}

describe('advanced resource drafts', () => {
  const FW = POLICY.replace('/firewallPolicies/fp', '/azureFirewalls/fw');
  const policySettings = (): PolicyAdvancedSettings => ({
    dns: { inherit: true, enableProxy: false, servers: [] },
    allowlistIps: [],
    allowlistFqdns: [],
    autoLearnSnat: false,
    tls: { enabled: false, certificateName: '', secretId: '', identityIds: [] },
  });
  const firewall: FirewallConfiguration = {
    name: 'fw',
    provisioningState: 'Succeeded',
    routeServerId: '',
    minCapacity: null,
    maxCapacity: null,
    powerState: 'Running',
  };

  it('retains the draft without resubmitting an accepted firewall operation that failed with a nested busy error', async () => {
    const c = await freshCandidate();
    resourceOperations.getFirewallConfigurationForDraft.mockResolvedValue(
      firewall,
    );
    resourceOperations.putFirewallConfiguration.mockRejectedValueOnce(
      Object.assign(
        new Error('AnotherOperationInProgress: Allocation failed.'),
        {
          code: 'ResourceOperationFailure',
          operationStatus: 'failed',
        },
      ),
    );
    c.stageFirewallConfiguration(
      FW,
      POLICY,
      { ...firewall, powerState: 'Stopped' },
      firewall,
    );
    const result = await c.commit([FW], 'stop', 'me', () => {});
    expect(result.results[0]).toMatchObject({
      ok: false,
      error: 'AnotherOperationInProgress: Allocation failed.',
    });
    expect(result.results[0].conflict).toBeUndefined();
    expect(resourceOperations.putFirewallConfiguration).toHaveBeenCalledTimes(
      1,
    );
    expect(c.status().pending).toHaveLength(1);
  });

  it('refuses to start Azure writes if the saved draft cannot be persisted', async () => {
    const c = await freshCandidate();
    c.stageFirewallConfiguration(
      FW,
      POLICY,
      { ...firewall, powerState: 'Stopped' },
      firewall,
    );
    store.writable = false;
    expect(() => c.save()).toThrow('not writable');
    await expect(c.commit([FW], 'stop', 'me', () => {})).rejects.toThrow(
      'No Azure changes were started',
    );
    expect(resourceOperations.putFirewallConfiguration).not.toHaveBeenCalled();
    expect(c.status().unsaved).toBe(true);
  });

  it('preserves advanced drafts when toggling mode back, and saves both resource kinds without Azure writes', async () => {
    const c = await freshCandidate();
    const before = {
      name: 'fp',
      threatIntelMode: 'Alert' as const,
      settings: policySettings(),
    };
    const desired = structuredClone(before);
    desired.settings.dns = {
      inherit: false,
      enableProxy: true,
      servers: ['10.0.0.4'],
    };
    c.stagePolicyMode(POLICY, 'Deny', before);
    c.stagePolicyConfiguration(
      POLICY,
      { ...desired, threatIntelMode: 'Deny' },
      before,
    );
    c.stagePolicyMode(POLICY, 'Alert', {
      name: 'fp',
      threatIntelMode: 'Alert',
    });
    c.stageFirewallConfiguration(
      FW,
      POLICY,
      { ...firewall, powerState: 'Stopped' },
      firewall,
    );
    expect(
      c.status().pending.find((p) => p.target === 'policy')?.policyMode,
    ).toBeUndefined();
    expect(
      c.status().pending.find((p) => p.target === 'policy')?.changes[0].detail,
    ).toContain('DNS');
    c.save();
    const reloaded = await freshCandidate();
    expect(reloaded.status()).toMatchObject({
      unsaved: false,
      pending: [
        expect.objectContaining({ target: 'policy' }),
        expect.objectContaining({ target: 'firewall' }),
      ],
    });
    expect(resourceOperations.putPolicyConfiguration).not.toHaveBeenCalled();
    expect(resourceOperations.putFirewallConfiguration).not.toHaveBeenCalled();
  });

  it('rebases untouched fields without accidentally drafting unrelated Azure edits', async () => {
    const c = await freshCandidate();
    const before = {
      name: 'fp',
      threatIntelMode: 'Alert' as const,
      settings: policySettings(),
    };
    const first = structuredClone(before);
    first.settings.dns = {
      inherit: false,
      enableProxy: true,
      servers: ['10.0.0.4'],
    };
    c.stagePolicyConfiguration(POLICY, first, before);
    const current = structuredClone(before);
    current.settings.allowlistFqdns = ['external.contoso.com'];
    const effective = c.effectivePolicyConfiguration(POLICY, current);
    expect(effective.settings?.dns.enableProxy).toBe(true);
    expect(effective.settings?.allowlistFqdns).toEqual([
      'external.contoso.com',
    ]);
    const next = {
      ...effective,
      settings: {
        ...current.settings,
        dns: first.settings.dns,
        allowlistIps: ['192.0.2.1'],
      },
    };
    c.stagePolicyConfiguration(POLICY, next, current);
    const details = c
      .status()
      .pending[0].changes.map((change) => change.detail)
      .join(' ');
    expect(details).toContain('DNS');
    expect(details).toContain('allowlist IPs');
    expect(details).not.toContain('allowlist FQDNs');
  });

  it('restores recorded advanced policy settings and preserves them when later restoring an older mode-only snapshot', async () => {
    const c = await freshCandidate();
    const runningPolicy = {
      name: 'fp',
      threatIntelMode: 'Alert' as const,
      settings: policySettings(),
    };
    runningPolicy.settings.dns = {
      inherit: false,
      enableProxy: true,
      servers: ['10.0.0.4'],
    };
    const savedSettings = policySettings();
    savedSettings.allowlistIps = ['192.0.2.1'];
    const snapshot = {
      id: 'advanced-snapshot',
      policyId: POLICY,
      policyName: 'fp',
      time: '2026-01-01',
      description: 'settings',
      groups: [],
    };
    c.restoreSnapshot(
      { ...snapshot, threatIntelMode: 'Deny', settings: savedSettings },
      [],
      runningPolicy,
    );
    expect(c.effectivePolicyConfiguration(POLICY, runningPolicy)).toMatchObject(
      {
        threatIntelMode: 'Deny',
        settings: { dns: { inherit: true }, allowlistIps: ['192.0.2.1'] },
      },
    );
    c.restoreSnapshot(
      { ...snapshot, threatIntelMode: 'Off' },
      [],
      runningPolicy,
    );
    expect(c.effectivePolicyConfiguration(POLICY, runningPolicy)).toMatchObject(
      {
        threatIntelMode: 'Off',
        settings: { dns: { inherit: true }, allowlistIps: ['192.0.2.1'] },
      },
    );
  });

  it('commits mode and advanced settings through one policy resource operation', async () => {
    const c = await freshCandidate();
    const before = {
      name: 'fp',
      threatIntelMode: 'Alert' as const,
      settings: policySettings(),
    };
    const desired = {
      ...before,
      threatIntelMode: 'Deny' as const,
      settings: { ...before.settings, allowlistIps: ['192.0.2.1'] },
    };
    c.stagePolicyConfiguration(POLICY, desired, before);
    const result = await c.commit(
      [POLICY],
      'mode and allowlist',
      'me',
      () => {},
    );
    expect(result.results[0].ok).toBe(true);
    expect(azure.putPolicyMode).not.toHaveBeenCalled();
    expect(resourceOperations.putPolicyConfiguration).toHaveBeenCalledTimes(1);
    expect(resourceOperations.putPolicyConfiguration).toHaveBeenCalledWith(
      POLICY,
      before.settings,
      desired.settings,
      { before: 'Alert', after: 'Deny' },
    );
  });

  it('does not revert an unrelated mode change while committing advanced settings', async () => {
    const c = await freshCandidate();
    const before = {
      name: 'fp',
      threatIntelMode: 'Alert' as const,
      settings: policySettings(),
    };
    const desired = structuredClone(before);
    desired.settings.dns = {
      inherit: false,
      enableProxy: true,
      servers: ['10.0.0.4'],
    };
    c.stagePolicyConfiguration(POLICY, desired, before);
    azure.getPolicyMode.mockResolvedValue({
      ...before,
      threatIntelMode: 'Deny',
      provisioningState: 'Succeeded',
    });
    const result = await c.commit([POLICY], 'DNS', 'me', () => {});
    expect(result.results[0].ok).toBe(true);
    expect(azure.putPolicyMode).not.toHaveBeenCalled();
    expect(resourceOperations.putPolicyConfiguration).toHaveBeenCalled();
    expect(snapshotStorage.saveSnapshotToCentralStorage).toHaveBeenCalledWith(
      expect.objectContaining({
        threatIntelMode: 'Deny',
        settings: desired.settings,
      }),
    );
  });

  it.each([POLICY, ''])(
    'stops a firewall after selected policy writes, and records firewall changes in history rather than a fabricated policy snapshot (policy: %s)',
    async (policyId) => {
      const c = await freshCandidate();
      resourceOperations.getFirewallConfigurationForDraft.mockResolvedValue(
        firewall,
      );
      c.stagePolicyMode(POLICY, 'Deny', {
        name: 'fp',
        threatIntelMode: 'Alert',
      });
      c.stageFirewallConfiguration(
        FW,
        policyId,
        { ...firewall, powerState: 'Stopped' },
        firewall,
      );
      const result = await c.commit(
        [FW, POLICY],
        'stop after settings',
        'me',
        () => {},
      );
      expect(result.results.map((r) => [r.target, r.ok])).toEqual([
        ['policy', true],
        ['firewall', true],
      ]);
      expect(azure.putPolicyMode.mock.invocationCallOrder[0]).toBeLessThan(
        resourceOperations.putFirewallConfiguration.mock.invocationCallOrder[0],
      );
      expect(azure.getPolicyMode.mock.calls.some(([id]) => id === FW)).toBe(
        false,
      );
      expect(c.status().pending).toEqual([]);
    },
  );

  it('resumes a firewall write through Updating and verifies its final outcome', async () => {
    const c = await freshCandidate();
    const desired = { ...firewall, powerState: 'Stopped' as const };
    c.stageFirewallConfiguration(FW, POLICY, desired, firewall);
    c.save();
    store.state.activeCommits = [
      {
        changeCount: 1,
        results: [],
        written: {},
        scopes: { [FW.toLowerCase()]: POLICY },
        writtenFirewalls: { [FW.toLowerCase()]: desired },
        progress: {
          commitId: 'firewall-resume',
          startedAt: '2026-01-01T00:00:00.000Z',
          description: 'stop',
          index: 0,
          total: 1,
          groupName: 'fw',
          policyName: 'fp',
          groups: [
            {
              target: 'firewall',
              groupId: FW,
              groupName: 'fw',
              policyName: 'fp',
              action: 'update',
              state: 'updating',
              changes: c.status().pending[0].changes,
            },
          ],
        },
      },
    ];
    resourceOperations.getFirewallConfigurationForDraft
      .mockResolvedValueOnce({
        ...desired,
        powerState: 'Unknown',
        provisioningState: 'Updating',
      })
      .mockResolvedValue({ ...desired, provisioningState: 'Succeeded' });
    const reloaded = await freshCandidate();
    reloaded.resume(() => {});
    await vi.waitFor(() => expect(store.state.activeCommits).toEqual([]));
    expect(store.state.history[0].results[0]).toMatchObject({
      target: 'firewall',
      ok: true,
    });
    expect(reloaded.status().pending).toEqual([]);
    expect(snapshotStorage.saveSnapshotToCentralStorage).not.toHaveBeenCalled();
  });
});

describe('policy threat-intelligence drafts', () => {
  beforeEach(() => {
    azure.getRuleCollectionGroup.mockReset().mockResolvedValue(running[0]);
    azure.putRuleCollectionGroup.mockReset().mockResolvedValue({});
  });

  it('saves and restores policy drafts separately from rule groups without writing to Azure', async () => {
    const c = await freshCandidate();
    c.stagePolicyMode(POLICY, 'Deny', { name: 'fp', threatIntelMode: 'Alert' });
    expect(c.status()).toMatchObject({
      unsaved: true,
      pending: [
        {
          target: 'policy',
          groupId: POLICY,
          policyMode: { before: 'Alert', after: 'Deny' },
          changes: [
            {
              target: 'policy',
              kind: 'modified',
              detail: 'Threat intelligence: Alert -> Deny',
            },
          ],
        },
      ],
    });
    c.save();
    const reloaded = await freshCandidate();
    expect(reloaded.status()).toMatchObject({
      unsaved: false,
      pending: [{ target: 'policy' }],
    });
    expect(reloaded.view(POLICY, running)).toHaveLength(1);
    expect(azure.putPolicyMode).not.toHaveBeenCalled();
    reloaded.stagePolicyMode(POLICY, 'Alert', {
      name: 'fp',
      threatIntelMode: 'Alert',
    });
    expect(reloaded.status().pending).toEqual([]);
  });

  it('does not claim success when Azure reports a canceled policy update with matching fields', async () => {
    const c = await freshCandidate();
    c.stagePolicyMode(POLICY, 'Deny', { name: 'fp', threatIntelMode: 'Alert' });
    azure.getPolicyMode.mockResolvedValue({
      name: 'fp',
      threatIntelMode: 'Deny',
      provisioningState: 'Canceled',
    });
    azure.putPolicyMode.mockResolvedValueOnce(undefined);
    const result = await c.commit([POLICY], 'mode', 'me', () => {});
    expect(result.results[0].ok).toBe(false);
    expect(c.status().pending).toHaveLength(1);
  });

  it('discards one policy setting without dropping unrelated rule drafts', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'new-group', 200, running);
    c.stagePolicyMode(POLICY, 'Off', { name: 'fp', threatIntelMode: 'Alert' });
    const status = c.revert([POLICY]);
    expect(status.pending).toHaveLength(1);
    expect(status.pending[0].groupName).toBe('new-group');
  });

  it('commits policy settings and rules sequentially with history and a cumulative mode snapshot', async () => {
    const c = await freshCandidate();
    const edited = { ...running[0], priority: 200 };
    c.stage(POLICY, edited, running[0]);
    c.stagePolicyMode(POLICY, 'Deny', { name: 'fp', threatIntelMode: 'Alert' });
    azure.putRuleCollectionGroup.mockImplementationOnce(async () => {
      azure.getRuleCollectionGroup.mockResolvedValue(edited);
    });
    const events: CommitProgress[] = [];
    const result = await c.commit(
      [running[0].id, POLICY],
      'tighten policy',
      'me',
      (p) => events.push(p),
    );
    expect(result.results.map((r) => [r.target, r.ok])).toEqual([
      ['policy', true],
      [undefined, true],
    ]);
    expect(azure.putPolicyMode).toHaveBeenCalledWith(POLICY, 'Alert', 'Deny');
    expect(azure.putPolicyMode.mock.invocationCallOrder[0]).toBeLessThan(
      azure.putRuleCollectionGroup.mock.invocationCallOrder[0],
    );
    expect(events.at(-1)).toMatchObject({ done: true });
    expect(snapshotStorage.saveSnapshotToCentralStorage).toHaveBeenCalledWith(
      expect.objectContaining({ threatIntelMode: 'Deny', groups: [edited] }),
    );
    expect(store.state.history[0].results[0].changes[0].target).toBe('policy');
    expect(c.status().pending).toEqual([]);
  });

  it('keeps failed policy changes drafted and does not snapshot an unapplied mode', async () => {
    const c = await freshCandidate();
    c.stagePolicyMode(POLICY, 'Deny', { name: 'fp', threatIntelMode: 'Alert' });
    c.stage(POLICY, { ...running[0], priority: 200 }, running[0]);
    azure.putPolicyMode.mockRejectedValueOnce(
      Object.assign(new Error('Changed in Azure'), {
        code: 'PolicyModeConflict',
      }),
    );
    const result = await c.commit(
      [POLICY, running[0].id],
      'mixed',
      'me',
      () => {},
    );
    expect(result.results[0]).toMatchObject({
      target: 'policy',
      ok: false,
      conflict: true,
    });
    expect(c.status().pending).toEqual([
      expect.objectContaining({ target: 'policy' }),
    ]);
    expect(snapshotStorage.saveSnapshotToCentralStorage).toHaveBeenCalledWith(
      expect.objectContaining({ threatIntelMode: 'Alert' }),
    );
  });

  it('reports snapshot read failures rather than recording an empty rule snapshot for a policy-only commit', async () => {
    const c = await freshCandidate();
    c.stagePolicyMode(POLICY, 'Deny', { name: 'fp', threatIntelMode: 'Alert' });
    azure.listRuleCollectionGroups.mockRejectedValueOnce(
      new Error('Cannot read policy rules'),
    );
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const record = await c.commit([POLICY], 'mode', 'me', () => {});
      expect(record.results[0].ok).toBe(true);
      expect(record.snapshotError).toContain('Cannot read policy rules');
      expect(
        snapshotStorage.saveSnapshotToCentralStorage,
      ).not.toHaveBeenCalled();
    } finally {
      logged.mockRestore();
    }
  });

  it('prevents another write to the same policy while a settings commit is running', async () => {
    const c = await freshCandidate();
    c.stagePolicyMode(POLICY, 'Deny', { name: 'fp', threatIntelMode: 'Alert' });
    c.stage(POLICY, { ...running[0], priority: 200 }, running[0]);
    let finish: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      finish = resolve;
    });
    azure.putPolicyMode.mockImplementationOnce(async () => {
      await held;
      azure.getPolicyMode.mockResolvedValue({
        name: 'fp',
        threatIntelMode: 'Deny',
        provisioningState: 'Succeeded',
      });
    });
    const commit = c.commit([POLICY], 'hold', 'me', () => {});
    await vi.waitFor(() => expect(azure.putPolicyMode).toHaveBeenCalled());
    await expect(
      c.commit([running[0].id], 'second', 'me', () => {}),
    ).rejects.toThrow('already being committed');
    expect(() =>
      c.stagePolicyMode(POLICY, 'Off', {
        name: 'fp',
        threatIntelMode: 'Alert',
      }),
    ).toThrow('being committed');
    finish();
    await commit;
    expect(c.status().pending).toHaveLength(1);
  });

  it.each([true, false])(
    'resumes saved policy commits (sent to Azure: %s)',
    async (sent) => {
      const c = await freshCandidate();
      c.stagePolicyMode(POLICY, 'Deny', {
        name: 'fp',
        threatIntelMode: 'Alert',
      });
      c.save();
      const changes = c.status().pending[0].changes;
      store.state.activeCommits = [
        {
          user: 'me',
          changeCount: 1,
          results: [],
          written: {},
          writtenPolicies: sent
            ? {
                [POLICY.toLowerCase()]: { name: 'fp', threatIntelMode: 'Deny' },
              }
            : {},
          progress: {
            commitId: 'policy-resume',
            startedAt: '2026-01-01T00:00:00.000Z',
            description: 'mode',
            index: 0,
            total: 1,
            groupName: 'fp',
            policyName: 'fp',
            groups: [
              {
                target: 'policy',
                groupId: POLICY,
                groupName: 'fp',
                policyName: 'fp',
                action: 'update',
                state: 'updating',
                changes,
              },
            ],
          },
        },
      ];
      azure.getPolicyMode.mockResolvedValue({
        name: 'fp',
        threatIntelMode: 'Deny',
        provisioningState: 'Succeeded',
      });
      const reloaded = await freshCandidate();
      reloaded.resume(() => {});
      await vi.waitFor(() => expect(store.state.activeCommits).toEqual([]));
      expect(store.state.history[0].results[0].ok).toBe(sent);
      expect(reloaded.status().pending).toHaveLength(sent ? 0 : 1);
    },
  );

  it('restores recorded modes using the current baseline and preserves them for older rule-only snapshots', async () => {
    const c = await freshCandidate();
    c.stagePolicyMode(POLICY, 'Off', { name: 'fp', threatIntelMode: 'Alert' });
    const snapshot = {
      id: 'snapshot',
      policyId: POLICY,
      policyName: 'fp',
      time: '2026-01-01',
      description: 'Policy mode snapshot',
      groups: [],
    };
    c.restoreSnapshot({ ...snapshot, threatIntelMode: 'Deny' }, [], {
      name: 'fp',
      threatIntelMode: 'Off',
    });
    expect(c.status().pending[0].policyMode).toEqual({
      before: 'Off',
      after: 'Deny',
    });
    c.restoreSnapshot(snapshot, []);
    expect(c.status().pending[0].policyMode).toEqual({
      before: 'Off',
      after: 'Deny',
    });
  });
});

describe('bulk CSV draft imports', () => {
  const row = {
    'Rule collection group': 'Platform',
    'Group priority': '100',
    'Rule collection': 'net-import',
    'Collection priority': '100',
    'Collection type': 'Network',
    Action: 'Allow',
    'Rule name': 'imported',
    'Source addresses': '10.0.0.0/24',
    Protocols: 'TCP',
    'Destination addresses': '10.20.0.0/24',
    'Destination ports': '443',
  };
  const csv = (...rows: Record<string, string>[]) =>
    [
      RULE_IMPORT_COLUMNS.join(','),
      ...rows.map((r) =>
        RULE_IMPORT_COLUMNS.map((column) => csvCell(r[column])).join(','),
      ),
    ].join('\r\n');

  it('stages several groups atomically without writing to Azure and survives a normal save', async () => {
    azure.putRuleCollectionGroup.mockClear();
    const c = await freshCandidate();
    const text = csv(row, {
      ...row,
      'Rule collection group': 'New',
      'Group priority': '200',
      'Source addresses': '192.168.0.0/24',
    });
    const result = c.importRulesCsv(POLICY, text, {}, running);
    expect(result.ruleCount).toBe(2);
    expect(result.groupIds).toHaveLength(2);
    expect(result.status.pending).toHaveLength(2);
    expect(azure.putRuleCollectionGroup).not.toHaveBeenCalled();
    c.save();
    const restored = await freshCandidate();
    const views = restored.view(POLICY, running);
    expect(
      views.flatMap((v) =>
        v.group.ruleCollections.flatMap<FirewallRule>((col) => col.rules),
      ),
    ).toHaveLength(2);
    expect(views.find((v) => v.group.name === 'New')?.isNew).toBe(true);
  });

  it('preserves unrelated draft edits and leaves them unchanged when any CSV row is invalid', async () => {
    const c = await freshCandidate();
    const edited = structuredClone(running[0]);
    edited.ruleCollections.push({
      ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
      name: 'keep-this',
      priority: 200,
      action: { type: 'Deny' },
      rules: [],
    });
    c.stage(POLICY, edited, running[0]);
    const before = c.status();
    expect(() =>
      c.importRulesCsv(
        POLICY,
        csv(row, {
          ...row,
          'Rule collection group': 'Invalid',
          'Group priority': '300',
          'Source addresses': '999.0.0.1',
        }),
        {},
        running,
      ),
    ).toThrow('CSV import failed');
    expect(c.status()).toEqual(before);
    c.importRulesCsv(POLICY, csv(row), {}, running);
    expect(
      c.view(POLICY, running)[0].group.ruleCollections.map((col) => col.name),
    ).toEqual(['keep-this', 'net-import']);
  });

  it('requires explicit current consent for replacement and keeps the original baseline', async () => {
    const c = await freshCandidate();
    c.importRulesCsv(POLICY, csv(row), {}, running);
    const text = csv({ ...row, 'Destination ports': '8443' });
    const preview = planRuleImport(text, {
      policyId: POLICY,
      groups: c.view(POLICY, running).map((v) => v.group),
    });
    expect(() => c.importRulesCsv(POLICY, text, {}, running)).toThrow(
      'No rules were selected',
    );
    c.importRulesCsv(
      POLICY,
      text,
      { 2: { action: 'replace', token: preview.rows[0].token } },
      running,
    );
    const view = c.view(POLICY, running)[0];
    expect(view.group.ruleCollections[0].rules).toHaveLength(1);
    expect(view.group.ruleCollections[0].rules[0]).toMatchObject({
      destinationPorts: ['8443'],
    });
    expect(view.baseline).toEqual(running[0]);
    const before = c.status();
    expect(() =>
      c.importRulesCsv(
        POLICY,
        text,
        { 2: { action: 'replace', token: preview.rows[0].token } },
        running,
      ),
    ).toThrow();
    expect(c.status()).toEqual(before);
  });
});

describe('drafting new rule collection groups', () => {
  beforeEach(() => {
    azure.getRuleCollectionGroup.mockReset();
    azure.putRuleCollectionGroup.mockReset();
  });

  it('drafts an empty group that shows in the view and as a pending change', async () => {
    const c = await freshCandidate();
    const status = c.create(POLICY, 'rcg-new', 200, running);
    expect(status.pending).toEqual([
      expect.objectContaining({
        groupId: NEW_ID,
        groupName: 'rcg-new',
        changes: [
          {
            kind: 'added',
            target: 'group',
            detail: 'new group, priority 200',
          },
        ],
      }),
    ]);
    const view = c.view(POLICY, running);
    expect(view.map((v) => [v.group.name, v.isNew ?? false])).toEqual([
      ['Platform', false],
      ['rcg-new', true],
    ]);
    // Other policies don't see it.
    expect(c.view(`${POLICY}-other`, [])).toEqual([]);
  });

  it('rejects duplicate names/priorities, including other drafted groups', async () => {
    const c = await freshCandidate();
    expect(() => c.create(POLICY, 'PLATFORM', 300, running)).toThrow(
      /already has a rule collection group/,
    );
    expect(() => c.create(POLICY, 'rcg-x', 100, running)).toThrow(
      /already used by "Platform"/,
    );
    c.create(POLICY, 'rcg-new', 200, running);
    expect(() => c.create(POLICY, 'rcg-other', 200, running)).toThrow(
      /already used by "rcg-new"/,
    );
  });

  it('stages edits to a drafted group without Azure, and keeps it when emptied', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    const edited: RuleCollectionGroup = {
      id: NEW_ID,
      name: 'rcg-new',
      priority: 200,
      ruleCollections: [
        {
          ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
          name: 'allow-dns',
          priority: 100,
          action: { type: 'Allow' },
          rules: [],
        },
      ],
    };
    const status = c.stage(POLICY, edited, undefined);
    expect(status.pending[0].changes.map((x) => x.target)).toEqual([
      'group',
      'collection',
    ]);
    // Removing everything again leaves the new (empty) group drafted.
    const emptied = c.stage(
      POLICY,
      { ...edited, ruleCollections: [] },
      undefined,
    );
    expect(emptied.pending).toHaveLength(1);
    expect(azure.getRuleCollectionGroup).not.toHaveBeenCalled();
  });

  it('discarding a drafted group removes it', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    expect(c.revert([NEW_ID]).pending).toEqual([]);
    expect(c.view(POLICY, running)).toHaveLength(1);
  });

  it('creates the group in Azure on commit when it still does not exist', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    azure.getRuleCollectionGroup
      .mockRejectedValueOnce(notFound)
      .mockResolvedValue({ ...running[0], id: NEW_ID });
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const record = await c.commit([NEW_ID], 'add group', 'me', () => {});
    expect(record.results).toEqual([
      expect.objectContaining({ groupId: NEW_ID, ok: true }),
    ]);
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledWith(
      expect.objectContaining({ id: NEW_ID, priority: 200 }),
    );
    expect(c.status().pending).toEqual([]);
    // The history records what was done, not just that it worked.
    expect(record.results[0]).toMatchObject({
      action: 'create',
      changes: [
        {
          kind: 'added',
          target: 'group',
          detail: 'new group, priority 200',
        },
      ],
    });
  });

  it('refuses to overwrite a same-named group created in Azure meanwhile', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    azure.getRuleCollectionGroup.mockResolvedValue({ ...running[0] });
    const record = await c.commit([NEW_ID], 'add group', 'me', () => {});
    expect(record.results[0]).toMatchObject({ ok: false, conflict: true });
    expect(azure.putRuleCollectionGroup).not.toHaveBeenCalled();
    // It stays drafted, flagged as conflicting once Azure lists it.
    const view = c.view(POLICY, [
      ...running,
      { ...running[0], id: NEW_ID, name: 'rcg-new', priority: 200 },
    ]);
    expect(view.find((v) => v.group.id === NEW_ID)).toMatchObject({
      isNew: true,
      drift: true,
    });
  });
});

describe('committing edits to existing groups', () => {
  beforeEach(() => {
    azure.getRuleCollectionGroup.mockReset();
    azure.putRuleCollectionGroup.mockReset();
  });
  const edited = (): RuleCollectionGroup => ({
    ...running[0],
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
        name: 'net-allow-core',
        priority: 100,
        action: { type: 'Allow' },
        rules: [],
      },
    ],
  });

  it('commits when only the etag changed (e.g. Azure finished provisioning)', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    // Same contents, new etag.
    azure.getRuleCollectionGroup.mockResolvedValue({
      ...running[0],
      etag: 'e2',
    });
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const events: CommitProgress[] = [];
    const record = await c.commit([running[0].id], 'x', 'me', (p) =>
      events.push(p),
    );
    expect(record.results[0]).toMatchObject({ ok: true });
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledWith(
      expect.objectContaining({ etag: 'e2' }),
    );
    expect(events.map((e) => e.groups[0].state)).toEqual([
      'checking',
      'updating',
      'succeeded',
      'succeeded',
    ]);
    expect(events.at(-1)).toMatchObject({ done: true, commitId: record.id });
    // The draft view doesn't call this a conflict either.
    expect(c.view(POLICY, [{ ...running[0], etag: 'e3' }])[0].drift).toBe(
      false,
    );
  });

  it('merges a draft onto unrelated changes made in Azure', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    const theirs = { ...running[0], etag: 'e2', priority: 150 };
    azure.getRuleCollectionGroup.mockResolvedValue(theirs);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const record = await c.commit([running[0].id], 'x', 'me', () => {});
    expect(record.results[0]).toMatchObject({ ok: true });
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledWith(
      expect.objectContaining({
        etag: 'e2',
        priority: 150,
        ruleCollections: edited().ruleCollections,
      }),
    );
  });

  it('refuses when Azure changed the same thing differently', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    const theirs = {
      ...running[0],
      etag: 'e2',
      ruleCollections: [{ ...edited().ruleCollections[0], priority: 300 }],
    };
    azure.getRuleCollectionGroup.mockResolvedValue(theirs);
    const events: CommitProgress[] = [];
    const record = await c.commit([running[0].id], 'x', 'me', (p) =>
      events.push(p),
    );
    expect(record.results[0]).toMatchObject({ ok: false, conflict: true });
    expect(azure.putRuleCollectionGroup).not.toHaveBeenCalled();
    expect(events.at(-1)?.groups[0].state).toBe('conflict');
    const view = c.view(POLICY, [theirs])[0];
    expect(view.drift).toBe(true);
    expect(view.conflicts?.[0]).toMatch(/net-allow-core/);
  });

  it('moves a saved draft onto Azure’s version when they don’t overlap', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    c.save();
    const theirs = { ...running[0], etag: 'e2', priority: 150 };
    const view = c.view(POLICY, [theirs])[0];
    expect(view).toMatchObject({ staged: true, drift: false });
    expect(view.group.priority).toBe(150);
    expect(view.baseline?.etag).toBe('e2');
  });

  it('marks groups as committing and refuses a second commit of them meanwhile', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    let finish!: () => void;
    azure.putRuleCollectionGroup.mockReturnValue(
      new Promise((r) => (finish = () => r({}))),
    );
    const first = c.commit([running[0].id], 'x', 'me', () => {});
    expect(c.status().pending[0].committing).toBe(true);
    await expect(
      c.commit([running[0].id], 'again', 'me', () => {}),
    ).rejects.toThrow(/already being committed/);
    expect(() => c.stage(POLICY, edited(), running[0])).toThrow(
      /being committed/,
    );
    await vi.waitFor(() =>
      expect(azure.putRuleCollectionGroup).toHaveBeenCalled(),
    );
    finish();
    expect((await first).results[0].ok).toBe(true);
    expect(c.status().pending).toEqual([]);
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledTimes(1);
  });

  it('waits for Azure to finish earlier and current changes before reporting success', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    const updating = { ...running[0], provisioningState: 'Updating' };
    const done = { ...edited(), etag: 'e3', provisioningState: 'Succeeded' };
    azure.getRuleCollectionGroup
      .mockResolvedValueOnce(updating)
      .mockResolvedValueOnce({ ...running[0], provisioningState: 'Succeeded' })
      .mockResolvedValueOnce({ ...done, provisioningState: 'Updating' })
      .mockResolvedValueOnce(done);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const events: CommitProgress[] = [];
    const record = await c.commit([running[0].id], 'x', 'me', (p) =>
      events.push(p),
    );
    expect(record.results[0].ok).toBe(true);
    expect(events.map((e) => e.groups[0].state)).toEqual([
      'checking',
      'waiting',
      'checking',
      'updating',
      'succeeded',
      'succeeded',
    ]);
    expect(azure.getRuleCollectionGroup).toHaveBeenCalledTimes(4);
    expect(store.state.activeCommits).toEqual([]);
  });

  it('retries when Azure says the group is still busy', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    azure.putRuleCollectionGroup
      .mockRejectedValueOnce(
        Object.assign(new Error('busy'), {
          code: 'FirewallPolicyRuleCollectionGroupUpdateNotAllowedWhenUpdatingOrDeleting',
        }),
      )
      .mockResolvedValueOnce({});
    const record = await c.commit([running[0].id], 'x', 'me', () => {});
    expect(record.results[0].ok).toBe(true);
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledTimes(2);
  });

  it('resumes a commit interrupted by closing the app', async () => {
    const other = { ...running[0], id: `${POLICY}/ruleCollectionGroups/Other` };
    store.state.candidate = [
      {
        groupId: running[0].id,
        policyId: POLICY,
        policyName: 'fp',
        stagedAt: '',
        baseline: running[0],
        candidate: edited(),
      },
      {
        groupId: other.id,
        policyId: POLICY,
        policyName: 'fp',
        stagedAt: '',
        baseline: other,
        candidate: { ...edited(), id: other.id },
      },
    ];
    const group = (id: string, state: string) => ({
      groupId: id,
      groupName: 'g',
      policyName: 'fp',
      action: 'update' as const,
      state: state as never,
    });
    store.state.activeCommits = [
      {
        changeCount: 2,
        results: [],
        written: { [running[0].id.toLowerCase()]: edited() },
        progress: {
          commitId: 'c1',
          startedAt: '',
          description: 'interrupted',
          index: 0,
          total: 2,
          groupName: 'g',
          policyName: 'fp',
          groups: [
            group(running[0].id, 'updating'),
            group(other.id, 'pending'),
          ],
        },
      },
    ];
    const c = await freshCandidate();
    azure.getRuleCollectionGroup
      .mockResolvedValueOnce({ ...edited(), provisioningState: 'Updating' })
      .mockResolvedValueOnce({ ...edited(), provisioningState: 'Succeeded' });
    const events: CommitProgress[] = [];
    const snapshot = c.resume((p) => events.push(p));
    expect(snapshot?.commitId).toBe('c1');
    expect(c.status().pending.every((p) => p.committing)).toBe(true);
    await vi.waitFor(() => expect(events.at(-1)?.done).toBe(true));
    expect(events.at(-1)?.groups.map((g) => g.state)).toEqual([
      'succeeded',
      'failed',
    ]);
    expect(store.state.history[0]).toMatchObject({ id: 'c1' });
    expect(store.state.activeCommits).toEqual([]);
    // The written group left the draft; the unsent one is still there.
    expect(c.status().pending.map((p) => p.groupId)).toEqual([other.id]);
    expect(c.resume(() => {})).toBeNull();
  });

  it('reports "creating" for new groups', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    azure.getRuleCollectionGroup
      .mockRejectedValueOnce(notFound)
      .mockResolvedValue({ ...running[0], id: NEW_ID });
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const events: CommitProgress[] = [];
    await c.commit([NEW_ID], 'x', 'me', (p) => events.push(p));
    expect(events.map((e) => e.groups[0].state)).toContain('creating');
    expect(events[0].groups[0].action).toBe('create');
  });

  it('keeps every concurrently running commit on disk until it finishes', async () => {
    const other = { ...running[0], id: `${POLICY}/ruleCollectionGroups/Other` };
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    c.stage(POLICY, { ...edited(), id: other.id }, other);
    azure.getRuleCollectionGroup.mockImplementation(async (id: string) =>
      id === other.id ? other : running[0],
    );
    const finishers: (() => void)[] = [];
    azure.putRuleCollectionGroup.mockImplementation(
      () => new Promise((r) => finishers.push(() => r({}))),
    );
    const first = c.commit([running[0].id], 'one', 'me', () => {});
    const second = c.commit([other.id], 'two', 'me', () => {});
    await vi.waitFor(() => expect(finishers).toHaveLength(2));
    expect(store.state.activeCommits).toHaveLength(2);
    finishers[0]();
    const firstRecord = await first;
    // The second commit is still running, so it must still be resumable.
    expect(
      store.state.activeCommits.map(
        (a: { progress: CommitProgress }) => a.progress.description,
      ),
    ).toEqual(['two']);
    finishers[1]();
    const secondRecord = await second;
    expect(store.state.activeCommits).toEqual([]);
    expect(store.state.history.map((h: { id: string }) => h.id).sort()).toEqual(
      [firstRecord.id, secondRecord.id].sort(),
    );
  });

  it('drops groups that succeeded before the app closed from the draft on resume', async () => {
    const other = { ...running[0], id: `${POLICY}/ruleCollectionGroups/Other` };
    const staged = (g: RuleCollectionGroup) => ({
      groupId: g.id,
      policyId: POLICY,
      policyName: 'fp',
      stagedAt: '',
      baseline: g,
      candidate: { ...edited(), id: g.id },
    });
    store.state.candidate = [staged(running[0]), staged(other)];
    const group = (id: string, state: string) => ({
      groupId: id,
      groupName: 'g',
      policyName: 'fp',
      action: 'update' as const,
      state: state as never,
    });
    const interrupted = (
      commitId: string,
      groups: ReturnType<typeof group>[],
    ) => ({
      changeCount: groups.length,
      results: [],
      written: {},
      progress: {
        commitId,
        startedAt: '',
        description: commitId,
        index: 0,
        total: groups.length,
        groupName: 'g',
        policyName: 'fp',
        groups,
      },
    });
    store.state.activeCommits = [
      interrupted('c1', [group(running[0].id, 'succeeded')]),
      interrupted('c2', [group(other.id, 'pending')]),
    ];
    const c = await freshCandidate();
    const events: CommitProgress[] = [];
    expect(c.resume((p) => events.push(p))?.commitId).toBe('c1');
    await vi.waitFor(() => expect(store.state.activeCommits).toEqual([]));
    expect(
      events
        .filter((e) => e.done)
        .map((e) => e.commitId)
        .sort(),
    ).toEqual(['c1', 'c2']);
    expect(c.status().pending.map((p) => p.groupId)).toEqual([other.id]);
    expect(azure.getRuleCollectionGroup).not.toHaveBeenCalled();
  });

  it('records one cumulative snapshot in central storage only when a commit completes, and restores a former snapshot', async () => {
    const c = await freshCandidate();
    // Viewing or staging draft changes must never create snapshots.
    c.view(POLICY, running);
    const nextGroup = edited();
    c.stage(POLICY, nextGroup, running[0]);
    expect(snapshotStorage.saveSnapshotToCentralStorage).not.toHaveBeenCalled();

    // Committing records a single cumulative snapshot for the policy in centralized storage.
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    azure.listRuleCollectionGroups.mockResolvedValue([nextGroup]);
    await c.commit([running[0].id], 'CHG001 cumulative update', 'me', () => {});
    expect(
      snapshotStorage.requireSnapshotStorageConfigured,
    ).toHaveBeenCalledTimes(1);
    expect(snapshotStorage.saveSnapshotToCentralStorage).toHaveBeenCalledTimes(
      1,
    );
    const savedSnapshot =
      snapshotStorage.saveSnapshotToCentralStorage.mock.calls[0][0];
    expect(savedSnapshot).toMatchObject({
      policyId: POLICY,
      policyName: 'fp',
      user: 'me',
      description: 'CHG001 cumulative update',
    });

    // Restoring a prior snapshot stages the rollback over the modified running state.
    const initialSnapshot = {
      ...savedSnapshot,
      groups: running,
    };
    const restoredStatus = c.restoreSnapshot(initialSnapshot, [nextGroup], {
      name: 'fp',
      threatIntelMode: 'Alert',
    });
    expect(restoredStatus.pending).toHaveLength(1);
    expect(restoredStatus.pending[0].changes).toEqual([
      expect.objectContaining({
        kind: 'removed',
        target: 'collection',
        collection: 'net-allow-core',
      }),
    ]);
  });

  it('adds every finished commit to the shared history', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    azure.listRuleCollectionGroups.mockResolvedValue([edited()]);
    const record = await c.commit([running[0].id], 'shared', 'alice', () => {});
    expect(snapshotStorage.saveCommitToCentralHistory).toHaveBeenCalledTimes(1);
    expect(
      snapshotStorage.saveCommitToCentralHistory.mock.calls[0][0],
    ).toMatchObject({ id: record.id, user: 'alice', description: 'shared' });
    expect(record.historyError).toBeUndefined();
  });

  it('keeps a commit that could not be shared, and says so', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    azure.listRuleCollectionGroups.mockResolvedValue([edited()]);
    snapshotStorage.saveCommitToCentralHistory.mockRejectedValue(
      new Error('history denied'),
    );
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const record = await c.commit([running[0].id], 'x', 'me', () => {});
    expect(record.results).toEqual([expect.objectContaining({ ok: true })]);
    expect(record.historyError).toMatch(/history denied/);
    expect(store.state.history).toHaveLength(1);
    error.mockRestore();
  });

  it('never saves a snapshot for draft saves, only for commits', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    c.save();
    c.save();
    expect(snapshotStorage.saveSnapshotToCentralStorage).not.toHaveBeenCalled();
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    azure.listRuleCollectionGroups.mockResolvedValue([edited()]);
    await c.commit([running[0].id], 'one commit', 'me', () => {});
    expect(snapshotStorage.saveSnapshotToCentralStorage).toHaveBeenCalledTimes(
      1,
    );
  });

  it('still finishes a commit Azure applied when its snapshot cannot be saved', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    azure.listRuleCollectionGroups.mockResolvedValue([edited()]);
    snapshotStorage.saveSnapshotToCentralStorage.mockRejectedValue(
      new Error('Snapshot upload denied'),
    );
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const record = await c.commit([running[0].id], 'x', 'me', () => {});
    expect(record.results).toEqual([expect.objectContaining({ ok: true })]);
    expect(record.snapshotError).toMatch(/Snapshot upload denied/);
    expect(store.state.history).toHaveLength(1);
    expect(store.state.activeCommits).toEqual([]);
    expect(c.status().pending).toEqual([]);
    error.mockRestore();
  });

  it('saves the snapshot of a commit that finished across a restart', async () => {
    store.state.candidate = [
      {
        groupId: running[0].id,
        policyId: POLICY,
        policyName: 'fp',
        stagedAt: '',
        baseline: running[0],
        candidate: edited(),
      },
    ];
    store.state.activeCommits = [
      {
        user: 'me',
        changeCount: 1,
        results: [],
        written: { [running[0].id.toLowerCase()]: edited() },
        progress: {
          commitId: 'c1',
          startedAt: '',
          description: 'resumed change',
          index: 0,
          total: 1,
          groupName: 'Platform',
          policyName: 'fp',
          groups: [
            {
              groupId: running[0].id,
              groupName: 'Platform',
              policyName: 'fp',
              action: 'update' as const,
              state: 'updating' as const,
            },
          ],
        },
      },
    ];
    azure.getRuleCollectionGroup.mockResolvedValue(edited());
    azure.listRuleCollectionGroups.mockResolvedValue([edited()]);
    const c = await freshCandidate();
    c.resume(() => {});
    await vi.waitFor(() => expect(store.state.activeCommits).toEqual([]));
    expect(snapshotStorage.saveSnapshotToCentralStorage).toHaveBeenCalledTimes(
      1,
    );
    expect(
      snapshotStorage.saveSnapshotToCentralStorage.mock.calls[0][0],
    ).toMatchObject({
      policyId: POLICY,
      user: 'me',
      description: 'resumed change',
      groups: [expect.objectContaining({ name: 'Platform' })],
    });
  });
});
