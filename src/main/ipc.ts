import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  shell,
  type IpcMainInvokeEvent,
  type WebContents,
} from 'electron';
import fs from 'node:fs/promises';
import path from 'node:path';
import { IPC, type IpcResult } from '../shared/ipc';
import {
  RESOURCE_TYPES,
  isResourceIdOfType,
  portalUrl,
} from '../shared/resourceId';
import type {
  CreateSnapshotStorageRequest,
  RuleCollectionGroup,
} from '../shared/types';
import {
  TIERS,
  type DeployRequest,
  type FirewallTier,
  type ThreatIntelMode,
} from '../shared/deploy';
import * as auth from './auth';
import * as azure from './azure';
import * as deploy from './deploy';
import * as ipGroups from './ipGroups';
import { MAX_IP_GROUP_ADDRESSES } from '../shared/ipGroups';
import { importRulesCsv } from './ruleImport';
import {
  MAX_RULE_IMPORT_BYTES,
  type RuleImportChoices,
} from '../shared/ruleImport';
import * as snapshotStorage from './snapshotStorage';
import { candidate } from './candidate';
import { clearLookupCache, getRuleLookups } from './lookups';
import { loadState, updateState } from './store';
import { isAppUrl } from './appProtocol';
import { isThreatIntelMode, type PolicyModeConfig } from '../shared/policyMode';
import * as resourceSettings from './resourceSettings';
import {
  mergeSettings,
  sanitizeAllocation,
  sanitizeFirewallConfiguration,
  sanitizePolicySettings,
  FIREWALL_SETTING_KEYS,
  POLICY_SETTING_KEYS,
  type FirewallConfiguration,
} from '../shared/resourceSettings';

const runningCache = new Map<string, RuleCollectionGroup>();
auth.onSignOut(() => runningCache.clear());

/** Only the app's own top-level page may call into the main process. */
function isTrustedSender(event: IpcMainInvokeEvent): boolean {
  const frame = event.senderFrame;
  return !!frame && frame === frame.top && isAppUrl(frame.url);
}

function handle<A extends unknown[], R>(
  channel: string,
  fn: (event: IpcMainInvokeEvent, ...args: A) => Promise<R> | R,
): void {
  ipcMain.handle(channel, async (event, ...args): Promise<IpcResult<R>> => {
    if (!isTrustedSender(event))
      return { ok: false, error: 'Untrusted sender.' };
    try {
      return { ok: true, data: await fn(event, ...(args as A)) };
    } catch (err) {
      // Full details go to the terminal (never tokens); the UI gets a readable summary.
      const e = err as {
        name?: string;
        code?: string;
        statusCode?: number;
        message?: string;
        response?: { headers?: { get?: (h: string) => string | undefined } };
      };
      console.error(`[${channel}] ${e?.name ?? 'Error'}`, {
        statusCode: e?.statusCode,
        code: e?.code,
        message: e?.message,
        wwwAuthenticate: e?.response?.headers?.get?.('www-authenticate'),
      });
      return { ok: false, error: azure.describeAzureError(err) };
    }
  });
}

function assertId(
  value: unknown,
  type: string,
  label: string,
): asserts value is string {
  if (!isResourceIdOfType(value, type)) throw new Error(`Invalid ${label} ID.`);
}

function assertGroup(value: unknown): asserts value is RuleCollectionGroup {
  const g = value as RuleCollectionGroup;
  if (
    !g ||
    typeof g !== 'object' ||
    typeof g.name !== 'string' ||
    !Array.isArray(g.ruleCollections)
  ) {
    throw new Error('Invalid rule collection group payload.');
  }
  assertId(g.id, RESOURCE_TYPES.ruleCollectionGroup, 'rule collection group');
  for (const c of g.ruleCollections) {
    if (!c || typeof c !== 'object' || !Array.isArray(c.rules)) {
      throw new Error('Invalid rule collection payload.');
    }
  }
}

function assertCandidateId(value: unknown): asserts value is string {
  if (
    !isResourceIdOfType(value, RESOURCE_TYPES.ruleCollectionGroup) &&
    !isResourceIdOfType(value, RESOURCE_TYPES.policy) &&
    !isResourceIdOfType(value, RESOURCE_TYPES.firewall)
  )
    throw new Error('Invalid draft resource ID.');
}

export function registerIpc(getContents: () => WebContents | undefined): void {
  // Progress keeps coming after the window is closed (e.g. on macOS); drop it then.
  const send = (channel: string, payload: unknown) => {
    const contents = getContents();
    if (contents && !contents.isDestroyed()) contents.send(channel, payload);
  };
  handle(IPC.signIn, (_e, method: unknown, tenantId: unknown) => {
    if (method !== 'window' && method !== 'browser' && method !== 'cli')
      throw new Error('Unknown sign-in method.');
    if (tenantId !== undefined && typeof tenantId !== 'string')
      throw new Error('Invalid tenant.');
    return auth.signIn(method, tenantId?.trim() || undefined);
  });
  handle(IPC.cancelSignIn, () => auth.cancelSignIn());
  handle(IPC.getAccount, () => auth.getAccount());
  handle(IPC.restoreSession, () => auth.restoreSession());
  handle(IPC.signOut, () => auth.signOut());
  handle(IPC.switchTenant, (_e, tenantId: unknown) => {
    if (typeof tenantId !== 'string') throw new Error('Invalid directory ID.');
    return auth.switchTenant(tenantId);
  });

  handle(IPC.discoverFirewalls, () => azure.discoverFirewalls());
  handle(IPC.discoverIpGroups, () => ipGroups.discoverIpGroups());
  handle(IPC.getIpGroupContext, (_e, subscriptionId: unknown) =>
    ipGroups.getIpGroupContext(assertSubscription(subscriptionId)),
  );
  handle(IPC.createIpGroup, async (_e, raw: unknown) => {
    if (!raw || typeof raw !== 'object')
      throw new Error('Invalid IP group request.');
    const r = raw as Record<string, unknown>;
    if (
      !Array.isArray(r.addresses) ||
      r.addresses.length > MAX_IP_GROUP_ADDRESSES ||
      !r.addresses.every(
        (address): address is string => typeof address === 'string',
      )
    )
      throw new Error('Invalid IP group address list (at most 5000 entries).');
    const group = await ipGroups.createIpGroup({
      subscriptionId: assertSubscription(r.subscriptionId),
      resourceGroup: str(r.resourceGroup, 'resource group'),
      location: str(r.location, 'location'),
      name: str(r.name, 'IP group name'),
      addresses: [
        ...new Set(r.addresses.map((address) => str(address, 'IP address'))),
      ],
    });
    clearLookupCache();
    return group;
  });
  handle(IPC.getManagedFirewalls, () => loadState().managedFirewallIds);
  handle(IPC.setManagedFirewalls, (_e, ids: unknown) => {
    if (!Array.isArray(ids) || ids.length > 5000)
      throw new Error('Invalid firewall list.');
    for (const id of ids) assertId(id, RESOURCE_TYPES.firewall, 'firewall');
    updateState((s) => {
      s.managedFirewallIds = [...new Set(ids as string[])];
    });
  });

  handle(IPC.getPolicy, async (_e, policyId: unknown) => {
    assertId(policyId, RESOURCE_TYPES.policy, 'firewall policy');
    const [policy, running] = await Promise.all([
      azure.getPolicy(policyId),
      azure.listRuleCollectionGroups(policyId),
    ]);
    for (const g of running) runningCache.set(g.id.toLowerCase(), g);
    return { policy, groups: candidate.view(policyId, running) };
  });

  handle(IPC.stageGroup, async (_e, policyId: unknown, group: unknown) => {
    assertId(policyId, RESOURCE_TYPES.policy, 'firewall policy');
    assertGroup(group);
    if (!group.id.toLowerCase().startsWith(`${policyId.toLowerCase()}/`)) {
      throw new Error('Rule collection group does not belong to this policy.');
    }
    // Groups drafted in the app don't exist in Azure yet, so there's nothing to fetch.
    if (candidate.isCreated(group.id))
      return candidate.stage(policyId, group, undefined);
    const k = group.id.toLowerCase();
    let running = runningCache.get(k);
    if (!running) {
      running = await azure.getRuleCollectionGroup(group.id);
      runningCache.set(k, running);
    }
    return candidate.stage(policyId, group, running);
  });

  handle(IPC.stagePolicyMode, async (_e, policyId: unknown, mode: unknown) => {
    assertId(policyId, RESOURCE_TYPES.policy, 'firewall policy');
    if (!isThreatIntelMode(mode))
      throw new Error('Unsupported threat-intelligence mode.');
    const policy = await azure.getPolicy(policyId);
    if (!isThreatIntelMode(policy.threatIntelMode))
      throw new Error(
        'Azure did not return a supported threat-intelligence mode. Refresh the policy before editing it.',
      );
    await azure.validatePolicyMode(policy, mode);
    return candidate.stagePolicyMode(policyId, mode, {
      name: policy.name,
      threatIntelMode: policy.threatIntelMode,
      settings: policy.settings,
    });
  });

  handle(
    IPC.createGroup,
    async (_e, policyId: unknown, name: unknown, priority: unknown) => {
      assertId(policyId, RESOURCE_TYPES.policy, 'firewall policy');
      if (typeof name !== 'string' || typeof priority !== 'number')
        throw new Error('Invalid rule collection group.');
      // Check against Azure's current groups, not a possibly stale cache.
      const running = await azure.listRuleCollectionGroups(policyId);
      for (const g of running) runningCache.set(g.id.toLowerCase(), g);
      return candidate.create(policyId, name.trim(), priority, running);
    },
  );

  handle(IPC.getPolicySettings, async (_e, id: unknown) => {
    assertId(id, RESOURCE_TYPES.policy, 'firewall policy');
    const view = await resourceSettings.getPolicySettings(id);
    view.draft = candidate.effectivePolicyConfiguration(id, {
      name: view.name,
      threatIntelMode: view.threatIntelMode,
      settings: view.running,
    }).settings;
    return view;
  });
  handle(
    IPC.stagePolicySettings,
    async (_e, id: unknown, before: unknown, after: unknown) => {
      assertId(id, RESOURCE_TYPES.policy, 'firewall policy');
      const initial = sanitizePolicySettings(before);
      const desired = sanitizePolicySettings(after);
      const running = await resourceSettings.getPolicyConfiguration(id);
      const effective = candidate.effectivePolicyConfiguration(id, running);
      const merged = mergeSettings(
        initial,
        desired,
        effective.settings ?? running.settings,
        POLICY_SETTING_KEYS,
      );
      await resourceSettings.validatePolicyConfiguration(
        id,
        merged,
        running.settings,
      );
      return candidate.stagePolicyConfiguration(
        id,
        { ...effective, settings: merged },
        running,
      );
    },
  );
  handle(IPC.getFirewallSettings, async (_e, id: unknown) => {
    assertId(id, RESOURCE_TYPES.firewall, 'firewall');
    const view = await resourceSettings.getFirewallSettings(id);
    view.draft = candidate.effectiveFirewallConfiguration(id, view.running);
    return view;
  });
  handle(IPC.getFirewallConfiguration, async (_e, id: unknown) => {
    assertId(id, RESOURCE_TYPES.firewall, 'firewall');
    return resourceSettings.getFirewallConfiguration(id);
  });
  handle(IPC.getLearnedPrefixes, async (_e, id: unknown) => {
    assertId(id, RESOURCE_TYPES.firewall, 'firewall');
    return resourceSettings.getLearnedPrefixes(id);
  });
  handle(
    IPC.stageFirewallSettings,
    async (_e, id: unknown, before: unknown, after: unknown) => {
      assertId(id, RESOURCE_TYPES.firewall, 'firewall');
      const initial = sanitizeFirewallConfiguration(before);
      const desired = sanitizeFirewallConfiguration(after);
      const running = await resourceSettings.getFirewallDraftContext(
        id,
        initial.maintenanceConfigurationIds !== undefined ||
          desired.maintenanceConfigurationIds !== undefined,
      );
      const effective = candidate.effectiveFirewallConfiguration(
        id,
        running.configuration,
      );
      const merged = mergeSettings(
        initial,
        desired,
        effective,
        FIREWALL_SETTING_KEYS,
      );
      merged.allocation = desired.allocation ?? effective.allocation;
      await resourceSettings.validateFirewallConfiguration(
        id,
        merged,
        running.configuration,
      );
      return candidate.stageFirewallConfiguration(
        id,
        running.policyId,
        merged,
        running.configuration,
      );
    },
  );
  handle(
    IPC.stageFirewallPower,
    async (_e, id: unknown, power: unknown, rawAllocation: unknown) => {
      assertId(id, RESOURCE_TYPES.firewall, 'firewall');
      if (power !== 'Running' && power !== 'Stopped')
        throw new Error('Unsupported firewall power state.');
      const running = await resourceSettings.getFirewallDraftContext(id, false);
      const effective = candidate.effectiveFirewallConfiguration(
        id,
        running.configuration,
      );
      const desired: FirewallConfiguration = {
        ...effective,
        powerState: power,
        allocation:
          rawAllocation === undefined
            ? effective.allocation
            : sanitizeAllocation(rawAllocation),
      };
      if (power === 'Running' && !desired.allocation)
        throw Object.assign(
          new Error(
            'Choose the existing network and public IP resources used to start this firewall.',
          ),
          { code: 'AllocationRequired' },
        );
      await resourceSettings.validateFirewallConfiguration(
        id,
        desired,
        running.configuration,
      );
      return candidate.stageFirewallConfiguration(
        id,
        running.policyId,
        desired,
        running.configuration,
      );
    },
  );

  handle(IPC.getCandidateStatus, () => candidate.status());
  handle(
    IPC.importRulesCsv,
    async (_e, policyId: unknown, csv: unknown, rawChoices: unknown) => {
      assertId(policyId, RESOURCE_TYPES.policy, 'firewall policy');
      if (
        typeof csv !== 'string' ||
        Buffer.byteLength(csv, 'utf8') > MAX_RULE_IMPORT_BYTES
      )
        throw new Error('Select a CSV file no larger than 5 MB.');
      if (
        !rawChoices ||
        typeof rawChoices !== 'object' ||
        Array.isArray(rawChoices)
      )
        throw new Error('Invalid rule import choices.');
      const choices: RuleImportChoices = {};
      const entries = Object.entries(rawChoices);
      if (entries.length > csv.split(/\r\n|\r|\n/).length)
        throw new Error('Invalid number of rule import choices.');
      for (const [line, value] of entries) {
        if (!/^[1-9]\d{0,6}$/.test(line) || !value || typeof value !== 'object')
          throw new Error('Invalid rule import choice.');
        const item = value as Record<string, unknown>;
        if (
          (item.action !== 'import' &&
            item.action !== 'replace' &&
            item.action !== 'skip') ||
          (item.token !== undefined &&
            (typeof item.token !== 'string' || item.token.length > 50_000_000))
        )
          throw new Error('Invalid rule import choice.');
        choices[line] = { action: item.action, token: item.token };
      }
      return importRulesCsv(policyId, csv, choices);
    },
  );
  // Refresh button: drop caches so the next reads come straight from Azure.
  handle(IPC.refresh, () => {
    runningCache.clear();
    clearLookupCache();
  });
  handle(
    IPC.getRuleLookups,
    (_e, subscriptionId: unknown, location: unknown) => {
      if (typeof location !== 'string' || !/^[a-z0-9]{2,40}$/i.test(location))
        throw new Error('Invalid region.');
      return getRuleLookups(assertSubscription(subscriptionId), location);
    },
  );
  handle(IPC.revert, (_e, ids: unknown) => {
    if (ids === undefined) return candidate.revert();
    if (!Array.isArray(ids)) throw new Error('Invalid group list.');
    for (const id of ids) assertCandidateId(id);
    return candidate.revert(ids as string[]);
  });
  handle(IPC.save, () => candidate.save());
  handle(IPC.commit, async (_e, ids: unknown, description: unknown) => {
    if (!Array.isArray(ids)) throw new Error('Invalid group list.');
    for (const id of ids) assertCandidateId(id);
    if (typeof description !== 'string' || description.length > 1000) {
      throw new Error(
        'Commit description must be text of at most 1000 characters.',
      );
    }
    const user = auth.getAccount();
    const record = await candidate.commit(
      ids as string[],
      description,
      user?.username ?? user?.displayName,
      (p) => send(IPC.commitProgress, p),
    );
    // Force fresh reads after commit so new etags are used as baselines.
    runningCache.clear();
    return record;
  });
  handle(IPC.resumeCommit, () =>
    candidate.resume((p) => {
      send(IPC.commitProgress, p);
      if (p.done) runningCache.clear();
    }),
  );
  handle(IPC.getHistory, () => loadState().history);
  handle(IPC.getCentralHistory, () =>
    snapshotStorage.listCommitHistoryFromCentralStorage(loadState().history),
  );
  handle(IPC.getSnapshots, () =>
    snapshotStorage.listSnapshotsFromCentralStorage(),
  );
  handle(IPC.restoreSnapshot, async (_e, snapshotId: unknown) => {
    if (typeof snapshotId !== 'string' || !snapshotId.trim()) {
      throw new Error('Invalid snapshot ID.');
    }
    const snapshot =
      await snapshotStorage.getSnapshotFromCentralStorage(snapshotId);
    if (!snapshot) throw new Error('Snapshot not found in central storage.');
    const [running, policy] = await Promise.all([
      azure.listRuleCollectionGroups(snapshot.policyId),
      snapshot.threatIntelMode !== undefined || snapshot.settings !== undefined
        ? azure.getPolicy(snapshot.policyId)
        : undefined,
    ]);
    let runningPolicy: PolicyModeConfig | undefined;
    if (
      snapshot.threatIntelMode !== undefined ||
      snapshot.settings !== undefined
    ) {
      if (!policy || !isThreatIntelMode(policy.threatIntelMode))
        throw new Error(
          'The current threat-intelligence mode could not be loaded. No snapshot changes were staged.',
        );
      if (snapshot.threatIntelMode !== undefined)
        await azure.validatePolicyMode(policy, snapshot.threatIntelMode);
      if (snapshot.settings)
        await resourceSettings.validatePolicyConfiguration(
          snapshot.policyId,
          sanitizePolicySettings(snapshot.settings),
        );
      runningPolicy = {
        name: policy.name,
        threatIntelMode: policy.threatIntelMode,
        settings: policy.settings,
      };
    }
    for (const g of running) runningCache.set(g.id.toLowerCase(), g);
    return candidate.restoreSnapshot(snapshot, running, runningPolicy);
  });
  handle(IPC.getSnapshotStorageConfig, () =>
    snapshotStorage.getSnapshotStorageConfig(),
  );
  handle(IPC.listSnapshotStorageAccounts, () =>
    snapshotStorage.listSnapshotStorageAccounts(),
  );
  handle(
    IPC.setSnapshotStorageAccount,
    (
      _e,
      storageAccountId: unknown,
      containerName: unknown,
      historyContainerName: unknown,
    ) => {
      assertId(
        storageAccountId,
        RESOURCE_TYPES.storageAccount,
        'storage account',
      );
      const container = optStr(containerName, 'container name');
      const history = optStr(historyContainerName, 'history container name');
      return snapshotStorage.setSnapshotStorageAccount(
        storageAccountId,
        container,
        history,
      );
    },
  );
  handle(IPC.createSnapshotStorageAccount, (_e, raw: unknown) => {
    const r = raw as Record<string, unknown>;
    if (!r || typeof r !== 'object') {
      throw new Error('Invalid storage account request.');
    }
    const skuRaw = optStr(r.skuName, 'SKU');
    const validSkus = [
      'Standard_GRS',
      'Standard_RAGRS',
      'Standard_GZRS',
      'Standard_RAGZRS',
    ] as const;
    const skuName = validSkus.includes(skuRaw as (typeof validSkus)[number])
      ? (skuRaw as CreateSnapshotStorageRequest['skuName'])
      : 'Standard_GRS';
    const req: CreateSnapshotStorageRequest = {
      subscriptionId: assertSubscription(r.subscriptionId),
      resourceGroup: str(r.resourceGroup, 'resource group'),
      createResourceGroup: r.createResourceGroup === true,
      location: str(r.location, 'region'),
      storageAccountName: str(r.storageAccountName, 'storage account name'),
      containerName: optStr(r.containerName, 'container name'),
      historyContainerName: optStr(
        r.historyContainerName,
        'history container name',
      ),
      skuName,
      softDeleteDays:
        typeof r.softDeleteDays === 'number' &&
        r.softDeleteDays >= 1 &&
        r.softDeleteDays <= 365
          ? Math.floor(r.softDeleteDays)
          : undefined,
    };
    return snapshotStorage.createSnapshotStorageAccount(req);
  });

  handle(IPC.openInPortal, async (_e, id: unknown) => {
    const valid = [
      RESOURCE_TYPES.firewall,
      RESOURCE_TYPES.policy,
      RESOURCE_TYPES.ruleCollectionGroup,
      RESOURCE_TYPES.deployment,
      RESOURCE_TYPES.storageAccount,
      RESOURCE_TYPES.ipGroup,
    ].some((type) => isResourceIdOfType(id, type));
    if (!valid) throw new Error('Invalid resource ID.');
    await shell.openExternal(portalUrl(id as string));
  });

  handle(IPC.saveCsv, async (event, name: unknown, content: unknown) => {
    if (typeof content !== 'string' || content.length > 50_000_000)
      throw new Error('Invalid export.');
    // Only a plain file name is accepted from the page; the user picks the folder.
    const base =
      (typeof name === 'string' &&
        path
          .basename(name)
          .replace(/[^A-Za-z0-9._-]+/g, '-')
          .replace(/^\.+/, '')) ||
      'export.csv';
    const win = BrowserWindow.fromWebContents(event.sender);
    const options = {
      title: 'Export to CSV',
      defaultPath: path.join(
        app.getPath('documents'),
        base.endsWith('.csv') ? base : `${base}.csv`,
      ),
      filters: [{ name: 'CSV (comma separated)', extensions: ['csv'] }],
    };
    const result = win
      ? await dialog.showSaveDialog(win, options)
      : await dialog.showSaveDialog(options);
    if (result.canceled || !result.filePath) return null;
    await fs.writeFile(result.filePath, content, 'utf8');
    return result.filePath;
  });
  handle(IPC.listSubscriptions, () => deploy.listSubscriptions());
  handle(IPC.getDeployContext, (_e, subscriptionId: unknown) =>
    deploy.getDeployContext(assertSubscription(subscriptionId)),
  );
  handle(IPC.registerNetworkProvider, (_e, subscriptionId: unknown) =>
    deploy.registerNetworkProvider(assertSubscription(subscriptionId)),
  );
  handle(IPC.deployFirewall, (_e, raw: unknown) => {
    const request = sanitizeDeployRequest(raw);
    return deploy.deployFirewall(request, (p) => send(IPC.deployProgress, p));
  });
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertSubscription(value: unknown): string {
  if (typeof value !== 'string' || !GUID.test(value)) {
    throw new Error('Invalid subscription ID.');
  }
  return value;
}

const str = (v: unknown, label: string): string => {
  if (typeof v !== 'string' || v.length > 512)
    throw new Error(`Invalid ${label}.`);
  return v.trim();
};
const optStr = (v: unknown, label: string) =>
  v === undefined || v === '' ? undefined : str(v, label);

/** Rebuilds the request from untrusted input so only known, correctly typed fields reach Azure. */
function sanitizeDeployRequest(raw: unknown): DeployRequest {
  const r = raw as Record<string, any>;
  if (!r || typeof r !== 'object')
    throw new Error('Invalid deployment request.');
  const tier = r.tier as FirewallTier;
  if (!TIERS.includes(tier)) throw new Error('Invalid firewall tier.');
  if (
    !Array.isArray(r.zones) ||
    r.zones.some((z: unknown) => typeof z !== 'string')
  ) {
    throw new Error('Invalid availability zones.');
  }
  const tags: Record<string, string> = {};
  if (r.tags && typeof r.tags === 'object') {
    for (const [k, v] of Object.entries(r.tags))
      tags[str(k, 'tag name')] = str(v, 'tag value');
  }

  const t = r.target ?? {};
  let target: DeployRequest['target'];
  if (t.kind === 'vnet-existing') {
    assertId(t.vnetId, RESOURCE_TYPES.virtualNetwork, 'virtual network');
    target = {
      kind: t.kind,
      vnetId: t.vnetId,
      subnetPrefix: optStr(t.subnetPrefix, 'subnet prefix'),
      managementSubnetPrefix: optStr(
        t.managementSubnetPrefix,
        'management subnet prefix',
      ),
    };
  } else if (t.kind === 'vnet-new') {
    target = {
      kind: t.kind,
      resourceGroup: str(t.resourceGroup, 'resource group'),
      createResourceGroup: t.createResourceGroup === true,
      vnetName: str(t.vnetName, 'VNet name'),
      addressSpace: str(t.addressSpace, 'address space'),
      subnetPrefix: str(t.subnetPrefix, 'subnet prefix'),
      managementSubnetPrefix: optStr(
        t.managementSubnetPrefix,
        'management subnet prefix',
      ),
    };
  } else if (t.kind === 'hub') {
    assertId(t.hubId, RESOURCE_TYPES.virtualHub, 'virtual hub');
    target = {
      kind: t.kind,
      hubId: t.hubId,
      publicIpCount: Number(t.publicIpCount),
    };
  } else {
    throw new Error('Invalid deployment target.');
  }

  const p = r.policy ?? {};
  let policy: DeployRequest['policy'];
  if (p.kind === 'existing') {
    assertId(p.policyId, RESOURCE_TYPES.policy, 'firewall policy');
    policy = { kind: 'existing', policyId: p.policyId };
  } else if (p.kind === 'new') {
    const basePolicyId: unknown = p.basePolicyId || undefined;
    if (basePolicyId !== undefined)
      assertId(basePolicyId, RESOURCE_TYPES.policy, 'parent policy');
    policy = {
      kind: 'new',
      name: str(p.name, 'policy name'),
      threatIntelMode: str(
        p.threatIntelMode,
        'threat intel mode',
      ) as ThreatIntelMode,
      basePolicyId,
      resourceGroup: str(p.resourceGroup, 'policy resource group'),
      createResourceGroup: p.createResourceGroup === true,
    };
  } else {
    throw new Error('Invalid policy option.');
  }

  return {
    subscriptionId: assertSubscription(r.subscriptionId),
    name: str(r.name, 'firewall name'),
    tier,
    resourceGroup: str(r.resourceGroup, 'resource group'),
    createResourceGroup: r.createResourceGroup === true,
    location: str(r.location, 'region'),
    zones: [...new Set(r.zones as string[])],
    tags,
    managementNic: r.managementNic === true && target.kind !== 'hub',
    target,
    policy,
    addToManaged: r.addToManaged === true,
  };
}
