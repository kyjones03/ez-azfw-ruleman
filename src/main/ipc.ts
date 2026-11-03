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
import * as snapshotStorage from './snapshotStorage';
import { candidate } from './candidate';
import { clearLookupCache, getRuleLookups } from './lookups';
import { loadState, updateState } from './store';
import { isAppUrl } from './appProtocol';

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

  handle(IPC.getCandidateStatus, () => candidate.status());
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
    for (const id of ids)
      assertId(id, RESOURCE_TYPES.ruleCollectionGroup, 'rule collection group');
    return candidate.revert(ids as string[]);
  });
  handle(IPC.save, () => candidate.save());
  handle(IPC.commit, async (_e, ids: unknown, description: unknown) => {
    if (!Array.isArray(ids)) throw new Error('Invalid group list.');
    for (const id of ids)
      assertId(id, RESOURCE_TYPES.ruleCollectionGroup, 'rule collection group');
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
    const running = await azure.listRuleCollectionGroups(snapshot.policyId);
    for (const g of running) runningCache.set(g.id.toLowerCase(), g);
    return candidate.restoreSnapshot(snapshot, running);
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
