// Exposes a narrow, typed API to the renderer. Runs sandboxed: only `electron` may be imported.
import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron';
import { IPC, type AzNetApi, type IpcResult } from './shared/ipc';
import type { CommitProgress } from './shared/types';
import type { DeployProgress } from './shared/deploy';
import type { LogBatch, LogStreamStatus } from './shared/logStream';
import type { ProvisionProgress } from './shared/logProvision';

async function call<T>(channel: string, ...args: unknown[]): Promise<T> {
  const result = (await ipcRenderer.invoke(channel, ...args)) as IpcResult<T>;
  if (!result.ok) throw new Error(result.error);
  return result.data;
}

const api: AzNetApi = {
  signIn: (method, tenantId) => call(IPC.signIn, method, tenantId),
  cancelSignIn: () => call(IPC.cancelSignIn),
  getAccount: () => call(IPC.getAccount),
  restoreSession: () => call(IPC.restoreSession),
  signOut: () => call(IPC.signOut),
  switchTenant: (tenantId) => call(IPC.switchTenant, tenantId),
  discoverFirewalls: () => call(IPC.discoverFirewalls),
  discoverIpGroups: () => call(IPC.discoverIpGroups),
  getIpGroupContext: (subscriptionId) =>
    call(IPC.getIpGroupContext, subscriptionId),
  createIpGroup: (request) => call(IPC.createIpGroup, request),
  getManagedFirewalls: () => call(IPC.getManagedFirewalls),
  setManagedFirewalls: (ids) => call(IPC.setManagedFirewalls, ids),
  getPolicy: (policyId) => call(IPC.getPolicy, policyId),
  stageGroup: (policyId, group) => call(IPC.stageGroup, policyId, group),
  stagePolicyMode: (policyId, mode) =>
    call(IPC.stagePolicyMode, policyId, mode),
  getPolicySettings: (id) => call(IPC.getPolicySettings, id),
  stagePolicySettings: (id, before, after) =>
    call(IPC.stagePolicySettings, id, before, after),
  getFirewallSettings: (id) => call(IPC.getFirewallSettings, id),
  getFirewallConfiguration: (id) => call(IPC.getFirewallConfiguration, id),
  getLearnedPrefixes: (id) => call(IPC.getLearnedPrefixes, id),
  stageFirewallSettings: (id, before, after) =>
    call(IPC.stageFirewallSettings, id, before, after),
  stageFirewallPower: (id, state, allocation) =>
    call(IPC.stageFirewallPower, id, state, allocation),
  createGroup: (policyId, name, priority) =>
    call(IPC.createGroup, policyId, name, priority),
  importRulesCsv: (policyId, csv, choices) =>
    call(IPC.importRulesCsv, policyId, csv, choices),
  getRuleLookups: (subscriptionId, location) =>
    call(IPC.getRuleLookups, subscriptionId, location),
  refresh: () => call(IPC.refresh),
  getCandidateStatus: () => call(IPC.getCandidateStatus),
  revert: (groupIds) => call(IPC.revert, groupIds),
  save: () => call(IPC.save),
  commit: (groupIds, description) => call(IPC.commit, groupIds, description),
  resumeCommit: () => call(IPC.resumeCommit),
  getHistory: () => call(IPC.getHistory),
  getCentralHistory: () => call(IPC.getCentralHistory),
  getSnapshots: () => call(IPC.getSnapshots),
  restoreSnapshot: (snapshotId) => call(IPC.restoreSnapshot, snapshotId),
  getSnapshotStorageConfig: () => call(IPC.getSnapshotStorageConfig),
  listSnapshotStorageAccounts: () => call(IPC.listSnapshotStorageAccounts),
  setSnapshotStorageAccount: (
    storageAccountId,
    containerName,
    historyContainerName,
  ) =>
    call(
      IPC.setSnapshotStorageAccount,
      storageAccountId,
      containerName,
      historyContainerName,
    ),
  createSnapshotStorageAccount: (request) =>
    call(IPC.createSnapshotStorageAccount, request),
  openInPortal: (resourceId) => call(IPC.openInPortal, resourceId),
  saveCsv: (name, content) => call(IPC.saveCsv, name, content),
  onCommitProgress: (listener) => {
    const wrapped = (_e: IpcRendererEvent, p: CommitProgress) => listener(p);
    ipcRenderer.on(IPC.commitProgress, wrapped);
    return () => ipcRenderer.removeListener(IPC.commitProgress, wrapped);
  },
  listSubscriptions: () => call(IPC.listSubscriptions),
  getDeployContext: (subscriptionId) =>
    call(IPC.getDeployContext, subscriptionId),
  deployFirewall: (request) => call(IPC.deployFirewall, request),
  registerNetworkProvider: (subscriptionId) =>
    call(IPC.registerNetworkProvider, subscriptionId),
  onDeployProgress: (listener) => {
    const wrapped = (_e: IpcRendererEvent, p: DeployProgress) => listener(p);
    ipcRenderer.on(IPC.deployProgress, wrapped);
    return () => ipcRenderer.removeListener(IPC.deployProgress, wrapped);
  },
  getLogStreamConfig: () => call(IPC.logsGetConfig),
  getLogStreamStatus: () => call(IPC.logsGetStatus),
  startLogStream: (config, options) => call(IPC.logsStart, config, options),
  stopLogStream: () => call(IPC.logsStop),
  discoverLogSources: () => call(IPC.logsDiscover),
  listEventHubs: (namespaceId) => call(IPC.logsListHubs, namespaceId),
  listConsumerGroups: (namespaceId, eventHub) =>
    call(IPC.logsListConsumerGroups, namespaceId, eventHub),
  grantLogReceiver: (config) => call(IPC.logsGrantReceiver, config),
  reviewLogCleanup: (firewallId, settingName) =>
    call(IPC.logsCleanupReview, firewallId, settingName),
  applyLogCleanup: (firewallId, settingName, reviewHash) =>
    call(IPC.logsCleanupApply, firewallId, settingName, reviewHash),
  listLogResourceGroups: (subscriptionId) =>
    call(IPC.logsListResourceGroups, subscriptionId),
  getLogSetupContext: (firewallIds, destinationSubscriptionId) =>
    call(IPC.logsSetupContext, firewallIds, destinationSubscriptionId),
  checkEventHubNamespaceName: (subscriptionId, name) =>
    call(IPC.logsSetupCheckName, subscriptionId, name),
  reviewLogSetup: (request) => call(IPC.logsSetupReview, request),
  applyLogSetup: (request, reviewHash) =>
    call(IPC.logsSetupApply, request, reviewHash),
  onLogSetupProgress: (listener) => {
    const wrapped = (_e: IpcRendererEvent, p: ProvisionProgress) => listener(p);
    ipcRenderer.on(IPC.logSetupProgress, wrapped);
    return () => ipcRenderer.removeListener(IPC.logSetupProgress, wrapped);
  },
  onLogBatch: (listener) => {
    const wrapped = (_e: IpcRendererEvent, b: LogBatch) => listener(b);
    ipcRenderer.on(IPC.logBatch, wrapped);
    return () => ipcRenderer.removeListener(IPC.logBatch, wrapped);
  },
  onLogStreamStatus: (listener) => {
    const wrapped = (_e: IpcRendererEvent, s: LogStreamStatus) => listener(s);
    ipcRenderer.on(IPC.logStatus, wrapped);
    return () => ipcRenderer.removeListener(IPC.logStatus, wrapped);
  },
};

contextBridge.exposeInMainWorld('api', api);
