// Exposes a narrow, typed API to the renderer. Runs sandboxed: only `electron` may be imported.
import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron';
import { IPC, type AzNetApi, type IpcResult } from './shared/ipc';
import type { CommitProgress } from './shared/types';
import type { DeployProgress } from './shared/deploy';

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
  getManagedFirewalls: () => call(IPC.getManagedFirewalls),
  setManagedFirewalls: (ids) => call(IPC.setManagedFirewalls, ids),
  getPolicy: (policyId) => call(IPC.getPolicy, policyId),
  stageGroup: (policyId, group) => call(IPC.stageGroup, policyId, group),
  createGroup: (policyId, name, priority) =>
    call(IPC.createGroup, policyId, name, priority),
  getRuleLookups: (subscriptionId, location) =>
    call(IPC.getRuleLookups, subscriptionId, location),
  refresh: () => call(IPC.refresh),
  getCandidateStatus: () => call(IPC.getCandidateStatus),
  revert: (groupIds) => call(IPC.revert, groupIds),
  save: () => call(IPC.save),
  commit: (groupIds, description) => call(IPC.commit, groupIds, description),
  resumeCommit: () => call(IPC.resumeCommit),
  getHistory: () => call(IPC.getHistory),
  getSnapshots: () => call(IPC.getSnapshots),
  restoreSnapshot: (snapshotId) => call(IPC.restoreSnapshot, snapshotId),
  getSnapshotStorageConfig: () => call(IPC.getSnapshotStorageConfig),
  listSnapshotStorageAccounts: () => call(IPC.listSnapshotStorageAccounts),
  setSnapshotStorageAccount: (storageAccountId, containerName) =>
    call(IPC.setSnapshotStorageAccount, storageAccountId, containerName),
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
};

contextBridge.exposeInMainWorld('api', api);
