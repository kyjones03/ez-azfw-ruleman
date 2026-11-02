import type {
  AccountInfo,
  AuthMethod,
  CandidateStatus,
  CommitProgress,
  CommitRecord,
  FirewallSummary,
  PolicySnapshot,
  PolicyView,
  RuleCollectionGroup,
  RuleLookups,
} from './types';
import type {
  DeployContext,
  DeployProgress,
  DeployRequest,
  NetworkAvailability,
  SubscriptionInfo,
} from './deploy';

export const IPC = {
  signIn: 'auth:signIn',
  cancelSignIn: 'auth:cancelSignIn',
  getAccount: 'auth:getAccount',
  restoreSession: 'auth:restoreSession',
  signOut: 'auth:signOut',
  switchTenant: 'auth:switchTenant',
  discoverFirewalls: 'firewalls:discover',
  getManagedFirewalls: 'firewalls:getManaged',
  setManagedFirewalls: 'firewalls:setManaged',
  getPolicy: 'policy:get',
  stageGroup: 'candidate:stage',
  createGroup: 'candidate:createGroup',
  getRuleLookups: 'rules:lookups',
  refresh: 'app:refresh',
  getCandidateStatus: 'candidate:status',
  revert: 'candidate:revert',
  save: 'candidate:save',
  commit: 'candidate:commit',
  resumeCommit: 'candidate:resumeCommit',
  getHistory: 'history:list',
  getSnapshots: 'snapshots:list',
  restoreSnapshot: 'snapshots:restore',
  openInPortal: 'app:openInPortal',
  saveCsv: 'app:saveCsv',
  commitProgress: 'event:commitProgress',
  listSubscriptions: 'deploy:subscriptions',
  getDeployContext: 'deploy:context',
  deployFirewall: 'deploy:start',
  registerNetworkProvider: 'deploy:registerNetwork',
  deployProgress: 'event:deployProgress',
} as const;

/** Envelope used for every invoke() so the renderer receives clean error messages. */
export type IpcResult<T> = { ok: true; data: T } | { ok: false; error: string };

export interface AzNetApi {
  signIn(method: AuthMethod, tenantId?: string): Promise<AccountInfo>;
  cancelSignIn(): Promise<void>;
  getAccount(): Promise<AccountInfo | null>;
  /** Silently signs back in with the saved sign-in; null when the user must sign in. */
  restoreSession(): Promise<AccountInfo | null>;
  signOut(): Promise<void>;
  /** Switches the directory (tenant) all Azure calls use. */
  switchTenant(tenantId: string): Promise<AccountInfo>;
  discoverFirewalls(): Promise<FirewallSummary[]>;
  getManagedFirewalls(): Promise<string[]>;
  setManagedFirewalls(ids: string[]): Promise<void>;
  getPolicy(policyId: string): Promise<PolicyView>;
  stageGroup(
    policyId: string,
    group: RuleCollectionGroup,
  ): Promise<CandidateStatus>;
  /** Drafts a new, empty rule collection group; it's created in Azure on commit. */
  createGroup(
    policyId: string,
    name: string,
    priority: number,
  ): Promise<CandidateStatus>;
  getCandidateStatus(): Promise<CandidateStatus>;
  /** IP Groups, service tags, FQDN tags and web categories for the rule editor's pickers. */
  getRuleLookups(
    subscriptionId: string,
    location: string,
  ): Promise<RuleLookups>;
  /** Clears cached Azure data so the following reads are fresh. */
  refresh(): Promise<void>;
  /** Reverts the given groups, or the whole candidate when omitted. */
  revert(groupIds?: string[]): Promise<CandidateStatus>;
  save(): Promise<CandidateStatus>;
  commit(groupIds: string[], description: string): Promise<CommitRecord>;
  /** Picks up a commit interrupted by closing the app; null when there is none. */
  resumeCommit(): Promise<CommitProgress | null>;
  getHistory(): Promise<CommitRecord[]>;
  getSnapshots(): Promise<PolicySnapshot[]>;
  /** Stages a former policy snapshot onto the current policy so it can be reviewed or committed. */
  restoreSnapshot(snapshotId: string): Promise<CandidateStatus>;
  openInPortal(resourceId: string): Promise<void>;
  /** Asks where to save, then writes the CSV; resolves to the path, or null if cancelled. */
  saveCsv(suggestedName: string, content: string): Promise<string | null>;
  onCommitProgress(listener: (progress: CommitProgress) => void): () => void;
  listSubscriptions(): Promise<SubscriptionInfo[]>;
  getDeployContext(subscriptionId: string): Promise<DeployContext>;
  /** Registers Microsoft.Network for the subscription (enables Azure networking). */
  registerNetworkProvider(subscriptionId: string): Promise<NetworkAvailability>;
  /** Resolves when the deployment finishes (succeeded or failed). */
  deployFirewall(request: DeployRequest): Promise<DeployProgress>;
  onDeployProgress(listener: (progress: DeployProgress) => void): () => void;
}
