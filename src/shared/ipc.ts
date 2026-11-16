import type {
  AccountInfo,
  AuthMethod,
  CandidateStatus,
  CommitHistoryEntry,
  CommitProgress,
  CommitRecord,
  CreateSnapshotStorageRequest,
  FirewallSummary,
  IpGroupInfo,
  PolicySnapshot,
  PolicyView,
  RuleCollectionGroup,
  RuleLookups,
  SnapshotStorageAccountInfo,
  SnapshotStorageConfig,
  SnapshotStorageSetup,
} from './types';
import type {
  DeployContext,
  DeployProgress,
  DeployRequest,
  NetworkAvailability,
  SubscriptionInfo,
} from './deploy';
import type { CreateIpGroupRequest, IpGroupContext } from './ipGroups';
import type { RuleImportChoices, RuleImportResult } from './ruleImport';
import type { ThreatIntelMode } from './deploy';
import type { EventHubInfo, LogSources } from './logSources';
import type { CleanupReview } from './logCleanup';
import type {
  ProvisionProgress,
  ProvisionRequest,
  SetupContext,
  SetupReview,
} from './logProvision';
import type { LogBatch, LogStreamConfig, LogStreamStatus } from './logStream';
import type {
  FirewallAllocation,
  FirewallConfiguration,
  FirewallSettingsView,
  PolicyAdvancedSettings,
  PolicySettingsView,
} from './resourceSettings';

export const IPC = {
  signIn: 'auth:signIn',
  cancelSignIn: 'auth:cancelSignIn',
  getAccount: 'auth:getAccount',
  restoreSession: 'auth:restoreSession',
  signOut: 'auth:signOut',
  switchTenant: 'auth:switchTenant',
  discoverFirewalls: 'firewalls:discover',
  discoverIpGroups: 'ipGroups:discover',
  getIpGroupContext: 'ipGroups:context',
  createIpGroup: 'ipGroups:create',
  getManagedFirewalls: 'firewalls:getManaged',
  setManagedFirewalls: 'firewalls:setManaged',
  getPolicy: 'policy:get',
  stageGroup: 'candidate:stage',
  stagePolicyMode: 'candidate:stagePolicyMode',
  getPolicySettings: 'policy:settings',
  stagePolicySettings: 'candidate:stagePolicySettings',
  getFirewallSettings: 'firewall:settings',
  getFirewallConfiguration: 'firewall:configuration',
  getLearnedPrefixes: 'firewall:learnedPrefixes',
  stageFirewallSettings: 'candidate:stageFirewallSettings',
  stageFirewallPower: 'candidate:stageFirewallPower',
  createGroup: 'candidate:createGroup',
  importRulesCsv: 'candidate:importRulesCsv',
  getRuleLookups: 'rules:lookups',
  refresh: 'app:refresh',
  getCandidateStatus: 'candidate:status',
  revert: 'candidate:revert',
  save: 'candidate:save',
  commit: 'candidate:commit',
  resumeCommit: 'candidate:resumeCommit',
  getHistory: 'history:list',
  getCentralHistory: 'history:listShared',
  getSnapshots: 'snapshots:list',
  restoreSnapshot: 'snapshots:restore',
  getSnapshotStorageConfig: 'snapshots:getStorageConfig',
  listSnapshotStorageAccounts: 'snapshots:listStorageAccounts',
  setSnapshotStorageAccount: 'snapshots:setStorageAccount',
  createSnapshotStorageAccount: 'snapshots:createStorageAccount',
  openInPortal: 'app:openInPortal',
  saveCsv: 'app:saveCsv',
  commitProgress: 'event:commitProgress',
  listSubscriptions: 'deploy:subscriptions',
  getDeployContext: 'deploy:context',
  deployFirewall: 'deploy:start',
  registerNetworkProvider: 'deploy:registerNetwork',
  deployProgress: 'event:deployProgress',
  logsGetConfig: 'logs:getConfig',
  logsGetStatus: 'logs:getStatus',
  logsStart: 'logs:start',
  logsStop: 'logs:stop',
  logsDiscover: 'logs:discover',
  logsListHubs: 'logs:listHubs',
  logsListConsumerGroups: 'logs:listConsumerGroups',
  logsGrantReceiver: 'logs:grantReceiver',
  logsCleanupReview: 'logs:cleanupReview',
  logsCleanupApply: 'logs:cleanupApply',
  logsListResourceGroups: 'logs:listResourceGroups',
  logsSetupContext: 'logs:setupContext',
  logsSetupCheckName: 'logs:setupCheckName',
  logsSetupReview: 'logs:setupReview',
  logsSetupApply: 'logs:setupApply',
  logSetupProgress: 'event:logSetupProgress',
  logBatch: 'event:logBatch',
  logStatus: 'event:logStatus',
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
  discoverIpGroups(): Promise<IpGroupInfo[]>;
  getIpGroupContext(subscriptionId: string): Promise<IpGroupContext>;
  /** Creates an IP group directly in Azure, outside the rule candidate workflow. */
  createIpGroup(request: CreateIpGroupRequest): Promise<IpGroupInfo>;
  getManagedFirewalls(): Promise<string[]>;
  setManagedFirewalls(ids: string[]): Promise<void>;
  getPolicy(policyId: string): Promise<PolicyView>;
  stageGroup(
    policyId: string,
    group: RuleCollectionGroup,
  ): Promise<CandidateStatus>;
  stagePolicyMode(
    policyId: string,
    mode: ThreatIntelMode,
  ): Promise<CandidateStatus>;
  getPolicySettings(policyId: string): Promise<PolicySettingsView>;
  stagePolicySettings(
    policyId: string,
    before: PolicyAdvancedSettings,
    after: PolicyAdvancedSettings,
  ): Promise<CandidateStatus>;
  getFirewallSettings(firewallId: string): Promise<FirewallSettingsView>;
  getFirewallConfiguration(firewallId: string): Promise<FirewallConfiguration>;
  getLearnedPrefixes(firewallId: string): Promise<string[]>;
  stageFirewallSettings(
    firewallId: string,
    before: FirewallConfiguration,
    after: FirewallConfiguration,
  ): Promise<CandidateStatus>;
  stageFirewallPower(
    firewallId: string,
    state: 'Running' | 'Stopped',
    allocation?: FirewallAllocation,
  ): Promise<CandidateStatus>;
  /** Drafts a new, empty rule collection group; it's created in Azure on commit. */
  createGroup(
    policyId: string,
    name: string,
    priority: number,
  ): Promise<CandidateStatus>;
  /** Stages a validated CSV file; never writes rules to Azure until commit. */
  importRulesCsv(
    policyId: string,
    csv: string,
    choices: RuleImportChoices,
  ): Promise<RuleImportResult>;
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
  /** The shared commit history from centralized storage (plus commits that only exist on this device). */
  getCentralHistory(): Promise<CommitHistoryEntry[]>;
  getSnapshots(): Promise<PolicySnapshot[]>;
  /** Stages a former policy snapshot onto the current policy so it can be reviewed or committed. */
  restoreSnapshot(snapshotId: string): Promise<CandidateStatus>;
  getSnapshotStorageConfig(): Promise<SnapshotStorageConfig | null>;
  listSnapshotStorageAccounts(): Promise<SnapshotStorageAccountInfo[]>;
  setSnapshotStorageAccount(
    storageAccountId: string,
    containerName?: string,
    historyContainerName?: string,
  ): Promise<SnapshotStorageConfig>;
  createSnapshotStorageAccount(
    request: CreateSnapshotStorageRequest,
  ): Promise<SnapshotStorageSetup>;
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
  /** The saved Event Hub for the current directory, or null. */
  getLogStreamConfig(): Promise<LogStreamConfig | null>;
  getLogStreamStatus(): Promise<LogStreamStatus>;
  /** Validates and saves the settings, then (re)connects. Progress arrives as status events. */
  /**
   * `waitForRole` keeps retrying a missing-role error for a few minutes (use it right after the
   * role was assigned).
   */
  startLogStream(
    config: LogStreamConfig,
    options?: { waitForRole?: boolean },
  ): Promise<LogStreamStatus>;
  stopLogStream(): Promise<void>;
  /** Event Hubs namespaces, plus what the managed firewalls' diagnostic settings send where. */
  discoverLogSources(): Promise<LogSources>;
  listEventHubs(namespaceId: string): Promise<EventHubInfo[]>;
  listConsumerGroups(namespaceId: string, eventHub: string): Promise<string[]>;
  /**
   * Assigns the signed-in user the Event Hubs Data Receiver role on the hub. Writes to Azure;
   * resolves to the scope that was used.
   */
  grantLogReceiver(config: LogStreamConfig): Promise<string>;
  /** Review removing the Event Hub destination of a setting whose namespace was deleted. Changes nothing. */
  reviewLogCleanup(
    firewallId: string,
    settingName: string,
  ): Promise<CleanupReview>;
  /** Apply a reviewed cleanup; refuses if Azure changed since the review. Writes to Azure directly. */
  applyLogCleanup(
    firewallId: string,
    settingName: string,
    reviewHash: string,
  ): Promise<{ action: 'trim' | 'delete' }>;
  listLogResourceGroups(
    subscriptionId: string,
  ): Promise<{ name: string; location: string }[]>;
  /** The firewalls' categories, current diagnostic settings and provider state, read from Azure. */
  getLogSetupContext(
    firewallIds: string[],
    destinationSubscriptionId?: string,
  ): Promise<SetupContext>;
  checkEventHubNamespaceName(
    subscriptionId: string,
    name: string,
  ): Promise<{ available: boolean; message?: string }>;
  /** Everything the setup would change in Azure; changes nothing. */
  reviewLogSetup(request: ProvisionRequest): Promise<SetupReview>;
  /**
   * Runs the reviewed setup (writes to Azure). Resolves when it finishes; progress arrives as
   * events. `reviewHash` must come from the review of the same request.
   */
  applyLogSetup(
    request: ProvisionRequest,
    reviewHash: string,
  ): Promise<ProvisionProgress>;
  onLogSetupProgress(
    listener: (progress: ProvisionProgress) => void,
  ): () => void;
  /** About one batch per second while connected. */
  onLogBatch(listener: (batch: LogBatch) => void): () => void;
  onLogStreamStatus(listener: (status: LogStreamStatus) => void): () => void;
}
