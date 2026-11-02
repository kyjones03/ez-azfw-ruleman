// Plain, IPC-serializable types shared by the main process, preload and renderer.

/** 'window': app sign-in window; 'browser': system browser; 'cli': Azure CLI. */
export type AuthMethod = 'window' | 'browser' | 'cli';

export type TenantStatus = 'ready' | 'needs-sign-in' | 'unavailable';

export interface TenantInfo {
  tenantId: string;
  displayName?: string;
  defaultDomain?: string;
  /** Result of a silent check after sign-in. */
  status?: TenantStatus;
  subscriptionCount?: number;
}

export interface AccountInfo {
  method: AuthMethod;
  username?: string;
  displayName?: string;
  /** The directory every Azure call currently uses; undefined until one is chosen. */
  tenantId?: string;
  /** Directories the account can access. */
  tenants?: TenantInfo[];
  /** False when the app couldn't list directories and the user must enter one. */
  tenantsListed?: boolean;
}

/** Remembered browser sign-in (no secrets): lets the next sign-in go straight to the directory. */
export interface LastSignIn {
  username: string;
  tenantId: string;
  tenantName?: string;
}

export interface FirewallSummary {
  id: string;
  name: string;
  subscriptionId: string;
  subscriptionName?: string;
  resourceGroup: string;
  location: string;
  /** AZFW_VNet or AZFW_Hub */
  skuName?: string;
  /** Basic, Standard or Premium */
  skuTier?: string;
  policyId?: string;
  provisioningState?: string;
  threatIntelMode?: string;
  privateIp?: string;
  hubId?: string;
  /** Number of classic (non-policy) rule collections on the firewall. */
  classicRuleCollectionCount: number;
  /** Azure resource tags. */
  tags?: Record<string, string>;
}

export interface PolicySummary {
  id: string;
  name: string;
  subscriptionId: string;
  resourceGroup: string;
  location?: string;
  tier?: string;
  threatIntelMode?: string;
  basePolicyId?: string;
  provisioningState?: string;
  firewallIds: string[];
  childPolicyIds: string[];
  /** Azure resource tags. */
  tags?: Record<string, string>;
}

export type NetworkProtocol = 'TCP' | 'UDP' | 'ICMP' | 'Any';
export type ApplicationProtocolType = 'Http' | 'Https' | 'Mssql';

interface RuleBase {
  name: string;
  description?: string;
}

export interface NetworkRule extends RuleBase {
  ruleType: 'NetworkRule';
  ipProtocols?: NetworkProtocol[];
  sourceAddresses?: string[];
  sourceIpGroups?: string[];
  destinationAddresses?: string[];
  destinationIpGroups?: string[];
  destinationFqdns?: string[];
  destinationPorts?: string[];
}

export interface ApplicationRule extends RuleBase {
  ruleType: 'ApplicationRule';
  protocols?: { protocolType?: ApplicationProtocolType; port?: number }[];
  sourceAddresses?: string[];
  sourceIpGroups?: string[];
  destinationAddresses?: string[];
  targetFqdns?: string[];
  targetUrls?: string[];
  fqdnTags?: string[];
  webCategories?: string[];
  terminateTLS?: boolean;
}

export interface NatRule extends RuleBase {
  ruleType: 'NatRule';
  ipProtocols?: NetworkProtocol[];
  sourceAddresses?: string[];
  sourceIpGroups?: string[];
  destinationAddresses?: string[];
  destinationPorts?: string[];
  translatedAddress?: string;
  translatedFqdn?: string;
  translatedPort?: string;
}

export type FirewallRule = NetworkRule | ApplicationRule | NatRule;
export type RuleType = FirewallRule['ruleType'];

export interface FilterRuleCollection {
  ruleCollectionType: 'FirewallPolicyFilterRuleCollection';
  name: string;
  priority: number;
  action: { type: 'Allow' | 'Deny' };
  rules: (NetworkRule | ApplicationRule)[];
}

export interface NatRuleCollection {
  ruleCollectionType: 'FirewallPolicyNatRuleCollection';
  name: string;
  priority: number;
  action: { type: 'DNAT' };
  rules: NatRule[];
}

export type RuleCollection = FilterRuleCollection | NatRuleCollection;

export interface RuleCollectionGroup {
  id: string;
  name: string;
  priority: number;
  etag?: string;
  provisioningState?: string;
  ruleCollections: RuleCollection[];
}

/** A rule collection group as shown to the user: candidate if staged, otherwise running. */
export interface GroupView {
  group: RuleCollectionGroup;
  staged: boolean;
  /** Azure changed something this draft also changed; committing it will be refused. */
  drift: boolean;
  /** What both Azure and the draft changed, when `drift` is set. */
  conflicts?: string[];
  /** Created in the draft; it doesn't exist in Azure until committed. */
  isNew?: boolean;
  /** For drafted groups: the version in Azure, so removed rules can be shown and restored. */
  baseline?: RuleCollectionGroup;
}

export interface PolicyView {
  policy: PolicySummary;
  groups: GroupView[];
}

export type ChangeKind = 'added' | 'modified' | 'removed';

export interface ChangeItem {
  kind: ChangeKind;
  target: 'group' | 'collection' | 'rule';
  collection?: string;
  rule?: string;
  detail?: string;
}

export interface PendingGroupChange {
  groupId: string;
  groupName: string;
  policyId: string;
  policyName: string;
  stagedAt: string;
  changes: ChangeItem[];
  /** Risky changes (broad rules, Allow↔Deny flips) that must be acknowledged at commit. */
  warnings?: string[];
  /** Being written to Azure right now; it can't be edited or committed again until that ends. */
  committing?: boolean;
}

export interface CandidateStatus {
  pending: PendingGroupChange[];
  /** Candidate has edits that are not yet saved to disk. */
  unsaved: boolean;
}

export interface CommitResult {
  groupId: string;
  groupName: string;
  policyName: string;
  ok: boolean;
  conflict?: boolean;
  error?: string;
  /** Whether the commit created the group or updated an existing one. */
  action?: 'create' | 'update';
  /** What was changed in this group (or would have been, if it failed). */
  changes?: ChangeItem[];
}

export interface CommitRecord {
  id: string;
  time: string;
  user?: string;
  description: string;
  changeCount: number;
  results: CommitResult[];
}

export interface PolicySnapshot {
  id: string;
  policyId: string;
  policyName: string;
  time: string;
  user?: string;
  description: string;
  groups: RuleCollectionGroup[];
}

export interface SnapshotStorageConfig {
  /** Azure resource ID of the storage account holding shared snapshots. */
  storageAccountId: string;
  storageAccountName: string;
  subscriptionId: string;
  resourceGroup: string;
  location: string;
  skuName?: string;
  /** Blob container name (defaults to ez-azfw-snapshots). */
  containerName: string;
}

export interface SnapshotStorageAccountInfo {
  id: string;
  name: string;
  subscriptionId: string;
  subscriptionName?: string;
  resourceGroup: string;
  location: string;
  skuName: string;
  kind?: string;
  isGRS: boolean;
  /** Tagged with ez-azfw-ruleman-snapshots = true so teammates can auto-discover it. */
  isAppTagged?: boolean;
  containerName?: string;
}

export interface CreateSnapshotStorageRequest {
  subscriptionId: string;
  resourceGroup: string;
  createResourceGroup?: boolean;
  location: string;
  storageAccountName: string;
  containerName?: string;
  skuName?:
    | 'Standard_GRS'
    | 'Standard_RAGRS'
    | 'Standard_GZRS'
    | 'Standard_RAGZRS';
  softDeleteDays?: number;
}

export type CommitGroupState =
  | 'pending'
  | 'checking'
  /** Azure is still applying an earlier change to the group; the commit waits for it. */
  | 'waiting'
  | 'creating'
  | 'updating'
  | 'succeeded'
  | 'failed'
  | 'conflict';

export interface CommitProgress {
  /** Same as the resulting CommitRecord's id. */
  commitId: string;
  startedAt: string;
  description: string;
  /** Index of the group being worked on. */
  index: number;
  total: number;
  groupName: string;
  policyName: string;
  groups: {
    groupId: string;
    groupName: string;
    policyName: string;
    action: 'create' | 'update';
    state: CommitGroupState;
    error?: string;
    changes?: ChangeItem[];
  }[];
  /** Set on the last event, when every group has finished. */
  done?: boolean;
}

export interface IpGroupInfo {
  id: string;
  name: string;
  resourceGroup: string;
  subscriptionId: string;
  location: string;
  /** Member addresses, CIDRs and ranges. */
  addresses: string[];
}

/** Values the rule editor can pick from instead of typing, loaded from Azure. */
export interface RuleLookups {
  ipGroups: IpGroupInfo[];
  /** Service tags valid in the policy's region, e.g. "AzureCloud", "Sql.EastUS". */
  serviceTags: { name: string; region?: string; prefixCount: number }[];
  fqdnTags: string[];
  webCategories: { name: string; group?: string }[];
  /** Lookups that couldn't be loaded (the editor falls back to free text for those). */
  errors: string[];
}
