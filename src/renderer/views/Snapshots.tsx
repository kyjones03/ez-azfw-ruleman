import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Camera,
  ChevronRight,
  Database,
  ExternalLink,
  Layers,
  ListTree,
  Plus,
  RotateCcw,
  Settings2,
  ShieldCheck,
} from 'lucide-react';
import { SelectMenu } from '../components/Dropdown';
import { ConfirmModal, Modal } from '../components/Modal';
import { Segmented } from '../components/Segmented';
import {
  Badge,
  EmptyState,
  Notice,
  Spinner,
  Truncate,
  ValueList,
} from '../components/ui';
import { errorMessage, useToast } from '../components/Toast';
import { collectionKindOf } from '../../shared/ruleDraft';
import { sameResourceId } from '../../shared/resourceId';
import type { DeployContext, SubscriptionInfo } from '../../shared/deploy';
import type {
  CandidateStatus,
  CreateSnapshotStorageRequest,
  FirewallRule,
  PolicySnapshot,
  RuleCollection,
  RuleCollectionGroup,
  SnapshotStorageAccountInfo,
  SnapshotStorageConfig,
} from '../../shared/types';
import type { PolicyOption } from './PolicyEditor';

const DEFAULT_CONTAINER = 'ez-azfw-snapshots';

const GRS_SKU_OPTIONS: {
  value: NonNullable<CreateSnapshotStorageRequest['skuName']>;
  label: string;
  hint: string;
}[] = [
  {
    value: 'Standard_GRS',
    label: 'Standard GRS (Geo-redundant storage)',
    hint: 'Recommended',
  },
  {
    value: 'Standard_RAGRS',
    label: 'Standard RA-GRS (Read-access geo-redundant)',
    hint: 'Secondary read',
  },
  {
    value: 'Standard_GZRS',
    label: 'Standard GZRS (Geo-zone-redundant)',
    hint: 'Zone + region',
  },
  {
    value: 'Standard_RAGZRS',
    label: 'Standard RA-GZRS (Read-access geo-zone-redundant)',
    hint: 'Zone + secondary read',
  },
];

function validateAccountNameInput(name: string): string | undefined {
  const v = name.trim();
  if (!v) return undefined;
  if (v.length < 3 || v.length > 24) {
    return `Must be 3-24 characters (currently ${v.length}).`;
  }
  if (!/^[a-z0-9]+$/.test(v)) {
    return 'Only lowercase letters and numbers are allowed.';
  }
  return undefined;
}

function validateContainerInput(name: string): string | undefined {
  const v = name.trim();
  if (!v) return 'Container name is required.';
  if (v.length < 3 || v.length > 63) {
    return `Must be 3-63 characters (currently ${v.length}).`;
  }
  if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(v) || v.includes('--')) {
    return 'Use lowercase letters, numbers, and single hyphens.';
  }
  return undefined;
}

function StorageSetupCard({
  currentConfig,
  onConfigured,
  onCancel,
}: {
  currentConfig: SnapshotStorageConfig | null;
  onConfigured: (config: SnapshotStorageConfig) => void;
  onCancel?: () => void;
}) {
  const toast = useToast();
  const [mode, setMode] = useState<'existing' | 'new'>('existing');
  const [accounts, setAccounts] = useState<SnapshotStorageAccountInfo[] | null>(
    null,
  );
  const [accountsError, setAccountsError] = useState('');
  const [selectedAccountId, setSelectedAccountId] = useState(
    currentConfig?.storageAccountId ?? '',
  );
  const [containerName, setContainerName] = useState(
    currentConfig?.containerName ?? DEFAULT_CONTAINER,
  );

  // Create new storage account fields
  const [subscriptions, setSubscriptions] = useState<SubscriptionInfo[]>([]);
  const [subscriptionId, setSubscriptionId] = useState('');
  const [ctx, setCtx] = useState<DeployContext | null>(null);
  const [rgMode, setRgMode] = useState<'existing' | 'new'>('existing');
  const [resourceGroup, setResourceGroup] = useState('');
  const [location, setLocation] = useState('');
  const [newAccountName, setNewAccountName] = useState('');
  const [skuName, setSkuName] =
    useState<NonNullable<CreateSnapshotStorageRequest['skuName']>>(
      'Standard_GRS',
    );
  const [softDeleteDays, setSoftDeleteDays] = useState('30');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    window.api
      .listSnapshotStorageAccounts()
      .then((list) => {
        if (cancelled) return;
        setAccounts(list);
        setAccountsError('');
        if (!selectedAccountId && list.length > 0) {
          const preferred =
            list.find((a) => a.isAppTagged) ??
            list.find((a) => a.isGRS) ??
            list[0];
          setSelectedAccountId(preferred.id);
          if (preferred.containerName) {
            setContainerName(preferred.containerName);
          }
        }
        if (list.length === 0) setMode('new');
      })
      .catch((err) => {
        if (!cancelled) setAccountsError(errorMessage(err));
      });
    window.api
      .listSubscriptions()
      .then((subs) => {
        if (cancelled) return;
        setSubscriptions(subs);
        if (subs.length > 0) setSubscriptionId(subs[0].subscriptionId);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!subscriptionId) return;
    let cancelled = false;
    setCtx(null);
    window.api
      .getDeployContext(subscriptionId)
      .then((c) => {
        if (cancelled) return;
        setCtx(c);
        if (c.resourceGroups.length > 0) {
          setRgMode('existing');
          setResourceGroup(c.resourceGroups[0].name);
        } else {
          setRgMode('new');
          setResourceGroup('rg-ezazfw-snapshots');
        }
        setLocation(c.locations[0] ?? 'eastus');
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [subscriptionId]);

  const selectedAccount = useMemo(
    () =>
      accounts?.find((a) => sameResourceId(a.id, selectedAccountId)) ?? null,
    [accounts, selectedAccountId],
  );

  const containerErr = validateContainerInput(containerName);
  const accountNameErr = validateAccountNameInput(newAccountName);

  const handleSaveExisting = async () => {
    if (!selectedAccountId || containerErr) return;
    setSubmitting(true);
    try {
      const cfg = await window.api.setSnapshotStorageAccount(
        selectedAccountId,
        containerName.trim(),
      );
      toast(
        'success',
        `Connected centralized snapshot storage: ${cfg.storageAccountName}/${cfg.containerName} (blob soft delete & versioning enabled).`,
      );
      onConfigured(cfg);
    } catch (err) {
      toast('error', errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleCreateNew = async () => {
    const cleanName = newAccountName.trim().toLowerCase();
    if (
      !subscriptionId ||
      !resourceGroup.trim() ||
      !location ||
      !cleanName ||
      accountNameErr ||
      containerErr
    ) {
      return;
    }
    setSubmitting(true);
    try {
      const days = Math.min(
        365,
        Math.max(1, Number.parseInt(softDeleteDays, 10) || 30),
      );
      const cfg = await window.api.createSnapshotStorageAccount({
        subscriptionId,
        resourceGroup: resourceGroup.trim(),
        createResourceGroup: rgMode === 'new',
        location,
        storageAccountName: cleanName,
        containerName: containerName.trim(),
        skuName,
        softDeleteDays: days,
      });
      toast(
        'success',
        `Provisioned GRS storage account ${cfg.storageAccountName} with ${days}-day soft delete and blob versioning.`,
      );
      onConfigured(cfg);
    } catch (err) {
      toast('error', errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <Segmented
          label="Storage account mode"
          value={mode}
          onChange={setMode}
          options={[
            { value: 'existing', label: 'Use existing storage account' },
            { value: 'new', label: 'Create new GRS storage account' },
          ]}
        />
      </div>

      {mode === 'existing' ? (
        <div className="space-y-4">
          {accountsError && (
            <Notice tone="error" title="Couldn't list storage accounts">
              {accountsError}
            </Notice>
          )}
          {!accounts ? (
            <Spinner label="Scanning subscriptions for Azure Storage accounts…" />
          ) : !accounts.length ? (
            <Notice tone="warn" title="No storage accounts found">
              No Azure Storage accounts were found in this directory. Switch to
              "Create new GRS storage account" above to provision one.
            </Notice>
          ) : (
            <>
              <div>
                <span className="label">Storage account</span>
                <SelectMenu
                  label="Select storage account"
                  widthClass="w-full"
                  value={selectedAccountId}
                  onChange={(id) => {
                    setSelectedAccountId(id);
                    const found = accounts.find((a) =>
                      sameResourceId(a.id, id),
                    );
                    if (found?.containerName) {
                      setContainerName(found.containerName);
                    }
                  }}
                  options={accounts.map((a) => ({
                    value: a.id,
                    label: `${a.name}${a.isAppTagged ? ' ★ Shared team storage' : ''}`,
                    hint: `${a.skuName} · ${a.location} · ${a.resourceGroup}`,
                  }))}
                />
                {selectedAccount && !selectedAccount.isGRS && (
                  <p className="mt-1 text-xs text-candidate">
                    Note: {selectedAccount.name} uses {selectedAccount.skuName}.
                    A geo-redundant SKU (Standard_GRS / Standard_GZRS) is
                    recommended for shared firewall snapshots.
                  </p>
                )}
              </div>

              <div>
                <label className="label" htmlFor="snap-container-existing">
                  Blob container name
                </label>
                <input
                  id="snap-container-existing"
                  className="input"
                  value={containerName}
                  onChange={(e) =>
                    setContainerName(e.target.value.toLowerCase())
                  }
                  placeholder={DEFAULT_CONTAINER}
                />
                {containerErr ? (
                  <p className="mt-0.5 text-xs text-deny">{containerErr}</p>
                ) : (
                  <p className="mt-0.5 text-xs text-fg-faint">
                    Created automatically if it doesn't exist. Blob soft delete
                    (30 days), container soft delete, and blob versioning will
                    be enabled on this storage account.
                  </p>
                )}
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                {onCancel && (
                  <button
                    type="button"
                    className="btn-ghost"
                    onClick={onCancel}
                    disabled={submitting}
                  >
                    Cancel
                  </button>
                )}
                <button
                  type="button"
                  className="btn-primary"
                  disabled={!selectedAccountId || !!containerErr || submitting}
                  onClick={handleSaveExisting}
                >
                  <Database size={14} />
                  {submitting
                    ? 'Configuring storage…'
                    : 'Use this storage account'}
                </button>
              </div>
            </>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <span className="label">Subscription</span>
              <SelectMenu
                label="Subscription"
                widthClass="w-full"
                value={subscriptionId}
                onChange={setSubscriptionId}
                options={subscriptions.map((s) => ({
                  value: s.subscriptionId,
                  label: s.name,
                }))}
              />
            </div>

            <div>
              <span className="label">Redundancy (GRS)</span>
              <SelectMenu
                label="Redundancy SKU"
                widthClass="w-full"
                value={skuName}
                onChange={(v) =>
                  setSkuName(
                    v as NonNullable<CreateSnapshotStorageRequest['skuName']>,
                  )
                }
                options={GRS_SKU_OPTIONS}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <div className="mb-1 flex items-center justify-between">
                <span className="label !mb-0">Resource group</span>
                <button
                  type="button"
                  className="text-xs text-azure hover:underline"
                  onClick={() =>
                    setRgMode((m) => (m === 'existing' ? 'new' : 'existing'))
                  }
                >
                  {rgMode === 'existing' ? 'Create new' : 'Use existing'}
                </button>
              </div>
              {rgMode === 'existing' && ctx?.resourceGroups.length ? (
                <SelectMenu
                  label="Resource group"
                  widthClass="w-full"
                  value={resourceGroup}
                  onChange={setResourceGroup}
                  options={ctx.resourceGroups.map((g) => ({
                    value: g.name,
                    label: g.name,
                    hint: g.location,
                  }))}
                />
              ) : (
                <input
                  className="input"
                  value={resourceGroup}
                  onChange={(e) => setResourceGroup(e.target.value)}
                  placeholder="rg-ezazfw-snapshots"
                />
              )}
            </div>

            <div>
              <span className="label">Region</span>
              <SelectMenu
                label="Region"
                widthClass="w-full"
                value={location}
                onChange={setLocation}
                options={
                  ctx?.locations.length
                    ? ctx.locations.map((loc) => ({
                        value: loc,
                        label: ctx.locationNames?.[loc] ?? loc,
                        hint: loc,
                      }))
                    : [{ value: 'eastus', label: 'East US', hint: 'eastus' }]
                }
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="sm:col-span-2">
              <label className="label" htmlFor="new-storage-name">
                Storage account name
              </label>
              <input
                id="new-storage-name"
                className="input font-mono"
                value={newAccountName}
                onChange={(e) =>
                  setNewAccountName(e.target.value.toLowerCase())
                }
                placeholder="ezazfwsnapshots01"
                maxLength={24}
              />
              {accountNameErr ? (
                <p className="mt-0.5 text-xs text-deny">{accountNameErr}</p>
              ) : (
                <p className="mt-0.5 text-xs text-fg-faint">
                  3–24 lowercase letters and numbers, globally unique across
                  Azure.
                </p>
              )}
            </div>

            <div>
              <label className="label" htmlFor="soft-delete-days">
                Soft delete retention (days)
              </label>
              <input
                id="soft-delete-days"
                type="number"
                min={1}
                max={365}
                className="input font-mono"
                value={softDeleteDays}
                onChange={(e) => setSoftDeleteDays(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="label" htmlFor="snap-container-new">
              Blob container name
            </label>
            <input
              id="snap-container-new"
              className="input font-mono"
              value={containerName}
              onChange={(e) => setContainerName(e.target.value.toLowerCase())}
              placeholder={DEFAULT_CONTAINER}
            />
            {containerErr && (
              <p className="mt-0.5 text-xs text-deny">{containerErr}</p>
            )}
          </div>

          <div className="border border-line bg-ink-950 px-3 py-2 text-xs text-fg-muted">
            Provisions a <span className="text-fg">{skuName}</span> StorageV2
            account with{' '}
            <span className="text-fg">
              blob soft delete ({softDeleteDays || 30} days)
            </span>
            ,{' '}
            <span className="text-fg">
              container soft delete ({softDeleteDays || 30} days)
            </span>
            , <span className="text-fg">blob versioning</span>, HTTPS-only, and
            tags it so teammates using EZ AzFW Rule Manager automatically
            connect to the same snapshot store.
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            {onCancel && (
              <button
                type="button"
                className="btn-ghost"
                onClick={onCancel}
                disabled={submitting}
              >
                Cancel
              </button>
            )}
            <button
              type="button"
              className="btn-primary"
              disabled={
                !subscriptionId ||
                !resourceGroup.trim() ||
                !location ||
                !newAccountName.trim() ||
                !!accountNameErr ||
                !!containerErr ||
                submitting
              }
              onClick={handleCreateNew}
            >
              <Plus size={14} />
              {submitting
                ? 'Provisioning GRS storage (~20s)…'
                : 'Create GRS storage account'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

const ACTION_COLOR: Record<string, string> = {
  Allow: 'bg-allow text-allow',
  Deny: 'bg-deny text-deny',
  DNAT: 'bg-dnat text-dnat',
};

function ActionMark({ action }: { action: string }) {
  const [bar, text] = (
    ACTION_COLOR[action] ?? 'bg-fg-faint text-fg-muted'
  ).split(' ');
  return (
    <span className={`inline-flex items-center gap-1.5 font-medium ${text}`}>
      <span className={`h-3.5 w-[3px] ${bar}`} aria-hidden />
      {action}
    </span>
  );
}

function sourceOf(r: FirewallRule) {
  return [...(r.sourceAddresses ?? []), ...(r.sourceIpGroups ?? [])];
}

function destinationOf(r: FirewallRule) {
  switch (r.ruleType) {
    case 'NetworkRule':
      return [
        ...(r.destinationAddresses ?? []),
        ...(r.destinationIpGroups ?? []),
        ...(r.destinationFqdns ?? []),
      ];
    case 'ApplicationRule':
      return [
        ...(r.targetFqdns ?? []),
        ...(r.fqdnTags ?? []).map((t) => `tag:${t}`),
        ...(r.webCategories ?? []).map((c) => `category:${c}`),
        ...(r.targetUrls ?? []),
        ...(r.destinationAddresses ?? []),
      ];
    case 'NatRule':
      return (r.destinationAddresses ?? []).map(
        (a) => `${a}:${r.destinationPorts?.[0] ?? '*'}`,
      );
  }
}

function serviceOf(r: FirewallRule) {
  if (r.ruleType === 'ApplicationRule')
    return (r.protocols ?? []).map((p) => `${p.protocolType}:${p.port}`);
  const protos = (r.ipProtocols ?? []).join('/');
  if (r.ruleType === 'NatRule') return [protos];
  return (r.destinationPorts ?? []).map((p) => `${protos} ${p}`);
}

function countSnapshotTotals(groups: RuleCollectionGroup[]) {
  return {
    groups: groups.length,
    collections: groups.reduce((n, g) => n + g.ruleCollections.length, 0),
    rules: groups.reduce(
      (n, g) => n + g.ruleCollections.reduce((m, c) => m + c.rules.length, 0),
      0,
    ),
  };
}

export function Snapshots({
  policies,
  refreshKey,
  onRestored,
}: {
  policies: PolicyOption[];
  refreshKey: number;
  onRestored: (policyId: string, status: CandidateStatus) => void;
}) {
  const toast = useToast();
  const [storageConfig, setStorageConfig] = useState<
    SnapshotStorageConfig | null | undefined
  >(undefined);
  const [showStorageModal, setShowStorageModal] = useState(false);
  const [snapshots, setSnapshots] = useState<PolicySnapshot[] | null>(null);
  const [error, setError] = useState('');
  const [policyFilter, setPolicyFilter] = useState<string>('all');
  const [openSnapshots, setOpenSnapshots] = useState<Set<string>>(new Set());
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const [openCollections, setOpenCollections] = useState<Set<string>>(
    new Set(),
  );
  const [confirmRestore, setConfirmRestore] = useState<PolicySnapshot | null>(
    null,
  );
  const [restoringId, setRestoringId] = useState<string | null>(null);

  const loadAll = useCallback(async () => {
    setError('');
    try {
      const cfg = await window.api.getSnapshotStorageConfig();
      setStorageConfig(cfg);
      if (!cfg) {
        setSnapshots([]);
        return;
      }
      setSnapshots(null);
      const list = await window.api.getSnapshots();
      setSnapshots(list);
    } catch (err) {
      setError(errorMessage(err));
      setSnapshots([]);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll, refreshKey]);

  const policyOptions = useMemo(() => {
    const map = new Map<string, { value: string; label: string }>();
    for (const p of policies) {
      map.set(p.id.toLowerCase(), { value: p.id, label: p.name });
    }
    for (const s of snapshots ?? []) {
      const k = s.policyId.toLowerCase();
      if (!map.has(k)) {
        map.set(k, { value: s.policyId, label: s.policyName });
      }
    }
    return [
      { value: 'all', label: 'All policies' },
      ...[...map.values()].sort((a, b) => a.label.localeCompare(b.label)),
    ];
  }, [policies, snapshots]);

  const filtered = useMemo(() => {
    if (!snapshots) return [];
    if (policyFilter === 'all') return snapshots;
    return snapshots.filter((s) => sameResourceId(s.policyId, policyFilter));
  }, [snapshots, policyFilter]);

  const toggleSet = (
    setter: React.Dispatch<React.SetStateAction<Set<string>>>,
    key: string,
  ) => {
    setter((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const handleRestore = async (snap: PolicySnapshot) => {
    setConfirmRestore(null);
    setRestoringId(snap.id);
    try {
      const nextStatus = await window.api.restoreSnapshot(snap.id);
      toast(
        'success',
        `Staged policy state from ${new Date(snap.time).toLocaleString()} into your draft. Review and commit to apply to Azure.`,
      );
      onRestored(snap.policyId, nextStatus);
    } catch (err) {
      toast('error', errorMessage(err));
    } finally {
      setRestoringId(null);
    }
  };

  if (storageConfig === undefined) {
    return (
      <div className="p-6">
        <Spinner label="Checking centralized snapshot storage…" />
      </div>
    );
  }

  // Centralized storage is mandatory — never store snapshots locally.
  if (storageConfig === null) {
    return (
      <div className="flex h-full flex-col overflow-y-auto p-6">
        <div className="mx-auto w-full max-w-2xl border border-line bg-ink-900 p-6">
          <div className="flex items-start gap-3">
            <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded border border-azure/40 bg-azure/10 text-azure">
              <Database size={18} />
            </span>
            <div>
              <h1 className="text-lg font-semibold text-fg">
                Centralized snapshot storage required
              </h1>
              <p className="mt-1 text-sm text-fg-muted">
                Snapshots are never stored on local devices. Choose an existing
                Azure Storage account or provision a new geo-redundant (GRS)
                Blob Storage account with soft delete enabled so every teammate
                shares the same cumulative commit snapshots.
              </p>
            </div>
          </div>

          <div className="mt-5 border-t border-line pt-5">
            <StorageSetupCard
              currentConfig={null}
              onConfigured={(cfg) => {
                setStorageConfig(cfg);
                void loadAll();
              }}
            />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-line px-6 pb-4 pt-5">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-semibold">Firewall snapshots</h1>
            <span className="inline-flex items-center gap-1.5 rounded border border-line bg-ink-900 px-2.5 py-0.5 text-xs text-fg-muted">
              <Database size={12} className="text-azure" />
              <span className="font-mono text-fg">
                {storageConfig.storageAccountName}/{storageConfig.containerName}
              </span>
              {storageConfig.skuName && (
                <Badge tone="blue">{storageConfig.skuName}</Badge>
              )}
              <button
                type="button"
                className="ml-1 text-fg-faint hover:text-fg"
                title="Open storage account in Azure portal"
                onClick={() =>
                  window.api
                    .openInPortal(storageConfig.storageAccountId)
                    .catch((err) => toast('error', errorMessage(err)))
                }
              >
                <ExternalLink size={12} />
              </button>
            </span>
            <button
              type="button"
              className="btn-ghost h-7 px-2 text-xs"
              onClick={() => setShowStorageModal(true)}
            >
              <Settings2 size={13} />
              Change storage
            </button>
          </div>
          <p className="mt-1 text-sm text-fg-muted">
            Cumulative policy states saved in shared Azure Blob Storage each
            time a commit is applied to Azure, newest first. Expand a snapshot
            to inspect its rule collection groups, rule collections, and rules,
            or roll back to a former state.
          </p>
        </div>
        {policyOptions.length > 2 && (
          <div className="w-64 shrink-0">
            <span className="label">Policy</span>
            <SelectMenu
              label="Filter by policy"
              widthClass="w-full"
              value={policyFilter}
              onChange={setPolicyFilter}
              options={policyOptions}
            />
          </div>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-6">
        {error && (
          <div className="mb-4">
            <Notice tone="error" title="Couldn't load policy snapshots">
              {error}
            </Notice>
          </div>
        )}
        {!snapshots ? (
          <Spinner label="Loading snapshots from Azure Blob Storage…" />
        ) : !snapshots.length ? (
          <EmptyState
            icon={<Camera size={22} />}
            title="No committed snapshots in shared storage yet"
          >
            A single cumulative snapshot is uploaded to{' '}
            <span className="font-mono text-fg">
              {storageConfig.storageAccountName}/{storageConfig.containerName}
            </span>{' '}
            whenever you or a teammate commits firewall policy changes to Azure.
          </EmptyState>
        ) : !filtered.length ? (
          <p className="text-sm text-fg-muted">
            No snapshots for the selected policy.
          </p>
        ) : (
          <div className="space-y-3">
            {filtered.map((snap) => {
              const snapOpen = openSnapshots.has(snap.id);
              const totals = countSnapshotTotals(snap.groups);
              const isLatestForPolicy =
                snapshots.findIndex((s) =>
                  sameResourceId(s.policyId, snap.policyId),
                ) === snapshots.indexOf(snap);

              return (
                <div key={snap.id} className="border border-line bg-ink-900">
                  <div className="flex items-center gap-3 px-4 py-3 hover:bg-ink-850">
                    <button
                      type="button"
                      aria-expanded={snapOpen}
                      aria-label={`Rule collection groups for snapshot from ${new Date(snap.time).toLocaleString()}`}
                      onClick={() => toggleSet(setOpenSnapshots, snap.id)}
                      className="flex min-w-0 flex-1 items-center gap-3 text-left"
                    >
                      <ChevronRight
                        size={16}
                        className={`shrink-0 text-fg-muted transition-transform ${snapOpen ? 'rotate-90' : ''}`}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-semibold text-fg">
                            {snap.policyName}
                          </span>
                          <span className="text-xs text-fg-muted">
                            {new Date(snap.time).toLocaleString()}
                          </span>
                          {isLatestForPolicy && (
                            <Badge tone="blue">Latest</Badge>
                          )}
                          {snap.user && (
                            <span className="text-xs text-fg-faint">
                              by {snap.user}
                            </span>
                          )}
                        </div>
                        <div className="mt-0.5 truncate text-xs text-fg-muted">
                          {snap.description || 'Policy state snapshot'}
                        </div>
                      </div>
                      <div className="shrink-0 text-right text-xs text-fg-muted">
                        <span className="inline-flex items-center gap-1.5 rounded border border-line bg-ink-950 px-2.5 py-1 font-medium text-fg">
                          <Layers size={13} className="text-azure" />
                          {totals.groups} rule collection{' '}
                          {totals.groups === 1 ? 'group' : 'groups'}
                          <span className="text-fg-faint">·</span>
                          {totals.collections}{' '}
                          {totals.collections === 1
                            ? 'collection'
                            : 'collections'}
                          <span className="text-fg-faint">·</span>
                          {totals.rules} {totals.rules === 1 ? 'rule' : 'rules'}
                        </span>
                      </div>
                    </button>
                    <button
                      type="button"
                      className="btn-outline h-8 shrink-0 px-3 text-xs"
                      disabled={restoringId === snap.id}
                      onClick={() => setConfirmRestore(snap)}
                      title="Stage this policy state in your draft so you can roll back to it"
                    >
                      <RotateCcw size={13} />
                      Roll back to state
                    </button>
                  </div>

                  {snapOpen && (
                    <div className="border-t border-line bg-ink-950 px-4 py-3">
                      {!snap.groups.length ? (
                        <p className="text-xs text-fg-faint">
                          This policy had no rule collection groups in this
                          snapshot.
                        </p>
                      ) : (
                        <div className="space-y-2">
                          {[...snap.groups]
                            .sort((a, b) => a.priority - b.priority)
                            .map((group) => {
                              const groupKey = `${snap.id}:${group.name}`;
                              const groupOpen = openGroups.has(groupKey);
                              const groupRules = group.ruleCollections.reduce(
                                (n, c) => n + c.rules.length,
                                0,
                              );
                              return (
                                <div
                                  key={groupKey}
                                  className="border border-line/80 bg-ink-900"
                                >
                                  <button
                                    type="button"
                                    aria-expanded={groupOpen}
                                    onClick={() =>
                                      toggleSet(setOpenGroups, groupKey)
                                    }
                                    className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm hover:bg-ink-850"
                                  >
                                    <ChevronRight
                                      size={14}
                                      className={`shrink-0 text-fg-muted transition-transform ${groupOpen ? 'rotate-90' : ''}`}
                                    />
                                    <ShieldCheck
                                      size={14}
                                      className="shrink-0 text-azure"
                                    />
                                    <span className="font-medium text-fg">
                                      {group.name}
                                    </span>
                                    <span className="font-mono text-xs text-fg-faint">
                                      priority {group.priority}
                                    </span>
                                    <span className="ml-auto text-xs text-fg-muted">
                                      {group.ruleCollections.length} rule{' '}
                                      {group.ruleCollections.length === 1
                                        ? 'collection'
                                        : 'collections'}{' '}
                                      · {groupRules}{' '}
                                      {groupRules === 1 ? 'rule' : 'rules'}
                                    </span>
                                  </button>

                                  {groupOpen && (
                                    <div className="border-t border-line/60 bg-ink-950 px-3 py-2">
                                      {!group.ruleCollections.length ? (
                                        <p className="py-1 text-xs text-fg-faint">
                                          No rule collections in this group.
                                        </p>
                                      ) : (
                                        <div className="space-y-2">
                                          {[...group.ruleCollections]
                                            .sort(
                                              (a, b) => a.priority - b.priority,
                                            )
                                            .map((col: RuleCollection) => {
                                              const colKey = `${groupKey}:${col.name}`;
                                              const colOpen =
                                                openCollections.has(colKey);
                                              return (
                                                <div
                                                  key={colKey}
                                                  className="border border-line/60 bg-ink-900"
                                                >
                                                  <button
                                                    type="button"
                                                    aria-expanded={colOpen}
                                                    onClick={() =>
                                                      toggleSet(
                                                        setOpenCollections,
                                                        colKey,
                                                      )
                                                    }
                                                    className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm hover:bg-ink-850"
                                                  >
                                                    <ChevronRight
                                                      size={14}
                                                      className={`shrink-0 text-fg-muted transition-transform ${colOpen ? 'rotate-90' : ''}`}
                                                    />
                                                    <ListTree
                                                      size={14}
                                                      className="shrink-0 text-fg-muted"
                                                    />
                                                    <span className="font-medium text-fg">
                                                      {col.name}
                                                    </span>
                                                    <ActionMark
                                                      action={col.action.type}
                                                    />
                                                    <span className="text-xs text-fg-muted">
                                                      {collectionKindOf(col)}{' '}
                                                      collection · priority{' '}
                                                      {col.priority}
                                                    </span>
                                                    <span className="ml-auto text-xs text-fg-muted">
                                                      {col.rules.length}{' '}
                                                      {col.rules.length === 1
                                                        ? 'rule'
                                                        : 'rules'}
                                                    </span>
                                                  </button>

                                                  {colOpen && (
                                                    <div className="border-t border-line/60 bg-ink-950">
                                                      {!col.rules.length ? (
                                                        <p className="px-4 py-2 text-xs text-fg-faint">
                                                          No rules in this
                                                          collection.
                                                        </p>
                                                      ) : (
                                                        <table className="w-full table-fixed text-left text-xs">
                                                          <thead className="border-b border-line/60 bg-ink-900 text-fg-muted">
                                                            <tr>
                                                              <th className="w-48 px-3 py-1.5 font-medium">
                                                                Rule
                                                              </th>
                                                              <th className="w-24 px-3 py-1.5 font-medium">
                                                                Type
                                                              </th>
                                                              <th className="px-3 py-1.5 font-medium">
                                                                Source
                                                              </th>
                                                              <th className="w-32 px-3 py-1.5 font-medium">
                                                                Service
                                                              </th>
                                                              <th className="px-3 py-1.5 font-medium">
                                                                Destination
                                                              </th>
                                                              <th className="w-36 px-3 py-1.5 font-medium">
                                                                Action
                                                              </th>
                                                            </tr>
                                                          </thead>
                                                          <tbody>
                                                            {(
                                                              col.rules as FirewallRule[]
                                                            ).map((r) => (
                                                              <tr
                                                                key={r.name}
                                                                className="border-b border-line/40 align-top last:border-b-0 hover:bg-ink-900/60"
                                                              >
                                                                <td className="px-3 py-2">
                                                                  <Truncate className="font-medium text-fg">
                                                                    {r.name}
                                                                  </Truncate>
                                                                  {r.description && (
                                                                    <Truncate className="text-[11px] text-fg-faint">
                                                                      {
                                                                        r.description
                                                                      }
                                                                    </Truncate>
                                                                  )}
                                                                </td>
                                                                <td className="px-3 py-2 text-fg-muted">
                                                                  {r.ruleType ===
                                                                  'NetworkRule'
                                                                    ? 'Network'
                                                                    : r.ruleType ===
                                                                        'ApplicationRule'
                                                                      ? 'Application'
                                                                      : 'DNAT'}
                                                                </td>
                                                                <td className="px-3 py-2">
                                                                  <ValueList
                                                                    values={sourceOf(
                                                                      r,
                                                                    )}
                                                                  />
                                                                </td>
                                                                <td className="px-3 py-2">
                                                                  <ValueList
                                                                    values={serviceOf(
                                                                      r,
                                                                    )}
                                                                    max={2}
                                                                  />
                                                                </td>
                                                                <td className="px-3 py-2">
                                                                  <ValueList
                                                                    values={destinationOf(
                                                                      r,
                                                                    )}
                                                                  />
                                                                </td>
                                                                <td className="px-3 py-2">
                                                                  {r.ruleType ===
                                                                  'NatRule' ? (
                                                                    <span
                                                                      className="netval block break-all"
                                                                      title={`${r.translatedAddress ?? r.translatedFqdn}:${r.translatedPort}`}
                                                                    >
                                                                      to{' '}
                                                                      {r.translatedAddress ??
                                                                        r.translatedFqdn}
                                                                      :
                                                                      {
                                                                        r.translatedPort
                                                                      }
                                                                    </span>
                                                                  ) : (
                                                                    <ActionMark
                                                                      action={
                                                                        col
                                                                          .action
                                                                          .type
                                                                      }
                                                                    />
                                                                  )}
                                                                </td>
                                                              </tr>
                                                            ))}
                                                          </tbody>
                                                        </table>
                                                      )}
                                                    </div>
                                                  )}
                                                </div>
                                              );
                                            })}
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {confirmRestore && (
        <ConfirmModal
          title={`Roll back ${confirmRestore.policyName}?`}
          message={`This stages the policy state from ${new Date(confirmRestore.time).toLocaleString()} into your local draft, replacing any uncommitted edits on ${confirmRestore.policyName}. You can review the changes in Rules before committing them to Azure.`}
          confirmLabel="Roll back to state"
          onCancel={() => setConfirmRestore(null)}
          onConfirm={() => handleRestore(confirmRestore)}
        />
      )}

      {showStorageModal && (
        <Modal
          title="Centralized snapshot storage"
          subtitle="Select an existing Azure Storage account or provision a new GRS Blob Storage account with soft delete enabled."
          widthClass="max-w-2xl"
          onClose={() => setShowStorageModal(false)}
        >
          <StorageSetupCard
            currentConfig={storageConfig}
            onCancel={() => setShowStorageModal(false)}
            onConfigured={(cfg) => {
              setStorageConfig(cfg);
              setShowStorageModal(false);
              void loadAll();
            }}
          />
        </Modal>
      )}
    </div>
  );
}
