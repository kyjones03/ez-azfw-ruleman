import { Fragment, useEffect, useMemo, useState } from 'react';
import {
  Camera,
  ChevronRight,
  Layers,
  ListTree,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react';
import { SelectMenu } from '../components/Dropdown';
import { ConfirmModal } from '../components/Modal';
import { Badge, EmptyState, Notice, Spinner, Truncate, ValueList } from '../components/ui';
import { errorMessage, useToast } from '../components/Toast';
import { collectionKindOf } from '../../shared/ruleDraft';
import { sameResourceId } from '../../shared/resourceId';
import type {
  CandidateStatus,
  FirewallRule,
  PolicySnapshot,
  RuleCollection,
  RuleCollectionGroup,
} from '../../shared/types';
import type { PolicyOption } from './PolicyEditor';

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
  const collections = groups.reduce(
    (n, g) => n + g.ruleCollections.length,
    0,
  );
  const rules = groups.reduce(
    (n, g) =>
      n + g.ruleCollections.reduce((m, c) => m + c.rules.length, 0),
    0,
  );
  return { groups: groups.length, collections, rules };
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

  useEffect(() => {
    let cancelled = false;
    window.api
      .getSnapshots()
      .then((list) => {
        if (cancelled) return;
        setSnapshots(list);
        setError('');
      })
      .catch((err) => !cancelled && setError(errorMessage(err)));
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

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

  if (!snapshots) {
    return (
      <div className="p-6">
        {error ? (
          <Notice tone="error" title="Couldn't load policy snapshots">
            {error}
          </Notice>
        ) : (
          <Spinner label="Loading snapshots…" />
        )}
      </div>
    );
  }

  if (!snapshots.length) {
    return (
      <EmptyState icon={<Camera size={22} />} title="No policy snapshots yet">
        Policy state snapshots are captured automatically whenever a firewall
        policy is loaded or updated so you can inspect and roll back to any
        former state.
      </EmptyState>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-end justify-between gap-4 border-b border-line px-6 pb-4 pt-5">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-semibold">Firewall snapshots</h1>
          <p className="mt-1 text-sm text-fg-muted">
            Policy states captured when rules or rule collection groups are
            updated, newest first. Expand a snapshot to inspect its rule
            collection groups, rule collections, and rules, or roll back to a
            former state.
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
        {!filtered.length ? (
          <p className="text-sm text-fg-muted">
            No snapshots for the selected policy.
          </p>
        ) : (
          <div className="space-y-3">
            {filtered.map((snap, idx) => {
              const snapOpen = openSnapshots.has(snap.id);
              const totals = countSnapshotTotals(snap.groups);
              const isLatestForPolicy =
                snapshots.findIndex((s) =>
                  sameResourceId(s.policyId, snap.policyId),
                ) === snapshots.indexOf(snap);

              return (
                <div
                  key={snap.id}
                  className="border border-line bg-ink-900"
                >
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
                          {isLatestForPolicy && idx === 0 && (
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
                          {totals.rules}{' '}
                          {totals.rules === 1 ? 'rule' : 'rules'}
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
                                              (a, b) =>
                                                a.priority - b.priority,
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
    </div>
  );
}
