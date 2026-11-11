import {
  Fragment,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import {
  ChevronRight,
  KeyRound,
  ListTree,
  Settings2,
  ShieldCheck,
} from 'lucide-react';
import { EllipsisMenu } from '../components/Dropdown';
import { Segmented } from '../components/Segmented';
import { useResourceMenuItems } from '../components/resourceMenu';
import { EmptyState, Spinner } from '../components/ui';
import { parseResourceId, sameResourceId } from '../../shared/resourceId';
import { FilterBar } from '../components/FilterBar';
import { TreeLines, treeIndent } from '../components/TreeLines';
import {
  matchesFilters,
  tagPairs,
  useStoredFilters,
  type FilterValues,
} from '../filters';
import type { CandidateStatus, PolicyView } from '../../shared/types';
import type { PolicyOption } from './PolicyEditor';
import { MAX_POLICY_DEPTH } from '../policyChain';
import { errorMessage, useToast } from '../components/Toast';
import { isThreatIntelMode, THREAT_INTEL_MODES } from '../../shared/policyMode';
import type { ThreatIntelMode } from '../../shared/deploy';
import { PolicySettings } from './PolicySettings';

function PolicyModeButtons({
  mode,
  name,
  disabled,
  drafted,
  onStage,
}: {
  mode: ThreatIntelMode;
  name: string;
  disabled: boolean;
  drafted: boolean;
  onStage: (mode: ThreatIntelMode) => Promise<boolean>;
}) {
  const [value, setValue] = useState(mode);
  const [saving, setSaving] = useState(false);
  const committing = useRef(false);
  useEffect(() => {
    setValue(mode);
  }, [mode]);
  const stage = async (next: ThreatIntelMode) => {
    if (disabled || committing.current || next === mode) return;
    committing.current = true;
    setSaving(true);
    setValue(next);
    try {
      if (!(await onStage(next))) {
        setValue(mode);
      }
    } finally {
      committing.current = false;
      setSaving(false);
    }
  };
  return (
    <div
      className="inline-flex rounded bg-ink-900"
      title={
        disabled
          ? 'Inherited-only parent policies are read-only, or this policy is being committed.'
          : `${value}. Changes stay in your draft until committed.`
      }
    >
      <Segmented
        label={`Threat intelligence for ${name}`}
        value={value}
        options={THREAT_INTEL_MODES.map((option) => ({
          value: option,
          label: option,
          disabled: disabled || saving,
        }))}
        onChange={(next) => void stage(next)}
        activeClass={() =>
          drafted ? 'bg-candidate text-ink-950' : 'bg-azure text-ink-950'
        }
      />
    </div>
  );
}

interface Row {
  id: string;
  name: string;
  /** Applied to one of the managed firewalls (as opposed to only being a parent of one). */
  managed: boolean;
  firewallNames: string[];
  view?: PolicyView;
  error?: string;
}

interface TreeNode {
  row: Row;
  /** Child policies, which inherit from this one. */
  children: TreeNode[];
}

/** Firewall policies of the managed firewalls, with their parent policies and rule counts. */
export function Policies({
  policies,
  status,
  reloadKey,
  onOpenPolicy,
  subscriptionNames,
  onStatus,
}: {
  policies: PolicyOption[];
  /** Display names by lower-cased subscription ID. */
  subscriptionNames: Record<string, string>;
  status: CandidateStatus;
  reloadKey: number;
  onOpenPolicy: (policyId: string) => void;
  onStatus: (status: CandidateStatus) => void;
}) {
  const [views, setViews] = useState<
    Record<string, { view?: PolicyView; error?: string }>
  >({});
  const [loading, setLoading] = useState(false);
  const resourceMenuItems = useResourceMenuItems();
  const toast = useToast();
  const [settingsId, setSettingsId] = useState<string>();

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    (async () => {
      const out: Record<string, { view?: PolicyView; error?: string }> = {};
      const fetchAll = (ids: string[]) =>
        Promise.all(
          ids.map(async (id) => {
            try {
              out[id.toLowerCase()] = { view: await window.api.getPolicy(id) };
            } catch (err) {
              out[id.toLowerCase()] = { error: errorMessage(err) };
            }
          }),
        );
      await fetchAll(policies.map((p) => p.id));
      // Then their parents (and theirs), so the hierarchy is complete.
      for (let depth = 0; depth < MAX_POLICY_DEPTH; depth++) {
        const parents = [
          ...new Set(
            Object.values(out)
              .map((v) => v.view?.policy.basePolicyId)
              .filter((id): id is string => !!id && !out[id.toLowerCase()]),
          ),
        ];
        if (!parents.length || cancelled) break;
        await fetchAll(parents);
      }
      if (!cancelled) {
        setViews(out);
        setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [policies, reloadKey]);

  const rows = useMemo(() => {
    const map = new Map<string, Row>();
    for (const p of policies)
      map.set(p.id.toLowerCase(), {
        id: p.id,
        name: p.name,
        managed: true,
        firewallNames: p.firewallNames,
        ...views[p.id.toLowerCase()],
      });
    for (const [key, v] of Object.entries(views))
      if (!map.has(key) && v.view)
        map.set(key, {
          id: v.view.policy.id,
          name: v.view.policy.name,
          managed: false,
          firewallNames: [],
          ...v,
        });
    return [...map.values()];
  }, [policies, views]);

  const { filters, setFilter, clear, active } = useStoredFilters(
    'ez-azfw-ruleman.policyFilters',
  );
  const values = useMemo<FilterValues<Row>>(() => {
    const sub = (r: Row) => parseResourceId(r.id).subscriptionId;
    return {
      name: (r) => [r.name],
      subscription: (r) => [subscriptionNames[sub(r).toLowerCase()] ?? sub(r)],
      resourceGroup: (r) => [parseResourceId(r.id).resourceGroup],
      location: (r) =>
        r.view?.policy.location ? [r.view.policy.location] : [],
      tag: (r) => tagPairs(r.view?.policy.tags),
    };
  }, [subscriptionNames]);
  const shown = useMemo(
    () => rows.filter((r) => matchesFilters(r, filters, values)),
    [rows, filters, values],
  );

  // Grouped by subscription; within each, parents first with their children beneath. A child
  // whose parent is elsewhere (another subscription, or filtered out) is shown on its own.
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const bySubscription = useMemo(() => {
    const subOf = (r: Row) => parseResourceId(r.id).subscriptionId;
    const map = new Map<string, Row[]>();
    for (const r of shown) {
      const key = subOf(r).toLowerCase();
      map.set(key, [...(map.get(key) ?? []), r]);
    }
    const treeOf = (rows: Row[]): TreeNode[] => {
      const parentOf = (r: Row) => r.view?.policy.basePolicyId;
      // `path` guards against a malformed (cyclic) hierarchy.
      const nodeOf = (r: Row, path: Row[]): TreeNode => ({
        row: r,
        children: rows
          .filter((c) => sameResourceId(parentOf(c), r.id) && !path.includes(c))
          .sort((a, b) => a.name.localeCompare(b.name))
          .map((c) => nodeOf(c, [...path, c])),
      });
      return rows
        .filter(
          (r) =>
            !parentOf(r) ||
            !rows.some((p) => sameResourceId(p.id, parentOf(r))),
        )
        .map((r) => nodeOf(r, [r]))
        .sort(
          (a, b) =>
            b.children.length - a.children.length ||
            a.row.name.localeCompare(b.row.name),
        );
    };
    return [...map.entries()]
      .map(([key, rows]) => {
        const id = subOf(rows[0]);
        return {
          id,
          name: subscriptionNames[key] ?? id,
          count: rows.length,
          tree: treeOf(rows),
        };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [shown, subscriptionNames]);

  const pendingFor = (id: string) =>
    status.pending
      .filter((p) => p.target !== 'firewall' && sameResourceId(p.policyId, id))
      .reduce((n, p) => n + p.changes.length, 0);

  const renderRow = (
    r: Row,
    depth: number,
    last: boolean,
    ancestorsContinue: boolean[] = [],
  ) => {
    const own = r.view?.groups.filter((g) => !g.isNew) ?? [];
    const collections = own.reduce(
      (n, g) => n + g.group.ruleCollections.length,
      0,
    );
    const rules = own.reduce(
      (n, g) =>
        n + g.group.ruleCollections.reduce((m, c) => m + c.rules.length, 0),
      0,
    );
    const p = r.view?.policy;
    const pending = pendingFor(r.id);
    const childCount = p?.childPolicyIds.length ?? 0;
    const policyDraft = status.pending.find(
      (change) =>
        change.target === 'policy' && sameResourceId(change.policyId, r.id),
    );
    const mode = policyDraft?.policyMode?.after ?? p?.threatIntelMode;
    const committing = status.pending.some(
      (change) => change.committing && sameResourceId(change.policyId, r.id),
    );
    return (
      <tr key={r.id} className="border-b border-line/60 hover:bg-ink-850">
        <td
          className="relative py-2 pr-3"
          style={{ paddingLeft: treeIndent(depth) }}
        >
          <TreeLines
            depth={depth}
            last={last}
            ancestorsContinue={ancestorsContinue}
          />
          <div className="flex items-center gap-2">
            <ListTree size={14} className="shrink-0 text-fg-muted" />
            {r.managed ? (
              <button
                className="truncate font-medium hover:text-azure hover:underline"
                title={`Edit the rules in ${r.name}`}
                onClick={() => onOpenPolicy(r.id)}
              >
                {r.name}
              </button>
            ) : (
              <span className="truncate font-medium" title={r.id}>
                {r.name}
              </span>
            )}
            {childCount > 0 && (
              <span
                className="shrink-0 rounded bg-ink-800 px-1.5 text-[11px] text-fg-muted"
                title="Child policies inherit this policy's rules, which are evaluated before their own."
              >
                Parent of {childCount}
              </span>
            )}
            {pending > 0 && (
              <span className="shrink-0 text-xs text-candidate">
                {pending} uncommitted
              </span>
            )}
          </div>
        </td>
        <td
          className="truncate px-3 py-2 text-fg-muted"
          title={r.firewallNames.join(', ')}
        >
          {r.firewallNames.length
            ? r.firewallNames.join(', ')
            : p?.firewallIds.length
              ? `${p.firewallIds.length} not managed here`
              : '—'}
        </td>
        <td className="px-3 py-2 text-fg-muted">{p?.tier ?? '—'}</td>
        <td className="px-3 py-2 text-fg-muted">{p?.location ?? '—'}</td>
        <td className="px-3 py-2 text-fg-muted">
          {isThreatIntelMode(mode) ? (
            <PolicyModeButtons
              mode={mode}
              name={r.name}
              disabled={!r.managed || committing}
              drafted={!!policyDraft?.policyMode}
              onStage={async (next) => {
                try {
                  onStatus(await window.api.stagePolicyMode(r.id, next));
                  return true;
                } catch (err) {
                  toast('error', errorMessage(err));
                  return false;
                }
              }}
            />
          ) : (
            <span title="Refresh to load a supported threat-intelligence mode.">
              {mode ?? '—'}
            </span>
          )}
          {policyDraft?.policyMode &&
            isThreatIntelMode(p?.threatIntelMode) &&
            p.threatIntelMode !== policyDraft.policyMode.before &&
            p.threatIntelMode !== policyDraft.policyMode.after && (
              <p className="mt-1 text-[11px] text-deny" role="alert">
                Changed in Azure; discard and refresh before retrying.
              </p>
            )}
        </td>
        <td className="px-3 py-2 text-right tabular-nums text-fg-muted">
          {r.view ? (
            <span
              title={`${own.length} rule collection groups, ${collections} collections`}
            >
              {own.length} / {collections} / {rules}
            </span>
          ) : r.error ? (
            <span className="text-deny" title={r.error}>
              Couldn't load
            </span>
          ) : (
            '…'
          )}
        </td>
        <td className="py-1.5 pr-4">
          <EllipsisMenu
            label={`Actions for ${r.name}`}
            items={[
              ...(r.managed
                ? [
                    {
                      label: 'Edit policy settings',
                      icon: <Settings2 size={14} />,
                      disabled: committing,
                      onSelect: () => setSettingsId(r.id),
                    },
                    {
                      label: 'Edit rules',
                      icon: <ListTree size={14} />,
                      onSelect: () => onOpenPolicy(r.id),
                    },
                  ]
                : []),
              ...resourceMenuItems(r.id),
            ]}
          />
        </td>
      </tr>
    );
  };

  const renderTree = (
    nodes: TreeNode[],
    depth: number,
    ancestorsContinue: boolean[],
  ): ReactNode =>
    nodes.map((node, i) => {
      const last = i === nodes.length - 1;
      return (
        <Fragment key={node.row.id}>
          {renderRow(node.row, depth, last, ancestorsContinue)}
          {renderTree(node.children, depth + 1, [...ancestorsContinue, !last])}
        </Fragment>
      );
    });

  const managedCount = rows.filter((r) => r.managed).length;
  const parentCount = rows.length - managedCount;

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-end gap-3 border-b border-line px-6 pb-4 pt-5">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-semibold">Policies</h1>
          <p className="mt-1 text-sm text-fg-muted">
            {managedCount} {managedCount === 1 ? 'policy' : 'policies'} applied
            to your firewalls
            {parentCount > 0 &&
              `, plus ${parentCount} parent ${parentCount === 1 ? 'policy' : 'policies'} they inherit from`}
            . Threat-intelligence buttons change the local draft; save and
            commit to apply them.
          </p>
        </div>
        {loading && <Spinner label="Loading policy details…" />}
      </div>
      <FilterBar
        items={rows}
        values={values}
        filters={filters}
        onChange={setFilter}
        onClear={clear}
        active={active}
        summary={
          active ? `Showing ${shown.length} of ${rows.length}` : undefined
        }
      />
      {!rows.length ? (
        <EmptyState
          icon={<ShieldCheck size={22} />}
          title="No policies to show"
        >
          Policies appear here for the firewalls you show. Use Choose firewalls
          to show on the Firewalls page.
        </EmptyState>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full min-w-[1100px] table-fixed text-left text-sm">
            <thead className="sticky top-0 z-10 bg-ink-900 text-xs text-fg-muted">
              <tr className="border-b border-line">
                <th className="py-2 pl-6 pr-3 font-medium">Name</th>
                <th className="w-64 px-3 py-2 font-medium">Applied to</th>
                <th className="w-24 px-3 py-2 font-medium">Tier</th>
                <th className="w-40 px-3 py-2 font-medium">Region</th>
                <th className="w-44 px-3 py-2 font-medium">Threat intel</th>
                <th
                  className="w-40 px-3 py-2 text-right font-medium"
                  title="Own rule collection groups / collections / rules (inherited rules not counted)"
                >
                  Groups / colls / rules
                </th>
                <th className="w-12 py-2 pr-4" />
              </tr>
            </thead>
            <tbody>
              {!shown.length && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-6 py-6 text-center text-fg-muted"
                  >
                    No policies match these filters.
                  </td>
                </tr>
              )}
              {bySubscription.map((sub) => {
                const isCollapsed = collapsed.has(sub.id);
                return (
                  <Fragment key={sub.id}>
                    <tr className="border-b border-line bg-ink-850">
                      <td colSpan={7} className="p-0">
                        <button
                          type="button"
                          aria-expanded={!isCollapsed}
                          className="flex w-full items-center gap-2 py-2 pl-6 pr-3 text-left hover:bg-ink-800"
                          onClick={() =>
                            setCollapsed((c) => {
                              const next = new Set(c);
                              if (next.has(sub.id)) next.delete(sub.id);
                              else next.add(sub.id);
                              return next;
                            })
                          }
                        >
                          <ChevronRight
                            size={14}
                            className={`text-fg-muted transition-transform ${isCollapsed ? '' : 'rotate-90'}`}
                          />
                          <KeyRound size={14} className="text-fg-muted" />
                          <span className="font-semibold">{sub.name}</span>
                          {sub.name !== sub.id && (
                            <span className="font-mono text-xs text-fg-faint">
                              ({sub.id})
                            </span>
                          )}
                          <span className="text-fg-muted">
                            {sub.count}{' '}
                            {sub.count === 1 ? 'policy' : 'policies'}
                          </span>
                        </button>
                      </td>
                    </tr>
                    {!isCollapsed && renderTree(sub.tree, 1, [])}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {settingsId && (
        <PolicySettings
          policyId={settingsId}
          onStatus={onStatus}
          onClose={() => setSettingsId(undefined)}
        />
      )}
    </div>
  );
}
