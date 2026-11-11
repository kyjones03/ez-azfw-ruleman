import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import {
  ListTree,
  Lock,
  Plus,
  Pencil,
  Copy,
  Trash2,
  RefreshCw,
  Search,
  Undo2,
  AlertTriangle,
  Layers,
  ArrowRightLeft,
  Loader2,
  Download,
  Upload,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';
import { readSetting, writeSetting } from '../storage';

const LIST_PANEL_KEY = 'ez-azfw-ruleman.groups-panel';
import { EllipsisMenu, SelectMenu } from '../components/Dropdown';
import { useResourceMenuItems } from '../components/resourceMenu';
import { loadPolicyChain } from '../policyChain';
import { ConfirmModal } from '../components/Modal';
import { EmptyState, Badge, Truncate, ValueList } from '../components/ui';
import { QuipSpinner } from '../components/QuipSpinner';
import { errorMessage, useToast } from '../components/Toast';
import { collectionKindOf } from '../../shared/ruleDraft';
import { ruleMatches } from '../../shared/search';
import type { FlowHit } from '../../shared/flow';
import { TransferRuleDialog } from './RuleTools';
import { TreeLines } from '../components/TreeLines';
import { csvFileName, groupsToCsv, type CsvGroup } from '../../shared/csv';
import { RuleLookupsContext, type LookupsState } from '../lookups';
import { ImportRules } from './ImportRules';
import {
  CollectionEditor,
  GroupPriorityEditor,
  NewGroupEditor,
} from './CollectionEditor';
import {
  changeKindOf,
  nextGroupPriority,
  removedItems,
} from '../../shared/rules';
import { resourceName, sameResourceId } from '../../shared/resourceId';
import type {
  CandidateStatus,
  ChangeKind,
  FirewallRule,
  GroupView,
  PolicyView,
  RuleCollection,
  RuleCollectionGroup,
} from '../../shared/types';

export interface PolicyOption {
  id: string;
  name: string;
  firewallNames: string[];
}

type ModalState =
  | {
      kind: 'collection';
      /** Existing collection name; omitted for a new collection. */
      collection?: string;
      focusRule?: string;
      addRule?: boolean;
      duplicateRule?: string;
    }
  | { kind: 'group' }
  | { kind: 'newGroup' }
  | { kind: 'import' }
  | {
      kind: 'transfer';
      collection: string;
      rule: FirewallRule;
      mode: 'move' | 'copy';
    }
  | { kind: 'confirm'; title: string; message: string; action: () => void }
  | null;

const DIFF_GLYPH: Record<ChangeKind, { glyph: string; label: string }> = {
  added: { glyph: '+', label: 'Added, not committed' },
  modified: { glyph: '~', label: 'Changed, not committed' },
  removed: { glyph: '−', label: 'Removed, not committed' },
};

/** Version-control style gutter marker for uncommitted rows. */
function DiffMark({ kind }: { kind?: ChangeKind }) {
  if (!kind) return null;
  const { glyph, label } = DIFF_GLYPH[kind];
  return (
    <span title={label} aria-label={label}>
      {glyph}
    </span>
  );
}

const ACTION_COLOR: Record<string, string> = {
  Allow: 'bg-allow text-allow',
  Deny: 'bg-deny text-deny',
  DNAT: 'bg-dnat text-dnat',
};

/** Rule action as a colored word with a short edge bar, instead of a pill. */
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

/** Rules in a group that match the search (collection names match all their rules). */
function countMatches(g: RuleCollectionGroup, q: string) {
  return g.ruleCollections.reduce(
    (n, c) =>
      n +
      (c.name.toLowerCase().includes(q)
        ? c.rules.length
        : (c.rules as FirewallRule[]).filter((r) => ruleMatches(r, q)).length),
    0,
  );
}

export function PolicyEditor({
  policies,
  policyId,
  onSelectPolicy,
  status,
  onStatus,
  reloadKey,
  focus,
}: {
  policies: PolicyOption[];
  policyId?: string;
  onSelectPolicy: (id: string) => void;
  status: CandidateStatus;
  onStatus: (s: CandidateStatus) => void;
  reloadKey: number;
  /** A rule to show, e.g. one picked in the flow tester (a new object each time). */
  focus?: FlowHit;
}) {
  const toast = useToast();
  const [listOpen, setListOpen] = useState(
    () => readSetting(LIST_PANEL_KEY) !== 'collapsed',
  );
  const toggleList = () => {
    writeSetting(LIST_PANEL_KEY, listOpen ? 'collapsed' : 'open');
    setListOpen(!listOpen);
  };
  const [view, setView] = useState<PolicyView | null>(null);
  /** Parent (base) policies, nearest first. Their groups are processed before this policy's. */
  const [parents, setParents] = useState<PolicyView[]>([]);
  const [parentError, setParentError] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [groupId, setGroupId] = useState<string>();
  const [query, setQuery] = useState('');
  const [modal, setModal] = useState<ModalState>(null);
  const resourceMenuItems = useResourceMenuItems();
  // Only the latest load may update the view (switching policies quickly can reorder replies).
  const loadSeq = useRef(0);

  const load = useCallback(async () => {
    if (!policyId) return;
    const seq = ++loadSeq.current;
    setLoading(true);
    setError('');
    setParentError('');
    try {
      const {
        view: v,
        parents: chain,
        parentError,
      } = await loadPolicyChain(policyId);
      if (seq !== loadSeq.current) return;
      if (parentError)
        setParentError(
          `Couldn't load the parent policy ${parentError.name}: ${parentError.message}`,
        );
      setView(v);
      setParents(chain);
      const all = [...v.groups, ...chain.flatMap((p) => p.groups)];
      setGroupId((current) =>
        all.some((g) => sameResourceId(g.group.id, current))
          ? current
          : v.groups[0]?.group.id,
      );
    } catch (err) {
      if (seq !== loadSeq.current) return;
      setError(errorMessage(err));
      setView(null);
      setParents([]);
    } finally {
      if (seq === loadSeq.current) setLoading(false);
    }
  }, [policyId]);

  useEffect(() => {
    load();
  }, [load, reloadKey]);

  // Show the focused rule once its policy has loaded; inherited rules are read-only here.
  const [focusDone, setFocusDone] = useState<FlowHit>();
  useEffect(() => {
    if (!focus || focus === focusDone || !view) return;
    const groups = [...view.groups, ...parents.flatMap((p) => p.groups)];
    if (!groups.some((g) => sameResourceId(g.group.id, focus.groupId))) return;
    setFocusDone(focus);
    setQuery('');
    setGroupId(focus.groupId);
    if (!focus.inherited)
      setModal({
        kind: 'collection',
        collection: focus.collection,
        focusRule: focus.rule,
      });
  }, [focus, focusDone, view, parents]);

  // Picker data (IP Groups, service tags…) for the policy's subscription and region.
  const [lookups, setLookups] = useState<LookupsState>({ loading: false });
  const lookupSub = view?.policy.subscriptionId;
  const lookupRegion = view?.policy.location?.toLowerCase().replace(/\s+/g, '');
  useEffect(() => {
    if (!lookupSub || !lookupRegion) return;
    let cancelled = false;
    setLookups((l) => ({ ...l, loading: true }));
    window.api
      .getRuleLookups(lookupSub, lookupRegion)
      .then(
        (data) => !cancelled && setLookups({ lookups: data, loading: false }),
      )
      .catch(
        (err) =>
          !cancelled &&
          setLookups({
            loading: false,
            lookups: {
              ipGroups: [],
              serviceTags: [],
              fqdnTags: [],
              webCategories: [],
              errors: [errorMessage(err)],
            },
          }),
      );
    return () => {
      cancelled = true;
    };
  }, [lookupSub, lookupRegion, reloadKey]);

  const own = view?.groups.find((g) => sameResourceId(g.group.id, groupId));
  const inheritedFrom = own
    ? undefined
    : parents.find((p) =>
        p.groups.some((g) => sameResourceId(g.group.id, groupId)),
      );
  const current: GroupView | undefined =
    own ??
    inheritedFrom?.groups.find((g) => sameResourceId(g.group.id, groupId));
  /** Inherited groups belong to the parent policy and are edited there. */
  const readOnly = !!inheritedFrom;
  const pendingEntry = useMemo(
    () => status.pending.find((p) => sameResourceId(p.groupId, groupId)),
    [status, groupId],
  );
  const changes = pendingEntry?.changes ?? [];

  /** Stages an edited copy of one of this policy's groups and updates the view. */
  const stageIn = async (
    target: GroupView | undefined,
    mutate: (g: RuleCollectionGroup) => void,
  ) => {
    if (!target || !policyId || readOnlyGroup(target)) return false;
    try {
      const next = structuredClone(target.group);
      mutate(next);
      const st = await window.api.stageGroup(policyId, next);
      onStatus(st);
      const staged = st.pending.some((p) => sameResourceId(p.groupId, next.id));
      setView(
        (v) =>
          v && {
            ...v,
            groups: v.groups.map((g) =>
              sameResourceId(g.group.id, next.id)
                ? {
                    ...g,
                    group: next,
                    staged,
                    // The first edit's starting point is what's in Azure.
                    baseline: g.baseline ?? g.group,
                  }
                : g,
            ),
          },
      );
      return true;
    } catch (err) {
      toast('error', errorMessage(err));
      return false;
    }
  };
  const readOnlyGroup = (g: GroupView) =>
    !view?.groups.some((x) => sameResourceId(x.group.id, g.group.id));
  const stage = (mutate: (g: RuleCollectionGroup) => void) =>
    stageIn(current, mutate);

  const collectionOf = (g: RuleCollectionGroup, name: string) =>
    g.ruleCollections.find((c) => c.name === name);
  const requireCollection = (g: RuleCollectionGroup, name: string) => {
    const c = collectionOf(g, name);
    if (!c) throw new Error(`Collection ${name} no longer exists.`);
    return c;
  };

  const saveCollection = async (col: RuleCollection, originalName?: string) => {
    const ok = await stage((g) => {
      const idx = originalName
        ? g.ruleCollections.findIndex((c) => c.name === originalName)
        : -1;
      if (idx >= 0) g.ruleCollections[idx] = col;
      else g.ruleCollections.push(col);
    });
    if (ok) setModal(null);
    return !!ok;
  };

  const sameName = (a: string, b: string) =>
    a.toLowerCase() === b.toLowerCase();

  /** Puts a rule removed in the draft back where it was. */
  const restoreRule = (collection: string, index: number, rule: FirewallRule) =>
    stage((g) => {
      const c = requireCollection(g, collection);
      if (c.rules.some((r) => sameName(r.name, rule.name)))
        throw new Error(
          `${collection} already has a rule named ${rule.name}. Rename it first.`,
        );
      (c.rules as FirewallRule[]).splice(
        Math.min(index, c.rules.length),
        0,
        rule,
      );
    });

  const restoreCollection = (c: RuleCollection) =>
    stage((g) => {
      if (g.ruleCollections.some((x) => sameName(x.name, c.name)))
        throw new Error(
          `This group already has a collection named ${c.name}. Rename it first.`,
        );
      g.ruleCollections.push(c);
    });

  /** Moves or copies a rule to another collection, possibly in another group of this policy. */
  const transferRule = async (
    from: { collection: string; rule: FirewallRule },
    to: { groupId: string; collection: string; name: string },
    mode: 'move' | 'copy',
  ) => {
    if (!current) return false;
    const copy = { ...structuredClone(from.rule), name: to.name };
    const removeFrom = (g: RuleCollectionGroup) => {
      const c = requireCollection(g, from.collection);
      c.rules = (c.rules as FirewallRule[]).filter(
        (r) => r.name !== from.rule.name,
      ) as never;
    };
    const addTo = (g: RuleCollectionGroup) => {
      const c = requireCollection(g, to.collection);
      if (c.rules.some((r) => sameName(r.name, to.name)))
        throw new Error(
          `${to.collection} already has a rule named ${to.name}.`,
        );
      (c.rules as FirewallRule[]).push(copy);
    };
    let ok: boolean;
    if (sameResourceId(to.groupId, current.group.id)) {
      ok = await stage((g) => {
        if (mode === 'move') removeFrom(g);
        addTo(g);
      });
    } else {
      // Add to the target first, so a failure never loses the rule.
      const target = view?.groups.find((g) =>
        sameResourceId(g.group.id, to.groupId),
      );
      ok = await stageIn(target, addTo);
      if (ok && mode === 'move') ok = await stage(removeFrom);
    }
    if (ok) {
      setModal(null);
      toast(
        'success',
        `${mode === 'move' ? 'Moved' : 'Copied'} ${from.rule.name} to ${to.collection}${to.name !== from.rule.name ? ` as ${to.name}` : ''}.`,
      );
    }
    return ok;
  };

  const revertGroup = async () => {
    if (!current) return;
    try {
      onStatus(await window.api.revert([current.group.id]));
      await load();
      toast(
        'info',
        current.isNew
          ? `Discarded the new group ${current.group.name}.`
          : `Reverted ${current.group.name} to the running configuration.`,
      );
    } catch (err) {
      toast('error', errorMessage(err));
    }
  };

  /** Exports the shown group, or every group the policy applies (inherited ones first), as CSV. */
  const exportCsv = async (scope: 'group' | 'policy') => {
    if (!view) return;
    const byPriority = (a: GroupView, b: GroupView) =>
      a.group.priority - b.group.priority;
    const rows: CsvGroup[] =
      scope === 'group'
        ? current
          ? [
              {
                group: current.group,
                policyName: view.policy.name,
                inheritedFrom: inheritedFrom?.policy.name,
                drafted: current.staged,
              },
            ]
          : []
        : [
            ...[...parents].reverse().flatMap((p) =>
              [...p.groups].sort(byPriority).map((g) => ({
                group: g.group,
                policyName: view.policy.name,
                inheritedFrom: p.policy.name,
              })),
            ),
            ...[...view.groups].sort(byPriority).map((g) => ({
              group: g.group,
              policyName: view.policy.name,
              drafted: g.staged,
            })),
          ];
    if (!rows.length) return;
    try {
      const saved = await window.api.saveCsv(
        csvFileName(
          view.policy.name,
          scope === 'group' ? rows[0].group.name : 'all-groups',
        ),
        groupsToCsv(rows),
      );
      if (saved) toast('success', `Exported to ${saved}`);
    } catch (err) {
      toast('error', errorMessage(err));
    }
  };

  const allGroups = view?.groups.map((g) => g.group) ?? [];
  const createGroup = async (
    name: string,
    priority: number,
    ruleCollections: RuleCollection[],
  ) => {
    if (!policyId) return false;
    const id = `${policyId}/ruleCollectionGroups/${name}`;
    try {
      let st = await window.api.createGroup(policyId, name, priority);
      if (ruleCollections.length) {
        try {
          st = await window.api.stageGroup(policyId, {
            id,
            name,
            priority,
            ruleCollections,
          });
        } catch (err) {
          // The group exists in the draft; keep it and say what went wrong with its contents.
          onStatus(st);
          setGroupId(id);
          await load();
          setModal(null);
          toast(
            'error',
            `Drafted ${name}, but its collections weren't added: ${errorMessage(err)}`,
          );
          return true;
        }
      }
      onStatus(st);
      // Select it before reloading; load() keeps the selection when it still exists.
      setGroupId(id);
      await load();
      setModal(null);
      toast(
        'success',
        ruleCollections.length
          ? `Drafted ${name} with ${ruleCollections.length} ${ruleCollections.length === 1 ? 'collection' : 'collections'}. Commit to create it in Azure.`
          : `Drafted ${name}. Add rule collections, then commit to create it in Azure.`,
      );
      return true;
    } catch (err) {
      toast('error', errorMessage(err));
      return false;
    }
  };

  const q = query.trim().toLowerCase();
  const collections = [...(current?.group.ruleCollections ?? [])]
    .sort((a, b) => a.priority - b.priority)
    .map((c) => ({
      c,
      rules: q
        ? (c.rules as FirewallRule[]).filter((r) => ruleMatches(r, q))
        : (c.rules as FirewallRule[]),
    }))
    .filter(
      ({ c, rules }) =>
        !q || rules.length > 0 || c.name.toLowerCase().includes(q),
    );
  const nextPriority = nextGroupPriority(current?.group.ruleCollections ?? []);
  const transferFrom =
    modal?.kind === 'transfer' && current
      ? collectionOf(current.group, modal.collection)
      : undefined;
  const removed = q
    ? { rules: [], collections: [] }
    : removedItems(
        current?.baseline,
        current?.group ?? {
          id: '',
          name: '',
          priority: 0,
          ruleCollections: [],
        },
      );
  // Search covers every group (including inherited ones), so the sidebar shows where matches are.
  const searchable = [
    ...(view?.groups ?? []),
    ...parents.flatMap((p) => p.groups),
  ];
  const matchCounts = q
    ? new Map(searchable.map((g) => [g.group.id, countMatches(g.group, q)]))
    : undefined;
  const elsewhere = searchable.filter(
    (g) =>
      !sameResourceId(g.group.id, groupId) &&
      (matchCounts?.get(g.group.id) ?? 0) > 0,
  );

  if (!policies.length) {
    return (
      <EmptyState
        icon={<ListTree size={22} />}
        title="No firewall policies to edit"
      >
        None of the firewalls you chose use a Firewall Policy. Firewalls with
        classic rules are read-only here; migrate them to Firewall Policy to
        edit their rules.
      </EmptyState>
    );
  }

  const groupButton = (
    { group, staged, drift }: GroupView,
    inherited: boolean,
  ) => {
    const active = sameResourceId(group.id, groupId);
    return (
      <button
        key={group.id}
        onClick={() => setGroupId(group.id)}
        aria-current={active ? 'true' : undefined}
        className={`flex h-9 w-full items-center gap-3 border-l-2 pl-[14px] pr-3 text-left ${
          active
            ? 'border-azure bg-ink-800 text-fg'
            : `border-transparent hover:bg-ink-850 hover:text-fg ${inherited ? 'text-fg-faint' : 'text-fg-muted'}`
        }`}
        title={
          inherited
            ? `${group.name}: inherited, read-only here. Processed before this policy's groups.`
            : group.name
        }
      >
        <span
          className="w-10 shrink-0 font-mono text-xs text-fg-faint"
          title="Priority"
        >
          {group.priority}
        </span>
        <span className={`flex-1 truncate ${inherited ? 'italic' : ''}`}>
          {group.name}
        </span>
        {matchCounts && (
          <span
            className={`shrink-0 rounded px-1.5 font-mono text-[11px] ${matchCounts.get(group.id) ? 'bg-azure/20 text-azure' : 'text-fg-faint'}`}
            title="Rules matching your search"
          >
            {matchCounts.get(group.id) ?? 0}
          </span>
        )}
        {drift && (
          <AlertTriangle
            size={13}
            className="shrink-0 text-deny"
            aria-label="Changed in Azure since you started editing"
          />
        )}
        {staged &&
          !inherited &&
          (status.pending.find((p) => sameResourceId(p.groupId, group.id))
            ?.committing ? (
            <Loader2
              size={12}
              className="shrink-0 animate-spin text-azure"
              aria-label="Committing to Azure"
            />
          ) : (
            <span
              className="h-2 w-2 shrink-0 rounded-full bg-candidate"
              title="Uncommitted changes"
            />
          ))}
      </button>
    );
  };

  const facts: [string, ReactNode][] = view
    ? [
        ['Tier', view.policy.tier ?? '—'],
        ['Region', view.policy.location ?? '—'],
        ['Threat intelligence', view.policy.threatIntelMode ?? '—'],
        [
          'Inherits from',
          view.policy.basePolicyId ? (
            <span className="truncate" title={view.policy.basePolicyId}>
              {resourceName(view.policy.basePolicyId)}
            </span>
          ) : (
            'Nothing'
          ),
        ],
        [
          'Applied to',
          view.policy.firewallIds.length ? (
            <span className="flex min-w-0 flex-col">
              {view.policy.firewallIds.map((id) => (
                <span key={id} className="truncate" title={id}>
                  {resourceName(id)}
                </span>
              ))}
            </span>
          ) : (
            'No firewalls'
          ),
        ],
      ]
    : [];

  return (
    <RuleLookupsContext.Provider value={lookups}>
      <div className="flex h-full min-h-0">
        <aside
          className={`flex shrink-0 flex-col border-r border-line transition-[width] duration-150 ${listOpen ? 'w-64' : 'w-[52px]'}`}
          aria-label="Policy and rule collection groups"
        >
          {!listOpen && (
            <button
              type="button"
              onClick={toggleList}
              aria-label="Show policy and rule collection groups"
              aria-expanded={false}
              title="Show policy and rule collection groups"
              className="flex h-12 w-full items-center justify-center text-fg-muted hover:bg-ink-800 hover:text-fg"
            >
              <PanelLeftOpen size={18} />
            </button>
          )}
          <div className={listOpen ? 'contents' : 'hidden'}>
            <div className="p-4 pb-3">
              <div className="flex items-center justify-between">
                <span className="label !mb-0">Policy</span>
                <button
                  type="button"
                  onClick={toggleList}
                  aria-label="Hide policy and rule collection groups"
                  aria-expanded
                  title="Hide policy and rule collection groups"
                  className="btn-ghost -mr-2 h-7 w-7 justify-center px-0"
                >
                  <PanelLeftClose size={16} />
                </button>
              </div>
              <div className="mt-1">
                <SelectMenu
                  label="Firewall policy"
                  widthClass="w-full"
                  value={
                    policies.find((p) => sameResourceId(p.id, policyId))?.id
                  }
                  onChange={onSelectPolicy}
                  options={policies.map((p) => ({
                    value: p.id,
                    label: p.name,
                    hint: `${p.firewallNames.length} ${p.firewallNames.length === 1 ? 'firewall' : 'firewalls'}`,
                  }))}
                />
              </div>
              <button
                className="btn-outline mt-3 w-full justify-center"
                disabled={!view || loading}
                onClick={() => setModal({ kind: 'import' })}
              >
                <Upload size={15} /> Import rules from CSV
              </button>
            </div>

            {view && (
              <dl className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 border-b border-line px-4 pb-4 text-xs">
                {facts.map(([k, v]) => (
                  <Fragment key={k}>
                    <dt className="text-fg-faint">{k}</dt>
                    <dd className="min-w-0 text-fg-muted">{v}</dd>
                  </Fragment>
                ))}
              </dl>
            )}

            <div className="flex items-center justify-between py-2 pl-4 pr-2">
              <h2 className="text-sm font-semibold">Rule collection groups</h2>
              <div className="flex">
                <button
                  className="btn-ghost w-8 justify-center px-0"
                  onClick={() => setModal({ kind: 'newGroup' })}
                  disabled={!view}
                  title="New rule collection group"
                  aria-label="New rule collection group"
                >
                  <Plus size={15} />
                </button>
                <button
                  className="btn-ghost w-8 justify-center px-0"
                  onClick={() => exportCsv('policy')}
                  disabled={!view}
                  title="Export all groups to CSV (including inherited ones and your draft)"
                  aria-label="Export all groups to CSV"
                >
                  <Download size={14} />
                </button>
                <button
                  className="btn-ghost w-8 justify-center px-0"
                  onClick={load}
                  title="Reload from Azure"
                  aria-label="Reload from Azure"
                >
                  <RefreshCw
                    size={14}
                    className={loading ? 'animate-spin' : ''}
                  />
                </button>
              </div>
            </div>
            <nav
              aria-label="Rule collection groups"
              className="min-h-0 flex-1 overflow-y-auto pb-3"
            >
              {view && (parents.length > 0 || view.groups.length > 0) && (
                <p className="px-4 pb-2 text-[11px] leading-4 text-fg-faint">
                  Azure checks DNAT, then Network, then Application rules;
                  {parents.length > 0 && ' inherited groups first,'} groups and
                  collections by priority. First match wins.
                </p>
              )}
              {view?.groups.map((g) => groupButton(g, false))}
              {view && !view.groups.length && (
                <p className="px-4 py-3 text-sm text-fg-faint">
                  No groups yet.{' '}
                  <button
                    className="text-azure hover:underline"
                    onClick={() => setModal({ kind: 'newGroup' })}
                  >
                    Create one
                  </button>
                </p>
              )}
              {parents.map((p) => (
                <div key={p.policy.id} className="mt-3">
                  <h3
                    className="flex items-center gap-1.5 px-4 pb-1 text-xs font-semibold text-fg-muted"
                    title="Inherited groups are processed before this policy's, whatever their priority."
                  >
                    <Lock size={11} /> Inherited from {p.policy.name}
                  </h3>
                  {p.groups.map((g) => groupButton(g, true))}
                  {!p.groups.length && (
                    <p className="px-4 py-1 text-xs text-fg-faint">
                      No rule collection groups.
                    </p>
                  )}
                </div>
              ))}
              {parentError && (
                <p className="mx-4 mt-3 border-l-2 border-candidate bg-candidate/10 px-2 py-1 text-xs text-fg-muted">
                  {parentError} Its rules are processed first but aren't shown.
                </p>
              )}
            </nav>
          </div>
        </aside>

        <section className="flex min-w-0 flex-1 flex-col">
          {loading && !view ? (
            <div className="flex flex-1 items-center justify-center">
              <QuipSpinner topic="policy" />
            </div>
          ) : error ? (
            <div className="m-6 border-l-2 border-deny bg-deny/10 p-4 text-sm">
              <p className="font-semibold">Couldn't load this policy.</p>
              <p className="mt-1 text-fg-muted">{error}</p>
            </div>
          ) : !current ? (
            view && !view.groups.length ? (
              <EmptyState
                icon={<Layers size={22} />}
                title="This policy has no rule collection groups"
              >
                <p>
                  Rules live in rule collections, and rule collections live in
                  groups. Create a group to start adding rules.
                </p>
                <button
                  className="btn-primary mt-4"
                  onClick={() => setModal({ kind: 'newGroup' })}
                >
                  <Plus size={15} /> Create rule collection group
                </button>
              </EmptyState>
            ) : (
              <EmptyState
                icon={<Layers size={22} />}
                title="Choose a rule collection group"
              />
            )
          ) : (
            <>
              <div className="flex items-end gap-3 border-b border-line px-6 pb-4 pt-5">
                <div className="min-w-0 flex-1">
                  <h1
                    className="flex items-center gap-2 text-xl font-semibold"
                    title={current.group.name}
                  >
                    <span className="truncate">{current.group.name}</span>
                    {current.isNew && (
                      <Badge
                        tone="candidate"
                        title="Drafted in EZ AzFW Manager; created in Azure when you commit."
                      >
                        New
                      </Badge>
                    )}
                    {readOnly && (
                      <Badge tone="neutral" title="Edit it in its own policy.">
                        <Lock size={11} /> Inherited
                      </Badge>
                    )}
                  </h1>
                  <p className="mt-1 text-sm text-fg-muted">
                    Priority {current.group.priority}.
                    {readOnly ? (
                      <span>
                        {' '}
                        From {inheritedFrom!.policy.name}; processed before this
                        policy's groups.{' '}
                        {policies.some((p) =>
                          sameResourceId(p.id, inheritedFrom!.policy.id),
                        ) && (
                          <button
                            className="text-azure hover:underline"
                            onClick={() =>
                              onSelectPolicy(inheritedFrom!.policy.id)
                            }
                          >
                            Open {inheritedFrom!.policy.name} to edit it
                          </button>
                        )}
                      </span>
                    ) : current.isNew ? (
                      <span className="text-candidate">
                        {' '}
                        Not in Azure yet: commit to create it.
                      </span>
                    ) : (
                      current.staged &&
                      !pendingEntry?.committing && (
                        <span className="text-candidate">
                          {' '}
                          {changes.length} uncommitted{' '}
                          {changes.length === 1 ? 'change' : 'changes'}.
                        </span>
                      )
                    )}
                  </p>
                </div>
                <div className="relative w-60">
                  <Search
                    size={14}
                    className="absolute left-2.5 top-[9px] text-fg-faint"
                  />
                  <input
                    className="input pl-8"
                    aria-label="Filter rules"
                    placeholder="Search all groups: name, IP, port…"
                    title="Searches every group in this policy. IPs also find the CIDRs and ranges that contain them; ports find the ranges that cover them."
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                  />
                </div>
                {!readOnly && (
                  <button
                    className="btn-outline"
                    onClick={() => setModal({ kind: 'collection' })}
                  >
                    <Plus size={15} /> Add rule collection
                  </button>
                )}
                {current.staged && !readOnly && (
                  <button className="btn-ghost" onClick={revertGroup}>
                    <Undo2 size={15} />{' '}
                    {current.isNew ? 'Discard new group' : 'Discard changes'}
                  </button>
                )}
                <EllipsisMenu
                  label="Group actions"
                  items={[
                    ...(readOnly
                      ? []
                      : [
                          {
                            label: 'Change priority…',
                            icon: <Pencil size={14} />,
                            onSelect: () => setModal({ kind: 'group' }),
                          },
                        ]),
                    ...(current.isNew
                      ? []
                      : resourceMenuItems(current.group.id)),
                    { label: '', divider: true },
                    {
                      label: 'Export this group to CSV…',
                      icon: <Download size={14} />,
                      onSelect: () => exportCsv('group'),
                    },
                    {
                      label: 'Export all groups to CSV…',
                      icon: <Download size={14} />,
                      onSelect: () => exportCsv('policy'),
                    },
                  ]}
                />
              </div>

              {current.drift && (
                <div className="mx-6 mt-4 flex items-start gap-2 border-l-2 border-deny bg-deny/10 px-3 py-2 text-sm">
                  <AlertTriangle
                    size={15}
                    className="mt-0.5 shrink-0 text-deny"
                  />
                  <div>
                    <p>
                      This group was changed in Azure in the same places you
                      edited, so it can't be committed. Discard your changes to
                      this group to load the latest version, then make them
                      again.
                    </p>
                    {current.conflicts?.length ? (
                      <ul className="mt-1 list-disc pl-5 text-xs text-fg-muted">
                        {current.conflicts.map((c) => (
                          <li key={c}>{c}</li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                </div>
              )}

              <div className="min-h-0 flex-1 overflow-auto">
                {!collections.length && !removed.collections.length ? (
                  <EmptyState
                    icon={<ListTree size={22} />}
                    title={
                      q
                        ? 'No rules match your filter'
                        : 'This group has no rule collections'
                    }
                  >
                    {q ? (
                      elsewhere.length ? (
                        <span>
                          Matches in:{' '}
                          {elsewhere.map((g, i) => (
                            <Fragment key={g.group.id}>
                              {i > 0 && ', '}
                              <button
                                className="text-azure hover:underline"
                                onClick={() => setGroupId(g.group.id)}
                              >
                                {g.group.name} ({matchCounts?.get(g.group.id)})
                              </button>
                            </Fragment>
                          ))}
                        </span>
                      ) : (
                        'Nothing in this policy matches. Try a rule name, address or port.'
                      )
                    ) : (
                      'Add a rule collection to start writing rules.'
                    )}
                  </EmptyState>
                ) : (
                  <table className="w-full table-fixed text-left text-sm">
                    <thead className="sticky top-0 z-10 bg-ink-900 text-xs text-fg-muted">
                      <tr className="border-b border-line">
                        <th className="w-7" aria-label="Change" />
                        <th className="w-48 px-3 py-2 font-medium">Name</th>
                        <th className="w-24 px-3 py-2 font-medium">Type</th>
                        <th className="px-3 py-2 font-medium">Source</th>
                        <th className="w-32 px-3 py-2 font-medium">Service</th>
                        <th className="px-3 py-2 font-medium">Destination</th>
                        <th className="w-36 px-3 py-2 font-medium">Action</th>
                        <th className="w-12 pr-4" />
                      </tr>
                    </thead>
                    <tbody>
                      {collections.map(({ c, rules }) => {
                        const colMark = changeKindOf(changes, c.name);
                        const colModified = changes.some(
                          (x) =>
                            x.target === 'collection' &&
                            x.collection === c.name &&
                            x.kind === 'modified',
                        );
                        const removedHere = removed.rules.filter(
                          (x) => x.collection === c.name,
                        );
                        return (
                          <Fragment key={c.name}>
                            <tr className="border-b border-line bg-ink-850">
                              <td className="text-center font-mono text-base font-bold text-candidate">
                                <DiffMark
                                  kind={
                                    colMark ??
                                    (colModified ? 'modified' : undefined)
                                  }
                                />
                              </td>
                              <td colSpan={6} className="py-2 pr-3">
                                <div className="flex items-center gap-3">
                                  {readOnly ? (
                                    <span className="truncate font-semibold text-fg">
                                      {c.name}
                                    </span>
                                  ) : (
                                    <button
                                      type="button"
                                      className="truncate font-semibold text-fg hover:text-azure hover:underline"
                                      title={`Edit ${c.name} and its rules`}
                                      onClick={() =>
                                        setModal({
                                          kind: 'collection',
                                          collection: c.name,
                                        })
                                      }
                                    >
                                      {c.name}
                                    </button>
                                  )}
                                  <ActionMark action={c.action.type} />
                                  <span className="text-fg-muted">
                                    {collectionKindOf(c)} collection, priority{' '}
                                    {c.priority}, {c.rules.length}{' '}
                                    {c.rules.length === 1 ? 'rule' : 'rules'}
                                  </span>
                                  {!readOnly && (
                                    <button
                                      type="button"
                                      className="btn-ghost ml-auto h-7 px-2 text-xs"
                                      onClick={() =>
                                        setModal({
                                          kind: 'collection',
                                          collection: c.name,
                                          addRule: true,
                                        })
                                      }
                                    >
                                      <Plus size={13} /> Add rule
                                    </button>
                                  )}
                                </div>
                              </td>
                              <td className="py-1.5 pr-4">
                                {!readOnly && (
                                  <EllipsisMenu
                                    label={`Actions for ${c.name}`}
                                    items={[
                                      {
                                        label: 'Edit collection and rules…',
                                        icon: <Pencil size={14} />,
                                        onSelect: () =>
                                          setModal({
                                            kind: 'collection',
                                            collection: c.name,
                                          }),
                                      },
                                      { label: '', divider: true },
                                      {
                                        label: 'Delete collection…',
                                        icon: <Trash2 size={14} />,
                                        danger: true,
                                        onSelect: () =>
                                          setModal({
                                            kind: 'confirm',
                                            title: `Delete ${c.name}?`,
                                            message: `The collection and its ${c.rules.length} ${c.rules.length === 1 ? 'rule' : 'rules'} are removed from your draft; you can undo this until you commit.`,
                                            action: () =>
                                              stage((g) => {
                                                g.ruleCollections =
                                                  g.ruleCollections.filter(
                                                    (x) => x.name !== c.name,
                                                  );
                                              }),
                                          }),
                                      },
                                    ]}
                                  />
                                )}
                              </td>
                            </tr>
                            {rules.map((r, ri) => {
                              const lastRule =
                                ri === rules.length - 1 && !removedHere.length;
                              const mark = changeKindOf(
                                changes,
                                c.name,
                                r.name,
                              );
                              return (
                                <tr
                                  key={r.name}
                                  className={`border-b border-line/60 align-top ${readOnly ? '' : 'cursor-pointer'} ${mark ? 'bg-candidate/[0.06]' : 'hover:bg-ink-850'}`}
                                  title={readOnly ? undefined : 'Click to edit'}
                                  onClick={() =>
                                    !readOnly &&
                                    setModal({
                                      kind: 'collection',
                                      collection: c.name,
                                      focusRule: r.name,
                                    })
                                  }
                                >
                                  <td className="py-2 text-center font-mono text-base font-bold leading-[18px] text-candidate">
                                    <DiffMark kind={mark} />
                                  </td>
                                  <td className="relative py-2 pl-[30px] pr-3">
                                    <TreeLines
                                      depth={1}
                                      last={lastRule}
                                      left={12}
                                      branchAt={18}
                                    />
                                    <Truncate className="font-medium">
                                      {r.name}
                                    </Truncate>
                                    {r.description && (
                                      <Truncate className="text-xs text-fg-faint">
                                        {r.description}
                                      </Truncate>
                                    )}
                                  </td>
                                  <td className="px-3 py-2 text-fg-muted">
                                    {r.ruleType === 'NetworkRule'
                                      ? 'Network'
                                      : r.ruleType === 'ApplicationRule'
                                        ? 'Application'
                                        : 'DNAT'}
                                  </td>
                                  <td className="px-3 py-2">
                                    <ValueList values={sourceOf(r)} />
                                  </td>
                                  <td className="px-3 py-2">
                                    <ValueList values={serviceOf(r)} max={2} />
                                  </td>
                                  <td className="px-3 py-2">
                                    <ValueList values={destinationOf(r)} />
                                  </td>
                                  <td className="px-3 py-2">
                                    {r.ruleType === 'NatRule' ? (
                                      <span
                                        className="netval block break-all"
                                        title={`${r.translatedAddress ?? r.translatedFqdn}:${r.translatedPort}`}
                                      >
                                        to{' '}
                                        {r.translatedAddress ??
                                          r.translatedFqdn}
                                        :{r.translatedPort}
                                      </span>
                                    ) : (
                                      <ActionMark action={c.action.type} />
                                    )}
                                  </td>
                                  <td
                                    className="py-1.5 pr-4"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    {!readOnly && (
                                      <EllipsisMenu
                                        label={`Actions for ${r.name}`}
                                        items={[
                                          {
                                            label: 'Edit rule…',
                                            icon: <Pencil size={14} />,
                                            onSelect: () =>
                                              setModal({
                                                kind: 'collection',
                                                collection: c.name,
                                                focusRule: r.name,
                                              }),
                                          },
                                          {
                                            label: 'Duplicate here…',
                                            icon: <Copy size={14} />,
                                            onSelect: () =>
                                              setModal({
                                                kind: 'collection',
                                                collection: c.name,
                                                duplicateRule: r.name,
                                              }),
                                          },
                                          {
                                            label: 'Move to…',
                                            icon: <ArrowRightLeft size={14} />,
                                            onSelect: () =>
                                              setModal({
                                                kind: 'transfer',
                                                collection: c.name,
                                                rule: r,
                                                mode: 'move',
                                              }),
                                          },
                                          {
                                            label: 'Copy to…',
                                            icon: <Copy size={14} />,
                                            onSelect: () =>
                                              setModal({
                                                kind: 'transfer',
                                                collection: c.name,
                                                rule: r,
                                                mode: 'copy',
                                              }),
                                          },
                                          { label: '', divider: true },
                                          {
                                            label: 'Delete rule',
                                            icon: <Trash2 size={14} />,
                                            danger: true,
                                            // Deleting is undoable until commit, so no confirmation.
                                            onSelect: () =>
                                              stage((g) => {
                                                const col = requireCollection(
                                                  g,
                                                  c.name,
                                                );
                                                col.rules = (
                                                  col.rules as FirewallRule[]
                                                ).filter(
                                                  (x) => x.name !== r.name,
                                                ) as never;
                                              }),
                                          },
                                        ]}
                                      />
                                    )}
                                  </td>
                                </tr>
                              );
                            })}
                            {removedHere.map(({ rule, index }, ri) => (
                              <tr
                                key={`removed:${rule.name}`}
                                className="border-b border-line/60 bg-deny/[0.05] align-top text-fg-faint"
                              >
                                <td className="py-2 text-center font-mono text-base font-bold leading-[18px] text-deny">
                                  <DiffMark kind="removed" />
                                </td>
                                <td className="relative py-2 pl-[30px] pr-3">
                                  <TreeLines
                                    depth={1}
                                    last={ri === removedHere.length - 1}
                                    left={12}
                                    branchAt={18}
                                  />
                                  <span className="block truncate font-medium line-through">
                                    {rule.name}
                                  </span>
                                  <span className="text-xs">
                                    Removed in your draft
                                  </span>
                                </td>
                                <td colSpan={5} className="px-3 py-2">
                                  <span className="block truncate font-mono text-xs line-through">
                                    {[
                                      sourceOf(rule).join(', '),
                                      serviceOf(rule).join(', '),
                                      destinationOf(rule).join(', '),
                                    ]
                                      .filter(Boolean)
                                      .join('  →  ')}
                                  </span>
                                </td>
                                <td className="py-1.5 pr-4">
                                  <button
                                    className="btn-ghost h-7 px-2 text-xs"
                                    onClick={() =>
                                      restoreRule(c.name, index, rule)
                                    }
                                  >
                                    <Undo2 size={13} /> Undo
                                  </button>
                                </td>
                              </tr>
                            ))}
                            {!rules.length && !removedHere.length && (
                              <tr className="border-b border-line/60">
                                <td colSpan={1} />
                                <td
                                  colSpan={7}
                                  className="px-3 py-2 text-sm text-fg-faint"
                                >
                                  No rules yet.{' '}
                                  {!readOnly && (
                                    <button
                                      className="text-azure hover:underline"
                                      onClick={() =>
                                        setModal({
                                          kind: 'collection',
                                          collection: c.name,
                                          addRule: true,
                                        })
                                      }
                                    >
                                      Add a rule
                                    </button>
                                  )}
                                </td>
                              </tr>
                            )}
                          </Fragment>
                        );
                      })}
                      {removed.collections.map((c) => (
                        <tr
                          key={`removed-collection:${c.name}`}
                          className="border-b border-line bg-deny/[0.05] text-fg-faint"
                        >
                          <td className="text-center font-mono text-base font-bold text-deny">
                            <DiffMark kind="removed" />
                          </td>
                          <td colSpan={6} className="py-2 pr-3">
                            <span className="font-semibold line-through">
                              {c.name}
                            </span>{' '}
                            <span className="text-xs">
                              {collectionKindOf(c)} collection with{' '}
                              {c.rules.length}{' '}
                              {c.rules.length === 1 ? 'rule' : 'rules'}, removed
                              in your draft
                            </span>
                          </td>
                          <td className="py-1.5 pr-4">
                            <button
                              className="btn-ghost h-7 px-2 text-xs"
                              onClick={() => restoreCollection(c)}
                            >
                              <Undo2 size={13} /> Undo
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </>
          )}
        </section>

        {modal?.kind === 'collection' && current && (
          <CollectionEditor
            collection={
              modal.collection
                ? collectionOf(current.group, modal.collection)
                : undefined
            }
            groupName={current.group.name}
            others={current.group.ruleCollections.filter(
              (c) => c.name !== modal.collection,
            )}
            suggestedPriority={nextPriority}
            focusRule={modal.focusRule}
            addRule={modal.addRule}
            duplicateRule={modal.duplicateRule}
            onClose={() => setModal(null)}
            onSave={(c) => saveCollection(c, modal.collection)}
          />
        )}
        {modal?.kind === 'group' && current && (
          <GroupPriorityEditor
            name={current.group.name}
            priority={current.group.priority}
            onClose={() => setModal(null)}
            onSave={async (p) =>
              (await stage((g) => {
                g.priority = p;
              })) && setModal(null)
            }
          />
        )}
        {modal?.kind === 'newGroup' && view && (
          <NewGroupEditor
            policyName={view.policy.name}
            existing={allGroups}
            suggestedPriority={nextGroupPriority(allGroups)}
            onClose={() => setModal(null)}
            onSave={createGroup}
          />
        )}
        {modal?.kind === 'import' && view && (
          <ImportRules
            view={view}
            parents={parents}
            parentError={parentError}
            onClose={() => setModal(null)}
            onRefresh={load}
            onImported={async (result) => {
              onStatus(result.status);
              setGroupId(result.groupIds[0]);
              setQuery('');
              await load();
              setModal(null);
              toast(
                'success',
                `Imported ${result.ruleCount} ${result.ruleCount === 1 ? 'rule' : 'rules'} to the draft${result.skippedCount ? `; skipped ${result.skippedCount}` : ''}. Review and commit to apply them in Azure.`,
              );
            }}
          />
        )}
        {modal?.kind === 'transfer' && current && view && transferFrom && (
          <TransferRuleDialog
            view={view}
            fromGroupId={current.group.id}
            fromCollection={transferFrom}
            rule={modal.rule}
            mode={modal.mode}
            onClose={() => setModal(null)}
            onSubmit={(to, mode) =>
              transferRule(
                { collection: modal.collection, rule: modal.rule },
                to,
                mode,
              )
            }
          />
        )}
        {modal?.kind === 'confirm' && (
          <ConfirmModal
            title={modal.title}
            message={modal.message}
            onCancel={() => setModal(null)}
            onConfirm={() => {
              modal.action();
              setModal(null);
            }}
          />
        )}
      </div>
    </RuleLookupsContext.Provider>
  );
}
