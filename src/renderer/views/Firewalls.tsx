import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  ListTree,
  ChevronRight,
  KeyRound,
  Plus,
  Server,
  SlidersHorizontal,
  Settings2,
} from 'lucide-react';
import { EllipsisMenu } from '../components/Dropdown';
import { Segmented } from '../components/Segmented';
import { useResourceMenuItems } from '../components/resourceMenu';
import { FilterBar } from '../components/FilterBar';
import { TreeLines, treeIndent } from '../components/TreeLines';
import {
  matchesFilters,
  tagPairs,
  useStoredFilters,
  type FilterValues,
} from '../filters';
import { EmptyState, StatusDot } from '../components/ui';
import { resourceName } from '../../shared/resourceId';
import type { CandidateStatus, FirewallSummary } from '../../shared/types';
import {
  allocationErrors,
  type FirewallConfiguration,
  type FirewallPowerState,
} from '../../shared/resourceSettings';
import { errorMessage, useToast } from '../components/Toast';
import { FirewallSettings } from './FirewallSettings';

function FirewallPowerButtons({
  firewall,
  status,
  reloadKey,
  onStatus,
  onNeedAllocation,
  onConfiguration,
}: {
  firewall: FirewallSummary;
  status: CandidateStatus;
  reloadKey: number;
  onStatus: (status: CandidateStatus) => void;
  onNeedAllocation: () => void;
  onConfiguration: (id: string, value: FirewallConfiguration) => void;
}) {
  const [configuration, setConfiguration] = useState<FirewallConfiguration>();
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const toast = useToast();
  const working = useRef(false);
  const draft = status.pending.find(
    (p) =>
      p.target === 'firewall' &&
      p.groupId.toLowerCase() === firewall.id.toLowerCase(),
  );
  const mode =
    draft?.firewallConfiguration?.after.powerState ??
    configuration?.powerState ??
    'Unknown';
  const [value, setValue] = useState<FirewallPowerState>(mode);
  useEffect(() => {
    setValue(mode);
  }, [mode]);
  useEffect(() => {
    let cancelled = false;
    setError('');
    window.api
      .getFirewallConfiguration(firewall.id)
      .then((config) => {
        if (!cancelled) {
          setConfiguration(config);
          onConfiguration(firewall.id, config);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err));
      });
    return () => {
      cancelled = true;
    };
  }, [firewall.id, reloadKey, onConfiguration]);
  const busy =
    saving ||
    status.pending.some(
      (p) =>
        p.committing &&
        (p.groupId.toLowerCase() === firewall.id.toLowerCase() ||
          (!!firewall.policyId &&
            p.policyId.toLowerCase() === firewall.policyId.toLowerCase())),
    );
  const stage = async (goal: FirewallPowerState) => {
    if (
      busy ||
      working.current ||
      goal === mode ||
      goal === 'Unknown' ||
      !configuration
    )
      return;
    if (
      goal === 'Running' &&
      (!configuration.allocation ||
        allocationErrors(configuration.allocation, firewall.skuTier ?? '')
          .length)
    ) {
      onNeedAllocation();
      return;
    }
    working.current = true;
    setSaving(true);
    setValue(goal);
    try {
      onStatus(
        await window.api.stageFirewallPower(
          firewall.id,
          goal,
          configuration.allocation,
        ),
      );
    } catch (err) {
      setValue(mode);
      toast('error', errorMessage(err));
    } finally {
      try {
        const fresh = await window.api.getFirewallConfiguration(firewall.id);
        setConfiguration(fresh);
        onConfiguration(firewall.id, fresh);
      } catch (err) {
        setError(errorMessage(err));
      }
      working.current = false;
      setSaving(false);
    }
  };
  if (error)
    return (
      <span className="text-deny text-xs" title={error} role="status">
        Power unavailable
      </span>
    );
  if (!configuration)
    return <span className="text-xs text-fg-faint">Loading state…</span>;
  if (configuration.powerState === 'Unknown')
    return (
      <span
        className="text-xs text-fg-faint"
        title="Azure is updating the firewall or has not returned a settled allocation state. Refresh before starting or stopping."
      >
        Updating / unknown
      </span>
    );
  return (
    <div
      className="inline-flex rounded bg-ink-900"
      title={`${draft ? `Draft: ${mode}. ` : ''}Azure: ${configuration.powerState}. Start/stop takes effect only after commit.`}
    >
      <Segmented
        label={`Power for ${firewall.name}`}
        value={value}
        options={(['Stopped', 'Running'] as const).map((option) => ({
          value: option,
          label:
            option === configuration.powerState
              ? option
              : option === 'Stopped'
                ? 'Stop'
                : 'Start',
          disabled: busy,
        }))}
        onChange={(next) => void stage(next)}
        activeClass={() =>
          draft ? 'bg-candidate text-ink-950' : 'bg-azure text-ink-950'
        }
      />
    </div>
  );
}

const FIREWALL_FILTERS: FilterValues<FirewallSummary> = {
  name: (f) => [f.name],
  subscription: (f) => [f.subscriptionName ?? f.subscriptionId],
  resourceGroup: (f) => [f.resourceGroup],
  location: (f) => [f.location],
  tag: (f) => tagPairs(f.tags),
};

/** The firewalls being managed, grouped by subscription, with portal-style filters. */
export function Firewalls({
  firewalls,
  onOpenPolicy,
  onChooseFirewalls,
  onDeploy,
  status,
  onStatus,
  reloadKey,
}: {
  firewalls: FirewallSummary[];
  /** Opens a policy's rules. */
  onOpenPolicy: (policyId: string) => void;
  onChooseFirewalls: () => void;
  onDeploy: () => void;
  status: CandidateStatus;
  onStatus: (status: CandidateStatus) => void;
  reloadKey: number;
}) {
  const { filters, setFilter, clear, active } = useStoredFilters(
    'ez-azfw-ruleman.firewallFilters',
  );
  const resourceMenuItems = useResourceMenuItems();
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [settings, setSettings] = useState<{ id: string; start?: boolean }>();
  const [configurations, setConfigurations] = useState<
    Record<string, FirewallConfiguration>
  >({});
  const recordConfiguration = useCallback(
    (id: string, value: FirewallConfiguration) =>
      setConfigurations((old) => ({ ...old, [id]: value })),
    [],
  );
  const shown = useMemo(
    () => firewalls.filter((f) => matchesFilters(f, filters, FIREWALL_FILTERS)),
    [firewalls, filters],
  );
  const bySubscription = useMemo(() => {
    const map = new Map<string, FirewallSummary[]>();
    for (const f of shown) {
      const key = f.subscriptionId.toLowerCase();
      map.set(key, [...(map.get(key) ?? []), f]);
    }
    return [...map.values()]
      .map((list) => ({
        id: list[0].subscriptionId,
        name: list[0].subscriptionName ?? list[0].subscriptionId,
        list: list.sort((a, b) => a.name.localeCompare(b.name)),
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [shown]);
  const subscriptions = new Set(firewalls.map((f) => f.subscriptionId)).size;
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-end gap-3 border-b border-line px-6 pb-4 pt-5">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-semibold">Firewalls</h1>
          <p className="mt-1 text-sm text-fg-muted">
            {firewalls.length
              ? `Managing ${firewalls.length} ${firewalls.length === 1 ? 'firewall' : 'firewalls'} in ${subscriptions} ${subscriptions === 1 ? 'subscription' : 'subscriptions'}.`
              : 'No firewalls are being managed yet.'}
          </p>
        </div>
        <button className="btn-outline" onClick={onChooseFirewalls}>
          <SlidersHorizontal size={15} /> Choose firewalls to show
        </button>
        <button className="btn-outline" onClick={onDeploy}>
          <Plus size={15} /> Deploy firewall
        </button>
      </div>
      <FilterBar
        items={firewalls}
        values={FIREWALL_FILTERS}
        filters={filters}
        onChange={setFilter}
        onClear={clear}
        active={active}
        summary={`${active ? `Showing ${shown.length} of ${firewalls.length}` : `${firewalls.length} ${firewalls.length === 1 ? 'firewall' : 'firewalls'}`} in ${bySubscription.length} ${bySubscription.length === 1 ? 'subscription' : 'subscriptions'}`}
      />
      {!firewalls.length ? (
        <EmptyState icon={<Server size={22} />} title="No firewalls chosen yet">
          Choose which of your Azure Firewalls to show here, or deploy a new
          one.
          <div className="mt-4 flex justify-center gap-2">
            <button className="btn-primary" onClick={onChooseFirewalls}>
              <SlidersHorizontal size={15} /> Choose firewalls to show
            </button>
          </div>
        </EmptyState>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full min-w-[1400px] table-fixed text-left text-sm">
            <thead className="sticky top-0 z-10 bg-ink-900 text-xs text-fg-muted">
              <tr className="border-b border-line">
                <th className="py-2 pl-6 pr-3 font-medium">Name</th>
                <th className="w-40 px-3 py-2 font-medium">State</th>
                <th className="w-52 px-3 py-2 font-medium">Policy</th>
                <th className="w-32 px-3 py-2 font-medium">Private IP</th>
                <th className="w-44 px-3 py-2 font-medium">Resource group</th>
                <th className="w-24 px-3 py-2 font-medium">Tier</th>
                <th className="w-36 px-3 py-2 font-medium">Deployed in</th>
                <th className="w-40 px-3 py-2 font-medium">Location</th>
                <th className="w-12 py-2 pr-4" />
              </tr>
            </thead>
            <tbody>
              {bySubscription.map(({ id, name, list }) => {
                const isCollapsed = collapsed.has(id);
                return (
                  <Fragment key={id}>
                    <tr className="border-b border-line bg-ink-850">
                      <td colSpan={9} className="p-0">
                        <button
                          type="button"
                          aria-expanded={!isCollapsed}
                          className="flex w-full items-center gap-2 py-2 pl-6 pr-3 text-left hover:bg-ink-800"
                          onClick={() =>
                            setCollapsed((c) => {
                              const next = new Set(c);
                              if (next.has(id)) next.delete(id);
                              else next.add(id);
                              return next;
                            })
                          }
                        >
                          <ChevronRight
                            size={14}
                            className={`text-fg-muted transition-transform ${isCollapsed ? '' : 'rotate-90'}`}
                          />
                          <KeyRound size={14} className="text-fg-muted" />
                          <span className="font-semibold">{name}</span>
                          {name !== id && (
                            <span className="font-mono text-xs text-fg-faint">
                              ({id})
                            </span>
                          )}
                          <span className="text-fg-muted">
                            {list.length}{' '}
                            {list.length === 1 ? 'firewall' : 'firewalls'}
                          </span>
                        </button>
                      </td>
                    </tr>
                    {!isCollapsed &&
                      list.map((f, i) => (
                        <tr
                          key={f.id}
                          className="border-b border-line/60 hover:bg-ink-850"
                        >
                          <td
                            className="relative py-2 pr-3"
                            style={{ paddingLeft: treeIndent(1) }}
                          >
                            <TreeLines depth={1} last={i === list.length - 1} />
                            <div className="flex items-center gap-2">
                              <StatusDot state={f.provisioningState} />
                              <button
                                className="truncate"
                                title={[f.name, ...tagPairs(f.tags)].join('\n')}
                                onClick={() => setSettings({ id: f.id })}
                              >
                                {f.name}
                              </button>
                              {status.pending.some(
                                (p) =>
                                  p.target === 'firewall' &&
                                  p.groupId.toLowerCase() ===
                                    f.id.toLowerCase(),
                              ) && (
                                <span className="shrink-0 text-xs text-candidate">
                                  Uncommitted
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-3 py-2">
                            <FirewallPowerButtons
                              firewall={f}
                              status={status}
                              reloadKey={reloadKey}
                              onStatus={onStatus}
                              onConfiguration={recordConfiguration}
                              onNeedAllocation={() =>
                                setSettings({ id: f.id, start: true })
                              }
                            />
                          </td>
                          <td className="truncate px-3 py-2">
                            {f.policyId ? (
                              <button
                                className="truncate text-azure hover:underline"
                                title={`Edit the rules in ${resourceName(f.policyId)}`}
                                onClick={() => onOpenPolicy(f.policyId!)}
                              >
                                {resourceName(f.policyId)}
                              </button>
                            ) : (
                              <span
                                className="text-fg-faint"
                                title="This firewall uses classic rules, which can't be edited here. Migrate it to Firewall Policy to manage its rules."
                              >
                                Classic rules
                              </span>
                            )}
                          </td>
                          <td className="netval px-3 py-2">
                            {configurations[f.id]
                              ? (configurations[f.id].privateIp ?? '—')
                              : (f.privateIp ?? '—')}
                          </td>
                          <td
                            className="truncate px-3 py-2 text-fg-muted"
                            title={f.resourceGroup}
                          >
                            {f.resourceGroup}
                          </td>
                          <td className="px-3 py-2 text-fg-muted">
                            {f.skuTier ?? '—'}
                          </td>
                          <td className="px-3 py-2 text-fg-muted">
                            {f.skuName === 'AZFW_Hub'
                              ? 'Virtual WAN hub'
                              : 'Virtual network'}
                          </td>
                          <td className="px-3 py-2 text-fg-muted">
                            {f.location}
                          </td>
                          <td className="py-1.5 pr-4">
                            <EllipsisMenu
                              label={`Actions for ${f.name}`}
                              items={[
                                {
                                  label: 'Edit firewall settings',
                                  icon: <Settings2 size={14} />,
                                  onSelect: () => setSettings({ id: f.id }),
                                },
                                ...(f.policyId
                                  ? [
                                      {
                                        label: 'Edit rules',
                                        icon: <ListTree size={14} />,
                                        onSelect: () =>
                                          onOpenPolicy(f.policyId!),
                                      },
                                    ]
                                  : []),
                                ...resourceMenuItems(f.id),
                              ]}
                            />
                          </td>
                        </tr>
                      ))}
                  </Fragment>
                );
              })}
              {!shown.length && (
                <tr>
                  <td
                    colSpan={9}
                    className="px-6 py-6 text-center text-fg-muted"
                  >
                    No firewalls match these filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      {settings && (
        <FirewallSettings
          firewallId={settings.id}
          startRequested={settings.start}
          onStatus={onStatus}
          onClose={() => setSettings(undefined)}
        />
      )}
    </div>
  );
}
