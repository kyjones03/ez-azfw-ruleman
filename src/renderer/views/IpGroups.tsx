import { Fragment, useEffect, useMemo, useState } from 'react';
import { ChevronRight, KeyRound, Network, Plus } from 'lucide-react';
import { FilterBar } from '../components/FilterBar';
import { EllipsisMenu } from '../components/Dropdown';
import { Modal } from '../components/Modal';
import { useResourceMenuItems } from '../components/resourceMenu';
import { TreeLines, treeIndent } from '../components/TreeLines';
import {
  EmptyState,
  Notice,
  Spinner,
  StatusDot,
  ValueList,
} from '../components/ui';
import { errorMessage, useToast } from '../components/Toast';
import {
  matchesFilters,
  tagPairs,
  useStoredFilters,
  type FilterValues,
} from '../filters';
import type { IpGroupInfo } from '../../shared/types';
import { CreateIpGroup } from './CreateIpGroup';

const IP_GROUP_FILTERS: FilterValues<IpGroupInfo> = {
  name: (g) => [g.name],
  subscription: (g) => [g.subscriptionName ?? g.subscriptionId],
  resourceGroup: (g) => [g.resourceGroup],
  location: (g) => [g.location],
  tag: (g) => tagPairs(g.tags),
};

export function IpGroups({
  reloadKey,
  defaultSubscriptionId,
  onCreated,
}: {
  reloadKey: number;
  defaultSubscriptionId?: string;
  onCreated: () => void;
}) {
  const [groups, setGroups] = useState<IpGroupInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [retryKey, setRetryKey] = useState(0);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<IpGroupInfo>();
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const toast = useToast();
  const resourceMenuItems = useResourceMenuItems();
  const { filters, setFilter, clear, active } = useStoredFilters(
    'ez-azfw-ruleman.ipGroupFilters',
  );

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    window.api
      .discoverIpGroups()
      .then((items) => {
        if (cancelled) return;
        setGroups(items);
        setError('');
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [reloadKey, retryKey]);

  const shown = useMemo(
    () => groups.filter((g) => matchesFilters(g, filters, IP_GROUP_FILTERS)),
    [groups, filters],
  );
  const bySubscription = useMemo(() => {
    const map = new Map<string, IpGroupInfo[]>();
    for (const group of shown) {
      const key = group.subscriptionId.toLowerCase();
      const list = map.get(key) ?? [];
      list.push(group);
      map.set(key, list);
    }
    return [...map.entries()]
      .map(([key, list]) => ({
        key,
        id: list[0].subscriptionId,
        name:
          list.find((g) => g.subscriptionName)?.subscriptionName ??
          list[0].subscriptionId,
        list: list.sort((a, b) => a.name.localeCompare(b.name)),
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [shown]);

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-end gap-3 border-b border-line px-6 pb-4 pt-5">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-semibold">IP groups</h1>
          <p className="mt-1 text-sm text-fg-muted">
            IP groups across the subscriptions you can access in this directory.
          </p>
        </div>
        <button className="btn-outline" onClick={() => setShowCreate(true)}>
          <Plus size={15} /> Create IP group
        </button>
      </div>
      <FilterBar
        items={groups}
        values={IP_GROUP_FILTERS}
        filters={filters}
        onChange={setFilter}
        onClear={clear}
        active={active}
        summary={`${active ? `Showing ${shown.length} of ${groups.length}` : `${groups.length} IP groups`} in ${bySubscription.length} ${bySubscription.length === 1 ? 'subscription' : 'subscriptions'}`}
      />
      {error && (
        <Notice
          tone="error"
          title="Couldn't load IP groups"
          action={
            <button
              className="btn-outline"
              disabled={loading}
              onClick={() => setRetryKey((k) => k + 1)}
            >
              Try again
            </button>
          }
        >
          {error}
        </Notice>
      )}
      {loading && (
        <div className="px-6 py-3">
          <Spinner label="Loading IP groups…" />
        </div>
      )}
      {!loading && !error && !groups.length ? (
        <EmptyState icon={<Network size={22} />} title="No IP groups found">
          Create an IP group to reuse addresses in your firewall rules.
        </EmptyState>
      ) : groups.length > 0 ? (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full table-fixed text-left text-sm">
            <thead className="sticky top-0 z-10 bg-ink-900 text-xs text-fg-muted">
              <tr className="border-b border-line">
                <th className="py-2 pl-6 pr-3 font-medium">Name</th>
                <th className="w-60 px-3 py-2 font-medium">Addresses</th>
                <th className="w-48 px-3 py-2 font-medium">Resource group</th>
                <th className="w-40 px-3 py-2 font-medium">Location</th>
                <th className="w-12 py-2 pr-4" />
              </tr>
            </thead>
            <tbody>
              {bySubscription.map(({ key, id, name, list }) => (
                <Fragment key={key}>
                  <tr className="border-b border-line bg-ink-850">
                    <td colSpan={5} className="p-0">
                      <button
                        type="button"
                        aria-expanded={!collapsed.has(key)}
                        className="flex w-full items-center gap-2 py-2 pl-6 pr-3 text-left hover:bg-ink-800"
                        onClick={() =>
                          setCollapsed((old) => {
                            const next = new Set(old);
                            if (next.has(key)) next.delete(key);
                            else next.add(key);
                            return next;
                          })
                        }
                      >
                        <ChevronRight
                          size={14}
                          className={`text-fg-muted transition-transform ${collapsed.has(key) ? '' : 'rotate-90'}`}
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
                          {list.length === 1 ? 'IP group' : 'IP groups'}
                        </span>
                      </button>
                    </td>
                  </tr>
                  {!collapsed.has(key) &&
                    list.map((group, i) => (
                      <tr
                        key={group.id}
                        className="border-b border-line/60 hover:bg-ink-850"
                      >
                        <td
                          className="relative py-2 pr-3"
                          style={{ paddingLeft: treeIndent(1) }}
                        >
                          <TreeLines depth={1} last={i === list.length - 1} />
                          <div className="flex items-center gap-2">
                            <StatusDot state={group.provisioningState} />
                            <button
                              className="truncate font-medium hover:text-azure hover:underline"
                              title={[group.name, ...tagPairs(group.tags)].join(
                                '\n',
                              )}
                              onClick={() => setSelected(group)}
                            >
                              {group.name}
                            </button>
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <ValueList
                            values={group.addresses}
                            empty="No addresses"
                          />
                        </td>
                        <td
                          className="truncate px-3 py-2 text-fg-muted"
                          title={group.resourceGroup}
                        >
                          {group.resourceGroup}
                        </td>
                        <td className="px-3 py-2 text-fg-muted">
                          {group.location}
                        </td>
                        <td className="py-1.5 pr-4">
                          <EllipsisMenu
                            label={`Actions for ${group.name}`}
                            items={[
                              {
                                label: 'View addresses',
                                onSelect: () => setSelected(group),
                              },
                              ...resourceMenuItems(group.id),
                            ]}
                          />
                        </td>
                      </tr>
                    ))}
                </Fragment>
              ))}
              {!shown.length && (
                <tr>
                  <td
                    colSpan={5}
                    className="px-6 py-6 text-center text-fg-muted"
                  >
                    No IP groups match these filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      ) : null}
      {selected && (
        <Modal
          title={selected.name}
          subtitle={`${selected.resourceGroup} · ${selected.location}`}
          onClose={() => setSelected(undefined)}
          footer={
            <button
              className="btn-outline"
              onClick={() => setSelected(undefined)}
            >
              Close
            </button>
          }
        >
          <label className="block">
            <span className="label">
              {selected.addresses.length} address entries
            </span>
            <textarea
              readOnly
              className="input h-72 font-mono text-sm"
              value={selected.addresses.join('\n')}
            />
          </label>
        </Modal>
      )}
      {showCreate && (
        <CreateIpGroup
          defaultSubscriptionId={defaultSubscriptionId}
          onClose={() => setShowCreate(false)}
          onCreated={(group) => {
            setGroups((items) => [
              ...items.filter(
                (g) => g.id.toLowerCase() !== group.id.toLowerCase(),
              ),
              group,
            ]);
            setShowCreate(false);
            toast('success', `IP group "${group.name}" was created in Azure.`);
            onCreated();
          }}
        />
      )}
    </div>
  );
}
