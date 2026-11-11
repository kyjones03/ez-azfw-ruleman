import { useMemo, useState } from 'react';
import { Search, RefreshCw, Flame } from 'lucide-react';
import { EllipsisMenu, SelectMenu } from '../components/Dropdown';
import { useResourceMenuItems } from '../components/resourceMenu';
import { EmptyState, StatusDot, Truncate } from '../components/ui';
import { QuipSpinner } from '../components/QuipSpinner';
import { resourceName } from '../../shared/resourceId';
import type { FirewallSummary, TenantInfo } from '../../shared/types';

export function FirewallPicker({
  firewalls,
  loading,
  error,
  errorAt,
  onSignInAgain,
  tenants,
  tenantId,
  onSwitchTenant,
  initialSelection,
  onRefresh,
  onConfirm,
  onCancel,
}: {
  firewalls: FirewallSummary[];
  loading: boolean;
  error?: string;
  errorAt?: Date;
  onSignInAgain: () => void;
  tenants: TenantInfo[];
  tenantId?: string;
  onSwitchTenant: (tenantId: string) => void;
  initialSelection: string[];
  onRefresh: () => void;
  onConfirm: (ids: string[]) => void;
  onCancel?: () => void;
}) {
  const [selected, setSelected] = useState(
    () => new Set(initialSelection.map((i) => i.toLowerCase())),
  );
  const [query, setQuery] = useState('');
  const [directory, setDirectory] = useState('');
  const resourceMenuItems = useResourceMenuItems();

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return firewalls;
    return firewalls.filter((f) =>
      [
        f.name,
        f.resourceGroup,
        f.location,
        f.subscriptionName,
        f.privateIp,
        f.policyId && resourceName(f.policyId),
      ]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q)),
    );
  }, [firewalls, query]);

  const bySubscription = useMemo(() => {
    const map = new Map<string, FirewallSummary[]>();
    for (const f of filtered) {
      const key = f.subscriptionName ?? f.subscriptionId;
      map.set(key, [...(map.get(key) ?? []), f]);
    }
    return [...map.entries()];
  }, [filtered]);

  const toggle = (ids: string[], on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        if (on) next.add(id.toLowerCase());
        else next.delete(id.toLowerCase());
      }
      return next;
    });

  const isSel = (f: FirewallSummary) => selected.has(f.id.toLowerCase());
  const visibleIds = filtered.map((f) => f.id);
  const allVisibleSelected = visibleIds.length > 0 && filtered.every(isSel);
  const chosen = firewalls.filter(isSel).map((f) => f.id);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-end gap-3 border-b border-line px-6 pb-4 pt-5">
        <div className="min-w-0 flex-1">
          <h1 className="text-xl font-semibold">
            Choose which firewalls to show
          </h1>
          <p className="mt-1 text-sm text-fg-muted">
            {loading && !firewalls.length
              ? 'Searching every subscription you can access.'
              : error && !firewalls.length
                ? "The search didn't finish."
                : `${firewalls.length} ${firewalls.length === 1 ? 'firewall' : 'firewalls'} found in the subscriptions you can access. Ticked firewalls appear in EZ AzFW Manager; unticking one only hides it here. Nothing in Azure is changed or deleted.`}
          </p>
        </div>
        {tenants.length > 1 && (
          <SelectMenu
            label="Directory"
            widthClass="w-56"
            value={tenantId}
            onChange={onSwitchTenant}
            options={tenants.map((t) => ({
              value: t.tenantId,
              label: t.displayName ?? t.defaultDomain ?? t.tenantId,
              hint: t.displayName ? t.defaultDomain : undefined,
            }))}
          />
        )}
        <div className="relative w-64">
          <Search
            size={14}
            className="absolute left-2.5 top-[9px] text-fg-faint"
          />
          <input
            className="input pl-8"
            aria-label="Filter firewalls"
            placeholder="Filter by name, group, region, IP…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <button className="btn-outline" onClick={onRefresh} disabled={loading}>
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />{' '}
          Refresh
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {loading && !firewalls.length ? (
          <div className="px-6 py-8">
            <QuipSpinner topic="discover" />
          </div>
        ) : error && !firewalls.length ? (
          <div className="m-6 max-w-2xl border-l-2 border-deny bg-deny/10 p-4 text-sm">
            <p className="font-semibold">Couldn't search your subscriptions.</p>
            <p className="mt-1 whitespace-pre-line break-words text-fg-muted">
              {error}
            </p>
            {errorAt && (
              <p className="mt-1 text-xs text-fg-faint">
                Last tried at {errorAt.toLocaleTimeString()}.
              </p>
            )}
            <div className="mt-3 flex gap-2">
              <button className="btn-outline" onClick={onRefresh}>
                <RefreshCw size={15} /> Try again
              </button>
              <button className="btn-ghost" onClick={onSignInAgain}>
                Sign in again
              </button>
            </div>
            <form
              className="mt-4 border-t border-line pt-3"
              onSubmit={(e) => {
                e.preventDefault();
                if (directory.trim()) onSwitchTenant(directory.trim());
              }}
            >
              <label className="label" htmlFor="directory">
                Use a specific directory
              </label>
              <div className="flex gap-2">
                <input
                  id="directory"
                  className="input max-w-sm"
                  placeholder="Directory ID or domain, e.g. contoso.onmicrosoft.com"
                  value={directory}
                  onChange={(e) => setDirectory(e.target.value)}
                />
                <button
                  className="btn-primary"
                  type="submit"
                  disabled={!directory.trim()}
                >
                  Use directory
                </button>
              </div>
              <p className="mt-1 text-xs text-fg-faint">
                Find it in the Azure portal under Subscriptions, in the
                Directory column, or under Microsoft Entra ID, Overview, Tenant
                ID.
              </p>
            </form>
          </div>
        ) : !firewalls.length ? (
          <EmptyState
            icon={<Flame size={22} />}
            title="No Azure Firewalls found"
          >
            Check that you signed in to the right tenant and have at least
            Reader access. To create one, use Deploy firewall on the Firewalls
            page.
          </EmptyState>
        ) : (
          <table className="w-full table-fixed text-left text-sm">
            <thead className="sticky top-0 z-10 bg-ink-900 text-xs text-fg-muted">
              <tr className="border-b border-line">
                <th className="w-12 py-2 pl-6">
                  <input
                    type="checkbox"
                    aria-label="Select all"
                    className="accent-azure"
                    checked={allVisibleSelected}
                    onChange={(e) => toggle(visibleIds, e.target.checked)}
                  />
                </th>
                <th className="px-3 py-2 font-medium">Firewall</th>
                <th className="w-44 px-3 py-2 font-medium">Resource group</th>
                <th className="w-32 px-3 py-2 font-medium">Region</th>
                <th className="w-40 px-3 py-2 font-medium">Tier</th>
                <th className="w-56 px-3 py-2 font-medium">Policy</th>
                <th className="w-32 px-3 py-2 font-medium">Private IP</th>
                <th className="w-12 pr-4" />
              </tr>
            </thead>
            {bySubscription.map(([sub, list]) => (
              <tbody key={sub}>
                <tr className="border-b border-line bg-ink-850">
                  <td className="py-2 pl-6">
                    <input
                      type="checkbox"
                      aria-label={`Select all in ${sub}`}
                      className="accent-azure"
                      checked={list.every(isSel)}
                      onChange={(e) =>
                        toggle(
                          list.map((f) => f.id),
                          e.target.checked,
                        )
                      }
                    />
                  </td>
                  <td colSpan={7} className="px-3 py-2">
                    <span className="font-semibold">{sub}</span>
                    <span className="ml-2 text-fg-muted">
                      {list.length}{' '}
                      {list.length === 1 ? 'firewall' : 'firewalls'}
                    </span>
                  </td>
                </tr>
                {list.map((f) => (
                  <tr
                    key={f.id}
                    className={`cursor-pointer border-b border-line/60 ${isSel(f) ? 'bg-azure/[0.08]' : 'hover:bg-ink-850'}`}
                    onClick={() => toggle([f.id], !isSel(f))}
                  >
                    <td className="py-2 pl-6">
                      <input
                        type="checkbox"
                        aria-label={`Select ${f.name}`}
                        className="accent-azure"
                        checked={isSel(f)}
                        onChange={(e) => toggle([f.id], e.target.checked)}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </td>
                    <td className="px-3 py-2">
                      <span className="flex items-center gap-2">
                        <StatusDot state={f.provisioningState} />
                        <Truncate className="font-medium">{f.name}</Truncate>
                      </span>
                    </td>
                    <td className="px-3 py-2 text-fg-muted">
                      <Truncate>{f.resourceGroup}</Truncate>
                    </td>
                    <td className="px-3 py-2 text-fg-muted">{f.location}</td>
                    <td className="px-3 py-2 text-fg-muted">
                      {f.skuTier ?? '—'}
                      {f.skuName === 'AZFW_Hub' && (
                        <span className="text-fg-faint">, Virtual WAN</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {f.policyId ? (
                        <Truncate>{resourceName(f.policyId)}</Truncate>
                      ) : (
                        <span
                          className="text-fg-faint"
                          title="Classic rules are read-only in EZ AzFW Manager."
                        >
                          Classic rules (read-only)
                        </span>
                      )}
                    </td>
                    <td className="netval px-3 py-2">{f.privateIp ?? '—'}</td>
                    <td
                      className="py-1.5 pr-4"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <EllipsisMenu
                        label={`Actions for ${f.name}`}
                        items={resourceMenuItems(f.id)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            ))}
          </table>
        )}
      </div>

      <div className="flex h-14 shrink-0 items-center gap-3 border-t border-line px-6">
        <span className="text-sm text-fg-muted">
          {chosen.length} of {firewalls.length} shown here
        </span>
        <span className="text-xs text-fg-faint">
          Hiding a firewall doesn't change or delete it in Azure.
        </span>
        <div className="flex-1" />
        {onCancel && (
          <button className="btn-ghost" onClick={onCancel}>
            Cancel
          </button>
        )}
        <button
          className="btn-primary"
          disabled={!chosen.length}
          onClick={() => onConfirm(chosen)}
        >
          Show {chosen.length || ''}{' '}
          {chosen.length === 1 ? 'firewall' : 'firewalls'}
        </button>
      </div>
    </div>
  );
}
