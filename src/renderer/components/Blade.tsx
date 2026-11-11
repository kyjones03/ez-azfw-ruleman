import type { ReactNode } from 'react';
import {
  Camera,
  ChevronUp,
  History,
  ListTree,
  LogOut,
  Network,
  Route,
  Server,
  ShieldCheck,
  UserCircle2,
} from 'lucide-react';
import { Dropdown } from './Dropdown';
import type { AccountInfo } from '../../shared/types';

export type Tab =
  | 'firewalls'
  | 'policies'
  | 'rules'
  | 'ipGroups'
  | 'flow'
  | 'snapshots'
  | 'history';

function NavItem({
  icon,
  label,
  open,
  active,
  onClick,
  trailing,
}: {
  icon: ReactNode;
  label: string;
  open: boolean;
  active?: boolean;
  onClick: () => void;
  trailing?: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={open ? undefined : label}
      aria-label={label}
      aria-current={active ? 'page' : undefined}
      className={`flex h-9 w-full items-center gap-3 border-l-2 pl-[15px] pr-3 text-left text-sm ${
        active
          ? 'border-azure bg-ink-800 text-fg'
          : 'border-transparent text-fg-muted hover:bg-ink-800 hover:text-fg'
      }`}
    >
      <span className="shrink-0">{icon}</span>
      {open && <span className="flex-1 truncate">{label}</span>}
      {open && trailing}
    </button>
  );
}

/** Collapsible left navigation blade. */
export function Blade({
  open,
  tab,
  onTab,
  account,
  onSignOut,
  onSwitchTenant,
}: {
  open: boolean;
  tab: Tab;
  onTab: (t: Tab) => void;
  account: AccountInfo;
  onSignOut: () => void;
  onSwitchTenant: (tenantId: string) => void;
}) {
  const who = account.displayName ?? account.username ?? 'Signed in';
  const tenants = account.tenants ?? [];
  const current = tenants.find((t) => t.tenantId === account.tenantId);
  return (
    <nav
      aria-label="Main"
      className={`flex shrink-0 flex-col border-r border-line bg-ink-950 py-2 transition-[width] duration-150 ${open ? 'w-56' : 'w-[52px]'}`}
    >
      <NavItem
        open={open}
        icon={<Server size={18} />}
        label="Firewalls"
        active={tab === 'firewalls'}
        onClick={() => onTab('firewalls')}
      />
      <NavItem
        open={open}
        icon={<ShieldCheck size={18} />}
        label="Policies"
        active={tab === 'policies'}
        onClick={() => onTab('policies')}
      />
      <NavItem
        open={open}
        icon={<ListTree size={18} />}
        label="Rules"
        active={tab === 'rules'}
        onClick={() => onTab('rules')}
      />
      <NavItem
        open={open}
        icon={<Network size={18} />}
        label="IP groups"
        active={tab === 'ipGroups'}
        onClick={() => onTab('ipGroups')}
      />
      <NavItem
        open={open}
        icon={<Route size={18} />}
        label="Flow tester"
        active={tab === 'flow'}
        onClick={() => onTab('flow')}
      />
      <NavItem
        open={open}
        icon={<Camera size={18} />}
        label="Snapshots"
        active={tab === 'snapshots'}
        onClick={() => onTab('snapshots')}
      />
      <NavItem
        open={open}
        icon={<History size={18} />}
        label="Commit history"
        active={tab === 'history'}
        onClick={() => onTab('history')}
      />
      <div className="flex-1" />
      <Dropdown
        align="left"
        label="Account"
        widthClass="w-64"
        triggerClassName={`flex h-10 items-center gap-3 pl-[17px] pr-3 text-left text-sm text-fg-muted hover:bg-ink-800 hover:text-fg ${open ? 'w-56' : 'w-[52px]'}`}
        trigger={() => (
          <>
            <UserCircle2 size={18} className="shrink-0" />
            {open && <span className="flex-1 truncate">{who}</span>}
            {open && <ChevronUp size={14} className="shrink-0" />}
          </>
        )}
        header={
          <div className="min-w-0 text-sm">
            <div className="truncate font-semibold text-fg">{who}</div>
            {account.username && (
              <div className="truncate text-fg-muted">{account.username}</div>
            )}
            <div className="mt-1 text-xs text-fg-faint">
              Signed in with{' '}
              {account.method === 'cli'
                ? 'the Azure CLI'
                : 'a Microsoft account'}
            </div>
            {account.tenantId && (
              <div
                className="truncate text-xs text-fg-faint"
                title={account.tenantId}
              >
                Directory:{' '}
                {current?.displayName ??
                  current?.defaultDomain ??
                  account.tenantId}
              </div>
            )}
          </div>
        }
        items={[
          ...(tenants.length > 1
            ? [
                ...tenants.map((t) => ({
                  id: t.tenantId,
                  label: t.displayName ?? t.defaultDomain ?? t.tenantId,
                  hint: t.displayName ? t.defaultDomain : undefined,
                  checked: t.tenantId === account.tenantId,
                  onSelect: () => onSwitchTenant(t.tenantId),
                })),
                { label: '', divider: true },
              ]
            : []),
          {
            label: 'Sign out',
            icon: <LogOut size={14} />,
            onSelect: onSignOut,
            danger: true,
          },
        ]}
      />
    </nav>
  );
}
