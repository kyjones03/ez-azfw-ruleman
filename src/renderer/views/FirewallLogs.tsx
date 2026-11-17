import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  Download,
  ListTree,
  ShieldPlus,
  Pause,
  Play,
  KeyRound,
  Plug,
  PlugZap,
  ScrollText,
  Settings2,
  Trash2,
  X,
} from 'lucide-react';
import { Badge, EmptyState, Notice, Spinner } from '../components/ui';
import { SelectMenu } from '../components/Dropdown';
import { Modal } from '../components/Modal';
import { errorMessage, useToast } from '../components/Toast';
import { useLogStream } from '../logStream';
import { LogConnectionForm } from './LogConnectionForm';
import type { FirewallLogRow } from '../../shared/fwLogs';
import { parseAddress } from '../../shared/ipAddress';
import { resolveRowOwner, type OwnerFirewall } from '../../shared/logOwner';
import { logRuleRef, type LogRuleRef } from '../../shared/logRuleRef';
import {
  canSuggestRule,
  suggestRuleFromRow,
  type RuleSuggestion,
} from '../../shared/logRuleSuggest';
import { logsCsvFileName, logsToCsv } from '../../shared/logCsv';
import {
  CATEGORY_OPTIONS,
  filterRows,
  DEFAULT_FILTERS,
  differsFromDefault,
  type LogFilters,
} from '../../shared/logFilters';
import { LOG_RECEIVER_ROLE, type LogStreamState } from '../../shared/logStream';

const ROW_HEIGHT = 28;
const OVERSCAN = 12;
const COLUMNS =
  'grid-cols-[92px_104px_64px_minmax(0,1fr)_minmax(0,1.2fr)_56px_88px_minmax(0,1.6fr)]';

const STATE_LABEL: Record<LogStreamState, string> = {
  idle: 'Not connected',
  connecting: 'Connecting…',
  connected: 'Live',
  retrying: 'Retrying',
  reconnecting: 'Reconnecting',
  failed: 'Failed',
  stopped: 'Disconnected',
};
const RUNNING: LogStreamState[] = [
  'connecting',
  'connected',
  'retrying',
  'reconnecting',
];

/** "10.0.0.1:443", "[fd00::1]:443"; a missing port leaves just the address. */
function endpoint(address: string, port: string): string {
  if (!port || port === '-') return address;
  return parseAddress(address)?.version === 6
    ? `[${address}]:${port}`
    : `${address}:${port}`;
}

function localTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

const CATEGORY_TONE: Record<string, 'neutral' | 'blue' | 'violet' | 'red'> = {
  AppRule: 'blue',
  NATRule: 'violet',
  ThreatIntel: 'red',
  IDPS: 'red',
  DnsFailure: 'red',
};

function actionClass(action: string): string {
  const a = action.toLowerCase();
  if (a === 'allow') return 'text-allow';
  if (a === 'deny' || a === 'resolvefail') return 'text-deny';
  if (a === 'dnat') return 'text-dnat';
  return 'text-fg-muted';
}

export function FirewallLogs({
  managedFirewalls,
  onOpenRule,
  onCreateRule,
}: {
  /** The firewalls managed in this app, to tell which one wrote a row. */
  managedFirewalls: OwnerFirewall[];
  /** Shows the rule a row matched in the Rules view. */
  onOpenRule: (ref: LogRuleRef) => void;
  /** Starts an Allow rule for a denied flow in the policy of the firewall that wrote the row. */
  onCreateRule: (suggestion: RuleSuggestion, firewallPolicyId: string) => void;
}) {
  const stream = useLogStream();
  const toast = useToast();
  const { status, config, buffer, paused } = stream;
  const running = RUNNING.includes(status.state);
  const [editing, setEditing] = useState(false);
  const showForm = editing || (stream.ready && !config);
  const [filters, setFilters] = useState<LogFilters>(DEFAULT_FILTERS);
  const [selected, setSelected] = useState<FirewallLogRow>();
  const [granting, setGranting] = useState(false);
  const [grantBusy, setGrantBusy] = useState(false);

  const visible = useMemo(
    () => filterRows(buffer.rows, filters),
    [buffer.rows, filters],
  );
  const set = (patch: Partial<LogFilters>) =>
    setFilters((f) => ({ ...f, ...patch }));

  const exportCsv = async () => {
    try {
      const saved = await window.api.saveCsv(
        logsCsvFileName(),
        logsToCsv(visible),
      );
      if (saved)
        toast('success', `Exported ${visible.length} rows to ${saved}`);
    } catch (err) {
      toast('error', errorMessage(err));
    }
  };

  const toggleConnection = async () => {
    try {
      if (running) await stream.disconnect();
      else if (config) await stream.connect(config);
    } catch (err) {
      toast('error', errorMessage(err));
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="border-b border-line px-6 pb-3 pt-5">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 className="text-xl font-semibold">Firewall logs</h1>
          <StatusChip state={status.state} detail={status.detail} />
          {config && !showForm && (
            <>
              <span
                className="truncate font-mono text-xs text-fg-muted"
                title={`${config.namespace} · ${config.eventHub} · ${config.consumerGroup}`}
              >
                {config.namespace} / {config.eventHub}
              </span>
              <button
                type="button"
                className={running ? 'btn-outline' : 'btn-primary'}
                onClick={toggleConnection}
              >
                {running ? <PlugZap size={14} /> : <Plug size={14} />}
                {running ? 'Disconnect' : 'Connect'}
              </button>
              <button
                type="button"
                className="btn-ghost h-7 px-2 text-xs"
                onClick={() => setEditing(true)}
              >
                <Settings2 size={13} />
                Event Hub settings
              </button>
            </>
          )}
        </div>
        <p className="mt-1 text-sm text-fg-muted">
          Live Azure Firewall diagnostic logs from an Event Hub, read with your
          own sign-in. Nothing is saved to disk unless you export it.
        </p>
      </div>

      {showForm && (
        <LogConnectionForm
          initial={config}
          onCancel={config ? () => setEditing(false) : undefined}
          onConnect={async (next) => {
            await stream.connect(next);
            setEditing(false);
          }}
          onSetupDone={async (next, waitForRole) => {
            await stream.connect(next, { waitForRole });
            setEditing(false);
          }}
        />
      )}

      {status.state === 'failed' || (status.error && status.hint) ? (
        <div className="px-6 pt-3">
          <Notice
            action={
              status.state === 'failed' &&
              status.errorKind === 'permission' &&
              status.config ? (
                <button
                  type="button"
                  className="btn-outline"
                  onClick={() => setGranting(true)}
                >
                  <KeyRound size={14} />
                  Assign me the role…
                </button>
              ) : undefined
            }
            tone={status.state === 'failed' ? 'error' : 'info'}
            title={
              status.state === 'failed'
                ? "Couldn't read from the Event Hub"
                : 'Connection problem, trying again'
            }
          >
            {status.error}
            {status.hint && `\n${status.hint}`}
          </Notice>
        </div>
      ) : null}

      {!showForm && config && (
        <>
          <Toolbar
            filters={filters}
            onChange={set}
            onClear={() => setFilters(DEFAULT_FILTERS)}
            shown={visible.length}
            total={buffer.rows.length}
            skipped={buffer.skipped}
          />
          <div className="flex items-center gap-2 border-b border-line px-6 py-1.5">
            <button
              type="button"
              className="btn-outline h-7 px-2.5 text-xs"
              onClick={paused ? stream.resume : stream.pause}
            >
              {paused ? <Play size={13} /> : <Pause size={13} />}
              {paused
                ? `Resume${buffer.held.length ? ` (${buffer.held.length} new)` : ''}`
                : 'Pause'}
            </button>
            <button
              type="button"
              className="btn-ghost h-7 px-2 text-xs"
              onClick={() => {
                stream.clear();
                setSelected(undefined);
              }}
            >
              <Trash2 size={13} />
              Clear
            </button>
            <button
              type="button"
              className="btn-ghost h-7 px-2 text-xs"
              disabled={visible.length === 0}
              title="Saves the rows shown (after filters) to a CSV file you choose."
              onClick={() => void exportCsv()}
            >
              <Download size={13} />
              Export CSV
            </button>
            {paused && (
              <Badge tone="blue">
                Paused: new rows are held, nothing is lost
              </Badge>
            )}
            {buffer.heldDropped > 0 && (
              <Badge tone="red">
                {buffer.heldDropped.toLocaleString()} older held rows dropped
                (hold limit reached)
              </Badge>
            )}
          </div>
          <div className="flex min-h-0 flex-1">
            <LogTable
              rows={visible}
              hasRows={buffer.rows.length > 0}
              state={status.state}
              selectedId={selected?.id}
              onSelect={setSelected}
            />
            {selected && (
              <DetailPanel
                row={selected}
                managedFirewalls={managedFirewalls}
                onOpenRule={onOpenRule}
                onCreateRule={onCreateRule}
                onClose={() => {
                  const id = selected?.id;
                  setSelected(undefined);
                  // Closing the panel hands focus back to the row it described.
                  if (id)
                    window.setTimeout(
                      () =>
                        document
                          .querySelector<HTMLElement>(`[data-row-id="${id}"]`)
                          ?.focus(),
                      0,
                    );
                }}
              />
            )}
          </div>
        </>
      )}
      {granting && status.config && (
        <Modal
          title="Assign yourself the Event Hubs Data Receiver role?"
          onClose={() => !grantBusy && setGranting(false)}
          widthClass="max-w-lg"
          footer={
            <>
              <button
                className="btn-ghost"
                disabled={grantBusy}
                onClick={() => setGranting(false)}
              >
                Cancel
              </button>
              <button
                className="btn-primary"
                disabled={grantBusy}
                autoFocus
                onClick={async () => {
                  if (!status.config) return;
                  setGrantBusy(true);
                  try {
                    const scope = await window.api.grantLogReceiver(
                      status.config,
                    );
                    toast(
                      'success',
                      `Role assigned on ${scope.split('/').pop()}. Connecting; a new role can take a few minutes to apply.`,
                    );
                    setGranting(false);
                    // Waits for the role instead of failing at once.
                    await stream.connect(status.config, { waitForRole: true });
                  } catch (err) {
                    toast('error', errorMessage(err));
                  } finally {
                    setGrantBusy(false);
                  }
                }}
              >
                {grantBusy ? <Spinner size={14} /> : <KeyRound size={14} />}
                Assign role
              </button>
            </>
          }
        >
          <div className="space-y-2 text-sm text-fg-muted">
            <p>
              <strong className="text-fg">This changes Azure directly</strong>,
              not your draft. It assigns you{' '}
              <span className="text-fg">{LOG_RECEIVER_ROLE}</span> on the event
              hub <span className="netval">{status.config.eventHub}</span> in{' '}
              <span className="netval">{status.config.namespace}</span>, and
              nothing broader.
            </p>
            <p>
              You need Owner or User Access Administrator on it. Role changes
              can take several minutes to take effect.
            </p>
          </div>
        </Modal>
      )}
    </div>
  );
}

function StatusChip({
  state,
  detail,
}: {
  state: LogStreamState;
  detail: string;
}) {
  const tone =
    state === 'connected'
      ? 'bg-allow'
      : state === 'failed'
        ? 'bg-deny'
        : state === 'idle' || state === 'stopped'
          ? 'bg-fg-faint'
          : 'bg-azure animate-pulse';
  return (
    <span className="inline-flex items-center gap-1.5 rounded border border-line bg-ink-900 px-2.5 py-0.5 text-xs text-fg-muted">
      <span className={`h-2 w-2 rounded-full ${tone}`} aria-hidden />
      {/* Only the state is announced; the retry text changes every few seconds and would chatter. */}
      <span role="status" className="text-fg">
        {STATE_LABEL[state]}
      </span>
      {detail && <span>{detail}</span>}
    </span>
  );
}

const FILTER_INPUTS: {
  key: 'source' | 'destination' | 'action' | 'protocol' | 'port';
  label: string;
  width: string;
}[] = [
  { key: 'source', label: 'Source IP / CIDR', width: 'w-40' },
  { key: 'destination', label: 'Destination / FQDN', width: 'w-44' },
  { key: 'action', label: 'Action', width: 'w-24' },
  { key: 'protocol', label: 'Protocol', width: 'w-24' },
  { key: 'port', label: 'Port', width: 'w-20' },
];

function Toolbar({
  filters,
  onChange,
  onClear,
  shown,
  total,
  skipped,
}: {
  filters: LogFilters;
  onChange: (patch: Partial<LogFilters>) => void;
  onClear: () => void;
  shown: number;
  total: number;
  skipped: number;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-line px-6 py-2.5">
      <SelectMenu<string>
        label="Category"
        widthClass="w-44"
        value={filters.category}
        onChange={(v) => onChange({ category: v })}
        options={[{ value: '', label: 'All categories' }, ...CATEGORY_OPTIONS]}
      />
      {FILTER_INPUTS.map(({ key, label, width }) => (
        <input
          key={key}
          aria-label={label}
          placeholder={label}
          className={`input ${width} font-mono`}
          value={filters[key]}
          onChange={(e) => onChange({ [key]: e.target.value })}
          spellCheck={false}
        />
      ))}
      <label className="flex items-center gap-1.5 text-sm text-fg-muted">
        <input
          type="checkbox"
          checked={filters.hideDns}
          onChange={(e) => onChange({ hideDns: e.target.checked })}
        />
        Hide DNS queries
      </label>
      {differsFromDefault(filters) && (
        <button
          type="button"
          className="text-sm text-azure hover:underline"
          onClick={onClear}
        >
          Clear filters
        </button>
      )}
      <span className="ml-auto text-xs text-fg-muted">
        Showing {shown.toLocaleString()} of {total.toLocaleString()}
        {skipped > 0 && ` · ${skipped.toLocaleString()} not shown`}
      </span>
    </div>
  );
}

function LogTable({
  rows,
  hasRows,
  state,
  selectedId,
  onSelect,
}: {
  rows: FirewallLogRow[];
  hasRows: boolean;
  state: LogStreamState;
  selectedId?: string;
  onSelect: (row: FirewallLogRow) => void;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(600);
  const firstId = useRef<string | undefined>(undefined);
  // Only one row is a tab stop (a table of thousands of rows must not be thousands of Tab presses);
  // the arrow keys move between rows. `wantFocus` is set by a key press, so rows arriving never
  // pull focus away from where the user is.
  const [stopId, setStopId] = useState<string>();
  const wantFocus = useRef<string | undefined>(undefined);

  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const observer = new ResizeObserver(() => setHeight(el.clientHeight));
    observer.observe(el);
    setHeight(el.clientHeight);
    return () => observer.disconnect();
  }, []);

  // Newest rows arrive at the top. At the top the view follows them; scrolled down, it stays on
  // the same row instead of jumping.
  useLayoutEffect(() => {
    const el = scroller.current;
    const previous = firstId.current;
    firstId.current = rows[0]?.id;
    if (!el || !previous || el.scrollTop <= ROW_HEIGHT) return;
    const index = rows.findIndex((r) => r.id === previous);
    if (index > 0) el.scrollTop += index * ROW_HEIGHT;
  }, [rows]);

  const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const end = Math.min(
    rows.length,
    Math.ceil((scrollTop + height) / ROW_HEIGHT) + OVERSCAN,
  );
  const tabStop = rows.some((r) => r.id === stopId)
    ? stopId
    : (selectedId ?? rows[0]?.id);

  // After a key press moved the tab stop, focus that row once it has been rendered.
  useLayoutEffect(() => {
    const id = wantFocus.current;
    if (!id) return;
    const el = scroller.current?.querySelector<HTMLElement>(
      `[data-row-id="${id}"]`,
    );
    if (el) {
      wantFocus.current = undefined;
      el.focus();
    }
  }, [rows, start, end, stopId]);

  const moveTo = (index: number) => {
    const el = scroller.current;
    const target = rows[Math.max(0, Math.min(rows.length - 1, index))];
    if (!el || !target) return;
    const top = rows.indexOf(target) * ROW_HEIGHT;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + ROW_HEIGHT > el.scrollTop + el.clientHeight)
      el.scrollTop = top + ROW_HEIGHT - el.clientHeight;
    setScrollTop(el.scrollTop); // render the new window now, not on the scroll event
    wantFocus.current = target.id;
    setStopId(target.id);
  };
  const page = Math.max(1, Math.floor(height / ROW_HEIGHT) - 1);
  const onRowKey = (e: React.KeyboardEvent, index: number) => {
    const next: Record<string, number> = {
      ArrowDown: index + 1,
      ArrowUp: index - 1,
      PageDown: index + page,
      PageUp: index - page,
      Home: 0,
      End: rows.length - 1,
    };
    if (e.key in next) {
      e.preventDefault();
      moveTo(next[e.key]);
    }
  };

  return (
    <div
      className="flex min-w-0 flex-1 flex-col"
      role="grid"
      aria-label="Firewall log rows"
      aria-rowcount={rows.length}
    >
      <div
        role="row"
        className={`grid ${COLUMNS} gap-x-3 border-b border-line bg-ink-900 py-2 pl-6 pr-4 text-xs font-medium text-fg-muted`}
      >
        {[
          'Time',
          'Category',
          'Proto',
          'Source',
          'Destination',
          'Port',
          'Action',
          'Rule info',
        ].map((h) => (
          <span key={h} role="columnheader">
            {h}
          </span>
        ))}
      </div>
      <div
        ref={scroller}
        className="min-h-0 flex-1 overflow-y-auto"
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        {rows.length === 0 ? (
          <EmptyState
            icon={<ScrollText size={22} />}
            title={hasRows ? 'No rows match the filters' : 'No log rows yet'}
          >
            {hasRows
              ? 'Change or clear the filters to see more.'
              : state === 'connected'
                ? 'Waiting for events. Rows appear as the firewall logs traffic; new diagnostic settings can take 10–15 minutes to deliver the first events.'
                : state === 'idle' || state === 'stopped'
                  ? 'Connect to start reading.'
                  : 'Connecting to the Event Hub…'}
          </EmptyState>
        ) : (
          <div
            role="rowgroup"
            style={{ height: rows.length * ROW_HEIGHT, position: 'relative' }}
          >
            {rows.slice(start, end).map((row, i) => (
              <LogRow
                key={row.id}
                row={row}
                index={start + i}
                selected={row.id === selectedId}
                tabStop={row.id === tabStop}
                onSelect={onSelect}
                onKey={onRowKey}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function LogRow({
  row,
  index,
  selected,
  tabStop,
  onSelect,
  onKey,
}: {
  row: FirewallLogRow;
  index: number;
  selected: boolean;
  /** The one row Tab lands on; the arrow keys move between rows. */
  tabStop: boolean;
  onSelect: (row: FirewallLogRow) => void;
  onKey: (e: React.KeyboardEvent, index: number) => void;
}) {
  return (
    <div
      role="row"
      data-row-id={row.id}
      aria-rowindex={index + 1}
      aria-selected={selected}
      tabIndex={tabStop ? 0 : -1}
      onClick={() => onSelect(row)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect(row);
        } else onKey(e, index);
      }}
      style={{
        position: 'absolute',
        top: index * ROW_HEIGHT,
        height: ROW_HEIGHT,
      }}
      className={`grid w-full ${COLUMNS} cursor-default items-center gap-x-3 border-b border-line/40 pl-6 pr-4 text-sm hover:bg-ink-850 focus:outline-none focus-visible:ring-1 focus-visible:ring-azure ${selected ? 'bg-ink-800' : ''}`}
    >
      <span role="gridcell" className="netval truncate text-fg-muted">
        {localTime(row.time)}
      </span>
      <span role="gridcell">
        <Badge tone={CATEGORY_TONE[row.category] ?? 'neutral'}>
          {row.category}
        </Badge>
      </span>
      <span
        role="gridcell"
        className="truncate text-fg-muted"
        title={row.protocol}
      >
        {row.protocol}
      </span>
      <span
        role="gridcell"
        className="netval truncate"
        title={endpoint(row.sourceIp, row.sourcePort)}
      >
        {endpoint(row.sourceIp, row.sourcePort)}
      </span>
      <span role="gridcell" className="netval truncate" title={row.targetIp}>
        {row.targetIp}
      </span>
      <span role="gridcell" className="netval truncate">
        {row.targetPort}
      </span>
      <span
        role="gridcell"
        className={`truncate font-medium ${actionClass(row.action)}`}
        title={row.action}
      >
        {row.action}
      </span>
      <span
        role="gridcell"
        className="truncate text-fg-muted"
        title={row.policy || row.moreInfo}
      >
        {row.policy || row.moreInfo}
      </span>
    </div>
  );
}

function DetailPanel({
  row,
  managedFirewalls,
  onOpenRule,
  onCreateRule,
  onClose,
}: {
  row: FirewallLogRow;
  managedFirewalls: OwnerFirewall[];
  onOpenRule: (ref: LogRuleRef) => void;
  onCreateRule: (suggestion: RuleSuggestion, firewallPolicyId: string) => void;
  onClose: () => void;
}) {
  const owner = resolveRowOwner(row, managedFirewalls);
  const ruleRef = logRuleRef(row, owner.policyId);
  const suggested =
    canSuggestRule(row) && owner.policyId ? suggestRuleFromRow(row) : undefined;
  const fields: [string, string][] = [
    ['Time (UTC)', row.time],
    ['Category', row.category],
    ['Protocol', row.protocol],
    ['Source', endpoint(row.sourceIp, row.sourcePort)],
    ['Destination', endpoint(row.targetIp, row.targetPort)],
    [
      'Public destination (DNAT)',
      row.natDstIp ? endpoint(row.natDstIp, row.natDstPort) : '',
    ],
    ['Action', row.action],
    ['Policy', row.fwPolicy],
    ['Rule collection group', row.ruleCollectionGroup],
    ['Rule collection', row.ruleCollection],
    ['Rule', row.ruleName],
    ['Info', row.moreInfo || (row.ruleName ? '' : row.policy)],
    ['Explicit proxy', row.explicitProxy],
    ['TLS inspected', row.tlsInspected],
    ['Firewall', row.resourceId.split('/').pop() ?? ''],
    [
      'Managed here',
      !row.resourceId
        ? ''
        : owner.firewall
          ? owner.policyName
            ? `Yes, policy ${owner.policyName}`
            : 'Yes, no policy'
          : 'No, not one of your managed firewalls',
    ],
  ];
  return (
    <aside
      aria-label="Log row details"
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          e.stopPropagation();
          onClose();
        }
      }}
      className="w-80 shrink-0 overflow-y-auto border-l border-line bg-ink-900 p-4"
    >
      <div className="mb-3 flex items-center">
        <h2 className="flex-1 text-sm font-semibold">Details</h2>
        <button
          type="button"
          className="btn-ghost h-7 px-1.5"
          onClick={onClose}
          aria-label="Close details"
        >
          <X size={14} />
        </button>
      </div>
      <dl className="space-y-2.5 text-sm">
        {fields
          .filter(([, v]) => v && v !== '-')
          .map(([k, v]) => (
            <div key={k}>
              <dt className="text-xs text-fg-muted">{k}</dt>
              <dd className="netval break-all">{v}</dd>
            </div>
          ))}
      </dl>
      {ruleRef && (
        <button
          type="button"
          className="btn-outline mt-4 h-8 w-full text-xs"
          title="Shows this rule in the Rules view, in the policy of the firewall that wrote the row."
          onClick={() => onOpenRule(ruleRef)}
        >
          <ListTree size={13} />
          Open rule
        </button>
      )}
      {suggested?.ok && owner.policyId && (
        <button
          type="button"
          className="btn-outline mt-2 h-8 w-full text-xs"
          title="Opens the rule editor with an Allow rule for exactly this flow. Nothing reaches Azure until you commit."
          onClick={() =>
            owner.policyId && onCreateRule(suggested.suggestion, owner.policyId)
          }
        >
          <ShieldPlus size={13} />
          Create an Allow rule…
        </button>
      )}
      {suggested && !suggested.ok && (
        <p className="mt-2 text-xs text-fg-muted">
          Can&apos;t suggest a rule: {suggested.reason}
        </p>
      )}
    </aside>
  );
}
