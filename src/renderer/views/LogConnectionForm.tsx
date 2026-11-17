import { useEffect, useId, useMemo, useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Plug,
  Trash2,
  Wrench,
} from 'lucide-react';
import { Badge, Spinner } from '../components/ui';
import { Segmented } from '../components/Segmented';
import { LogSetupWizard } from './LogSetupWizard';
import { LogCleanupDialog } from './LogCleanupDialog';
import type { DanglingSetting } from '../../shared/logCleanup';
import { errorMessage } from '../components/Toast';
import {
  detectedHubs,
  eventHubCoverage,
  type Coverage,
  type DetectedHub,
  type EventHubInfo,
  PUBLIC_ACCESS_DISABLED_READ,
  publicAccessDisabled,
  type LogSources,
} from '../../shared/logSources';
import {
  DEFAULT_CONSUMER_GROUP,
  LOG_RECEIVER_ROLE,
  normaliseNamespace,
  validateLogStreamConfig,
  type LogStreamConfig,
  type StartPosition,
} from '../../shared/logStream';

type Sources =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | { state: 'ready'; data: LogSources };

/** One line about what a hub carries, e.g. "Rule logs complete" or "Missing NetworkRule". */
function CoverageBadge({ coverage }: { coverage: Coverage }) {
  if (coverage.state === 'none')
    return <Badge tone="neutral">Not sent to this hub</Badge>;
  if (coverage.state === 'incomplete')
    return (
      <Badge
        tone="red"
        title="Without these categories the log view misses firewall decisions."
      >
        <AlertTriangle size={11} />
        Missing {coverage.missingCore.join(', ')}
      </Badge>
    );
  return (
    <Badge tone="green">
      <CheckCircle2 size={11} />
      Rule logs complete
    </Badge>
  );
}

function CoverageDetail({ coverage }: { coverage: Coverage }) {
  if (coverage.state === 'none' || !coverage.missingRecommended.length)
    return null;
  return (
    <span className="text-xs text-fg-muted">
      Also not sent: {coverage.missingRecommended.join(', ')}
    </span>
  );
}

export function LogConnectionForm({
  initial,
  onConnect,
  onSetupDone,
  onCancel,
}: {
  initial: LogStreamConfig | null;
  onConnect: (config: LogStreamConfig) => Promise<void>;
  /** The setup wizard finished: connect to the hub it prepared. */
  onSetupDone: (config: LogStreamConfig, waitForRole: boolean) => Promise<void>;
  onCancel?: () => void;
}) {
  const ids = useId();
  const [namespace, setNamespace] = useState(initial?.namespace ?? '');
  const [eventHub, setEventHub] = useState(initial?.eventHub ?? '');
  const [consumerGroup, setConsumerGroup] = useState(
    initial?.consumerGroup ?? DEFAULT_CONSUMER_GROUP,
  );
  const [startPosition, setStartPosition] = useState<StartPosition>(
    initial?.startPosition ?? 'latest',
  );
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [sources, setSources] = useState<Sources>({ state: 'loading' });
  /** Bumped after the setup wizard changed Azure, so the lists are read again. */
  const [reload, setReload] = useState(0);
  const [wizard, setWizard] = useState<{
    firewallIds: string[];
    hub?: { namespaceId: string; eventHub: string };
  }>();
  const [cleanup, setCleanup] = useState<DanglingSetting>();
  const [hubs, setHubs] = useState<EventHubInfo[]>([]);
  const [groups, setGroups] = useState<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    window.api
      .discoverLogSources()
      .then((data) => !cancelled && setSources({ state: 'ready', data }))
      .catch(
        (err) =>
          !cancelled &&
          setSources({ state: 'error', message: errorMessage(err) }),
      );
    return () => {
      cancelled = true;
    };
  }, [reload]);

  const data = sources.state === 'ready' ? sources.data : undefined;
  const fqdn = normaliseNamespace(namespace);
  const known = data?.namespaces.find((n) => n.fqdn === fqdn);

  // Hubs of the chosen namespace; failing to list them (no Reader) only costs the suggestions.
  useEffect(() => {
    setHubs([]);
    if (!known) return;
    let cancelled = false;
    window.api
      .listEventHubs(known.id)
      .then((list) => !cancelled && setHubs(list))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [known?.id]);

  const knownHub = hubs.find((h) => h.name === eventHub.trim());
  useEffect(() => {
    setGroups([]);
    if (!known || !knownHub) return;
    let cancelled = false;
    window.api
      .listConsumerGroups(known.id, knownHub.name)
      .then((list) => !cancelled && setGroups(list))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [known?.id, knownHub?.name]);

  const dangling = data?.dangling ?? [];
  // A hub whose namespace is gone can't be read, so it is offered for cleanup instead of "Use".
  const detected = useMemo(() => {
    if (!data) return [];
    const gone = new Set(data.dangling.map((d) => d.namespaceId.toLowerCase()));
    return detectedHubs(data.firewalls).filter(
      (h) => !gone.has(h.namespaceId.toLowerCase()),
    );
  }, [data]);
  const unreadable = data?.firewalls.filter((f) => f.readError) ?? [];
  /** Readable firewalls that send nowhere an event hub could be read from. */
  const withoutHub =
    data?.firewalls.filter(
      (f) => !f.readError && !f.settings.some((s) => s.eventHubNamespaceId),
    ) ?? [];

  /** What each firewall sends to the hub that is typed in. */
  const forSelection = useMemo(() => {
    if (!data || !fqdn || !eventHub.trim()) return [];
    return data.firewalls
      .map((fw) => ({
        fw,
        coverage: eventHubCoverage(
          fw.settings,
          fqdn,
          eventHub.trim(),
          fw.skuTier,
        ),
      }))
      .filter((x) => x.coverage.state !== 'none');
  }, [data, fqdn, eventHub]);

  const use = (hub: DetectedHub) => {
    setNamespace(`${hub.namespaceName.toLowerCase()}.servicebus.windows.net`);
    setEventHub(hub.eventHub);
    setError('');
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    let config: LogStreamConfig;
    try {
      config = validateLogStreamConfig({
        namespace,
        eventHub,
        consumerGroup,
        startPosition,
      });
    } catch (err) {
      setError(errorMessage(err));
      return;
    }
    setBusy(true);
    try {
      await onConnect(config);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const basicTierGroup =
    known?.skuTier?.toLowerCase() === 'basic' &&
    consumerGroup.trim() !== DEFAULT_CONSUMER_GROUP;

  return (
    <>
      <form
        onSubmit={submit}
        className="max-w-4xl border-b border-line px-6 py-4"
      >
        <section aria-label="Detected from your firewalls" className="mb-4">
          <div className="mb-1.5 flex items-center gap-3">
            <h2 className="text-sm font-semibold">
              Detected from your firewalls
            </h2>
            {data && (
              <button
                type="button"
                className="btn-outline h-7 px-2.5 text-xs"
                onClick={() => setWizard({ firewallIds: [] })}
              >
                <Wrench size={13} />
                Set up logging…
              </button>
            )}
          </div>
          {sources.state === 'loading' && (
            <Spinner label="Reading diagnostic settings…" size={14} />
          )}
          {sources.state === 'error' && (
            <p className="text-sm text-fg-muted">
              Couldn&apos;t look up Event Hubs ({sources.message}). You can
              still enter one below.
            </p>
          )}
          {data && detected.length === 0 && dangling.length === 0 && (
            <p className="text-sm text-fg-muted">
              No firewall&apos;s diagnostic settings send logs to an Event Hub
              {unreadable.length
                ? `, and ${unreadable.length} could not be read`
                : ''}
              . Enter a hub below, or set one up in the firewall&apos;s
              Diagnostic settings.
            </p>
          )}
          {detected.length > 0 && (
            <ul className="divide-y divide-line/60 border border-line">
              {detected.map((hub) => {
                const perCategory = hub.eventHub === '';
                return (
                  <li
                    key={`${hub.firewallId}|${hub.namespaceId}|${hub.eventHub}`}
                    className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">
                        {hub.firewallName}
                      </span>
                      <span className="netval block truncate text-fg-muted">
                        {hub.namespaceName} /{' '}
                        {perCategory ? '(one hub per category)' : hub.eventHub}
                      </span>
                    </span>
                    {perCategory ? (
                      <Badge
                        tone="neutral"
                        title="The diagnostic setting names no event hub, so Azure creates one per category. Name a single hub in the setting to read it here."
                      >
                        Needs a single hub
                      </Badge>
                    ) : (
                      <>
                        <CoverageDetail coverage={hub.coverage} />
                        <CoverageBadge coverage={hub.coverage} />
                        {hub.coverage.state === 'incomplete' && (
                          <button
                            type="button"
                            className="btn-ghost h-7 px-2 text-xs"
                            onClick={() =>
                              setWizard({
                                firewallIds: [hub.firewallId],
                                hub: {
                                  namespaceId: hub.namespaceId,
                                  eventHub: hub.eventHub,
                                },
                              })
                            }
                          >
                            <Wrench size={13} />
                            Fix categories
                          </button>
                        )}
                        <button
                          type="button"
                          className="btn-outline h-7 px-2.5 text-xs"
                          onClick={() => use(hub)}
                        >
                          Use
                        </button>
                      </>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
          {dangling.length > 0 && (
            <ul className="mt-2 divide-y divide-line/60 border border-dashed border-line">
              {dangling.map((d) => (
                <li
                  key={`${d.firewallId}|${d.settingName}`}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2"
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">
                      {d.firewallName}
                    </span>
                    <span className="netval block truncate text-fg-muted">
                      {d.settingName} → {d.namespaceId.split('/').pop()}
                    </span>
                  </span>
                  <Badge
                    tone="red"
                    title="Azure keeps a diagnostic setting after the namespace it sends to is deleted. It does nothing and counts towards the limit of five."
                  >
                    <AlertTriangle size={11} />
                    Namespace deleted
                  </Badge>
                  <button
                    type="button"
                    className="btn-outline h-7 px-2.5 text-xs"
                    onClick={() => setCleanup(d)}
                  >
                    <Trash2 size={13} />
                    Clean up…
                  </button>
                </li>
              ))}
            </ul>
          )}
          {withoutHub.length > 0 && (
            <ul className="mt-2 divide-y divide-line/60 border border-dashed border-line">
              {withoutHub.map((fw) => (
                <li
                  key={fw.firewallId}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2"
                >
                  <span className="min-w-0 flex-1 truncate text-sm font-medium">
                    {fw.firewallName}
                  </span>
                  <Badge tone="neutral">Not sending to an event hub</Badge>
                  <button
                    type="button"
                    className="btn-outline h-7 px-2.5 text-xs"
                    onClick={() => setWizard({ firewallIds: [fw.firewallId] })}
                  >
                    <Wrench size={13} />
                    Set up…
                  </button>
                </li>
              ))}
            </ul>
          )}
          {unreadable.length > 0 && detected.length > 0 && (
            <p className="mt-1 text-xs text-fg-muted">
              Diagnostic settings of{' '}
              {unreadable.map((f) => f.firewallName).join(', ')} couldn&apos;t
              be read (needs Reader or Monitoring Reader).
            </p>
          )}
        </section>

        <div className="grid grid-cols-2 gap-x-4 gap-y-3">
          <div>
            <label className="label" htmlFor={`${ids}-ns`}>
              Event Hubs namespace
            </label>
            <input
              id={`${ids}-ns`}
              list={`${ids}-ns-list`}
              className="input font-mono"
              placeholder="contoso-fw.servicebus.windows.net"
              value={namespace}
              onChange={(e) => setNamespace(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <datalist id={`${ids}-ns-list`}>
              {data?.namespaces.map((n) => (
                <option key={n.id} value={n.fqdn}>
                  {n.subscriptionName ?? n.subscriptionId} · {n.location}
                </option>
              ))}
            </datalist>
          </div>
          <div>
            <label className="label" htmlFor={`${ids}-hub`}>
              Event hub
            </label>
            <input
              id={`${ids}-hub`}
              list={`${ids}-hub-list`}
              className="input font-mono"
              placeholder="firewall-logs"
              value={eventHub}
              onChange={(e) => setEventHub(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <datalist id={`${ids}-hub-list`}>
              {hubs.map((h) => (
                <option key={h.name} value={h.name}>
                  {[
                    h.partitionCount && `${h.partitionCount} partitions`,
                    h.retentionHours && `${h.retentionHours} h retention`,
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                </option>
              ))}
            </datalist>
          </div>
          <div>
            <label className="label" htmlFor={`${ids}-cg`}>
              Consumer group
            </label>
            <input
              id={`${ids}-cg`}
              list={`${ids}-cg-list`}
              className="input font-mono"
              value={consumerGroup}
              onChange={(e) => setConsumerGroup(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <datalist id={`${ids}-cg-list`}>
              {(groups.length ? groups : [DEFAULT_CONSUMER_GROUP]).map((g) => (
                <option key={g} value={g} />
              ))}
            </datalist>
          </div>
          <div>
            <span className="label">Start from</span>
            <Segmented<StartPosition>
              label="Start position"
              value={startPosition}
              onChange={setStartPosition}
              options={[
                { value: 'latest', label: 'New events' },
                {
                  value: 'earliest',
                  label: 'Replay retained',
                  title:
                    'Reads everything the hub still holds (1 day by default)',
                },
              ]}
            />
          </div>
        </div>

        {publicAccessDisabled(known?.publicNetworkAccess) && (
          <p role="status" className="mt-3 text-sm text-deny">
            {PUBLIC_ACCESS_DISABLED_READ}
          </p>
        )}
        {basicTierGroup && (
          <p className="mt-3 text-sm text-fg-muted">
            This namespace is Basic tier, which only has the{' '}
            <span className="font-mono">$Default</span> consumer group.
          </p>
        )}
        {forSelection.length > 0 && (
          <ul
            className="mt-3 space-y-1"
            aria-label="Firewalls sending to this hub"
          >
            {forSelection.map(({ fw, coverage }) => (
              <li
                key={fw.firewallId}
                className="flex flex-wrap items-center gap-2 text-sm"
              >
                <span className="font-medium">{fw.firewallName}</span>
                <CoverageBadge coverage={coverage} />
                <CoverageDetail coverage={coverage} />
              </li>
            ))}
          </ul>
        )}
        {data && fqdn && eventHub.trim() && forSelection.length === 0 && (
          <p className="mt-3 text-xs text-fg-muted">
            None of the firewalls checked send logs to this hub, so it may stay
            quiet.
          </p>
        )}

        <p className="mt-3 text-xs text-fg-muted">
          Uses your signed-in identity. It needs the{' '}
          <span className="text-fg-muted">{LOG_RECEIVER_ROLE}</span> role on the
          event hub or namespace. The Basic tier only offers the{' '}
          <span className="font-mono">$Default</span> consumer group.
        </p>
        {error && (
          <p role="alert" className="mt-3 text-sm text-deny">
            {error}
          </p>
        )}
        <div className="mt-3 flex gap-2">
          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? <Spinner size={14} /> : <Plug size={14} />}
            Connect
          </button>
          {onCancel && (
            <button type="button" className="btn-ghost" onClick={onCancel}>
              Cancel
            </button>
          )}
        </div>
      </form>
      {cleanup && (
        <LogCleanupDialog
          target={cleanup}
          onClose={(changed) => {
            setCleanup(undefined);
            if (changed) setReload((n) => n + 1);
          }}
        />
      )}
      {wizard && (
        <LogSetupWizard
          sources={data}
          initialFirewallIds={wizard.firewallIds}
          initialHub={wizard.hub}
          onClose={() => {
            setWizard(undefined);
            // Azure may have changed: read the lists again.
            setReload((n) => n + 1);
          }}
          onDone={(config, waitForRole) => {
            setWizard(undefined);
            setReload((n) => n + 1);
            void onSetupDone(config, waitForRole).catch((err) =>
              setError(errorMessage(err)),
            );
          }}
        />
      )}
    </>
  );
}
