import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  Loader2,
  MinusCircle,
  XCircle,
  Wrench,
} from 'lucide-react';
import { Badge, Notice, Spinner } from '../components/ui';
import { Modal } from '../components/Modal';
import { SelectMenu } from '../components/Dropdown';
import { Segmented } from '../components/Segmented';
import { errorMessage } from '../components/Toast';
import { normalizeLocation, type SubscriptionInfo } from '../../shared/deploy';
import {
  DEFAULT_HUB_NAME,
  DEFAULT_RETENTION_HOURS,
  DEFAULT_SETTING_NAME,
  defaultCategories,
  eventHubNamespaceError,
  labelOf,
  selectableCategories,
  type HubTier,
  type ProvisionProgress,
  type ProvisionRequest,
  type ProvisionStepState,
  type SetupContext,
  type SetupReview,
} from '../../shared/logProvision';
import type { EventHubInfo, LogSources } from '../../shared/logSources';
import type { LogStreamConfig } from '../../shared/logStream';
import { parseResourceId } from '../../shared/resourceId';

type Step = 'firewalls' | 'destination' | 'categories' | 'review' | 'progress';
const STEPS: { id: Exclude<Step, 'progress'>; label: string }[] = [
  { id: 'firewalls', label: 'Firewalls' },
  { id: 'destination', label: 'Destination' },
  { id: 'categories', label: 'Categories' },
  { id: 'review', label: 'Review' },
];

export function LogSetupWizard({
  sources,
  initialFirewallIds,
  initialHub,
  onClose,
  onDone,
}: {
  sources?: LogSources;
  initialFirewallIds: string[];
  /** Start with an existing hub chosen (for "fix categories"). */
  initialHub?: { namespaceId: string; eventHub: string };
  onClose: () => void;
  /** Connect to the hub that was set up. */
  onDone: (config: LogStreamConfig, waitForRole: boolean) => void;
}) {
  const firewalls = sources?.firewalls ?? [];
  const [step, setStep] = useState<Step>('firewalls');
  const [selected, setSelected] = useState<string[]>(initialFirewallIds);
  const regionOf = (id: string) =>
    normalizeLocation(
      firewalls.find((f) => f.firewallId === id)?.location ?? '',
    );
  const region = selected.length ? regionOf(selected[0]) : '';

  // ── step 1 → 2: what Azure says about the chosen firewalls
  const [context, setContext] = useState<SetupContext>();
  const [contextError, setContextError] = useState('');
  const [loadingContext, setLoadingContext] = useState(false);

  // ── destination
  const [subs, setSubs] = useState<SubscriptionInfo[]>([]);
  const [kind, setKind] = useState<'new' | 'existing'>(
    initialHub ? 'existing' : 'new',
  );
  const [subscriptionId, setSubscriptionId] = useState('');
  const [groups, setGroups] = useState<{ name: string; location: string }[]>(
    [],
  );
  const [groupMode, setGroupMode] = useState<'existing' | 'new'>('existing');
  const [resourceGroup, setResourceGroup] = useState('');
  const [namespaceName, setNamespaceName] = useState('');
  const [nameState, setNameState] = useState<
    | { state: 'idle' }
    | { state: 'checking' }
    | { state: 'ok' }
    | { state: 'taken'; message: string }
  >({ state: 'idle' });
  const [tier, setTier] = useState<HubTier>('Basic');
  const [eventHub, setEventHub] = useState(
    initialHub?.eventHub ?? DEFAULT_HUB_NAME,
  );
  const [namespaceId, setNamespaceId] = useState(initialHub?.namespaceId ?? '');
  const [hubs, setHubs] = useState<EventHubInfo[]>([]);
  const [hubMode, setHubMode] = useState<'existing' | 'new'>(
    initialHub ? 'existing' : 'new',
  );
  const [grantRole, setGrantRole] = useState(true);

  // ── categories
  const [categories, setCategories] = useState<string[]>([]);
  const [settingName, setSettingName] = useState(DEFAULT_SETTING_NAME);

  // ── review / progress
  const [review, setReview] = useState<SetupReview>();
  const [reviewError, setReviewError] = useState('');
  const [reviewing, setReviewing] = useState(false);
  const [progress, setProgress] = useState<ProvisionProgress>();
  const [applyError, setApplyError] = useState('');
  const running =
    progress?.phase === 'running' ||
    (step === 'progress' && !progress && !applyError);

  const chosenNamespaces = useMemo(
    () =>
      (sources?.namespaces ?? []).filter(
        (n) => !region || normalizeLocation(n.location) === region,
      ),
    [sources, region],
  );
  const namespace = chosenNamespaces.find((n) => n.id === namespaceId);

  useEffect(() => {
    let cancelled = false;
    window.api
      .listSubscriptions()
      .then((list) => {
        if (cancelled) return;
        setSubs(list);
        const fromFirewall = selected[0]
          ? parseResourceId(selected[0]).subscriptionId.toLowerCase()
          : '';
        setSubscriptionId(
          (cur) =>
            cur ||
            list.find((s) => s.subscriptionId.toLowerCase() === fromFirewall)
              ?.subscriptionId ||
            list[0]?.subscriptionId ||
            '',
        );
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    setGroups([]);
    if (!subscriptionId) return;
    let cancelled = false;
    window.api
      .listLogResourceGroups(subscriptionId)
      .then((g) => {
        if (cancelled) return;
        setGroups(g);
        setResourceGroup((cur) => (g.some((x) => x.name === cur) ? cur : ''));
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [subscriptionId]);

  // Availability of a new namespace name, once it is well-formed.
  useEffect(() => {
    if (
      kind !== 'new' ||
      !subscriptionId ||
      eventHubNamespaceError(namespaceName)
    ) {
      setNameState({ state: 'idle' });
      return;
    }
    setNameState({ state: 'checking' });
    let cancelled = false;
    const timer = setTimeout(() => {
      window.api
        .checkEventHubNamespaceName(subscriptionId, namespaceName)
        .then((r) => {
          if (cancelled) return;
          setNameState(
            r.available
              ? { state: 'ok' }
              : {
                  state: 'taken',
                  message: r.message ?? 'That name is not available.',
                },
          );
        })
        .catch(() => !cancelled && setNameState({ state: 'idle' }));
    }, 500);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [kind, subscriptionId, namespaceName]);

  useEffect(() => {
    setHubs([]);
    if (kind !== 'existing' || !namespaceId) return;
    let cancelled = false;
    window.api
      .listEventHubs(namespaceId)
      .then((h) => !cancelled && setHubs(h))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [kind, namespaceId]);

  useEffect(() => {
    const off = window.api.onLogSetupProgress(setProgress);
    return off;
  }, []);

  // ── derived
  const offered = useMemo(() => {
    const states = (context?.firewalls ?? []).flatMap((f) =>
      f.state ? [f.state.offeredCategories] : [],
    );
    if (!states.length) return [];
    // Only categories every chosen firewall offers.
    return states[0].filter((c) =>
      states.every((o) => o.some((x) => x.toLowerCase() === c.toLowerCase())),
    );
  }, [context]);
  const groupsOfCategories = useMemo(
    () => selectableCategories(offered),
    [offered],
  );

  const request = (): ProvisionRequest => ({
    firewalls: selected.map((id) => {
      const f = firewalls.find((x) => x.firewallId === id);
      return {
        id,
        name: f?.firewallName ?? id,
        location: f?.location ?? '',
        skuTier: f?.skuTier,
      };
    }),
    destination:
      kind === 'new'
        ? {
            kind: 'new',
            subscriptionId,
            resourceGroup: resourceGroup.trim(),
            createResourceGroup: groupMode === 'new',
            namespaceName: namespaceName.trim(),
            tier,
            eventHub: eventHub.trim(),
            retentionHours: DEFAULT_RETENTION_HOURS,
          }
        : {
            kind: 'existing',
            namespaceId,
            namespaceLocation: namespace?.location ?? '',
            tier: namespace?.skuTier,
            eventHub: eventHub.trim(),
            createEventHub: hubMode === 'new',
            retentionHours: DEFAULT_RETENTION_HOURS,
          },
    categories,
    settingName: settingName.trim(),
    grantRole,
  });

  // ── navigation
  const toDestination = async () => {
    setContextError('');
    setLoadingContext(true);
    try {
      const ctx = await window.api.getLogSetupContext(selected);
      const bad = ctx.firewalls.find((f) => !f.state);
      if (bad) {
        setContextError(
          `Couldn't read ${bad.firewall.name}'s diagnostic settings: ${bad.readError ?? 'unknown error'}`,
        );
        return;
      }
      setContext(ctx);
      const all = ctx.firewalls.flatMap((f) =>
        f.state ? [f.state.offeredCategories] : [],
      );
      const common = all[0].filter((c) =>
        all.every((o) => o.some((x) => x.toLowerCase() === c.toLowerCase())),
      );
      setCategories((cur) => (cur.length ? cur : defaultCategories(common)));
      setStep('destination');
    } catch (err) {
      setContextError(errorMessage(err));
    } finally {
      setLoadingContext(false);
    }
  };

  const toReview = async () => {
    setStep('review');
    setReview(undefined);
    setReviewError('');
    setReviewing(true);
    try {
      setReview(await window.api.reviewLogSetup(request()));
    } catch (err) {
      setReviewError(errorMessage(err));
    } finally {
      setReviewing(false);
    }
  };

  const apply = async () => {
    if (!review) return;
    setApplyError('');
    setProgress(undefined);
    setStep('progress');
    try {
      const result = await window.api.applyLogSetup(request(), review.hash);
      setProgress(result);
    } catch (err) {
      setApplyError(errorMessage(err));
    }
  };

  // ── validation per step
  const mixedRegions = selected.some((id) => regionOf(id) !== region);
  const destinationProblem = (() => {
    if (kind === 'new') {
      if (!subscriptionId) return 'Choose a subscription.';
      if (!resourceGroup.trim()) return 'Choose or enter a resource group.';
      const e = eventHubNamespaceError(namespaceName);
      if (e) return e;
      if (nameState.state === 'taken') return nameState.message;
    } else if (!namespaceId) return 'Choose a namespace.';
    if (!eventHub.trim()) return 'Enter an event hub name.';
    return '';
  })();
  const stepIndex = STEPS.findIndex((s) => s.id === step);
  const showFooterBack =
    step === 'destination' || step === 'categories' || step === 'review';

  const closeGuard = () => {
    if (!running) onClose();
  };

  return (
    <Modal
      title="Set up firewall logging"
      subtitle={
        step === 'progress'
          ? 'Changing Azure'
          : `Step ${stepIndex + 1} of ${STEPS.length}: ${STEPS[stepIndex]?.label}`
      }
      onClose={closeGuard}
      widthClass="max-w-3xl"
      footer={
        <>
          {showFooterBack && (
            <button
              className="btn-ghost mr-auto"
              onClick={() =>
                setStep(
                  step === 'destination'
                    ? 'firewalls'
                    : step === 'categories'
                      ? 'destination'
                      : 'categories',
                )
              }
            >
              Back
            </button>
          )}
          {step !== 'progress' && (
            <button className="btn-ghost" onClick={onClose}>
              Cancel
            </button>
          )}
          {step === 'firewalls' && (
            <button
              className="btn-primary"
              disabled={!selected.length || mixedRegions || loadingContext}
              onClick={toDestination}
            >
              {loadingContext && <Spinner size={14} />}
              Next
            </button>
          )}
          {step === 'destination' && (
            <button
              className="btn-primary"
              disabled={!!destinationProblem}
              onClick={() => setStep('categories')}
            >
              Next
            </button>
          )}
          {step === 'categories' && (
            <button
              className="btn-primary"
              disabled={!categories.length || !settingName.trim()}
              onClick={toReview}
            >
              Review changes
            </button>
          )}
          {step === 'review' && (
            <button
              className="btn-primary"
              disabled={reviewing || !review || review.errors.length > 0}
              onClick={apply}
            >
              <Wrench size={14} />
              Make these changes in Azure
            </button>
          )}
          {step === 'progress' &&
            progress?.phase === 'succeeded' &&
            progress.connect && (
              <>
                <button className="btn-ghost" onClick={onClose}>
                  Close
                </button>
                <button
                  className="btn-primary"
                  autoFocus
                  onClick={() =>
                    onDone(
                      progress.connect!,
                      grantRole && progress.manual.length === 0,
                    )
                  }
                >
                  Connect and view logs
                </button>
              </>
            )}
          {step === 'progress' &&
            (progress?.phase === 'failed' || applyError) && (
              <>
                <button className="btn-ghost" onClick={onClose}>
                  Close
                </button>
                <button className="btn-primary" onClick={toReview}>
                  Review again
                </button>
              </>
            )}
        </>
      }
    >
      {step === 'firewalls' && (
        <section className="space-y-3">
          <p className="text-sm text-fg-muted">
            Choose the firewalls that should send their logs to the same Event
            Hub. An event hub has to be in the same region as the firewall that
            sends to it, so choose firewalls from one region at a time.
          </p>
          {firewalls.length === 0 && (
            <p className="text-sm text-fg-muted">
              No managed firewalls were found. Choose firewalls on the Firewalls
              page first.
            </p>
          )}
          <ul className="divide-y divide-line/60 border border-line">
            {firewalls.map((fw) => {
              const checked = selected.includes(fw.firewallId);
              const blocked =
                !checked &&
                selected.length > 0 &&
                normalizeLocation(fw.location ?? '') !== region;
              const sends = fw.settings.some((s) => s.eventHubNamespaceId);
              return (
                <li key={fw.firewallId}>
                  <label
                    className={`flex items-center gap-3 px-3 py-2 ${blocked ? 'opacity-50' : 'cursor-pointer hover:bg-ink-800'}`}
                    title={
                      blocked
                        ? `In a different region (${fw.location}).`
                        : undefined
                    }
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={blocked}
                      onChange={(e) =>
                        setSelected((cur) =>
                          e.target.checked
                            ? [...cur, fw.firewallId]
                            : cur.filter((id) => id !== fw.firewallId),
                        )
                      }
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">
                        {fw.firewallName}
                      </span>
                      <span className="block text-xs text-fg-muted">
                        {fw.location ?? 'unknown region'}
                        {fw.skuTier ? ` · ${fw.skuTier}` : ''}
                      </span>
                    </span>
                    <Badge tone={sends ? 'green' : 'neutral'}>
                      {sends
                        ? 'Already sends to an event hub'
                        : 'No event hub yet'}
                    </Badge>
                    {fw.readError && (
                      <Badge tone="red">Settings unreadable</Badge>
                    )}
                  </label>
                </li>
              );
            })}
          </ul>
          {contextError && (
            <p role="alert" className="text-sm text-deny">
              {contextError}
            </p>
          )}
        </section>
      )}

      {step === 'destination' && (
        <section className="space-y-4">
          <Segmented<'new' | 'existing'>
            label="Destination"
            value={kind}
            onChange={setKind}
            options={[
              { value: 'new', label: 'Create a new Event Hub' },
              { value: 'existing', label: 'Use an existing namespace' },
            ]}
          />
          <p className="text-xs text-fg-faint">
            Region:{' '}
            <span className="font-mono text-fg-muted">
              {region || 'unknown'}
            </span>
            , the firewall&apos;s region.
          </p>

          {kind === 'new' ? (
            <div className="grid grid-cols-2 gap-x-4 gap-y-3">
              <div>
                <span className="label">Subscription</span>
                <SelectMenu<string>
                  label="Subscription"
                  widthClass="w-full"
                  value={subscriptionId}
                  onChange={setSubscriptionId}
                  options={subs.map((s) => ({
                    value: s.subscriptionId,
                    label: s.name,
                  }))}
                />
              </div>
              <div>
                <span className="label">Resource group</span>
                <Segmented<'existing' | 'new'>
                  label="Resource group"
                  value={groupMode}
                  onChange={(m) => {
                    setGroupMode(m);
                    setResourceGroup('');
                  }}
                  options={[
                    { value: 'existing', label: 'Existing' },
                    { value: 'new', label: 'New' },
                  ]}
                />
                <div className="mt-1.5">
                  {groupMode === 'existing' ? (
                    <SelectMenu<string>
                      label="Resource group"
                      widthClass="w-full"
                      value={resourceGroup}
                      onChange={setResourceGroup}
                      options={groups.map((g) => ({
                        value: g.name,
                        label: g.name,
                        hint: g.location,
                      }))}
                      placeholder="Choose a resource group"
                    />
                  ) : (
                    <input
                      aria-label="New resource group name"
                      className="input font-mono"
                      value={resourceGroup}
                      onChange={(e) => setResourceGroup(e.target.value)}
                      placeholder="rg-firewall-logs"
                      spellCheck={false}
                    />
                  )}
                </div>
              </div>
              <div>
                <label className="label" htmlFor="setup-ns">
                  Namespace name
                </label>
                <input
                  id="setup-ns"
                  className="input font-mono"
                  value={namespaceName}
                  onChange={(e) => setNamespaceName(e.target.value)}
                  placeholder="contoso-fw-logs"
                  spellCheck={false}
                  autoComplete="off"
                />
                <p className="mt-1 min-h-4 text-xs">
                  {namespaceName && eventHubNamespaceError(namespaceName) ? (
                    <span className="text-deny">
                      {eventHubNamespaceError(namespaceName)}
                    </span>
                  ) : nameState.state === 'checking' ? (
                    <span className="text-fg-faint">Checking the name…</span>
                  ) : nameState.state === 'ok' ? (
                    <span className="text-allow">Available</span>
                  ) : nameState.state === 'taken' ? (
                    <span className="text-deny">{nameState.message}</span>
                  ) : (
                    <span className="text-fg-faint">
                      Unique across Azure: 6 to 50 letters, digits and hyphens.
                    </span>
                  )}
                </p>
              </div>
              <div>
                <span className="label">Tier</span>
                <Segmented<HubTier>
                  label="Tier"
                  value={tier}
                  onChange={setTier}
                  options={[
                    {
                      value: 'Basic',
                      label: 'Basic',
                      title:
                        'Cheapest. One day of retention and only the $Default consumer group.',
                    },
                    {
                      value: 'Standard',
                      label: 'Standard',
                      title:
                        'Adds consumer groups. The app creates its own, called ruleman.',
                    },
                  ]}
                />
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-x-4 gap-y-3">
              <div>
                <span className="label">
                  Namespace (same region as the firewall)
                </span>
                <SelectMenu<string>
                  label="Namespace"
                  widthClass="w-full"
                  value={namespaceId}
                  onChange={(id) => {
                    setNamespaceId(id);
                    setEventHub('');
                  }}
                  options={chosenNamespaces.map((n) => ({
                    value: n.id,
                    label: n.name,
                    hint: `${n.subscriptionName ?? n.subscriptionId} · ${n.skuTier ?? ''}`,
                  }))}
                  placeholder={
                    chosenNamespaces.length
                      ? 'Choose a namespace'
                      : `No namespace in ${region}`
                  }
                />
              </div>
              <div>
                <span className="label">Event hub</span>
                <Segmented<'existing' | 'new'>
                  label="Event hub"
                  value={hubMode}
                  onChange={(m) => {
                    setHubMode(m);
                    setEventHub(m === 'new' ? DEFAULT_HUB_NAME : '');
                  }}
                  options={[
                    { value: 'new', label: 'Create new' },
                    { value: 'existing', label: 'Use existing' },
                  ]}
                />
                <div className="mt-1.5">
                  {hubMode === 'existing' ? (
                    <SelectMenu<string>
                      label="Event hub"
                      widthClass="w-full"
                      value={eventHub}
                      onChange={setEventHub}
                      options={hubs.map((h) => ({
                        value: h.name,
                        label: h.name,
                      }))}
                      placeholder={
                        namespaceId
                          ? 'Choose an event hub'
                          : 'Choose a namespace first'
                      }
                    />
                  ) : (
                    <input
                      aria-label="New event hub name"
                      className="input font-mono"
                      value={eventHub}
                      onChange={(e) => setEventHub(e.target.value)}
                      spellCheck={false}
                    />
                  )}
                </div>
              </div>
            </div>
          )}

          {kind === 'new' && (
            <div>
              <label className="label" htmlFor="setup-hub">
                Event hub name
              </label>
              <input
                id="setup-hub"
                className="input w-64 font-mono"
                value={eventHub}
                onChange={(e) => setEventHub(e.target.value)}
                spellCheck={false}
              />
            </div>
          )}

          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={grantRole}
              onChange={(e) => setGrantRole(e.target.checked)}
            />
            <span>
              Also give me the{' '}
              <span className="text-fg">Azure Event Hubs Data Receiver</span>{' '}
              role on this event hub (this hub only). Without it you can create
              the hub but not read from it.
            </span>
          </label>
          {destinationProblem && selected.length > 0 && (
            <p className="text-xs text-fg-faint">{destinationProblem}</p>
          )}
        </section>
      )}

      {step === 'categories' && (
        <section className="space-y-4">
          <p className="text-sm text-fg-muted">
            The firewalls send the checked categories. The rule categories are
            what the log view is for.
          </p>
          {(
            [
              ['Rules and decisions', groupsOfCategories.core],
              ['Recommended', groupsOfCategories.recommended],
              [
                'Troubleshooting (a lot of data, needs an extra switch on the firewall)',
                groupsOfCategories.troubleshooting,
              ],
            ] as const
          ).map(([title, list]) =>
            list.length ? (
              <fieldset key={title}>
                <legend className="label">{title}</legend>
                <div className="flex flex-wrap gap-x-5 gap-y-1">
                  {list.map((c) => (
                    <label
                      key={c}
                      className="flex items-center gap-1.5 text-sm"
                    >
                      <input
                        type="checkbox"
                        checked={categories.includes(c)}
                        onChange={(e) =>
                          setCategories((cur) =>
                            e.target.checked
                              ? [...cur, c]
                              : cur.filter((x) => x !== c),
                          )
                        }
                      />
                      {labelOf(c)}
                    </label>
                  ))}
                </div>
              </fieldset>
            ) : null,
          )}
          <div>
            <label className="label" htmlFor="setup-setting">
              Diagnostic setting name
            </label>
            <input
              id="setup-setting"
              className="input w-72 font-mono"
              value={settingName}
              onChange={(e) => setSettingName(e.target.value)}
              spellCheck={false}
            />
            <p className="mt-1 text-xs text-fg-faint">
              If a firewall already has a setting that uses this hub&apos;s
              access rule, that one is updated instead. Other destinations in a
              setting are never removed.
            </p>
          </div>
        </section>
      )}

      {step === 'review' && (
        <section className="space-y-3">
          {reviewing && <Spinner label="Checking what would change…" />}
          {reviewError && (
            <Notice tone="error" title="Couldn't prepare the changes">
              {reviewError}
            </Notice>
          )}
          {review && (
            <>
              <Notice
                tone="info"
                title="This changes Azure directly, not your draft."
              >
                Nothing below has been done yet.
              </Notice>
              {review.errors.length > 0 && (
                <Notice tone="error" title="This can't run yet">
                  {review.errors.join('\n')}
                </Notice>
              )}
              <ol className="list-decimal space-y-1 pl-5 text-sm">
                {review.lines.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ol>
              {review.warnings.map((w) => (
                <p key={w} className="flex gap-2 text-sm text-fg-muted">
                  <AlertTriangle
                    size={14}
                    className="mt-0.5 shrink-0 text-candidate"
                  />
                  {w}
                </p>
              ))}
              {review.cost && (
                <p className="text-sm text-fg-muted">
                  Cost of the new namespace: {review.cost}.
                </p>
              )}
              <div>
                <h3 className="label">Permissions you need</h3>
                <ul className="space-y-0.5 text-sm text-fg-muted">
                  {review.permissions.map((p) => (
                    <li key={p.what}>
                      {p.what}: <span className="text-fg">{p.permission}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-1 text-xs text-fg-faint">
                  If you can&apos;t assign roles, everything else still runs and
                  you&apos;re told how to finish by hand.
                </p>
              </div>
            </>
          )}
        </section>
      )}

      {step === 'progress' && (
        <section className="space-y-3">
          {applyError && (
            <Notice tone="error" title="Couldn't make the changes">
              {applyError}
            </Notice>
          )}
          {!progress && !applyError && <Spinner label="Starting…" />}
          {progress && (
            <ul className="space-y-1.5" aria-label="Progress">
              {progress.steps.map((s) => (
                <li key={s.label} className="flex items-start gap-2 text-sm">
                  <StepIcon state={s.state} />
                  <span>
                    {s.label}
                    {s.detail && (
                      <span
                        className={`block text-xs ${s.state === 'failed' ? 'text-deny' : 'text-fg-muted'}`}
                      >
                        {s.detail}
                      </span>
                    )}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {progress?.phase === 'failed' && (
            <Notice tone="error" title="Stopped at the first problem">
              {progress.error}
              {'\n'}Nothing after this step was changed. You can fix it and run
              the setup again; what already exists is left alone.
            </Notice>
          )}
          {progress?.manual.map((m) => (
            <Notice key={m} tone="info" title="One step is left for you">
              {m}
            </Notice>
          ))}
          {progress?.phase === 'succeeded' && (
            <Notice tone="info" title="Done">
              New diagnostic settings can take 10 to 15 minutes to deliver the
              first events. A role that was just assigned can take a few minutes
              to apply; the log view waits for it.
            </Notice>
          )}
        </section>
      )}
    </Modal>
  );
}

function StepIcon({ state }: { state: ProvisionStepState }) {
  const common = { size: 16 };
  switch (state) {
    case 'done':
      return (
        <CheckCircle2
          {...common}
          className="mt-0.5 shrink-0 text-allow"
          aria-label="Done"
        />
      );
    case 'running':
      return (
        <Loader2
          {...common}
          className="mt-0.5 shrink-0 animate-spin text-azure"
          aria-label="Running"
        />
      );
    case 'failed':
      return (
        <XCircle
          {...common}
          className="mt-0.5 shrink-0 text-deny"
          aria-label="Failed"
        />
      );
    case 'manual':
      return (
        <AlertTriangle
          {...common}
          className="mt-0.5 shrink-0 text-candidate"
          aria-label="Needs you"
        />
      );
    case 'skipped':
      return (
        <MinusCircle
          {...common}
          className="mt-0.5 shrink-0 text-fg-faint"
          aria-label="Skipped"
        />
      );
    default:
      return (
        <Circle
          {...common}
          className="mt-0.5 shrink-0 text-fg-faint"
          aria-label="Waiting"
        />
      );
  }
}
