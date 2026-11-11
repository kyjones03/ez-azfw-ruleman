import { useEffect, useMemo, useState } from 'react';
import { Modal, useGuardedClose } from '../components/Modal';
import { SelectMenu } from '../components/Dropdown';
import { TokenPicker } from '../components/TokenPicker';
import { Segmented } from '../components/Segmented';
import { Notice, Spinner } from '../components/ui';
import { errorMessage, useToast } from '../components/Toast';
import { parseList, stableStringify } from '../../shared/rules';
import { resourceName, sameResourceId } from '../../shared/resourceId';
import {
  allocationErrors,
  firewallSettingsErrors,
  type FirewallAllocation,
  type FirewallConfiguration,
  type FirewallSettingsView,
} from '../../shared/resourceSettings';
import type { CandidateStatus } from '../../shared/types';

function AllocationFields({
  view,
  value,
  onChange,
  disabled,
}: {
  view: FirewallSettingsView;
  value?: FirewallAllocation;
  onChange: (value: FirewallAllocation) => void;
  disabled: boolean;
}) {
  const hub = view.skuName === 'AZFW_Hub';
  const allocation: FirewallAllocation = value ?? {
    skuName: hub ? 'AZFW_Hub' : 'AZFW_VNet',
    ipConfigurations: [],
    ...(hub ? { publicIpCount: 2 } : {}),
  };
  const subnetId = allocation.ipConfigurations.find((c) => c.subnet)?.subnet
    ?.id;
  const vnetId = subnetId?.replace(/\/subnets\/[^/]+$/i, '');
  const vnet = view.vnets.find((n) => sameResourceId(n.id, vnetId));
  const publicIds = allocation.ipConfigurations.flatMap((c) =>
    c.publicIPAddress ? [c.publicIPAddress.id] : [],
  );
  const [publicMode, setPublicMode] = useState<'managed' | 'existing'>(
    publicIds.length ? 'existing' : 'managed',
  );
  const pipOptions = view.publicIps.map((p) => ({
    value: p.id,
    label: p.name,
    hint: p.resourceGroup,
  }));
  const setPublicIds = (ids: string[], selectedSubnet = subnetId) => {
    const configs = (ids.length ? ids : ['']).map((id, i) => ({
      name: `AzureFirewallIpConfiguration${i}`,
      ...(id ? { publicIPAddress: { id } } : {}),
      ...(!hub && i === 0 && selectedSubnet
        ? { subnet: { id: selectedSubnet } }
        : {}),
    }));
    return configs;
  };
  return (
    <fieldset disabled={disabled} className="space-y-3 border border-line p-4">
      <legend className="px-2 font-semibold">Start allocation</legend>
      <Notice
        tone="info"
        title="Choose the existing resources used for this firewall"
      >
        Nothing is created. Starting can assign a different private IP. If the
        firewall was stopped outside this app, its original allocation might not
        be available on this device.
      </Notice>
      {hub ? (
        <>
          <div>
            <span className="label">Existing virtual hub</span>
            <SelectMenu
              label="Start virtual hub"
              widthClass="w-full"
              disabled={disabled}
              value={allocation.virtualHubId}
              placeholder="Select a virtual hub…"
              onChange={(id) => onChange({ ...allocation, virtualHubId: id })}
              options={view.hubs.map((h) => ({
                value: h.id,
                label: h.name,
                hint: h.resourceGroup,
              }))}
            />
          </div>
          <div>
            <span className="label">Public IP allocation</span>
            <Segmented
              label="Hub public IP allocation"
              value={publicMode}
              onChange={(mode) => {
                setPublicMode(mode);
                onChange({
                  ...allocation,
                  ipConfigurations:
                    mode === 'managed' ? [] : setPublicIds(publicIds),
                  publicIpCount:
                    mode === 'managed'
                      ? (allocation.publicIpCount ?? 2)
                      : undefined,
                });
              }}
              options={[
                { value: 'managed', label: 'Service managed' },
                { value: 'existing', label: 'Existing public IPs' },
              ]}
            />
          </div>
          {publicMode === 'managed' && (
            <label className="block">
              <span className="label">Service-managed public IP count</span>
              <input
                type="number"
                min={1}
                max={250}
                className="input"
                value={allocation.publicIpCount ?? 2}
                onChange={(e) =>
                  onChange({
                    ...allocation,
                    publicIpCount: Number(e.target.value),
                  })
                }
              />
            </label>
          )}
        </>
      ) : (
        <div>
          <span className="label">Existing virtual network</span>
          <SelectMenu
            label="Start virtual network"
            widthClass="w-full"
            disabled={disabled}
            value={vnetId}
            placeholder="Select a virtual network…"
            options={view.vnets
              .filter((n) => n.subnetId)
              .map((n) => ({
                value: n.id,
                label: n.name,
                hint: n.resourceGroup,
              }))}
            onChange={(id) => {
              const next = view.vnets.find((n) => n.id === id);
              onChange({
                ...allocation,
                ipConfigurations: setPublicIds(publicIds, next?.subnetId),
                managementIpConfiguration: allocation.managementIpConfiguration
                  ? {
                      ...allocation.managementIpConfiguration,
                      ...(next?.managementSubnetId
                        ? { subnet: { id: next.managementSubnetId } }
                        : {}),
                    }
                  : undefined,
              });
            }}
          />
        </div>
      )}
      {(!hub || publicMode === 'existing') && (
        <div>
          <span className="label">Existing data public IPs</span>
          <TokenPicker
            ariaLabel="Start public IPs"
            value={publicIds.join(', ')}
            disabled={disabled}
            options={pipOptions}
            placeholder="Choose public IPs…"
            onChange={(text) =>
              onChange({
                ...allocation,
                ipConfigurations: setPublicIds(parseList(text)),
              })
            }
          />
          <p className="mt-1 text-xs text-fg-faint">
            For forced tunneling, data public IPs can be empty when a management
            public IP is provided. Hub customer-provided IPs are selected here.
          </p>
        </div>
      )}
      {!hub && (
        <div>
          <span className="label">
            Existing management public IP{' '}
            {view.tier === 'Basic' ? '(required)' : '(optional)'}
          </span>
          <SelectMenu
            label="Start management public IP"
            widthClass="w-full"
            disabled={disabled}
            value={
              allocation.managementIpConfiguration?.publicIPAddress?.id ?? ''
            }
            options={[{ value: '', label: 'No management IP' }, ...pipOptions]}
            onChange={(id) =>
              onChange({
                ...allocation,
                managementIpConfiguration: id
                  ? {
                      name: 'AzureFirewallMgmtIpConfiguration',
                      publicIPAddress: { id },
                      ...(vnet?.managementSubnetId
                        ? { subnet: { id: vnet.managementSubnetId } }
                        : {}),
                    }
                  : undefined,
              })
            }
          />
        </div>
      )}
    </fieldset>
  );
}

export function FirewallSettings({
  firewallId,
  startRequested = false,
  onClose,
  onStatus,
}: {
  firewallId: string;
  startRequested?: boolean;
  onClose: () => void;
  onStatus: (status: CandidateStatus) => void;
}) {
  const [view, setView] = useState<FirewallSettingsView>();
  const [initial, setInitial] = useState<FirewallConfiguration>();
  const [value, setValue] = useState<FirewallConfiguration>();
  const [scale, setScale] = useState<'automatic' | 'prescale'>('automatic');
  const [min, setMin] = useState('2');
  const [max, setMax] = useState('4');
  const [prefixes, setPrefixes] = useState<string[]>();
  const [prefixError, setPrefixError] = useState('');
  const [prefixLoading, setPrefixLoading] = useState(false);
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);
  const [saving, setSaving] = useState(false);
  const toast = useToast();
  useEffect(() => {
    let cancelled = false;
    setView(undefined);
    setError('');
    window.api
      .getFirewallSettings(firewallId)
      .then((result) => {
        if (cancelled) return;
        const current = result.draft ?? result.running;
        setView(result);
        setInitial(current);
        setValue({
          ...structuredClone(current),
          ...(startRequested ? { powerState: 'Running' as const } : {}),
        });
        setScale(
          current.minCapacity === null && current.maxCapacity === null
            ? 'automatic'
            : 'prescale',
        );
        setMin(String(current.minCapacity ?? 2));
        setMax(String(current.maxCapacity ?? 4));
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err));
      });
    return () => {
      cancelled = true;
    };
  }, [firewallId, startRequested, retry]);
  const desired = useMemo<FirewallConfiguration | undefined>(
    () =>
      value
        ? {
            ...value,
            minCapacity: scale === 'automatic' ? null : Number(min),
            maxCapacity: scale === 'automatic' ? null : Number(max),
          }
        : undefined,
    [value, scale, min, max],
  );
  const needsAllocation =
    !!view &&
    desired?.powerState === 'Running' &&
    view.running.powerState === 'Stopped';
  const errors =
    desired && view
      ? [
          ...firewallSettingsErrors(desired, view.tier, view.skuName, initial),
          ...(needsAllocation
            ? desired.allocation
              ? allocationErrors(desired.allocation, view.tier)
              : ['Choose the existing resources used to start this firewall.']
            : []),
        ]
      : [];
  const dirty =
    !!desired && stableStringify(desired) !== stableStringify(initial);
  const guard = useGuardedClose(dirty, onClose);
  const close = () => {
    if (!saving) guard.request();
  };
  const save = async () => {
    if (!initial || !desired || !dirty || saving || errors.length) return;
    setSaving(true);
    setError('');
    try {
      onStatus(
        await window.api.stageFirewallSettings(firewallId, initial, desired),
      );
      toast(
        'success',
        'Firewall changes added to the draft. Save and commit to apply them.',
      );
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };
  const loadPrefixes = async () => {
    setPrefixLoading(true);
    setPrefixError('');
    try {
      setPrefixes(await window.api.getLearnedPrefixes(firewallId));
    } catch (err) {
      setPrefixError(errorMessage(err));
    } finally {
      setPrefixLoading(false);
    }
  };
  return (
    <>
      <Modal
        title={`${startRequested ? 'Start firewall' : 'Firewall settings'}${view ? `: ${view.running.name}` : ''}`}
        onClose={close}
        widthClass="max-w-4xl"
        subtitle="Changes stay in your local draft until you review and commit."
        footer={
          <>
            <button className="btn-ghost" disabled={saving} onClick={close}>
              Cancel
            </button>
            <button
              className="btn-primary"
              disabled={saving || !view || !dirty || !!errors.length}
              onClick={save}
            >
              {saving ? <Spinner label="Staging…" /> : 'Save to draft'}
            </button>
          </>
        }
      >
        <div className="space-y-5">
          {error && (
            <Notice
              tone="error"
              title="Couldn't load or stage firewall settings"
              action={
                !view ? (
                  <button
                    className="btn-outline"
                    onClick={() => setRetry((r) => r + 1)}
                  >
                    Try again
                  </button>
                ) : undefined
              }
            >
              {error}
            </Notice>
          )}
          {!view && !error && <Spinner label="Loading firewall settings…" />}
          {!!view?.errors.length && (
            <Notice tone="info" title="Some Azure options are unavailable">
              {view.errors.join('\n')}
            </Notice>
          )}
          {view && value && (
            <>
              {needsAllocation && (
                <AllocationFields
                  view={view}
                  value={value.allocation}
                  disabled={saving}
                  onChange={(next) => setValue({ ...value, allocation: next })}
                />
              )}
              <fieldset
                disabled={saving}
                className="space-y-3 border border-line p-4"
              >
                <legend className="px-2 font-semibold">
                  Learned SNAT prefixes / Route Server
                </legend>
                {!view.policyId && (
                  <p className="text-sm text-fg-muted">
                    This firewall uses classic rules. Associate a Firewall
                    Policy before enabling policy-based SNAT auto-learning.
                  </p>
                )}
                <div>
                  <span className="label">Existing Route Server</span>
                  <SelectMenu
                    label="Azure Route Server"
                    widthClass="w-full"
                    disabled={
                      saving ||
                      view.skuName === 'AZFW_Hub' ||
                      view.tier === 'Basic'
                    }
                    value={
                      view.skuName === 'AZFW_Hub' ? '' : value.routeServerId
                    }
                    placeholder={
                      view.skuName === 'AZFW_Hub'
                        ? 'Built-in Route Server'
                        : 'No Route Server assigned'
                    }
                    options={[
                      {
                        value: '',
                        label:
                          view.skuName === 'AZFW_Hub'
                            ? 'Built-in Route Server'
                            : 'No Route Server assigned',
                      },
                      ...view.routeServers.map((r) => ({
                        value: r.id,
                        label: r.name,
                        hint: r.resourceGroup,
                      })),
                      ...(value.routeServerId &&
                      !view.routeServers.some((r) =>
                        sameResourceId(r.id, value.routeServerId),
                      )
                        ? [
                            {
                              value: value.routeServerId,
                              label: resourceName(value.routeServerId),
                              hint: 'Configured reference',
                            },
                          ]
                        : []),
                    ]}
                    onChange={(id) => setValue({ ...value, routeServerId: id })}
                  />
                </div>
                <p className="text-xs text-fg-muted">
                  For VNet deployments, Route Server must be in the same VNet.
                  Commit the association first, then enable SNAT auto-learning
                  in the associated policy's settings. Learned prefixes are
                  read-only and can take up to 30 minutes to refresh.
                </p>
                <button
                  type="button"
                  className="btn-outline"
                  disabled={saving || prefixLoading || view.tier === 'Basic'}
                  onClick={loadPrefixes}
                >
                  {prefixLoading ? (
                    <Spinner label="Loading prefixes…" />
                  ) : (
                    'Refresh learned prefixes'
                  )}
                </button>
                {prefixError && (
                  <Notice tone="error" title="Couldn't load learned prefixes">
                    {prefixError}
                  </Notice>
                )}
                {prefixes && (
                  <label className="block">
                    <span className="label">
                      {prefixes.length} learned prefixes (read-only)
                    </span>
                    <textarea
                      className="input h-28 font-mono"
                      readOnly
                      value={prefixes.join('\n')}
                    />
                  </label>
                )}
              </fieldset>
              <fieldset
                disabled={saving}
                className="space-y-3 border border-line p-4"
              >
                <legend className="px-2 font-semibold">Scaling options</legend>
                <Segmented
                  label="Firewall scaling mode"
                  value={scale}
                  onChange={setScale}
                  options={[
                    { value: 'automatic', label: 'Service defaults' },
                    {
                      value: 'prescale',
                      label: 'Prescaling',
                      disabled: view.tier === 'Basic',
                    },
                  ]}
                />
                {scale === 'prescale' && (
                  <div className="grid grid-cols-2 gap-4">
                    <label className="block">
                      <span className="label">Minimum capacity</span>
                      <input
                        type="number"
                        min={2}
                        max={50}
                        className="input"
                        value={min}
                        onChange={(e) => setMin(e.target.value)}
                      />
                    </label>
                    <label className="block">
                      <span className="label">Maximum capacity</span>
                      <input
                        type="number"
                        min={2}
                        max={50}
                        className="input"
                        value={max}
                        onChange={(e) => setMax(e.target.value)}
                      />
                    </label>
                  </div>
                )}
                <p className="text-xs text-fg-muted">
                  Standard/Premium capacities must be 2–50, equal or at least 2
                  apart. Equal values disable autoscaling. Extra provisioned
                  capacity adds cost. Customer-provided public IPs in secured
                  hubs are not supported with prescaling.
                </p>
              </fieldset>
              <fieldset
                disabled={saving}
                className="space-y-3 border border-line p-4"
              >
                <legend className="px-2 font-semibold">
                  Maintenance configuration
                </legend>
                <TokenPicker
                  ariaLabel="Maintenance configurations"
                  disabled={
                    saving ||
                    view.running.maintenanceConfigurationIds === undefined
                  }
                  value={(value.maintenanceConfigurationIds ?? []).join(', ')}
                  placeholder="Choose existing maintenance configurations…"
                  options={view.maintenanceConfigurations.map((m) => ({
                    value: m.id,
                    label: m.name,
                    hint: m.resourceGroup,
                    title: m.schedule,
                  }))}
                  onChange={(text) =>
                    setValue({
                      ...value,
                      maintenanceConfigurationIds: parseList(text).sort(),
                    })
                  }
                />
                <p className="text-xs text-fg-muted">
                  Assign or remove existing Resource / NetworkSecurity
                  configurations in this region. Windows must recur daily for at
                  least 5 hours. No schedules are created or edited. Changes can
                  take up to 24 hours to take effect.
                </p>
                {view.running.maintenanceConfigurationIds === undefined && (
                  <p className="text-sm text-deny" role="alert">
                    Assignments could not be read, so maintenance changes are
                    disabled to avoid removing unknown assignments.
                  </p>
                )}
              </fieldset>
              {!!errors.length && (
                <Notice tone="error" title="Fix these settings before staging">
                  {errors.join('\n')}
                </Notice>
              )}
            </>
          )}
        </div>
      </Modal>
      {guard.dialog}
    </>
  );
}
