import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  Cloud,
  Network,
  Plus,
  Shield,
  Trash2,
  Waypoints,
} from 'lucide-react';
import { Modal } from '../components/Modal';
import { SelectMenu } from '../components/Dropdown';
import { Segmented } from '../components/Segmented';
import { QuipSpinner } from '../components/QuipSpinner';
import { Notice } from '../components/ui';
import { errorMessage } from '../components/Toast';
import { isPublicRange, suggestSubnet } from '../../shared/cidr';
import { nameError, tagError } from '../../shared/naming';
import {
  FIREWALL_SUBNET,
  MANAGEMENT_SUBNET,
  TIERS,
  addressSpaceError,
  firewallNameError,
  normalizeLocation,
  sameLocation,
  subnetErrors,
  supportedZones,
  validateDeployRequest,
  type DeployContext,
  type DeployRequest,
  type FirewallTier,
  type SubscriptionInfo,
  type ThreatIntelMode,
} from '../../shared/deploy';
import { sameResourceId } from '../../shared/resourceId';

type TargetKind = DeployRequest['target']['kind'];
type RgChoice = { mode: 'existing' | 'new'; name: string };
const STEPS = ['Basics', 'Network', 'Policy', 'Review'] as const;

/**
 * Existing-or-new resource group. With `inherited`, it shows the firewall's group and any change
 * becomes an override; `onReset` goes back to following the firewall's group.
 */
function ResourceGroupPicker({
  id,
  value,
  onChange,
  groups,
  suggested,
  inherited,
  onReset,
  error,
}: {
  id: string;
  value: RgChoice;
  onChange: (value: RgChoice) => void;
  groups: { name: string; location: string }[];
  suggested: string;
  inherited?: boolean;
  onReset?: () => void;
  error?: string;
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-3">
        <Segmented
          label="Existing or new resource group"
          value={value.mode}
          onChange={(mode) =>
            onChange({
              mode,
              name: mode === 'existing' ? (groups[0]?.name ?? '') : '',
            })
          }
          options={[
            { value: 'existing', label: 'Existing' },
            { value: 'new', label: 'Create new' },
          ]}
        />
        {onReset && (
          <button
            type="button"
            className="btn-ghost px-2 text-xs"
            onClick={onReset}
          >
            Use firewall's group
          </button>
        )}
      </div>
      {value.mode === 'existing' ? (
        <SelectMenu
          label="Resource group"
          widthClass="w-full"
          value={value.name}
          onChange={(name) => onChange({ mode: 'existing', name })}
          placeholder={
            groups.length ? 'Select a resource group…' : 'No resource groups'
          }
          options={groups.map((g) => ({
            value: g.name,
            label: g.name,
            hint: g.location,
          }))}
        />
      ) : (
        <input
          id={id}
          className="input"
          aria-label="New resource group name"
          placeholder={suggested}
          value={value.name}
          onChange={(e) => onChange({ mode: 'new', name: e.target.value })}
          aria-invalid={!!error}
        />
      )}
      {error && (
        <p className="text-xs text-deny" role="alert">
          {error}
        </p>
      )}
      {inherited && (
        <p className="text-xs text-fg-faint">
          Same as the firewall's resource group (set in Basics).
        </p>
      )}
    </div>
  );
}

function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string;
  htmlFor?: string;
  hint?: ReactNode;
  /** Shown instead of the hint when set. */
  error?: string;
  children: ReactNode;
}) {
  return (
    <div>
      <label className="label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {error ? (
        <p className="mt-0.5 text-xs text-deny" role="alert">
          {error}
        </p>
      ) : (
        hint && <p className="mt-0.5 text-xs text-fg-faint">{hint}</p>
      )}
    </div>
  );
}

function TargetCard({
  active,
  icon,
  title,
  text,
  onClick,
}: {
  active: boolean;
  icon: ReactNode;
  title: string;
  text: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`flex flex-1 flex-col items-start gap-1 border p-3 text-left transition-colors ${active ? 'border-azure bg-azure/[0.08]' : 'border-line hover:border-fg-faint'}`}
    >
      <span className={active ? 'text-azure' : 'text-fg-muted'}>{icon}</span>
      <span className="text-sm font-semibold text-fg">{title}</span>
      <span className="text-xs text-fg-muted">{text}</span>
    </button>
  );
}

export function DeployWizard({
  defaultSubscriptionId,
  onClose,
  onDeploy,
}: {
  defaultSubscriptionId?: string;
  onClose: () => void;
  onDeploy: (request: DeployRequest) => void;
}) {
  const [step, setStep] = useState(0);
  const [subscriptions, setSubscriptions] = useState<SubscriptionInfo[]>([]);
  const [subscriptionId, setSubscriptionId] = useState<string>();
  const [ctx, setCtx] = useState<DeployContext>();
  const [loadError, setLoadError] = useState('');
  const [reloadKey, setReloadKey] = useState(0);
  const [registering, setRegistering] = useState(false);
  const [registerMessage, setRegisterMessage] = useState('');

  const [name, setName] = useState('');
  const [tier, setTier] = useState<FirewallTier>('Standard');
  const [fwRg, setFwRg] = useState<RgChoice>({ mode: 'existing', name: '' });
  const [location, setLocation] = useState('');
  const [zones, setZones] = useState<string[]>([]);
  const [tags, setTags] = useState<
    { id: number; key: string; value: string }[]
  >([]);
  const nextTagId = useRef(0);
  const [managementNic, setManagementNic] = useState(false);

  const [targetKind, setTargetKind] = useState<TargetKind>('vnet-existing');
  const [vnetId, setVnetId] = useState<string>();
  const [subnetPrefix, setSubnetPrefix] = useState('');
  const [mgmtPrefix, setMgmtPrefix] = useState('');
  // null means "same as the firewall's resource group".
  const [vnetRg, setVnetRg] = useState<RgChoice | null>(null);
  const [vnetName, setVnetName] = useState('');
  const [copied, setCopied] = useState(false);
  const [zoneNotice, setZoneNotice] = useState('');
  const [addressSpace, setAddressSpace] = useState('10.0.0.0/16');
  const [newSubnet, setNewSubnet] = useState('10.0.0.0/26');
  const [newMgmtSubnet, setNewMgmtSubnet] = useState('10.0.0.64/26');
  const [hubId, setHubId] = useState<string>();
  const [publicIpCount, setPublicIpCount] = useState('1');

  const [policyKind, setPolicyKind] = useState<'existing' | 'new'>('new');
  const [policyId, setPolicyId] = useState<string>();
  const [policyName, setPolicyName] = useState('');
  const [threatIntel, setThreatIntel] = useState<ThreatIntelMode>('Alert');
  const [basePolicyId, setBasePolicyId] = useState<string>();
  const [policyRg, setPolicyRg] = useState<RgChoice | null>(null);

  const [addToManaged, setAddToManaged] = useState(true);
  const [confirmName, setConfirmName] = useState('');

  useEffect(() => {
    let cancelled = false;
    window.api
      .listSubscriptions()
      .then((subs) => {
        if (cancelled) return;
        setSubscriptions(subs);
        const preferred =
          subs.find((s) => s.subscriptionId === defaultSubscriptionId) ??
          subs[0];
        setSubscriptionId(preferred?.subscriptionId);
      })
      .catch((err) => !cancelled && setLoadError(errorMessage(err)));
    return () => {
      cancelled = true;
    };
  }, [defaultSubscriptionId]);

  useEffect(() => {
    if (!subscriptionId) return;
    setCtx(undefined);
    setLoadError('');
    setVnetId(undefined);
    setHubId(undefined);
    setPolicyId(undefined);
    setBasePolicyId(undefined);
    setVnetRg(null);
    setPolicyRg(null);
    // Switching subscriptions quickly must not let an older reply win.
    let cancelled = false;
    window.api
      .getDeployContext(subscriptionId)
      .then((c) => {
        if (cancelled) return;
        setCtx(c);
        const first = c.resourceGroups[0];
        setFwRg(
          first
            ? { mode: 'existing', name: first.name }
            : { mode: 'new', name: '' },
        );
        setLocation(
          first && c.locations.some((l) => sameLocation(l, first.location))
            ? normalizeLocation(first.location)
            : (c.locations[0] ?? ''),
        );
      })
      .catch((err) => !cancelled && setLoadError(errorMessage(err)));
    return () => {
      cancelled = true;
    };
  }, [subscriptionId, reloadKey]);

  const isVnet = targetKind !== 'hub';
  const mgmtRequired = tier === 'Basic' && isVnet;
  const useMgmt = isVnet && (managementNic || mgmtRequired);
  const regionVnets =
    ctx?.vnets.filter((v) => sameLocation(v.location, location)) ?? [];
  const regionHubs =
    ctx?.hubs.filter((h) => sameLocation(h.location, location)) ?? [];
  const vnet = regionVnets.find((v) => sameResourceId(v.id, vnetId));
  const hasFwSubnet = vnet?.subnets.some((s) => s.name === FIREWALL_SUBNET);
  const hasMgmtSubnet = vnet?.subnets.some((s) => s.name === MANAGEMENT_SUBNET);

  // The VNet or hub must share the firewall's region; drop a selection from another region.
  useEffect(() => {
    if (!ctx) return;
    if (
      vnetId &&
      !ctx.vnets.some(
        (v) =>
          sameResourceId(v.id, vnetId) && sameLocation(v.location, location),
      )
    )
      setVnetId(undefined);
    if (
      hubId &&
      !ctx.hubs.some(
        (h) =>
          sameResourceId(h.id, hubId) && sameLocation(h.location, location),
      )
    )
      setHubId(undefined);
  }, [ctx, location, vnetId, hubId]);

  // Suggest free /26 blocks when an existing VNet lacks the firewall subnets.
  useEffect(() => {
    if (!vnet) return;
    const used = vnet.subnets
      .map((s) => s.prefix)
      .filter((p): p is string => !!p);
    const fw = hasFwSubnet
      ? undefined
      : suggestSubnet(vnet.addressPrefixes, used);
    setSubnetPrefix(fw ?? '');
    setMgmtPrefix(
      hasMgmtSubnet
        ? ''
        : (suggestSubnet(vnet.addressPrefixes, fw ? [...used, fw] : used) ??
            ''),
    );
  }, [vnet, hasFwSubnet, hasMgmtSubnet]);

  useEffect(() => {
    if (tier === 'Basic') setThreatIntel('Alert');
  }, [tier]);

  // Picking an existing resource group moves the region to that group's region; it can still be changed.
  useEffect(() => {
    if (fwRg.mode !== 'existing') return;
    const rg = ctx?.resourceGroups.find((g) => g.name === fwRg.name);
    if (rg && ctx?.locations.some((l) => sameLocation(l, rg.location)))
      setLocation(normalizeLocation(rg.location));
  }, [fwRg.mode, fwRg.name, ctx]);

  // New resources get generic, region-based names unless the user types their own.
  const suggestedVnet = `vnet-hub-${location || 'region'}`;
  const suggestedRg = `rg-hub-${location || 'region'}`;
  const effectiveVnetName = vnetName.trim() || suggestedVnet;
  const rgNameOf = (c: RgChoice, suggested = suggestedRg) =>
    c.mode === 'new' ? c.name.trim() || suggested : c.name.trim();
  const effectiveRg = rgNameOf(fwRg);
  const vnetRgChoice = vnetRg ?? fwRg;
  const effectiveVnetRg = vnetRg
    ? rgNameOf(vnetRg, `rg-network-${location || 'region'}`)
    : effectiveRg;
  const policyRgChoice = policyRg ?? fwRg;
  const effectivePolicyRg = policyRg
    ? rgNameOf(policyRg, `rg-policy-${location || 'region'}`)
    : effectiveRg;

  const request: DeployRequest | undefined = useMemo(() => {
    if (!subscriptionId) return undefined;
    const target: DeployRequest['target'] =
      targetKind === 'vnet-existing'
        ? {
            kind: targetKind,
            vnetId: vnetId ?? '',
            subnetPrefix: hasFwSubnet ? undefined : subnetPrefix,
            managementSubnetPrefix:
              useMgmt && !hasMgmtSubnet ? mgmtPrefix : undefined,
          }
        : targetKind === 'vnet-new'
          ? {
              kind: targetKind,
              resourceGroup: effectiveVnetRg,
              createResourceGroup: vnetRgChoice.mode === 'new',
              vnetName: effectiveVnetName,
              addressSpace: addressSpace.trim(),
              subnetPrefix: newSubnet.trim(),
              managementSubnetPrefix: useMgmt
                ? newMgmtSubnet.trim()
                : undefined,
            }
          : {
              kind: 'hub',
              hubId: hubId ?? '',
              publicIpCount: Number(publicIpCount),
            };
    return {
      subscriptionId,
      name: name.trim(),
      tier,
      resourceGroup: effectiveRg,
      createResourceGroup: fwRg.mode === 'new',
      location,
      zones,
      tags: Object.fromEntries(
        tags.filter((t) => t.key.trim()).map((t) => [t.key.trim(), t.value]),
      ),
      managementNic: useMgmt,
      target,
      policy:
        policyKind === 'existing'
          ? { kind: 'existing', policyId: policyId ?? '' }
          : {
              kind: 'new',
              name: (policyName || `${name.trim()}-policy`).trim(),
              threatIntelMode: threatIntel,
              basePolicyId,
              resourceGroup: effectivePolicyRg,
              createResourceGroup: policyRgChoice.mode === 'new',
            },
      addToManaged,
    };
  }, [
    subscriptionId,
    targetKind,
    vnetId,
    hasFwSubnet,
    subnetPrefix,
    useMgmt,
    hasMgmtSubnet,
    mgmtPrefix,
    effectiveRg,
    fwRg.mode,
    effectiveVnetRg,
    vnetRgChoice.mode,
    effectivePolicyRg,
    policyRgChoice.mode,
    location,
    effectiveVnetName,
    addressSpace,
    newSubnet,
    newMgmtSubnet,
    hubId,
    publicIpCount,
    name,
    tier,
    zones,
    tags,
    policyKind,
    policyId,
    policyName,
    threatIntel,
    basePolicyId,
    addToManaged,
  ]);

  const errors = useMemo(() => {
    if (!request || !ctx) return [];
    const all = validateDeployRequest(request, ctx);
    // Duplicate tag names collapse when the request is built, so catch them on the raw rows.
    const seen = new Set<string>();
    for (const t of tags) {
      const k = t.key.trim().toLowerCase();
      if (!k) continue;
      if (seen.has(k))
        all.push(
          `Tag "${t.key.trim()}" is listed more than once (tag names aren't case-sensitive).`,
        );
      seen.add(k);
    }
    return all;
  }, [request, ctx, tags]);

  // Inline errors: only for fields the user has typed in, so a fresh form isn't covered in red.
  const typed = (v: string) => v.trim() !== '';
  const nameFieldError = typed(name)
    ? firewallNameError(name.trim(), isVnet, useMgmt)
    : undefined;
  const rgFieldError = (c: RgChoice, label: string) =>
    c.mode === 'new' && typed(c.name)
      ? nameError('resourceGroup', c.name.trim(), label)
      : undefined;
  const vnetNameError = typed(vnetName)
    ? nameError('vnet', vnetName.trim())
    : undefined;
  const addressSpaceFieldError = addressSpaceError(addressSpace, useMgmt);
  const newSubnetError = addressSpaceFieldError
    ? undefined
    : subnetErrors(FIREWALL_SUBNET, newSubnet, [addressSpace.trim()])[0];
  const newMgmtSubnetError =
    addressSpaceFieldError || !useMgmt
      ? undefined
      : subnetErrors(
          MANAGEMENT_SUBNET,
          newMgmtSubnet,
          [addressSpace.trim()],
          [{ name: FIREWALL_SUBNET, prefix: newSubnet.trim() }],
        )[0];
  const vnetUsed =
    vnet?.subnets
      .filter((s) => s.prefix)
      .map((s) => ({ name: s.name, prefix: s.prefix! })) ?? [];
  const existingSubnetError =
    vnet && !hasFwSubnet
      ? subnetErrors(
          FIREWALL_SUBNET,
          subnetPrefix,
          vnet.addressPrefixes,
          vnetUsed,
        )[0]
      : undefined;
  const existingMgmtSubnetError =
    vnet && useMgmt && !hasMgmtSubnet
      ? subnetErrors(MANAGEMENT_SUBNET, mgmtPrefix, vnet.addressPrefixes, [
          ...vnetUsed,
          ...(hasFwSubnet
            ? []
            : [{ name: FIREWALL_SUBNET, prefix: subnetPrefix.trim() }]),
        ])[0]
      : undefined;
  const effectivePolicyName = (policyName || `${name.trim()}-policy`).trim();
  const policyNameError =
    typed(policyName) || typed(name)
      ? nameError('policy', effectivePolicyName)
      : undefined;
  const publicSpace =
    !addressSpaceFieldError && isPublicRange(addressSpace.trim());
  const tierPolicies = ctx?.policies.filter((p) => p.tier === tier) ?? [];
  const canDeploy =
    !!request && !!ctx && !errors.length && confirmName === request.name;
  const networkReady = ctx?.network.state === 'registered';

  // Availability zones depend on the region chosen in Basics.
  const zoneOptions = ctx ? supportedZones(location, ctx) : undefined;
  const regionName = location
    ? (ctx?.locationNames?.[normalizeLocation(location)] ?? location)
    : 'this region';
  const zoneHint = !location
    ? 'Choose a region to see which zones it supports.'
    : !zoneOptions
      ? 'Spread instances across zones for a 99.99% SLA.'
      : zoneOptions.length
        ? `${regionName} supports zones ${zoneOptions.join(', ')}. Spreading across them gives a 99.99% SLA.`
        : `${regionName} has no availability zones, so the firewall is deployed without them.`;
  const zoneKey = zoneOptions?.join(',');

  // Drop zones the chosen region doesn't offer, and say so.
  useEffect(() => {
    if (!zoneOptions) return;
    const removed = zones.filter((z) => !zoneOptions.includes(z));
    if (!removed.length) return;
    setZones(zones.filter((z) => zoneOptions.includes(z)));
    setZoneNotice(
      `Removed ${removed.length === 1 ? 'zone' : 'zones'} ${removed.join(', ')}: ${regionName} ${zoneOptions.length ? `only offers zones ${zoneOptions.join(', ')}` : "doesn't offer availability zones"}.`,
    );
    // Only when the region's zones change; zoneKey captures zoneOptions' contents.
  }, [zoneKey, regionName]);

  const registerNetwork = async () => {
    if (!subscriptionId) return;
    setRegistering(true);
    setRegisterMessage('');
    try {
      const result = await window.api.registerNetworkProvider(subscriptionId);
      if (result.state === 'registered') setReloadKey((k) => k + 1);
      else
        setRegisterMessage(
          result.message ?? 'Registration is still in progress.',
        );
    } catch (err) {
      setRegisterMessage(errorMessage(err));
    } finally {
      setRegistering(false);
    }
  };

  const subscriptionName =
    subscriptions.find((s) => s.subscriptionId === subscriptionId)?.name ??
    'this subscription';

  const body = loadError ? (
    <Notice
      tone="error"
      title={`Couldn't load ${subscriptionName}`}
      action={
        <button
          className="btn-outline"
          onClick={() => setReloadKey((k) => k + 1)}
        >
          Try again
        </button>
      }
    >
      {loadError}
    </Notice>
  ) : !ctx ? (
    <div className="flex h-48 items-center justify-center">
      <QuipSpinner topic="deploy" />
    </div>
  ) : ctx.network.state === 'blocked' ? (
    <Notice
      tone="error"
      title={`${subscriptionName} can't host Azure Firewall`}
    >
      {ctx.network.message ??
        "This subscription's offer doesn't allow Azure networking resources. Choose a different subscription."}
      <span className="mt-2 block text-fg-faint">
        Switch subscriptions with the menu at the bottom of this window.
      </span>
    </Notice>
  ) : ctx.network.state === 'not-registered' ||
    ctx.network.state === 'registering' ? (
    <Notice
      tone="info"
      title="Azure networking isn't turned on for this subscription yet"
      action={
        <button
          className="btn-primary"
          onClick={registerNetwork}
          disabled={registering}
        >
          {registering
            ? 'Registering… this can take a minute'
            : 'Register Microsoft.Network'}
        </button>
      }
    >
      Firewalls, virtual networks and public IPs come from the Microsoft.Network
      resource provider, which hasn't been registered for this subscription.
      Registering it is free and needs Contributor access.
      {registerMessage && (
        <span className="mt-2 block text-fg">{registerMessage}</span>
      )}
    </Notice>
  ) : ctx.network.state === 'unknown' ? (
    <Notice
      tone="error"
      title="Couldn't check networking for this subscription"
      action={
        <button
          className="btn-outline"
          onClick={() => setReloadKey((k) => k + 1)}
        >
          Try again
        </button>
      }
    >
      {ctx.network.message}
    </Notice>
  ) : step === 0 ? (
    <div className="grid grid-cols-2 gap-4">
      {zoneNotice && (
        <div className="col-span-2">
          <Notice
            tone="info"
            title="Availability zones updated"
            action={
              <button className="btn-ghost" onClick={() => setZoneNotice('')}>
                Dismiss
              </button>
            }
          >
            {zoneNotice}
          </Notice>
        </div>
      )}
      <Field
        label="Firewall name"
        htmlFor="fw-name"
        hint="1-80 characters: letters, digits, _ . - (no spaces). Public IPs are named after it."
        error={nameFieldError}
      >
        <input
          id="fw-name"
          className="input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="fw-hub-eastus"
          aria-invalid={!!nameFieldError}
          autoFocus
        />
      </Field>
      <Field label="Tier">
        <Segmented
          label="Tier"
          value={tier}
          onChange={setTier}
          options={TIERS.map((t) => ({ value: t, label: t }))}
        />
      </Field>
      <Field
        label="Resource group"
        htmlFor="fw-rg"
        hint="For the firewall and its public IPs."
      >
        <ResourceGroupPicker
          id="fw-rg"
          value={fwRg}
          onChange={setFwRg}
          groups={ctx.resourceGroups}
          suggested={suggestedRg}
          error={rgFieldError(fwRg, 'Resource group name')}
        />
      </Field>
      <Field
        label="Region"
        hint={
          fwRg.mode === 'existing'
            ? "Defaults to the resource group's region. Everything created with the firewall uses this region."
            : 'Everything created with the firewall uses this region.'
        }
      >
        <SelectMenu
          label="Region"
          widthClass="w-full"
          value={location}
          onChange={setLocation}
          options={ctx.locations.map((l) => ({
            value: l,
            label: ctx.locationNames?.[l] ?? l,
            hint: ctx.locationZones?.[l]?.length ? `${l} · zones` : l,
          }))}
        />
      </Field>
      <Field label="Availability zones" hint={zoneHint}>
        <div className="flex gap-2">
          {['1', '2', '3'].map((z) => {
            const unavailable = !!zoneOptions && !zoneOptions.includes(z);
            return (
              <label
                key={z}
                className={`flex items-center gap-1.5 text-sm ${unavailable ? 'text-fg-faint' : 'text-fg-muted'}`}
                title={
                  unavailable
                    ? `Zone ${z} isn't available in ${regionName}.`
                    : undefined
                }
              >
                <input
                  type="checkbox"
                  className="accent-azure"
                  disabled={unavailable}
                  checked={zones.includes(z)}
                  onChange={(e) =>
                    setZones((cur) =>
                      e.target.checked
                        ? [...cur, z].sort()
                        : cur.filter((x) => x !== z),
                    )
                  }
                />
                Zone {z}
              </label>
            );
          })}
        </div>
      </Field>
      <Field
        label="Management NIC"
        hint={
          mgmtRequired
            ? 'Required for Basic firewalls.'
            : 'Needed for forced tunneling. Uses AzureFirewallManagementSubnet.'
        }
      >
        <label className="flex items-center gap-2 text-sm text-fg-muted">
          <input
            type="checkbox"
            className="accent-azure"
            disabled={!isVnet || mgmtRequired}
            checked={useMgmt}
            onChange={(e) => setManagementNic(e.target.checked)}
          />
          {isVnet
            ? 'Enable management NIC'
            : 'Not applicable to Virtual WAN hubs'}
        </label>
      </Field>
      <div className="col-span-2">
        <span className="label">Tags</span>
        <div className="space-y-1.5">
          {tags.map((t, i) => {
            const rowError =
              t.key.trim() || t.value
                ? tagError(t.key.trim(), t.value)
                : undefined;
            return (
              <div key={t.id}>
                <div className="flex gap-2">
                  <input
                    className="input"
                    placeholder="Name"
                    aria-label="Tag name"
                    value={t.key}
                    onChange={(e) =>
                      setTags((all) =>
                        all.map((x, j) =>
                          j === i ? { ...x, key: e.target.value } : x,
                        ),
                      )
                    }
                  />
                  <input
                    className="input"
                    placeholder="Value"
                    aria-label="Tag value"
                    value={t.value}
                    onChange={(e) =>
                      setTags((all) =>
                        all.map((x, j) =>
                          j === i ? { ...x, value: e.target.value } : x,
                        ),
                      )
                    }
                  />
                  <button
                    type="button"
                    className="btn-ghost p-1.5"
                    aria-label="Remove tag"
                    onClick={() =>
                      setTags((all) => all.filter((_, j) => j !== i))
                    }
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
                {rowError && (
                  <p className="mt-0.5 text-xs text-deny" role="alert">
                    {rowError}
                  </p>
                )}
              </div>
            );
          })}
          <button
            type="button"
            className="btn-ghost px-2 text-xs"
            onClick={() => {
              const id = nextTagId.current++;
              setTags((all) => [...all, { id, key: '', value: '' }]);
            }}
          >
            <Plus size={12} /> Add tag
          </button>
        </div>
        <p className="mt-0.5 text-xs text-fg-faint">
          A createdBy=EZ AzFW Manager tag is added automatically.
        </p>
      </div>
    </div>
  ) : step === 1 ? (
    <div className="space-y-4">
      <div className="flex gap-3">
        <TargetCard
          active={targetKind === 'vnet-existing'}
          icon={<Network size={18} />}
          title="Existing hub VNet"
          text="Deploy into a VNet you already have. Missing firewall subnets are created."
          onClick={() => setTargetKind('vnet-existing')}
        />
        <TargetCard
          active={targetKind === 'vnet-new'}
          icon={<Cloud size={18} />}
          title="New hub VNet"
          text="Create a new VNet with the firewall subnets."
          onClick={() => setTargetKind('vnet-new')}
        />
        <TargetCard
          active={targetKind === 'hub'}
          icon={<Waypoints size={18} />}
          title="Virtual WAN hub"
          text="Secure a Virtual WAN hub (secured virtual hub)."
          onClick={() => setTargetKind('hub')}
        />
      </div>

      {targetKind === 'vnet-existing' && (
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <Field
              label="Virtual network"
              hint={`Only VNets in ${regionName} are listed: the firewall must be in the same region as its VNet. Change the region in Basics.`}
            >
              <SelectMenu
                label="Virtual network"
                widthClass="w-full"
                value={vnetId}
                onChange={setVnetId}
                placeholder={
                  regionVnets.length
                    ? 'Select a VNet…'
                    : `No VNets in ${regionName}`
                }
                options={regionVnets.map((v) => ({
                  value: v.id,
                  label: v.name,
                  hint: `${v.resourceGroup}, ${v.location}`,
                }))}
              />
            </Field>
          </div>
          {vnet && (
            <>
              <Field
                label={FIREWALL_SUBNET}
                htmlFor="fw-subnet"
                error={existingSubnetError}
                hint={
                  hasFwSubnet
                    ? 'Already exists — it will be used.'
                    : `Will be created. Address space: ${vnet.addressPrefixes.join(', ')}`
                }
              >
                <input
                  id="fw-subnet"
                  className="input font-mono text-xs"
                  disabled={hasFwSubnet}
                  value={
                    hasFwSubnet
                      ? (vnet.subnets.find((s) => s.name === FIREWALL_SUBNET)
                          ?.prefix ?? '')
                      : subnetPrefix
                  }
                  onChange={(e) => setSubnetPrefix(e.target.value)}
                />
              </Field>
              {useMgmt && (
                <Field
                  label={MANAGEMENT_SUBNET}
                  htmlFor="mgmt-subnet"
                  error={existingMgmtSubnetError}
                  hint={
                    hasMgmtSubnet
                      ? 'Already exists — it will be used.'
                      : 'Will be created.'
                  }
                >
                  <input
                    id="mgmt-subnet"
                    className="input font-mono text-xs"
                    disabled={hasMgmtSubnet}
                    value={
                      hasMgmtSubnet
                        ? (vnet.subnets.find(
                            (s) => s.name === MANAGEMENT_SUBNET,
                          )?.prefix ?? '')
                        : mgmtPrefix
                    }
                    onChange={(e) => setMgmtPrefix(e.target.value)}
                  />
                </Field>
              )}
            </>
          )}
        </div>
      )}

      {targetKind === 'vnet-new' && (
        <div className="grid grid-cols-2 gap-4">
          <Field label="Resource group" htmlFor="vnet-rg">
            <ResourceGroupPicker
              id="vnet-rg"
              value={vnetRgChoice}
              onChange={setVnetRg}
              groups={ctx.resourceGroups}
              suggested={`rg-network-${location || 'region'}`}
              inherited={!vnetRg}
              onReset={vnetRg ? () => setVnetRg(null) : undefined}
              error={
                vnetRg ? rgFieldError(vnetRg, 'Resource group name') : undefined
              }
            />
          </Field>
          <Field
            label="Region"
            hint="Set in Basics: a VNet must be in the firewall's region."
          >
            <input
              className="input"
              aria-label="Region"
              disabled
              value={regionName}
            />
          </Field>
          <Field
            label="VNet name"
            htmlFor="vnet-name"
            error={vnetNameError}
            hint={
              vnetName.trim()
                ? undefined
                : `Leave blank to use ${suggestedVnet}.`
            }
          >
            <input
              id="vnet-name"
              className="input"
              placeholder={suggestedVnet}
              value={vnetName}
              onChange={(e) => setVnetName(e.target.value)}
            />
          </Field>
          <Field
            label="Address space"
            htmlFor="vnet-space"
            error={addressSpaceFieldError}
            hint={
              publicSpace
                ? 'Not a private (RFC 1918) range. Azure allows it, but traffic to those public addresses will stay inside the VNet.'
                : `Private range, /${useMgmt ? 25 : 26} or larger.`
            }
          >
            <input
              id="vnet-space"
              className="input font-mono text-xs"
              value={addressSpace}
              onChange={(e) => setAddressSpace(e.target.value)}
            />
          </Field>
          <Field
            label={FIREWALL_SUBNET}
            htmlFor="new-fw-subnet"
            error={newSubnetError}
            hint="/26 or larger."
          >
            <input
              id="new-fw-subnet"
              className="input font-mono text-xs"
              value={newSubnet}
              onChange={(e) => setNewSubnet(e.target.value)}
            />
          </Field>
          {useMgmt && (
            <Field
              label={MANAGEMENT_SUBNET}
              htmlFor="new-mgmt-subnet"
              error={newMgmtSubnetError}
              hint="/26 or larger."
            >
              <input
                id="new-mgmt-subnet"
                className="input font-mono text-xs"
                value={newMgmtSubnet}
                onChange={(e) => setNewMgmtSubnet(e.target.value)}
              />
            </Field>
          )}
        </div>
      )}

      {targetKind === 'hub' && (
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <Field
              label="Virtual hub"
              hint={`Only hubs in ${regionName} are listed: the firewall must be in its hub's region. Hubs that already have a firewall can't be selected.`}
            >
              <SelectMenu
                label="Virtual hub"
                widthClass="w-full"
                value={hubId}
                onChange={(id) =>
                  !ctx.hubs.find((h) => h.id === id)?.firewallId && setHubId(id)
                }
                placeholder={
                  regionHubs.length
                    ? 'Select a hub…'
                    : `No Virtual WAN hubs in ${regionName}`
                }
                options={regionHubs.map((h) => ({
                  value: h.id,
                  label: h.firewallId ? `${h.name} (already secured)` : h.name,
                  hint: [h.virtualWanName, h.location]
                    .filter(Boolean)
                    .join(', '),
                }))}
              />
            </Field>
          </div>
          <Field
            label="Public IP addresses"
            htmlFor="hub-pips"
            hint="1-250 public IPs for the hub firewall."
          >
            <input
              id="hub-pips"
              type="number"
              min={1}
              max={250}
              className="input"
              value={publicIpCount}
              onChange={(e) => setPublicIpCount(e.target.value)}
            />
          </Field>
        </div>
      )}
    </div>
  ) : step === 2 ? (
    <div className="space-y-4">
      <Segmented
        label="Existing or new policy"
        value={policyKind}
        onChange={setPolicyKind}
        options={[
          { value: 'new', label: 'Create new policy' },
          { value: 'existing', label: 'Use existing policy' },
        ]}
      />
      {policyKind === 'existing' ? (
        <Field
          label="Firewall policy"
          hint={`Only ${tier} policies in this subscription are listed; the policy tier must match the firewall tier.`}
        >
          <SelectMenu
            label="Firewall policy"
            widthClass="w-full"
            icon={<Shield size={14} />}
            value={policyId}
            onChange={setPolicyId}
            placeholder={
              tierPolicies.length
                ? 'Select a policy…'
                : `No ${tier} policies found`
            }
            options={tierPolicies.map((p) => ({
              value: p.id,
              label: p.name,
              hint: `${p.resourceGroup}, ${p.location}`,
            }))}
          />
        </Field>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          <Field
            label="Policy name"
            htmlFor="policy-name"
            error={policyNameError}
            hint={`Created in ${effectivePolicyRg || 'the selected resource group'} (${regionName}) as a ${tier} policy.`}
          >
            <input
              id="policy-name"
              className="input"
              value={policyName}
              placeholder={`${name.trim() || 'fw'}-policy`}
              onChange={(e) => setPolicyName(e.target.value)}
            />
          </Field>
          <Field label="Resource group" htmlFor="policy-rg">
            <ResourceGroupPicker
              id="policy-rg"
              value={policyRgChoice}
              onChange={setPolicyRg}
              groups={ctx.resourceGroups}
              suggested={`rg-policy-${location || 'region'}`}
              inherited={!policyRg}
              onReset={policyRg ? () => setPolicyRg(null) : undefined}
              error={
                policyRg
                  ? rgFieldError(policyRg, 'Resource group name')
                  : undefined
              }
            />
          </Field>
          <Field
            label="Threat intelligence"
            hint={
              tier === 'Basic'
                ? 'Basic supports Alert only.'
                : 'Deny blocks traffic to and from known-malicious IPs and domains.'
            }
          >
            <Segmented
              label="Threat intelligence"
              value={threatIntel}
              onChange={setThreatIntel}
              options={(['Off', 'Alert', 'Deny'] as const).map((m) => ({
                value: m,
                label: m,
                disabled: tier === 'Basic' && m !== 'Alert',
              }))}
            />
          </Field>
          <div className="col-span-2">
            <Field
              label="Parent policy (optional)"
              hint="Inherit rules from a parent policy of the same tier — like a Panorama shared device group."
            >
              <SelectMenu
                label="Parent policy"
                widthClass="w-full"
                value={basePolicyId ?? ''}
                onChange={(v) => setBasePolicyId(v || undefined)}
                options={[
                  { value: '', label: 'None' },
                  ...tierPolicies.map((p) => ({
                    value: p.id,
                    label: p.name,
                    hint: p.resourceGroup,
                  })),
                ]}
              />
            </Field>
          </div>
        </div>
      )}
      <label className="flex items-center gap-2 text-sm text-fg-muted">
        <input
          type="checkbox"
          className="accent-azure"
          checked={addToManaged}
          onChange={(e) => setAddToManaged(e.target.checked)}
        />
        Manage this firewall in EZ AzFW Manager after it's deployed
      </label>
    </div>
  ) : (
    <div className="space-y-4">
      <dl className="grid grid-cols-[10rem,1fr] gap-x-4 gap-y-1.5 border-y border-line py-3 text-sm">
        <dt className="text-fg-faint">Firewall</dt>
        <dd className="truncate text-fg">
          {request?.name || '—'}, {tier} tier
          {zones.length
            ? `, zones ${zones.join(', ')}`
            : ', no availability zones'}
        </dd>
        <dt className="text-fg-faint">Subscription</dt>
        <dd className="truncate">
          {subscriptions.find((s) => s.subscriptionId === subscriptionId)?.name}
        </dd>
        <dt className="text-fg-faint">Resource group</dt>
        <dd className="truncate">
          {effectiveRg || '—'}
          {fwRg.mode === 'new' ? ' (new)' : ''}
        </dd>
        <dt className="text-fg-faint">Region</dt>
        <dd>{location ? regionName : '—'}</dd>
        <dt className="text-fg-faint">Network</dt>
        <dd className="truncate">
          {targetKind === 'hub'
            ? `Virtual WAN hub ${regionHubs.find((h) => sameResourceId(h.id, hubId))?.name ?? '—'} with ${publicIpCount} public ${publicIpCount === '1' ? 'IP' : 'IPs'}`
            : targetKind === 'vnet-new'
              ? `New VNet ${effectiveVnetName} (${addressSpace}) in ${effectiveVnetRg}${vnetRgChoice.mode === 'new' ? ' (new)' : ''}`
              : `VNet ${vnet?.name ?? '—'}${vnet ? ` in ${vnet.resourceGroup}` : ''}${hasFwSubnet ? '' : ` + new ${FIREWALL_SUBNET} ${subnetPrefix}`}`}
        </dd>
        <dt className="text-fg-faint">Management NIC</dt>
        <dd>{useMgmt ? 'Yes' : 'No'}</dd>
        <dt className="text-fg-faint">Policy</dt>
        <dd className="truncate">
          {request?.policy.kind === 'new'
            ? `New: ${request.policy.name} in ${effectivePolicyRg}${policyRgChoice.mode === 'new' ? ' (new)' : ''} (threat intel ${threatIntel}${basePolicyId ? `, inherits ${ctx.policies.find((p) => sameResourceId(p.id, basePolicyId))?.name}` : ''})`
            : (ctx.policies.find((p) => sameResourceId(p.id, policyId))?.name ??
              '—')}
        </dd>
        <dt className="text-fg-faint">Tags</dt>
        <dd className="truncate">
          {[
            'createdBy=EZ AzFW Manager',
            ...tags
              .filter((t) => t.key.trim())
              .map((t) => `${t.key}=${t.value}`),
          ].join(', ')}
        </dd>
      </dl>

      {errors.length > 0 ? (
        <ul className="list-disc space-y-0.5 border border-deny/40 bg-deny/10 py-2 pl-7 pr-3 text-xs text-deny">
          {errors.map((e) => (
            <li key={e} className="whitespace-pre-line">
              {e}
            </li>
          ))}
        </ul>
      ) : (
        <>
          <div className="flex gap-3 border border-candidate/40 bg-candidate/10 p-3 text-xs text-candidate">
            <AlertTriangle size={16} className="shrink-0 text-candidate" />
            <div>
              <p className="font-semibold">
                This creates billable Azure resources.
              </p>
              <p className="mt-0.5 text-candidate">
                Azure Firewall is billed per hour from the moment it is
                deployed, plus data processed and public IP charges — even with
                no traffic. Azure validates the deployment before anything is
                created.
              </p>
            </div>
          </div>
          <div>
            <label
              className="mb-1 block text-xs text-fg-muted"
              htmlFor="confirm-name"
            >
              Type the firewall name to confirm
            </label>
            <div className="mb-2 flex items-center gap-2">
              <span className="netval rounded border border-line bg-ink-950 px-2 py-1 font-semibold">
                {request?.name}
              </span>
              <button
                type="button"
                className="btn-ghost h-7 px-2"
                onClick={async () => {
                  if (!request?.name) return;
                  try {
                    await navigator.clipboard.writeText(request.name);
                  } catch {
                    // Copy is a convenience; the name can still be typed.
                    return;
                  }
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }}
              >
                {copied ? (
                  <Check size={14} className="text-allow" />
                ) : (
                  <Copy size={14} />
                )}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <input
              id="confirm-name"
              className="input"
              value={confirmName}
              onChange={(e) => setConfirmName(e.target.value)}
              autoComplete="off"
            />
          </div>
        </>
      )}
    </div>
  );

  return (
    <Modal
      title="Deploy Azure Firewall"
      subtitle="Creates an ARM deployment you can also track in the Azure portal."
      onClose={onClose}
      widthClass="max-w-3xl"
      footer={
        <>
          <div className="mr-auto w-72">
            <SelectMenu
              label="Subscription"
              widthClass="w-72"
              value={subscriptionId}
              onChange={(id) => setSubscriptionId(id)}
              placeholder="Loading subscriptions…"
              options={subscriptions.map((s) => ({
                value: s.subscriptionId,
                label: s.name,
              }))}
            />
          </div>
          {step > 0 && (
            <button className="btn-ghost" onClick={() => setStep((s) => s - 1)}>
              Back
            </button>
          )}
          {step < STEPS.length - 1 ? (
            <button
              className="btn-primary"
              disabled={!ctx || !networkReady}
              onClick={() => setStep((s) => s + 1)}
            >
              Next
            </button>
          ) : (
            <button
              className="btn-primary"
              disabled={!canDeploy}
              onClick={() => request && onDeploy(request)}
            >
              Validate and deploy
            </button>
          )}
        </>
      }
    >
      <ol className="-mx-5 -mt-4 mb-5 flex border-b border-line px-5 text-sm">
        {STEPS.map((s, i) => (
          <li key={s}>
            <button
              type="button"
              disabled={!ctx || !networkReady}
              onClick={() => setStep(i)}
              aria-current={i === step ? 'step' : undefined}
              className={`-mb-px flex h-10 items-center gap-2 border-b-2 pr-6 ${
                i === step
                  ? 'border-azure text-fg'
                  : i < step
                    ? 'border-transparent text-fg-muted hover:text-fg'
                    : 'border-transparent text-fg-faint hover:text-fg-muted'
              }`}
            >
              {i < step ? (
                <Check size={14} className="text-allow" />
              ) : (
                <span className="font-mono text-xs">{i + 1}</span>
              )}
              {s}
            </button>
          </li>
        ))}
      </ol>
      {body}
    </Modal>
  );
}
