import { useEffect, useMemo, useState } from 'react';
import { Modal, useGuardedClose } from '../components/Modal';
import { SelectMenu } from '../components/Dropdown';
import { Segmented } from '../components/Segmented';
import { Notice, Spinner } from '../components/ui';
import { errorMessage, useToast } from '../components/Toast';
import { parseList, stableStringify } from '../../shared/rules';
import { resourceName } from '../../shared/resourceId';
import {
  policySettingsErrors,
  type PolicyAdvancedSettings,
  type PolicySettingsView,
} from '../../shared/resourceSettings';
import type { CandidateStatus } from '../../shared/types';

export function PolicySettings({
  policyId,
  onClose,
  onStatus,
}: {
  policyId: string;
  onClose: () => void;
  onStatus: (status: CandidateStatus) => void;
}) {
  const [view, setView] = useState<PolicySettingsView>();
  const [initial, setInitial] = useState<PolicyAdvancedSettings>();
  const [value, setValue] = useState<PolicyAdvancedSettings>();
  const [text, setText] = useState({ dns: '', ips: '', fqdns: '' });
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);
  const [saving, setSaving] = useState(false);
  const toast = useToast();
  useEffect(() => {
    let cancelled = false;
    setView(undefined);
    setError('');
    window.api
      .getPolicySettings(policyId)
      .then((result) => {
        if (cancelled) return;
        const current = result.draft ?? result.running;
        setView(result);
        setInitial(current);
        setValue(structuredClone(current));
        setText({
          dns: current.dns.servers.join('\n'),
          ips: current.allowlistIps.join('\n'),
          fqdns: current.allowlistFqdns.join('\n'),
        });
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err));
      });
    return () => {
      cancelled = true;
    };
  }, [policyId, retry]);
  const desired = useMemo<PolicyAdvancedSettings | undefined>(
    () =>
      value && view
        ? {
            ...value,
            dns: { ...value.dns, servers: parseList(text.dns) },
            allowlistIps: parseList(text.ips),
            allowlistFqdns: parseList(text.fqdns),
            tls: value.tls.enabled
              ? {
                  ...value.tls,
                  certificateName: value.tls.certificateName.trim(),
                  secretId: value.tls.secretId.trim(),
                }
              : {
                  enabled: false,
                  certificateName: '',
                  secretId: '',
                  identityIds: view.running.tls.identityIds,
                },
          }
        : undefined,
    [value, view, text],
  );
  const dirty =
    !!desired && stableStringify(desired) !== stableStringify(initial);
  const errors =
    desired && view ? policySettingsErrors(desired, view.tier, initial) : [];
  const guard = useGuardedClose(dirty, onClose);
  const close = () => {
    if (!saving) guard.request();
  };
  const save = async () => {
    if (!initial || !desired || !dirty || errors.length || saving) return;
    setSaving(true);
    setError('');
    try {
      onStatus(
        await window.api.stagePolicySettings(policyId, initial, desired),
      );
      toast(
        'success',
        'Policy settings added to the draft. Save and commit to apply them.',
      );
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };
  const identities =
    view?.identities.map((i) => ({
      value: i.id,
      label: i.name,
      hint: [i.resourceGroup, i.subscriptionId].filter(Boolean).join(' · '),
    })) ?? [];
  for (const id of initial?.tls.identityIds ?? [])
    if (!identities.some((i) => i.value.toLowerCase() === id.toLowerCase()))
      identities.push({
        value: id,
        label: resourceName(id),
        hint: 'Currently assigned',
      });
  return (
    <>
      <Modal
        title={`Policy settings${view ? `: ${view.name}` : ''}`}
        onClose={close}
        widthClass="max-w-4xl"
        subtitle="Local draft only. Existing unrelated settings are preserved; Azure changes only on commit."
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
              title="Couldn't load or stage policy settings"
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
          {!view && !error && <Spinner label="Loading policy settings…" />}
          {!!view?.errors.length && (
            <Notice tone="info" title="Some lookup data is unavailable">
              {view.errors.join('\n')}
            </Notice>
          )}
          {view && value && (
            <>
              <fieldset
                disabled={saving}
                className="space-y-3 border border-line p-4"
              >
                <legend className="px-2 font-semibold">DNS</legend>
                <Segmented
                  label="DNS configuration"
                  value={value.dns.inherit ? 'inherit' : 'override'}
                  onChange={(mode) =>
                    setValue({
                      ...value,
                      dns: { ...value.dns, inherit: mode === 'inherit' },
                    })
                  }
                  options={[
                    { value: 'inherit', label: 'Default / inherit parent' },
                    {
                      value: 'override',
                      label: 'Override',
                      disabled: view.tier === 'Basic',
                    },
                  ]}
                />
                <p className="text-xs text-fg-muted">
                  Default uses Azure DNS and disables proxy on a root policy, or
                  inherits the parent policy. DNS proxy and custom DNS require
                  Standard or Premium.
                </p>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="accent-azure"
                    checked={value.dns.enableProxy}
                    disabled={value.dns.inherit || view.tier === 'Basic'}
                    onChange={(e) =>
                      setValue({
                        ...value,
                        dns: { ...value.dns, enableProxy: e.target.checked },
                      })
                    }
                  />{' '}
                  Enable DNS proxy
                </label>
                <label className="block">
                  <span className="label">
                    Custom DNS servers (optional IPv4 addresses)
                  </span>
                  <textarea
                    className="input h-20 font-mono"
                    value={text.dns}
                    disabled={value.dns.inherit || view.tier === 'Basic'}
                    placeholder={'10.0.0.4\n10.0.0.5'}
                    onChange={(e) => setText({ ...text, dns: e.target.value })}
                  />
                </label>
                <p className="text-xs text-fg-faint">
                  Up to 15 servers. Leave blank for Azure DNS. Enabling proxy
                  does not change virtual-network or client DNS settings.
                </p>
              </fieldset>
              <fieldset
                disabled={saving}
                className="space-y-3 border border-line p-4"
              >
                <legend className="px-2 font-semibold">
                  Threat-intelligence allowlist
                </legend>
                <div className="grid grid-cols-2 gap-4">
                  <label className="block">
                    <span className="label">IP addresses, CIDRs or ranges</span>
                    <textarea
                      className="input h-28 font-mono"
                      value={text.ips}
                      placeholder={'192.0.2.1\n198.51.100.0/24'}
                      onChange={(e) =>
                        setText({ ...text, ips: e.target.value })
                      }
                    />
                  </label>
                  <label className="block">
                    <span className="label">FQDNs (no scheme or path)</span>
                    <textarea
                      className="input h-28 font-mono"
                      value={text.fqdns}
                      placeholder={'www.contoso.com\napi.contoso.com'}
                      onChange={(e) =>
                        setText({ ...text, fqdns: e.target.value })
                      }
                    />
                  </label>
                </div>
                <p className="text-xs text-fg-muted">
                  Separate entries with new lines, commas or semicolons. Entries
                  bypass threat-intelligence filtering and are inherited by
                  child policies.
                </p>
              </fieldset>
              <fieldset
                disabled={saving || view.tier === 'Basic'}
                className="space-y-3 border border-line p-4"
              >
                <legend className="px-2 font-semibold">
                  SNAT auto-learning
                </legend>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="accent-azure"
                    checked={value.autoLearnSnat}
                    onChange={(e) =>
                      setValue({ ...value, autoLearnSnat: e.target.checked })
                    }
                  />{' '}
                  Enable auto-learned SNAT prefixes
                </label>
                <p className="text-xs text-fg-muted">
                  For VNet firewalls, associate Azure Route Server in the same
                  VNet and commit that firewall change first. Secured hubs use
                  their built-in Route Server. Existing private SNAT ranges are
                  preserved.
                </p>
              </fieldset>
              <fieldset
                disabled={saving || view.tier !== 'Premium'}
                className="space-y-3 border border-line p-4"
              >
                <legend className="px-2 font-semibold">
                  TLS inspection (Premium)
                </legend>
                {view.tier !== 'Premium' && (
                  <p className="text-sm text-fg-muted">
                    A Premium policy and Premium firewalls are required.
                  </p>
                )}
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="accent-azure"
                    checked={value.tls.enabled}
                    onChange={(e) =>
                      setValue({
                        ...value,
                        tls: { ...value.tls, enabled: e.target.checked },
                      })
                    }
                  />{' '}
                  Enable TLS inspection configuration
                </label>
                <label className="block">
                  <span className="label">Key Vault secret identifier</span>
                  <input
                    className="input font-mono"
                    autoComplete="off"
                    disabled={!value.tls.enabled}
                    value={value.tls.secretId}
                    placeholder="https://vault-name.vault.azure.net/secrets/ca-certificate"
                    onChange={(e) => {
                      const name =
                        e.target.value.split('/secrets/')[1]?.split('/')[0] ??
                        value.tls.certificateName;
                      setValue({
                        ...value,
                        tls: {
                          ...value.tls,
                          secretId: e.target.value,
                          certificateName: name,
                        },
                      });
                    }}
                  />
                </label>
                <label className="block">
                  <span className="label">CA certificate name</span>
                  <input
                    className="input"
                    disabled={!value.tls.enabled}
                    value={value.tls.certificateName}
                    onChange={(e) =>
                      setValue({
                        ...value,
                        tls: { ...value.tls, certificateName: e.target.value },
                      })
                    }
                  />
                </label>
                <div>
                  <span className="label">
                    Existing user-assigned managed identity
                  </span>
                  <SelectMenu
                    label="TLS managed identity"
                    widthClass="w-full"
                    disabled={
                      saving || view.tier !== 'Premium' || !value.tls.enabled
                    }
                    value={
                      value.tls.identityIds.length === 1
                        ? value.tls.identityIds[0]
                        : undefined
                    }
                    onChange={(id) =>
                      setValue({
                        ...value,
                        tls: { ...value.tls, identityIds: [id] },
                      })
                    }
                    options={identities}
                    placeholder="Select an existing identity…"
                  />
                </div>
                <Notice
                  tone="info"
                  title="Existing certificate and access setup only"
                >
                  Use the certificate's corresponding Key Vault secret URI, not
                  a PFX, private key or secret value. The existing CA must be
                  trusted by clients and the identity must already have Key
                  Vault secret access. This app does not fetch certificate
                  contents or grant permissions. Configure TLS inspection on the
                  applicable application rules separately.
                </Notice>
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
