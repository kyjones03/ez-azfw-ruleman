import { useEffect, useId, useState } from 'react';
import { Modal } from '../components/Modal';
import { SelectMenu } from '../components/Dropdown';
import { Notice, Spinner } from '../components/ui';
import { errorMessage } from '../components/Toast';
import { ipGroupErrors, type IpGroupContext } from '../../shared/ipGroups';
import { parseList } from '../../shared/rules';
import type { SubscriptionInfo } from '../../shared/deploy';
import type { IpGroupInfo } from '../../shared/types';

export function CreateIpGroup({
  defaultSubscriptionId,
  onClose,
  onCreated,
}: {
  defaultSubscriptionId?: string;
  onClose: () => void;
  onCreated: (group: IpGroupInfo) => void;
}) {
  const formId = useId();
  const [subscriptions, setSubscriptions] = useState<SubscriptionInfo[]>([]);
  const [subscriptionId, setSubscriptionId] = useState(
    defaultSubscriptionId ?? '',
  );
  const [context, setContext] = useState<{
    subscriptionId: string;
    value: IpGroupContext;
  }>();
  const [resourceGroup, setResourceGroup] = useState('');
  const [location, setLocation] = useState('');
  const [name, setName] = useState('');
  const [addressText, setAddressText] = useState('');
  const [loadingSubscriptions, setLoadingSubscriptions] = useState(true);
  const [subscriptionError, setSubscriptionError] = useState('');
  const [contextError, setContextError] = useState('');
  const [createError, setCreateError] = useState('');
  const [retryKey, setRetryKey] = useState(0);
  const [submitted, setSubmitted] = useState(false);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoadingSubscriptions(true);
    setSubscriptionError('');
    window.api
      .listSubscriptions()
      .then((items) => {
        if (cancelled) return;
        setSubscriptions(items);
        setSubscriptionId(
          (id) =>
            items.find(
              (s) => s.subscriptionId.toLowerCase() === id.toLowerCase(),
            )?.subscriptionId ??
            items[0]?.subscriptionId ??
            '',
        );
      })
      .catch((err) => {
        if (!cancelled) setSubscriptionError(errorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoadingSubscriptions(false);
      });
    return () => {
      cancelled = true;
    };
  }, [retryKey]);

  useEffect(() => {
    let cancelled = false;
    setContext(undefined);
    setContextError('');
    if (subscriptionId) {
      window.api
        .getIpGroupContext(subscriptionId)
        .then((value) => {
          if (!cancelled) setContext({ subscriptionId, value });
        })
        .catch((err) => {
          if (!cancelled) setContextError(errorMessage(err));
        });
    }
    return () => {
      cancelled = true;
    };
  }, [subscriptionId, retryKey]);

  const currentContext =
    context?.subscriptionId === subscriptionId ? context.value : undefined;
  const request = {
    subscriptionId,
    resourceGroup,
    location,
    name: name.trim(),
    addresses: parseList(addressText),
  };
  const errors = ipGroupErrors(request);
  const close = () => {
    if (!creating) onClose();
  };
  const submit = async () => {
    setSubmitted(true);
    setCreateError('');
    if (creating || Object.keys(errors).length || !currentContext) return;
    if (
      !currentContext.resourceGroups.includes(resourceGroup) ||
      !currentContext.locations.some((l) => l.name === location)
    ) {
      setCreateError('Select an available resource group and location.');
      return;
    }
    setCreating(true);
    try {
      const group = await window.api.createIpGroup(request);
      onCreated({
        ...group,
        subscriptionName: subscriptions.find(
          (s) => s.subscriptionId === subscriptionId,
        )?.name,
      });
    } catch (err) {
      setCreateError(errorMessage(err));
    } finally {
      setCreating(false);
    }
  };
  const loadError = subscriptionError || contextError;
  return (
    <Modal
      title="Create IP group"
      subtitle="Group IPv4 addresses, CIDRs and ranges for firewall rules."
      onClose={close}
      footer={
        <>
          <button className="btn-ghost" onClick={close} disabled={creating}>
            Cancel
          </button>
          <button
            type="submit"
            form={formId}
            className="btn-primary"
            disabled={
              creating ||
              loadingSubscriptions ||
              !currentContext ||
              !subscriptions.length
            }
          >
            {creating ? <Spinner label="Creating…" /> : 'Create IP group'}
          </button>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
        className="space-y-4"
      >
        <Notice
          tone="info"
          title="This creates a resource in Azure immediately."
        >
          IP group creation is separate from the rule draft and commit workflow.
          Existing IP groups will not be overwritten.
        </Notice>
        {loadError && (
          <Notice
            tone="error"
            title="Couldn't load creation options"
            action={
              <button
                type="button"
                className="btn-outline"
                onClick={() => setRetryKey((k) => k + 1)}
              >
                Try again
              </button>
            }
          >
            {loadError}
          </Notice>
        )}
        {loadingSubscriptions ? (
          <Spinner label="Loading subscriptions…" />
        ) : !subscriptions.length && !subscriptionError ? (
          <Notice tone="info" title="No subscriptions available">
            Check your directory and Azure permissions.
          </Notice>
        ) : null}
        <fieldset disabled={creating} className="space-y-4">
          <div>
            <span className="label">Subscription</span>
            <SelectMenu
              label="Subscription"
              widthClass="w-full"
              value={subscriptionId}
              disabled={
                creating || loadingSubscriptions || !subscriptions.length
              }
              aria-invalid={submitted && !!errors.subscriptionId}
              onChange={(id) => {
                setSubscriptionId(id);
                setResourceGroup('');
                setLocation('');
              }}
              placeholder={
                loadingSubscriptions
                  ? 'Loading subscriptions…'
                  : 'Select a subscription…'
              }
              options={subscriptions.map((s) => ({
                value: s.subscriptionId,
                label: s.name,
              }))}
            />
          </div>
          {subscriptionId && !currentContext && !contextError && (
            <Spinner label="Loading resource groups and locations…" />
          )}
          {currentContext && !currentContext.resourceGroups.length && (
            <Notice tone="info" title="No resource groups available">
              Create a resource group in Azure first, or select another
              subscription.
            </Notice>
          )}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="label">Resource group</span>
              <SelectMenu
                label="Resource group"
                widthClass="w-full"
                value={resourceGroup}
                disabled={creating || !currentContext}
                aria-invalid={submitted && !!errors.resourceGroup}
                onChange={setResourceGroup}
                placeholder={
                  currentContext && !currentContext.resourceGroups.length
                    ? 'No resource groups'
                    : 'Select a resource group…'
                }
                options={(currentContext?.resourceGroups ?? []).map((rg) => ({
                  value: rg,
                  label: rg,
                }))}
              />
            </div>
            <div>
              <span className="label">Location</span>
              <SelectMenu
                label="Location"
                widthClass="w-full"
                value={location}
                disabled={creating || !currentContext}
                aria-invalid={submitted && !!errors.location}
                onChange={setLocation}
                placeholder="Select a location…"
                options={(currentContext?.locations ?? []).map((l) => ({
                  value: l.name,
                  label: l.displayName,
                  hint: l.name,
                }))}
              />
            </div>
          </div>
          <label className="block">
            <span className="label">Name</span>
            <input
              autoFocus
              className="input"
              value={name}
              placeholder="ipg-office-networks"
              aria-invalid={!!(name || submitted) && !!errors.name}
              onChange={(e) => setName(e.target.value)}
            />
            {(name || submitted) && errors.name && (
              <span className="mt-1 block text-xs text-deny" role="alert">
                {errors.name}
              </span>
            )}
          </label>
          <label className="block">
            <span className="label">IP addresses, CIDRs or ranges</span>
            <textarea
              className="input h-36 font-mono text-sm"
              value={addressText}
              placeholder={'10.0.0.1\n10.1.0.0/24\n10.2.0.1-10.2.0.20'}
              aria-invalid={!!(addressText || submitted) && !!errors.addresses}
              onChange={(e) => setAddressText(e.target.value)}
            />
            <span className="mt-1 block text-xs text-fg-muted">
              Separate entries with spaces, commas, semicolons or new lines.
              Duplicates are removed. Wildcards and IPv6 are not supported.
            </span>
            {(addressText || submitted) && errors.addresses && (
              <span className="mt-1 block text-xs text-deny" role="alert">
                {errors.addresses}
              </span>
            )}
          </label>
        </fieldset>
        {submitted && Object.keys(errors).length > 0 && (
          <Notice tone="error" title="Check the IP group details">
            {Object.values(errors).join('\n')}
          </Notice>
        )}
        {createError && (
          <Notice tone="error" title="Couldn't create IP group">
            {createError}
          </Notice>
        )}
      </form>
    </Modal>
  );
}
