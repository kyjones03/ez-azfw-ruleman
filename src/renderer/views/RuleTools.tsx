import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  HelpCircle,
  ShieldX,
  XCircle,
} from 'lucide-react';
import { Modal } from '../components/Modal';
import { SelectMenu } from '../components/Dropdown';
import { TokenPicker, type PickerOption } from '../components/TokenPicker';
import { parseList } from '../../shared/rules';
import {
  evaluateFlow,
  isIpv4,
  type Flow,
  type FlowHit,
  type FlowProtocol,
  type PolicyLayer,
} from '../../shared/flow';
import { collectionKindOf } from '../../shared/ruleDraft';
import { useRuleLookups } from '../lookups';
import type {
  FirewallRule,
  PolicyView,
  RuleCollection,
} from '../../shared/types';

// ---------------------------------------------------------------------------------------------
// Move / copy a rule
// ---------------------------------------------------------------------------------------------

/** Picks a target collection (of the same type) in this policy and a name for the rule there. */
export function TransferRuleDialog({
  view,
  fromGroupId,
  fromCollection,
  rule,
  mode,
  onSubmit,
  onClose,
}: {
  view: PolicyView;
  fromGroupId: string;
  fromCollection: RuleCollection;
  rule: FirewallRule;
  mode: 'move' | 'copy';
  onSubmit: (
    to: { groupId: string; collection: string; name: string },
    mode: 'move' | 'copy',
  ) => Promise<boolean>;
  onClose: () => void;
}) {
  const kind = collectionKindOf(fromCollection);
  // Only collections of the same type can hold this rule.
  const targets = view.groups.flatMap((g) =>
    g.group.ruleCollections
      .filter(
        (c) =>
          collectionKindOf(c) === kind &&
          !(
            mode === 'move' &&
            g.group.id === fromGroupId &&
            c.name === fromCollection.name
          ),
      )
      .map((c) => ({
        value: `${g.group.id}::${c.name}`,
        label: `${g.group.name} / ${c.name}`,
        hint: `${c.action.type}, priority ${c.priority}`,
        groupId: g.group.id,
        collection: c,
      })),
  );
  const [target, setTarget] = useState(targets[0]?.value);
  const chosen = targets.find((t) => t.value === target);
  const [name, setName] = useState(
    mode === 'copy' && chosen?.collection.name === fromCollection.name
      ? `${rule.name}-copy`
      : rule.name,
  );
  const [saving, setSaving] = useState(false);
  const trimmed = name.trim();
  const problem = !trimmed
    ? 'Rule name is required.'
    : !/^[A-Za-z0-9][\w.-]{0,79}$/.test(trimmed)
      ? 'Start with a letter or digit and use letters, digits, ".", "-" or "_" (max 80).'
      : chosen?.collection.rules.some(
            (r) => r.name.toLowerCase() === trimmed.toLowerCase(),
          )
        ? `${chosen.collection.name} already has a rule named "${trimmed}".`
        : undefined;
  const actionChanges =
    chosen && chosen.collection.action.type !== fromCollection.action.type;

  const submit = async () => {
    if (!chosen || problem || saving) return;
    setSaving(true);
    const ok = await onSubmit(
      {
        groupId: chosen.groupId,
        collection: chosen.collection.name,
        name: trimmed,
      },
      mode,
    );
    if (!ok) setSaving(false);
  };

  return (
    <Modal
      title={`${mode === 'move' ? 'Move' : 'Copy'} ${rule.name}`}
      subtitle={`From ${fromCollection.name}. Only ${kind} collections in this policy are listed.`}
      onClose={onClose}
      widthClass="max-w-lg"
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={!chosen || !!problem || saving}
            onClick={submit}
          >
            {mode === 'move' ? 'Move rule' : 'Copy rule'}
          </button>
        </>
      }
    >
      {!targets.length ? (
        <p className="text-sm text-fg-muted">
          There's no other {kind} collection in this policy. Create one first.
        </p>
      ) : (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div>
            <span className="label">To collection</span>
            <SelectMenu
              label="Target collection"
              widthClass="w-full"
              value={target}
              onChange={setTarget}
              options={targets}
            />
            {actionChanges && (
              <p className="mt-1 flex items-start gap-1.5 text-xs text-candidate">
                <AlertTriangle size={13} className="mt-px shrink-0" />
                This collection is {chosen!.collection.action.type}, so the rule
                will{' '}
                {chosen!.collection.action.type === 'Deny' ? 'block' : 'allow'}{' '}
                its traffic instead.
              </p>
            )}
          </div>
          <div>
            <label className="label" htmlFor="transfer-name">
              Rule name there
            </label>
            <input
              id="transfer-name"
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              aria-invalid={!!problem}
            />
            {problem && (
              <p className="mt-1 text-xs text-deny" role="alert">
                {problem}
              </p>
            )}
          </div>
          <p className="text-xs text-fg-faint">
            Goes to your draft. Azure changes only when you commit.
          </p>
          <button type="submit" hidden />
        </form>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------------------------------------
// Flow tester
// ---------------------------------------------------------------------------------------------

const PROTOCOLS: FlowProtocol[] = ['TCP', 'UDP', 'ICMP'];

function HitLine({
  hit,
  onOpen,
}: {
  hit: FlowHit;
  onOpen: (hit: FlowHit) => void;
}) {
  return (
    <button
      type="button"
      className="text-left text-azure hover:underline"
      onClick={() => onOpen(hit)}
    >
      {hit.inherited && (
        <span className="text-fg-faint">{hit.policyName} (inherited) / </span>
      )}
      {hit.groupName} / {hit.collection} / <strong>{hit.rule}</strong>
    </button>
  );
}

/**
 * "Would this flow be allowed?" Walks the rules in Azure's processing order (DNAT, Network,
 * Application; parent policy first; by priority) using the draft, and shows the first match.
 */
export function FlowTester({
  layers,
  onOpenHit,
}: {
  layers: PolicyLayer[];
  onOpenHit: (hit: FlowHit) => void;
}) {
  const [source, setSource] = useState('');
  const [destination, setDestination] = useState('');
  const [protocol, setProtocol] = useState<FlowProtocol>('TCP');
  const [port, setPort] = useState('443');
  const [categories, setCategories] = useState('');

  const sourceOk = isIpv4(source.trim());
  const dest = destination
    .trim()
    .replace(/^[a-z]+:\/\//i, '')
    .split('/')[0];
  const destOk = isIpv4(dest) || /^([a-z0-9_-]+\.)+[a-z0-9-]{2,}$/i.test(dest);
  const portNum = Number(port);
  const portOk =
    protocol === 'ICMP' ||
    (Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535);
  const ready = sourceOk && destOk && portOk;
  const { ipGroupMembers, lookups, known, loading } = useRuleLookups();
  const categoryOptions = useMemo<PickerOption[]>(
    () =>
      (lookups?.webCategories ?? []).map((c) => ({
        value: c.name,
        label: c.name,
        hint: c.group,
      })),
    [lookups],
  );
  const webCategories = useMemo(() => parseList(categories), [categories]);

  const result = useMemo(() => {
    if (!ready) return undefined;
    const flow: Flow = {
      source: source.trim(),
      destination: dest,
      protocol,
      port: protocol === 'ICMP' ? undefined : portNum,
      webCategories,
    };
    return evaluateFlow(flow, layers, ipGroupMembers);
  }, [
    ready,
    source,
    dest,
    protocol,
    portNum,
    webCategories,
    layers,
    ipGroupMembers,
  ]);

  const verdict = result?.verdict;
  const tone =
    verdict === 'Allow' || verdict === 'DNAT'
      ? 'border-allow/50 bg-allow/10'
      : 'border-deny/50 bg-deny/10';

  return (
    <div>
      <div className="grid grid-cols-[1fr_1fr_auto_6rem] items-start gap-3">
        <label className="block">
          <span className="label">Source IP</span>
          <input
            className="input font-mono text-xs"
            value={source}
            placeholder="10.1.2.3"
            onChange={(e) => setSource(e.target.value)}
            aria-invalid={!!source && !sourceOk}
            autoFocus
          />
        </label>
        <label className="block">
          <span className="label">Destination IP or host name</span>
          <input
            className="input font-mono text-xs"
            value={destination}
            placeholder="10.0.20.10 or login.microsoftonline.com"
            onChange={(e) => setDestination(e.target.value)}
            aria-invalid={!!destination && !destOk}
          />
        </label>
        <div>
          <span className="label">Protocol</span>
          <div className="inline-flex rounded border border-line p-0.5">
            {PROTOCOLS.map((p) => (
              <button
                key={p}
                type="button"
                aria-pressed={protocol === p}
                onClick={() => setProtocol(p)}
                className={`h-7 rounded-sm px-2.5 text-sm font-medium ${protocol === p ? 'bg-azure text-ink-950' : 'text-fg-muted hover:bg-ink-800'}`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
        <label className="block">
          <span className="label">Port</span>
          <input
            className="input font-mono text-xs"
            value={protocol === 'ICMP' ? '' : port}
            disabled={protocol === 'ICMP'}
            placeholder={protocol === 'ICMP' ? 'n/a' : '443'}
            onChange={(e) => setPort(e.target.value)}
            aria-invalid={!portOk}
          />
        </label>
      </div>

      <div className="mt-3">
        <span className="label">Destination web categories (optional)</span>
        <TokenPicker
          value={categories}
          onChange={setCategories}
          options={categoryOptions}
          ariaLabel="Destination web categories"
          placeholder={
            loading && !categoryOptions.length
              ? 'Loading from Azure…'
              : 'Pick the category Azure assigns to the destination'
          }
          loading={loading}
          allowCustom={!known.webCategories}
          emptyText={
            known.webCategories
              ? 'No matches'
              : "This list couldn't be loaded from Azure"
          }
        />
        <p className="mt-1 text-xs text-fg-faint">
          Azure can't look up a site's category from here. Find it with Web
          Category Check in the portal (Firewall Policy → Settings), then pick
          it so web category rules can be matched instead of showing as unsure.
        </p>
      </div>

      {!result ? (
        <p className="mt-5 text-sm text-fg-faint">
          Enter a source IP, a destination and a port to see the outcome.
        </p>
      ) : (
        <div className="mt-5 space-y-3">
          <div className={`flex gap-3 border p-3 ${tone}`}>
            {verdict === 'Allow' || verdict === 'DNAT' ? (
              <CheckCircle2 size={20} className="shrink-0 text-allow" />
            ) : verdict === 'Deny' ? (
              <XCircle size={20} className="shrink-0 text-deny" />
            ) : (
              <ShieldX size={20} className="shrink-0 text-deny" />
            )}
            <div className="min-w-0 text-sm">
              <p className="font-semibold text-fg">
                {verdict === 'Allow'
                  ? 'Allowed'
                  : verdict === 'DNAT'
                    ? 'Translated (DNAT)'
                    : verdict === 'Deny'
                      ? 'Denied'
                      : 'Denied by default: no rule matches'}
                {result.winner?.translatedTo && (
                  <span className="font-normal text-fg-muted">
                    {' '}
                    <ArrowRight size={13} className="inline" />{' '}
                    {result.winner.translatedTo}
                  </span>
                )}
              </p>
              {result.winner && (
                <p className="mt-0.5 text-fg-muted">
                  {result.winner.pass} rule{' '}
                  <HitLine hit={result.winner} onOpen={onOpenHit} />
                </p>
              )}
              <p className="mt-0.5 text-xs text-fg-faint">
                {result.rulesChecked} rules checked in processing order: DNAT,
                then Network, then Application; inherited policy first; groups
                and collections by priority.
              </p>
            </div>
          </div>

          {result.maybes.length > 0 && (
            <div className="border border-candidate/40 bg-candidate/10 p-3 text-sm">
              <p className="flex items-center gap-1.5 font-semibold text-candidate">
                <HelpCircle size={15} />
                The result could be different
              </p>
              <p className="mt-0.5 text-xs text-fg-muted">
                {result.maybes.length === 1
                  ? 'This rule comes'
                  : 'These rules come'}{' '}
                first and would{' '}
                {verdict === 'Allow' || verdict === 'DNAT' ? 'deny' : 'allow'}{' '}
                this traffic if{' '}
                {result.maybes.length === 1 ? 'it matches' : 'one matches'}, but
                the tester can't check everything Azure does.
              </p>
              <ul className="mt-1.5 space-y-1">
                {result.maybes.map((m) => (
                  <li key={`${m.groupId}/${m.collection}/${m.rule}`}>
                    <span className="text-xs text-fg-faint">
                      {m.pass}, {m.action}:
                    </span>{' '}
                    <HitLine hit={m} onOpen={onOpenHit} />
                    <span className="block text-xs text-fg-muted">
                      Unsure because {m.unknowns.join('; ')}.
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {result.notes.map((n) => (
            <p key={n} className="text-xs text-fg-faint">
              {n}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}
