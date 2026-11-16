// Suggesting an Allow rule for a flow the firewall denied, as seen in the logs.
//
// The suggestion is as narrow as the log allows: the exact source address, the exact destination
// (address, or FQDN for application rules), the exact protocol and port. It only becomes a rule in
// the user's draft after they choose where it goes and confirm in the editor. Log text comes from
// the network, so nothing here is trusted: values are checked before they become rule fields.
import { evaluateFlow, isIpv4, type Flow, type PolicyLayer } from './flow';
import type { FirewallLogRow } from './fwLogs';
import { nameError } from './naming';
import {
  collectionFromDraft,
  emptyCollection,
  emptyRow,
  ruleFromRow,
  type CollectionKind,
  type RuleRow,
} from './ruleDraft';

export type SuggestableKind = Extract<
  CollectionKind,
  'Network' | 'Application'
>;

export interface RuleSuggestion {
  kind: SuggestableKind;
  /** The denied flow, for checking what a rule would do. */
  flow: Flow;
  /** A ready-to-edit row. */
  row: RuleRow;
  /** One line describing the flow, e.g. "10.50.1.4 → 1.1.1.1 TCP 443". */
  summary: string;
  /** Set when an explicit rule denied the flow (not just the default deny). */
  deniedBy?: {
    rule: string;
    collection: string;
    group: string;
    policy: string;
  };
}

export type SuggestResult =
  | { ok: true; suggestion: RuleSuggestion }
  | { ok: false; reason: string };

const isDeny = (row: Pick<FirewallLogRow, 'action'>) =>
  row.action.toLowerCase() === 'deny';

/** Only denied network and application rule rows can be turned into a rule. */
export const canSuggestRule = (
  row: Pick<FirewallLogRow, 'category' | 'action'>,
) =>
  isDeny(row) && (row.category === 'NetworkRule' || row.category === 'AppRule');

const HOST =
  /^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*$/;
const portOf = (p: string) => {
  const n = Number(p);
  return /^\d{1,5}$/.test(p) && n >= 1 && n <= 65535 ? n : undefined;
};

/** A rule name Azure accepts, e.g. "allow-10.50.1.4-to-1.1.1.1-443". */
export function suggestedRuleName(parts: string[]): string {
  const base = `allow-${parts.join('-to-')}`
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^[^A-Za-z0-9]+/, '')
    .slice(0, 80)
    .replace(/[^A-Za-z0-9_]+$/, '');
  return nameError('rule', base) ? 'allow-logged-flow' : base;
}

export function suggestRuleFromRow(row: FirewallLogRow): SuggestResult {
  if (!isDeny(row))
    return { ok: false, reason: 'Only denied flows can become a rule.' };
  if (row.category !== 'NetworkRule' && row.category !== 'AppRule')
    return {
      ok: false,
      reason:
        'Only denied network and application rule rows can become a rule.',
    };
  if (!isIpv4(row.sourceIp))
    return {
      ok: false,
      reason:
        'The rule editor handles IPv4 addresses only, and the source is not one.',
    };

  const deniedBy = row.ruleName
    ? {
        rule: row.ruleName,
        collection: row.ruleCollection,
        group: row.ruleCollectionGroup,
        policy: row.fwPolicy,
      }
    : undefined;
  const out = emptyRow(row.category === 'AppRule' ? 'Application' : 'Network');
  out.description = 'Added from a denied flow in the firewall logs';
  out.lists.sourceAddresses = row.sourceIp;
  out.sourceField = 'sourceAddresses';

  if (row.category === 'NetworkRule') {
    const protocol = row.protocol.toUpperCase();
    if (protocol !== 'TCP' && protocol !== 'UDP' && protocol !== 'ICMP')
      return {
        ok: false,
        reason: `The protocol ${row.protocol || '(none)'} is not TCP, UDP or ICMP.`,
      };
    if (!isIpv4(row.targetIp))
      return {
        ok: false,
        reason:
          'The rule editor handles IPv4 addresses only, and the destination is not one.',
      };
    const port = protocol === 'ICMP' ? undefined : portOf(row.targetPort);
    if (protocol !== 'ICMP' && port === undefined)
      return {
        ok: false,
        reason: 'The log row has no usable destination port.',
      };
    out.protocols = [protocol];
    out.lists.destinationAddresses = row.targetIp;
    out.destField = 'destinationAddresses';
    out.lists.destinationPorts = port === undefined ? '*' : String(port);
    out.name = suggestedRuleName([
      row.sourceIp,
      port === undefined ? row.targetIp : `${row.targetIp}-${port}`,
    ]);
    return {
      ok: true,
      suggestion: {
        kind: 'Network',
        flow: {
          source: row.sourceIp,
          destination: row.targetIp,
          protocol,
          port,
        },
        row: out,
        summary: `${row.sourceIp} → ${row.targetIp} ${protocol}${port === undefined ? '' : ` ${port}`}`,
        deniedBy,
      },
    };
  }

  const scheme = { HTTPS: 'Https', HTTP: 'Http' }[row.protocol.toUpperCase()];
  if (!scheme)
    return {
      ok: false,
      reason: `The protocol ${row.protocol || '(none)'} is not HTTP or HTTPS.`,
    };
  const port = portOf(row.targetPort);
  if (port === undefined)
    return { ok: false, reason: 'The log row has no usable destination port.' };
  if (!HOST.test(row.targetIp))
    return { ok: false, reason: 'The log row has no usable destination FQDN.' };
  out.appProtocols = `${scheme}:${port}`;
  out.lists.targetFqdns = row.targetIp;
  out.destField = 'targetFqdns';
  out.name = suggestedRuleName([row.sourceIp, row.targetIp]);
  return {
    ok: true,
    suggestion: {
      kind: 'Application',
      flow: {
        source: row.sourceIp,
        destination: row.targetIp,
        protocol: 'TCP',
        port,
      },
      row: out,
      summary: `${row.sourceIp} → ${row.targetIp} ${scheme.toUpperCase()} ${port}`,
      deniedBy,
    },
  };
}

// ── what the rule would do ───────────────────────────────────────────────────

export interface RuleEffect {
  /** True when the flow would be allowed by the new rule. */
  allowed: boolean;
  /** Plain-language result, including what would still win when it is not allowed. */
  message: string;
}

/**
 * Evaluates the denied flow against the policy chain with the proposed rule added, so the user
 * sees whether it would really take effect: a Deny rule in a parent policy, an earlier group, or a
 * collection with a lower priority number is processed first and would still win.
 *
 * `own` is the policy the rule goes into; `target` is an existing Allow collection in one of its
 * groups, or a new one with the given name and priority.
 */
export function ruleEffect(
  suggestion: RuleSuggestion,
  layers: readonly PolicyLayer[],
  ownPolicyId: string,
  target: { groupId: string; collection?: string; newPriority: number },
): RuleEffect {
  const rule = ruleFromRow(suggestion.row, suggestion.kind);
  const proposed = layers.map((layer) => {
    if (layer.policyId.toLowerCase() !== ownPolicyId.toLowerCase())
      return layer;
    return {
      ...layer,
      groups: layer.groups.map((g) => {
        if (g.id.toLowerCase() !== target.groupId.toLowerCase()) return g;
        if (target.collection) {
          return {
            ...g,
            ruleCollections: g.ruleCollections.map((c) =>
              c.name === target.collection
                ? ({ ...c, rules: [...c.rules, rule] } as typeof c)
                : c,
            ),
          };
        }
        const draft = emptyCollection(target.newPriority, suggestion.kind);
        draft.name = 'proposed';
        draft.rows = [suggestion.row];
        return {
          ...g,
          ruleCollections: [...g.ruleCollections, collectionFromDraft(draft)],
        };
      }),
    };
  });
  const result = evaluateFlow(suggestion.flow, proposed);
  const ours = result.winner?.rule === rule.name && !result.winner.inherited;
  if (result.verdict === 'Allow' && ours)
    return {
      allowed: true,
      message: result.maybes.length
        ? 'With this rule the flow would be allowed, unless one of the rules the tester could not decide matches first.'
        : 'With this rule the flow would be allowed.',
    };
  const winner = result.winner;
  const what = !winner
    ? 'denied by the default deny'
    : `${winner.action === 'Allow' ? 'allowed' : winner.action === 'DNAT' ? 'translated' : 'denied'} by rule "${winner.rule}" in "${winner.collection}" (${winner.groupName}${winner.inherited ? `, parent policy ${winner.policyName}` : ''})`;
  return {
    allowed: false,
    message: `Even with this rule the flow would still be ${what}. A rule that is processed earlier wins: a parent policy, a group or collection with a lower priority number, or a rule type that is checked first.`,
  };
}
