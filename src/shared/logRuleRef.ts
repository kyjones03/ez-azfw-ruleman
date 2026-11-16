// From a log row to the rule that matched it, in the policies the app has loaded.
//
// A structured row names the policy, rule collection group, rule collection and rule as TEXT, not as
// resource IDs, and the policy can be a parent of the firewall's own. So the lookup walks the loaded
// chain (the firewall's policy first, then its parents) and matches names, case-insensitively.
import type { FirewallLogRow } from './fwLogs';
import type { FlowHit } from './flow';
import type { PolicyView } from './types';

/** Where the Rules view should go: enough to show one rule. A flow-tester hit already fits. */
export type RuleFocus = Pick<
  FlowHit,
  'policyId' | 'groupId' | 'collection' | 'rule' | 'inherited'
>;

/** A rule named by a log row, with the policy of the firewall that wrote it. */
export interface LogRuleRef {
  /** The firewall's own policy: the chain to search starts here. */
  firewallPolicyId: string;
  policyName: string;
  groupName: string;
  collection: string;
  rule: string;
}

/** The rule a row names, or nothing when the row has no matched rule (a default deny, DNS...). */
export function logRuleRef(
  row: Pick<
    FirewallLogRow,
    'fwPolicy' | 'ruleCollectionGroup' | 'ruleCollection' | 'ruleName'
  >,
  firewallPolicyId: string | undefined,
): LogRuleRef | undefined {
  if (
    !firewallPolicyId ||
    !row.ruleCollectionGroup ||
    !row.ruleCollection ||
    !row.ruleName
  )
    return undefined;
  return {
    firewallPolicyId,
    policyName: row.fwPolicy,
    groupName: row.ruleCollectionGroup,
    collection: row.ruleCollection,
    rule: row.ruleName,
  };
}

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

export type FoundRule =
  | { found: true; focus: RuleFocus }
  | { found: false; reason: string };

/**
 * Finds the rule among the loaded policies. `chain[0]` must be the firewall's own policy and the
 * rest its parents, nearest first. When the row names no policy, every layer is searched.
 */
export function findLoggedRule(
  ref: LogRuleRef,
  chain: readonly PolicyView[],
): FoundRule {
  const layers = chain.map((view, i) => ({ view, inherited: i > 0 }));
  const candidates = ref.policyName
    ? layers.filter((l) => same(l.view.policy.name, ref.policyName))
    : layers;
  if (!candidates.length)
    return {
      found: false,
      reason: `The policy ${ref.policyName} is not in this firewall's policy chain.`,
    };
  for (const { view, inherited } of candidates) {
    const group = view.groups.find((g) => same(g.group.name, ref.groupName));
    const collection = group?.group.ruleCollections.find((c) =>
      same(c.name, ref.collection),
    );
    const rule = (collection?.rules as { name: string }[] | undefined)?.find(
      (r) => same(r.name, ref.rule),
    );
    if (group && collection && rule)
      return {
        found: true,
        focus: {
          policyId: view.policy.id,
          groupId: group.group.id,
          collection: collection.name,
          rule: rule.name,
          inherited,
        },
      };
  }
  return {
    found: false,
    reason: `Rule ${ref.rule} was not found in ${ref.collection} (${ref.groupName}). It may have been renamed or removed since the log was written.`,
  };
}
