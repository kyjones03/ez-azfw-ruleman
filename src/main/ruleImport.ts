import { candidate } from './candidate';
import { getPolicy, listRuleCollectionGroups } from './azure';
import { getRuleLookups } from './lookups';
import { knownValuesFromLookups } from '../shared/ruleDraft';
import type { RuleImportChoices, RuleImportResult } from '../shared/ruleImport';
import type { RuleCollectionGroup } from '../shared/types';

/** Re-reads Azure before staging, so stale previews cannot silently replace changed rules. */
export async function importRulesCsv(
  policyId: string,
  csv: string,
  choices: RuleImportChoices,
): Promise<RuleImportResult> {
  const [policy, running] = await Promise.all([
    getPolicy(policyId),
    listRuleCollectionGroups(policyId),
  ]);
  if (!policy.location)
    throw new Error(
      'The firewall policy has no location; refresh the policy before importing.',
    );
  const lookups = await getRuleLookups(
    policy.subscriptionId,
    policy.location.toLowerCase().replace(/\s+/g, ''),
  );
  const inheritedGroups: RuleCollectionGroup[] = [];
  const visited = new Set([policyId.toLowerCase()]);
  let parentId = policy.basePolicyId;
  while (parentId) {
    if (visited.has(parentId.toLowerCase()) || visited.size > 16)
      throw new Error(
        'The parent policy chain could not be resolved safely. Check the policy inheritance before importing.',
      );
    visited.add(parentId.toLowerCase());
    const [parent, groups] = await Promise.all([
      getPolicy(parentId),
      listRuleCollectionGroups(parentId),
    ]);
    inheritedGroups.push(
      ...candidate.view(parentId, groups).map((v) => v.group),
    );
    parentId = parent.basePolicyId;
  }
  return candidate.importRulesCsv(policyId, csv, choices, running, {
    inheritedGroups,
    known: knownValuesFromLookups(lookups),
    ipGroups: new Map(
      lookups.ipGroups.map((g) => [g.id.toLowerCase(), g.addresses]),
    ),
  });
}
