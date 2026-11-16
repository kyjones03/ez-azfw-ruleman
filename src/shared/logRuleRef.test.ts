import { describe, expect, it } from 'vitest';
import { findLoggedRule, logRuleRef } from './logRuleRef';
import type { PolicyView } from './types';

const view = (
  name: string,
  groups: { name: string; collections: Record<string, string[]> }[],
): PolicyView =>
  ({
    policy: { id: `/p/${name}`, name },
    groups: groups.map((g) => ({
      group: {
        id: `/p/${name}/ruleCollectionGroups/${g.name}`,
        name: g.name,
        priority: 100,
        ruleCollections: Object.entries(g.collections).map(([c, rules]) => ({
          name: c,
          priority: 100,
          rules: rules.map((r) => ({ name: r })),
        })),
      },
    })),
  }) as unknown as PolicyView;

const child = view('fp-child', [
  { name: 'rcg-app', collections: { 'allow-web': ['allow-microsoft'] } },
]);
const parent = view('fp-parent', [
  { name: 'rcg-base', collections: { 'deny-bad': ['deny-cloudflare'] } },
]);

const row = (patch = {}) => ({
  fwPolicy: 'fp-child',
  ruleCollectionGroup: 'rcg-app',
  ruleCollection: 'allow-web',
  ruleName: 'allow-microsoft',
  ...patch,
});

describe('logRuleRef', () => {
  it('names the rule and keeps the firewall policy', () => {
    expect(logRuleRef(row(), '/p/fp-child')).toEqual({
      firewallPolicyId: '/p/fp-child',
      policyName: 'fp-child',
      groupName: 'rcg-app',
      collection: 'allow-web',
      rule: 'allow-microsoft',
    });
  });
  it('gives nothing for a row without a matched rule or without a policy', () => {
    expect(logRuleRef(row({ ruleName: '' }), '/p/fp-child')).toBeUndefined();
    expect(logRuleRef(row({ ruleCollectionGroup: '' }), '/p')).toBeUndefined();
    expect(logRuleRef(row(), undefined)).toBeUndefined();
  });
});

describe('findLoggedRule', () => {
  const ref = (patch = {}) => ({
    firewallPolicyId: '/p/fp-child',
    policyName: 'fp-child',
    groupName: 'rcg-app',
    collection: 'allow-web',
    rule: 'allow-microsoft',
    ...patch,
  });

  it('finds a rule in the firewall policy', () => {
    expect(findLoggedRule(ref(), [child, parent])).toEqual({
      found: true,
      focus: {
        policyId: '/p/fp-child',
        groupId: '/p/fp-child/ruleCollectionGroups/rcg-app',
        collection: 'allow-web',
        rule: 'allow-microsoft',
        inherited: false,
      },
    });
  });

  it('finds an inherited rule in a parent and marks it inherited', () => {
    const found = findLoggedRule(
      ref({
        policyName: 'FP-PARENT',
        groupName: 'RCG-BASE',
        collection: 'deny-bad',
        rule: 'DENY-CLOUDFLARE',
      }),
      [child, parent],
    );
    expect(found.found && found.focus.inherited).toBe(true);
    expect(found.found && found.focus.policyId).toBe('/p/fp-parent');
  });

  it('searches every layer when the row names no policy', () => {
    const found = findLoggedRule(
      ref({
        policyName: '',
        groupName: 'rcg-base',
        collection: 'deny-bad',
        rule: 'deny-cloudflare',
      }),
      [child, parent],
    );
    expect(found.found && found.focus.inherited).toBe(true);
  });

  it('says why when the policy is not in the chain', () => {
    const found = findLoggedRule(ref({ policyName: 'other' }), [child, parent]);
    expect(found).toMatchObject({ found: false });
    expect(!found.found && found.reason).toContain('not in this firewall');
  });

  it('says why when the rule is gone', () => {
    const found = findLoggedRule(ref({ rule: 'removed' }), [child, parent]);
    expect(!found.found && found.reason).toContain('renamed or removed');
  });
});
