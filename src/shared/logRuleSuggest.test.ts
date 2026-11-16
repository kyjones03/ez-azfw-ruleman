import { describe, expect, it } from 'vitest';
import {
  canSuggestRule,
  ruleEffect,
  suggestedRuleName,
  suggestRuleFromRow,
} from './logRuleSuggest';
import type { PolicyLayer } from './flow';
import type { FirewallLogRow } from './fwLogs';
import { nameError } from './naming';

const row = (patch: Partial<FirewallLogRow> = {}): FirewallLogRow => ({
  id: '1',
  time: '2026-11-16T17:30:00Z',
  category: 'NetworkRule',
  protocol: 'TCP',
  sourceIp: '10.50.1.4',
  sourcePort: '40000',
  targetIp: '1.1.1.1',
  targetPort: '443',
  action: 'Deny',
  policy: '',
  moreInfo: '',
  resourceId: '',
  fwPolicy: '',
  ruleCollectionGroup: '',
  ruleCollection: '',
  ruleName: '',
  natDstIp: '',
  natDstPort: '',
  explicitProxy: '',
  tlsInspected: '',
  ...patch,
});

describe('canSuggestRule', () => {
  it('is only true for denied network and application rule rows', () => {
    expect(canSuggestRule(row())).toBe(true);
    expect(canSuggestRule(row({ category: 'AppRule' }))).toBe(true);
    expect(canSuggestRule(row({ action: 'Allow' }))).toBe(false);
    expect(canSuggestRule(row({ category: 'NATRule', action: 'DNAT' }))).toBe(
      false,
    );
    expect(canSuggestRule(row({ category: 'DnsQuery' }))).toBe(false);
  });
});

describe('suggestRuleFromRow', () => {
  it('makes the narrowest network rule: exact source, destination, protocol and port', () => {
    const r = suggestRuleFromRow(row());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const { row: out, kind, flow, summary } = r.suggestion;
    expect(kind).toBe('Network');
    expect(out.lists.sourceAddresses).toBe('10.50.1.4');
    expect(out.lists.destinationAddresses).toBe('1.1.1.1');
    expect(out.lists.destinationPorts).toBe('443');
    expect(out.protocols).toEqual(['TCP']);
    expect(flow).toEqual({
      source: '10.50.1.4',
      destination: '1.1.1.1',
      protocol: 'TCP',
      port: 443,
    });
    expect(summary).toBe('10.50.1.4 → 1.1.1.1 TCP 443');
    expect(nameError('rule', out.name)).toBeUndefined();
  });

  it('uses any port for ICMP', () => {
    const r = suggestRuleFromRow(row({ protocol: 'ICMP', targetPort: '-' }));
    expect(r.ok && r.suggestion.row.lists.destinationPorts).toBe('*');
  });

  it('makes an application rule with the FQDN and the scheme and port that were denied', () => {
    const r = suggestRuleFromRow(
      row({
        category: 'AppRule',
        protocol: 'HTTPS',
        targetIp: 'www.example.com',
        targetPort: '443',
      }),
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.suggestion.kind).toBe('Application');
    expect(r.suggestion.row.appProtocols).toBe('Https:443');
    expect(r.suggestion.row.lists.targetFqdns).toBe('www.example.com');
    expect(r.suggestion.row.lists.sourceAddresses).toBe('10.50.1.4');
  });

  it('remembers which explicit rule denied the flow', () => {
    const r = suggestRuleFromRow(
      row({
        fwPolicy: 'fp',
        ruleCollectionGroup: 'g',
        ruleCollection: 'c',
        ruleName: 'deny-x',
      }),
    );
    expect(r.ok && r.suggestion.deniedBy).toEqual({
      rule: 'deny-x',
      collection: 'c',
      group: 'g',
      policy: 'fp',
    });
  });

  it.each([
    ['an allowed row', { action: 'Allow' }],
    ['a DNAT row', { category: 'NATRule' as const }],
    ['an IPv6 source', { sourceIp: '2001:db8::1' }],
    ['an IPv6 destination', { targetIp: '2001:db8::2' }],
    ['an unknown protocol', { protocol: 'GRE' }],
    ['no port', { targetPort: '-' }],
    ['a port out of range', { targetPort: '70000' }],
  ])('refuses %s', (_n, patch) => {
    expect(suggestRuleFromRow(row(patch)).ok).toBe(false);
  });

  it.each(['a b', 'evil\u202e.com', '', '*.example.com', 'x'.repeat(300)])(
    'refuses an application destination that is not a plain host name (%j)',
    (fqdn) => {
      expect(
        suggestRuleFromRow(
          row({ category: 'AppRule', protocol: 'HTTPS', targetIp: fqdn }),
        ).ok,
      ).toBe(false);
    },
  );
});

describe('suggestedRuleName', () => {
  it('is always a valid rule name', () => {
    for (const parts of [
      ['10.0.0.1', '1.1.1.1-443'],
      ['x'.repeat(200)],
      ['---'],
      ['a b/c'],
    ])
      expect(nameError('rule', suggestedRuleName(parts))).toBeUndefined();
  });
});

// ── what the rule would do ───────────────────────────────────────────────────

const netRule = (name: string, dest: string) => ({
  ruleType: 'NetworkRule',
  name,
  ipProtocols: ['TCP'],
  sourceAddresses: ['*'],
  destinationAddresses: [dest],
  destinationPorts: ['443'],
});
const collection = (
  name: string,
  priority: number,
  action: 'Allow' | 'Deny',
  rules: unknown[],
) => ({
  ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
  name,
  priority,
  action: { type: action },
  rules,
});
const layer = (
  id: string,
  inherited: boolean,
  groups: { id: string; priority: number; collections: unknown[] }[],
): PolicyLayer => ({
  policyId: id,
  policyName: id,
  inherited,
  groups: groups.map((g) => ({
    id: g.id,
    name: g.id,
    priority: g.priority,
    ruleCollections: g.collections,
  })) as PolicyLayer['groups'],
});

const suggestion = () => {
  const r = suggestRuleFromRow(row());
  if (!r.ok) throw new Error('expected a suggestion');
  return r.suggestion;
};

describe('ruleEffect', () => {
  it('allows the flow when only the default deny stands in the way', () => {
    const layers = [
      layer('own', false, [{ id: 'g', priority: 100, collections: [] }]),
    ];
    const effect = ruleEffect(suggestion(), layers, 'own', {
      groupId: 'g',
      newPriority: 1000,
    });
    expect(effect.allowed).toBe(true);
  });

  it('warns when a Deny rule in the parent policy is processed first', () => {
    const layers = [
      layer('parent', true, [
        {
          id: 'pg',
          priority: 100,
          collections: [
            collection('deny-all', 100, 'Deny', [
              netRule('deny-cf', '1.1.1.1'),
            ]),
          ],
        },
      ]),
      layer('own', false, [{ id: 'g', priority: 100, collections: [] }]),
    ];
    const effect = ruleEffect(suggestion(), layers, 'own', {
      groupId: 'g',
      newPriority: 1000,
    });
    expect(effect.allowed).toBe(false);
    expect(effect.message).toContain('deny-cf');
    expect(effect.message).toContain('parent policy parent');
  });

  it('warns when a Deny collection in the same group has the lower priority number', () => {
    const layers = [
      layer('own', false, [
        {
          id: 'g',
          priority: 100,
          collections: [
            collection('deny', 200, 'Deny', [netRule('deny-cf', '1.1.1.1')]),
          ],
        },
      ]),
    ];
    const late = ruleEffect(suggestion(), layers, 'own', {
      groupId: 'g',
      newPriority: 300,
    });
    expect(late.allowed).toBe(false);
    const early = ruleEffect(suggestion(), layers, 'own', {
      groupId: 'g',
      newPriority: 100,
    });
    expect(early.allowed).toBe(true);
  });

  it('adds the rule to an existing Allow collection', () => {
    const layers = [
      layer('own', false, [
        {
          id: 'g',
          priority: 100,
          collections: [
            collection('allow', 500, 'Allow', [netRule('other', '8.8.8.8')]),
          ],
        },
      ]),
    ];
    const effect = ruleEffect(suggestion(), layers, 'own', {
      groupId: 'g',
      collection: 'allow',
      newPriority: 0,
    });
    expect(effect.allowed).toBe(true);
  });

  it('does not change the layers it was given', () => {
    const layers = [
      layer('own', false, [{ id: 'g', priority: 100, collections: [] }]),
    ];
    const before = JSON.stringify(layers);
    ruleEffect(suggestion(), layers, 'own', {
      groupId: 'g',
      newPriority: 1000,
    });
    expect(JSON.stringify(layers)).toBe(before);
  });
});
