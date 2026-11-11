import { describe, expect, it } from 'vitest';
import { csvCell } from './csv';
import {
  planRuleImport,
  RULE_IMPORT_COLUMNS,
  ruleImportTemplate,
  type RuleImportChoices,
  type RuleImportContext,
} from './ruleImport';
import type { NetworkRule, RuleCollectionGroup } from './types';

const POLICY =
  '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/fp';
const base: Record<string, string> = {
  'Rule collection group': 'Imported',
  'Group priority': '200',
  'Rule collection': 'net',
  'Collection priority': '100',
  'Collection type': 'Network',
  Action: 'Allow',
  'Rule name': 'https',
  'Source addresses': '10.0.0.0/24',
  Protocols: 'TCP',
  'Destination addresses': '10.20.0.0/24',
  'Destination ports': '443',
};
const csv = (...rows: Record<string, string | undefined>[]) =>
  '\uFEFF' +
  [
    RULE_IMPORT_COLUMNS.join(','),
    ...rows.map((row) =>
      RULE_IMPORT_COLUMNS.map((column) => csvCell(row[column])).join(','),
    ),
  ].join('\r\n') +
  '\r\n';
const context: RuleImportContext = { policyId: POLICY, groups: [] };
const rule: NetworkRule = {
  ruleType: 'NetworkRule',
  name: 'https',
  sourceAddresses: ['10.0.0.0/24'],
  destinationAddresses: ['10.20.0.0/24'],
  destinationPorts: ['443'],
  ipProtocols: ['TCP'],
};
const existing: RuleCollectionGroup = {
  id: `${POLICY}/ruleCollectionGroups/Imported`,
  name: 'Imported',
  priority: 200,
  ruleCollections: [
    {
      name: 'net',
      priority: 100,
      ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
      action: { type: 'Allow' },
      rules: [rule],
    },
  ],
};

describe('CSV rule import', () => {
  it('ships a valid template covering all three rule types and IP Group resource IDs', () => {
    const text = ruleImportTemplate();
    expect(text.charCodeAt(0)).toBe(0xfeff);
    const preview = planRuleImport(text, context);
    expect(preview.errors).toEqual([]);
    expect(preview.rows.map((r) => r.kind)).toEqual([
      'Network',
      'Application',
      'DNAT',
      'Network',
    ]);
    const ipGroupExample = preview.rows.find(
      (r) => r.rule.name === 'example-ip-groups-https',
    );
    expect(ipGroupExample?.rule).toMatchObject({
      ruleType: 'NetworkRule',
      sourceIpGroups: [
        expect.stringMatching(
          /^\/subscriptions\/.+\/providers\/Microsoft\.Network\/ipGroups\/ipg-sources$/,
        ),
      ],
      destinationIpGroups: [
        expect.stringMatching(
          /^\/subscriptions\/.+\/providers\/Microsoft\.Network\/ipGroups\/ipg-destinations$/,
        ),
      ],
    });
    expect(ipGroupExample?.rule.description).toMatch(
      /full Azure resource IDs.*not their names/,
    );
    const choices: RuleImportChoices = {};
    for (const [index, original] of preview.rows.entries()) {
      const current = planRuleImport(text, context, choices).rows[index];
      choices[String(original.line)] = {
        action: 'import',
        token: current.token,
      };
    }
    const approved = planRuleImport(text, context, choices);
    expect(approved.errors).toEqual([]);
    expect(approved.ruleCount).toBe(4);
    expect(approved.newGroupCount).toBe(1);
    expect(approved.newCollectionCount).toBe(3);
  });

  it('handles quoted commas, escaped quotes, multiline descriptions, LF and blank lines', () => {
    const text =
      csv(
        { ...base, Description: 'DNS, "internal"\nsecond line' },
        {
          ...base,
          'Rule collection group': 'Other',
          'Group priority': '300',
          'Source addresses': '192.168.0.0/24',
        },
      ).replace(/\r\n/g, '\n') + '\n';
    const result = planRuleImport(text, context);
    expect(result.errors).toEqual([]);
    expect(result.ruleCount).toBe(2);
    expect(result.rows.map((r) => r.line)).toEqual([2, 4]);
    expect(result.rows[0].rule.description).toBe(
      'DNS, "internal"\nsecond line',
    );
  });

  it('rejects malformed, missing, duplicate and unsupported columns without staging partial rows', () => {
    for (const text of [
      '',
      'Rule name\nname',
      csv(base).replace('Protocols', 'Rule name'),
      csv(base).replace('Description', 'Unknown column'),
      csv(base).replace('https,', '"https,'),
      csv(base).replace(/,443,/, ',443,extra,'),
    ])
      expect(planRuleImport(text, context).errors.length).toBeGreaterThan(0);
    expect(
      planRuleImport(csv(base).replace('https,', '"https,'), context).errors[0]
        .line,
    ).toBe(2);
  });

  it('uses shared IP, name and rule-field validation and rejects ignored fields', () => {
    for (const change of [
      { 'Source addresses': '10.0.0.7/24' },
      { 'Rule name': 'bad name' },
      { Protocols: 'SCTP' },
      { 'Target URLs': 'www.contoso.com/path' },
      { 'Destination ports': '90000' },
    ])
      expect(
        planRuleImport(csv({ ...base, ...change }), context).errors.length,
      ).toBeGreaterThan(0);
    const application = {
      ...base,
      'Collection type': 'Application',
      'Destination ports': '',
      'Destination addresses': '',
      'Target FQDNs': 'www.contoso.com',
      Protocols: 'Https:443:ignored',
    };
    expect(
      planRuleImport(csv(application), context).errors.some((e) =>
        e.message.includes('Protocols'),
      ),
    ).toBe(true);
  });

  it('validates IP Group and service-tag references using the same loaded values as the editor', () => {
    const result = planRuleImport(
      csv({ ...base, 'Destination addresses': 'UnknownService' }),
      {
        ...context,
        known: { serviceTags: new Set(['azurecloud']) },
      },
    );
    expect(
      result.errors.some((e) => e.message.includes("isn't a service tag")),
    ).toBe(true);
  });

  it('rejects inconsistent settings and case-insensitive duplicate CSV rule names', () => {
    const ctx = { ...context, groups: [existing] };
    expect(
      planRuleImport(
        csv({ ...base, 'Group priority': '300' }),
        ctx,
      ).errors.some((e) => e.message.includes('cannot change')),
    ).toBe(true);
    expect(
      planRuleImport(csv({ ...base, Action: 'Deny' }), ctx).errors.some((e) =>
        e.message.includes('different settings'),
      ),
    ).toBe(true);
    expect(
      planRuleImport(
        csv(base, { ...base, 'Rule name': 'HTTPS' }),
        context,
      ).errors.some((e) => e.message.includes('already contains')),
    ).toBe(true);
  });

  it('skips unchanged same-name rules, and requires reviewed consent for replacement', () => {
    const ctx = { ...context, groups: [existing] };
    const identical = planRuleImport(csv(base), ctx);
    expect(identical.rows[0]).toMatchObject({
      unchanged: true,
      choice: 'skip',
    });
    expect(identical.groups).toEqual([]);
    const changed = csv({ ...base, 'Destination ports': '8443' });
    const preview = planRuleImport(changed, ctx);
    expect(preview.rows[0]).toMatchObject({
      sameName: true,
      unchanged: false,
      choice: 'skip',
    });
    const result = planRuleImport(changed, ctx, {
      2: { action: 'replace', token: preview.rows[0].token },
    });
    expect(result.errors).toEqual([]);
    expect(result.groups[0].ruleCollections[0].rules).toHaveLength(1);
    expect(result.groups[0].ruleCollections[0].rules[0]).toMatchObject({
      destinationPorts: ['8443'],
    });
    expect(existing.ruleCollections[0].rules[0]).toMatchObject({
      destinationPorts: ['443'],
    });
  });

  it('does not reuse approval after an existing rule changes', () => {
    const changed = csv({ ...base, 'Destination ports': '8443' });
    const preview = planRuleImport(changed, { ...context, groups: [existing] });
    const concurrent = structuredClone(existing);
    concurrent.ruleCollections[0].rules[0].description =
      'Changed after preview';
    const result = planRuleImport(
      changed,
      { ...context, groups: [concurrent] },
      {
        2: { action: 'replace', token: preview.rows[0].token },
      },
    );
    expect(
      result.errors.some((e) => e.message.includes('conflicts changed')),
    ).toBe(true);
  });

  it('requires a new review if a previously clean row gains a conflict', () => {
    const text = csv({ ...base, 'Rule name': 'new-name' });
    const preview = planRuleImport(text, context);
    expect(preview.rows[0].conflicts).toEqual([]);
    const changed = planRuleImport(
      text,
      { ...context, groups: [existing] },
      {
        2: { action: 'import', token: preview.rows[0].token },
      },
    );
    expect(
      changed.errors.some((e) => e.message.includes('conflicts changed')),
    ).toBe(true);
  });

  it('flags identical content under a different name and allows explicit continuation', () => {
    const text = csv({ ...base, 'Rule name': 'same-traffic' });
    const ctx = { ...context, groups: [existing] };
    const preview = planRuleImport(text, ctx);
    expect(preview.rows[0].conflicts[0].kind).toBe('duplicate');
    expect(preview.ruleCount).toBe(0);
    const approved = planRuleImport(text, ctx, {
      2: { action: 'import', token: preview.rows[0].token },
    });
    expect(approved.errors).toEqual([]);
    expect(approved.groups[0].ruleCollections[0].rules).toHaveLength(2);
  });

  it('warns about opposite-action overlaps in parent policies without editing them', () => {
    const parent = structuredClone(existing);
    parent.ruleCollections[0].action.type = 'Deny';
    const text = csv({ ...base, 'Rule collection group': 'Child' });
    const ctx = { ...context, inheritedGroups: [parent] };
    const preview = planRuleImport(text, ctx);
    expect(preview.rows[0].conflicts).toContainEqual(
      expect.objectContaining({
        kind: 'overlap',
        action: 'Deny',
        inherited: true,
      }),
    );
    const approved = planRuleImport(text, ctx, {
      2: { action: 'import', token: preview.rows[0].token },
    });
    expect(approved.errors).toEqual([]);
    expect(approved.groups.map((g) => g.name)).toEqual(['Child']);
  });

  it('enforces the actual UTF-8 byte limit', () => {
    const result = planRuleImport('\u00e9'.repeat(3 * 1024 * 1024), context);
    expect(result.errors[0].message).toContain('5 MB');
  });
});
