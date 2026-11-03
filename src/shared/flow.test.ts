import { describe, expect, it } from 'vitest';
import { evaluateFlow, fqdnMatches, type PolicyLayer } from './flow';
import type {
  ApplicationRule,
  NatRule,
  NetworkRule,
  RuleCollection,
  RuleCollectionGroup,
} from './types';

const IPG =
  '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/ipg-spokes';
const net = (name: string, over: Partial<NetworkRule>): NetworkRule => ({
  ruleType: 'NetworkRule',
  name,
  ipProtocols: ['TCP'],
  sourceAddresses: ['10.0.0.0/8'],
  destinationPorts: ['*'],
  ...over,
});
const filter = (
  name: string,
  priority: number,
  action: 'Allow' | 'Deny',
  rules: (NetworkRule | ApplicationRule)[],
): RuleCollection => ({
  ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
  name,
  priority,
  action: { type: action },
  rules,
});
const group = (
  name: string,
  priority: number,
  ruleCollections: RuleCollection[],
): RuleCollectionGroup => ({
  id: `g/${name}`,
  name,
  priority,
  ruleCollections,
});
const layer = (
  groups: RuleCollectionGroup[],
  inherited = false,
): PolicyLayer => ({
  policyId: inherited ? 'parent' : 'child',
  policyName: inherited ? 'fp-org-base' : 'fp-hub-eus',
  inherited,
  groups,
});

const dnat: NatRule = {
  ruleType: 'NatRule',
  name: 'web-https',
  ipProtocols: ['TCP'],
  sourceAddresses: ['*'],
  destinationAddresses: ['20.62.18.40'],
  destinationPorts: ['443'],
  translatedAddress: '10.20.1.4',
  translatedPort: '443',
};

describe('evaluateFlow', () => {
  const child = layer([
    group('rcg-deny', 65000, [
      filter('deny-smb', 100, 'Deny', [
        net('block-smb', {
          sourceAddresses: ['*'],
          destinationAddresses: ['*'],
          destinationPorts: ['445'],
        }),
      ]),
    ]),
    group('rcg-platform', 200, [
      filter('allow-core', 100, 'Allow', [
        net('dns', {
          destinationAddresses: ['10.0.10.4'],
          destinationPorts: ['53'],
          ipProtocols: ['UDP', 'TCP'],
        }),
        net('wide', {
          destinationAddresses: ['10.0.0.0/8'],
          destinationPorts: ['400-500'],
        }),
      ]),
    ]),
    group('rcg-dnat', 100, [
      {
        ruleCollectionType: 'FirewallPolicyNatRuleCollection',
        name: 'dnat-web',
        priority: 100,
        action: { type: 'DNAT' },
        rules: [dnat],
      },
    ]),
  ]);

  it('picks the first match in group/collection priority order', () => {
    // 445 is covered by "wide" (group 200) before "block-smb" (group 65000).
    const r = evaluateFlow(
      {
        source: '10.1.2.3',
        destination: '10.0.10.9',
        protocol: 'TCP',
        port: 445,
      },
      [child],
    );
    expect(r.verdict).toBe('Allow');
    expect(r.winner).toMatchObject({ groupName: 'rcg-platform', rule: 'wide' });
  });

  it('falls through to later groups and to the default deny', () => {
    expect(
      evaluateFlow(
        {
          source: '192.168.1.1',
          destination: '8.8.8.8',
          protocol: 'TCP',
          port: 445,
        },
        [child],
      ).winner?.rule,
    ).toBe('block-smb');
    const none = evaluateFlow(
      {
        source: '10.1.2.3',
        destination: '10.0.10.4',
        protocol: 'TCP',
        port: 25,
      },
      [child],
    );
    expect(none.verdict).toBe('default-deny');
    expect(none.rulesChecked).toBe(4);
  });

  it('processes DNAT before network rules, and reports the translation', () => {
    const r = evaluateFlow(
      {
        source: '203.0.113.9',
        destination: '20.62.18.40',
        protocol: 'TCP',
        port: 443,
      },
      [child],
    );
    expect(r.verdict).toBe('DNAT');
    expect(r.winner).toMatchObject({
      pass: 'DNAT',
      translatedTo: '10.20.1.4:443',
    });
  });

  it('processes the parent policy before the child, regardless of priority', () => {
    const parent = layer(
      [
        group('base-deny', 60000, [
          filter('deny-all-53', 100, 'Deny', [
            net('no-dns', {
              sourceAddresses: ['*'],
              destinationAddresses: ['*'],
              destinationPorts: ['53'],
              ipProtocols: ['UDP'],
            }),
          ]),
        ]),
      ],
      true,
    );
    const r = evaluateFlow(
      {
        source: '10.1.2.3',
        destination: '10.0.10.4',
        protocol: 'UDP',
        port: 53,
      },
      [child, parent],
    );
    expect(r.verdict).toBe('Deny');
    expect(r.winner).toMatchObject({ inherited: true, rule: 'no-dns' });
  });

  it('reports IP Groups and service tags as "maybe" instead of guessing', () => {
    const l = layer([
      group('g', 100, [
        filter('c', 100, 'Allow', [
          net('via-ipg', {
            sourceAddresses: [],
            sourceIpGroups: [IPG],
            destinationAddresses: ['10.0.10.4'],
            destinationPorts: ['53'],
          }),
          net('to-cloud', {
            destinationAddresses: ['AzureCloud'],
            destinationPorts: ['1688'],
          }),
        ]),
      ]),
    ]);
    const r = evaluateFlow(
      {
        source: '10.1.2.3',
        destination: '10.0.10.4',
        protocol: 'TCP',
        port: 53,
      },
      [l],
    );
    expect(r.verdict).toBe('default-deny');
    expect(r.maybes.map((m) => [m.rule, m.unknowns])).toEqual([
      ['via-ipg', ['the source IP Group’s members couldn’t be loaded']],
    ]);
    expect(
      evaluateFlow(
        {
          source: '10.1.2.3',
          destination: '52.1.1.1',
          protocol: 'TCP',
          port: 1688,
        },
        [l],
      ).maybes[0].unknowns,
    ).toEqual([
      'it depends on whether the address is in the AzureCloud service tag, whose ranges aren’t checked here',
    ]);
  });

  it('matches application rules on host name and port, after network rules', () => {
    const app: ApplicationRule = {
      ruleType: 'ApplicationRule',
      name: 'ms',
      protocols: [{ protocolType: 'Https', port: 443 }],
      sourceAddresses: ['10.0.0.0/8'],
      targetFqdns: ['*.microsoft.com'],
    };
    const l = layer([group('g', 100, [filter('apps', 200, 'Allow', [app])])]);
    expect(
      evaluateFlow(
        {
          source: '10.1.2.3',
          destination: 'login.microsoft.com',
          protocol: 'TCP',
          port: 443,
        },
        [l],
      ).winner?.rule,
    ).toBe('ms');
    expect(
      evaluateFlow(
        {
          source: '10.1.2.3',
          destination: 'login.microsoft.com',
          protocol: 'TCP',
          port: 80,
        },
        [l],
      ).verdict,
    ).toBe('default-deny');
  });

  it('resolves the Internet service tag as public address space', () => {
    const l = layer([
      group('g', 100, [
        filter('deny-out', 100, 'Deny', [
          net('block-smb-out', {
            sourceAddresses: ['*'],
            destinationAddresses: ['Internet'],
            destinationPorts: ['445'],
          }),
        ]),
      ]),
    ]);
    const flow = (destination: string) =>
      evaluateFlow(
        { source: '10.1.2.3', destination, protocol: 'TCP', port: 445 },
        [l],
      );
    expect(flow('8.8.8.8').winner?.rule).toBe('block-smb-out');
    expect(flow('10.0.10.9').verdict).toBe('default-deny');
    expect(flow('10.0.10.9').maybes).toEqual([]);
  });

  it('only lists uncertain rules that could change the result', () => {
    const app = (name: string, webCategories: string[]): ApplicationRule => ({
      ruleType: 'ApplicationRule',
      name,
      protocols: [{ protocolType: 'Https', port: 443 }],
      sourceAddresses: ['*'],
      webCategories,
    });
    const l = layer([
      group('g', 100, [
        filter('deny-cats', 100, 'Deny', [app('deny-gambling', ['Gambling'])]),
        filter('allow-cats', 200, 'Allow', [
          app('allow-news', ['NewsAndMedia']),
        ]),
      ]),
    ]);
    const flow = (destination: string) =>
      evaluateFlow(
        { source: '10.1.2.3', destination, protocol: 'TCP', port: 443 },
        [l],
      );
    // A possible Deny can't change a default deny; a possible Allow can.
    const pub = flow('52.1.1.1');
    expect(pub.verdict).toBe('default-deny');
    expect(pub.maybes.map((m) => m.rule)).toEqual(['allow-news']);
    // Web categories never apply to private addresses.
    expect(flow('10.15.1.0').maybes).toEqual([]);
  });

  it('decides web category rules from the categories the user supplies', () => {
    const app = (name: string, webCategories: string[]): ApplicationRule => ({
      ruleType: 'ApplicationRule',
      name,
      protocols: [{ protocolType: 'Https', port: 443 }],
      sourceAddresses: ['*'],
      webCategories,
    });
    const l = layer([
      group('g', 100, [
        filter('deny-cats', 100, 'Deny', [app('deny-gambling', ['Gambling'])]),
        filter('allow-cats', 200, 'Allow', [
          app('allow-news', ['NewsAndMedia']),
        ]),
      ]),
    ]);
    const flow = (webCategories: string[]) =>
      evaluateFlow(
        {
          source: '10.1.2.3',
          destination: 'www.example.com',
          protocol: 'TCP',
          port: 443,
          webCategories,
        },
        [l],
      );
    const news = flow(['newsandmedia']);
    expect(news.verdict).toBe('Allow');
    expect(news.winner?.rule).toBe('allow-news');
    expect(news.maybes).toEqual([]);
    const gambling = flow(['Gambling']);
    expect(gambling.verdict).toBe('Deny');
    expect(gambling.winner?.rule).toBe('deny-gambling');
    const other = flow(['Travel']);
    expect(other.verdict).toBe('default-deny');
    expect(other.maybes).toEqual([]);
    // No categories supplied: still unsure.
    expect(flow([]).maybes.map((m) => m.rule)).toEqual(['allow-news']);
  });

  it('handles ICMP without ports', () => {
    const l = layer([
      group('g', 100, [
        filter('c', 100, 'Allow', [
          net('ping', {
            ipProtocols: ['ICMP'],
            destinationAddresses: ['*'],
            destinationPorts: ['*'],
          }),
        ]),
      ]),
    ]);
    expect(
      evaluateFlow(
        { source: '10.1.2.3', destination: '10.9.9.9', protocol: 'ICMP' },
        [l],
      ).winner?.rule,
    ).toBe('ping');
  });
});

describe('fqdnMatches', () => {
  it('supports exact names and wildcard subdomains', () => {
    expect(fqdnMatches('*.contoso.com', 'www.contoso.com')).toBe(true);
    expect(fqdnMatches('*.contoso.com', 'contoso.com')).toBe(false);
    expect(fqdnMatches('WWW.contoso.com', 'www.contoso.com.')).toBe(true);
    expect(fqdnMatches('*', 'anything.example')).toBe(true);
  });

  it('treats a bare leading * as "ends with", like Azure Firewall', () => {
    expect(fqdnMatches('*contoso.com', 'contoso.com')).toBe(true);
    expect(fqdnMatches('*contoso.com', 'www.contoso.com')).toBe(true);
    expect(fqdnMatches('*contoso.com', 'mycontoso.com')).toBe(true);
    expect(fqdnMatches('*contoso.com', 'contoso.net')).toBe(false);
  });
});

describe('evaluateFlow with policy inheritance', () => {
  const dnatGroup = (name: string, rule: NatRule) =>
    group(name, 100, [
      {
        ruleCollectionType: 'FirewallPolicyNatRuleCollection',
        name: `${name}-dnat`,
        priority: 100,
        action: { type: 'DNAT' },
        rules: [rule],
      },
    ]);
  const inbound = {
    source: '203.0.113.5',
    destination: '20.62.18.40',
    protocol: 'TCP' as const,
    port: 443,
  };

  it("ignores a parent policy's DNAT rules (Azure doesn't inherit them)", () => {
    const parent = layer([dnatGroup('base', dnat)], true);
    expect(evaluateFlow(inbound, [parent, layer([])]).verdict).toBe(
      'default-deny',
    );
    const own = evaluateFlow(inbound, [
      parent,
      layer([dnatGroup('own', { ...dnat, name: 'own-https' })]),
    ]);
    expect(own.verdict).toBe('DNAT');
    expect(own.winner?.rule).toBe('own-https');
    expect(own.winner?.translatedTo).toBe('10.20.1.4:443');
  });

  it("still applies a parent's network rules before the child's", () => {
    const parent = layer(
      [
        group('base', 65000, [
          filter('deny', 100, 'Deny', [
            net('block', { destinationAddresses: ['*'] }),
          ]),
        ]),
      ],
      true,
    );
    const child = layer([
      group('own', 100, [
        filter('allow', 100, 'Allow', [
          net('allow', { destinationAddresses: ['*'] }),
        ]),
      ]),
    ]);
    const r = evaluateFlow(
      {
        source: '10.1.2.3',
        destination: '10.9.9.9',
        protocol: 'TCP',
        port: 22,
      },
      [child, parent],
    );
    expect(r.winner?.rule).toBe('block');
    expect(r.winner?.inherited).toBe(true);
  });

  it('shows an unknown translation target instead of "undefined"', () => {
    const r = evaluateFlow(inbound, [
      layer([
        dnatGroup('own', {
          ...dnat,
          translatedAddress: undefined,
          translatedPort: undefined,
        }),
      ]),
    ]);
    expect(r.winner?.translatedTo).toBe('?:?');
  });

  it('matches application rules with a bare leading * wildcard', () => {
    const app: ApplicationRule = {
      ruleType: 'ApplicationRule',
      name: 'contoso',
      protocols: [{ protocolType: 'Https', port: 443 }],
      sourceAddresses: ['*'],
      targetFqdns: ['*contoso.com'],
    };
    const l = layer([group('g', 100, [filter('c', 100, 'Allow', [app])])]);
    const flow = (destination: string) =>
      evaluateFlow(
        { source: '10.1.2.3', destination, protocol: 'TCP', port: 443 },
        [l],
      ).verdict;
    expect(flow('contoso.com')).toBe('Allow');
    expect(flow('login.contoso.com')).toBe('Allow');
    expect(flow('fabrikam.com')).toBe('default-deny');
  });
});
