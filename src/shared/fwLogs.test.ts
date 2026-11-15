import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  displaySafe,
  parseRecord,
  tcpDirection,
  type FirewallLogRow,
} from './fwLogs';

const FW_ID =
  '/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/rg-hub/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/FW-HUB';

const structured = (
  category: string,
  props: Record<string, unknown> = {},
  time = '2026-09-05T08:00:00Z',
) => ({
  resourceId: FW_ID,
  category,
  operationName: 'AzureFirewall',
  time,
  properties: props,
});
const legacy = (category: string, operationName: string, msg: string) => ({
  resourceId: FW_ID,
  category,
  operationName,
  time: '2026-09-05T08:00:00Z',
  properties: { msg },
});
const rowOf = (record: unknown): FirewallLogRow => {
  const r = parseRecord(record);
  if (r.kind !== 'row')
    throw new Error(`expected a row, got skip: ${r.reason}`);
  return r.row;
};
const skipOf = (record: unknown): string => {
  const r = parseRecord(record);
  if (r.kind !== 'skip') throw new Error('expected a skip');
  return r.reason;
};

const RULE = {
  Policy: 'pol',
  RuleCollectionGroup: 'rcg',
  RuleCollection: 'rc',
  Rule: 'r',
};

describe('skips', () => {
  it('skips non-firewall resources, case-insensitively matching firewalls', () => {
    expect(
      skipOf({
        ...structured('AZFWNetworkRule'),
        resourceId:
          '/SUBSCRIPTIONS/x/PROVIDERS/MICROSOFT.NETWORK/VIRTUALNETWORKS/v',
      }),
    ).toBe('ResourceType');
    expect(
      rowOf({
        ...structured('AZFWNetworkRule'),
        resourceId: FW_ID.toLowerCase(),
      }).category,
    ).toBe('NetworkRule');
  });
  it.each([
    'AZFWDnsAdditional',
    'AZFWNetworkRuleAggregation',
    'AzureFirewallMetrics',
    '',
  ])('skips unknown category %j with its name', (c) =>
    expect(skipOf(structured(c))).toBe(`Category:${c}`),
  );
  it('never throws on junk', () => {
    for (const junk of [
      null,
      undefined,
      5,
      'x',
      [],
      {},
      { resourceId: 5, category: {} },
    ])
      expect(parseRecord(junk).kind).toBe('skip');
  });
  it('tolerates a missing or odd properties value', () => {
    expect(
      rowOf({ resourceId: FW_ID, category: 'AZFWNetworkRule', time: 't' })
        .category,
    ).toBe('NetworkRule');
    expect(
      rowOf({ resourceId: FW_ID, category: 'AZFWNetworkRule', properties: 'x' })
        .category,
    ).toBe('NetworkRule');
  });
  it('keeps skip reasons display-safe', () => {
    expect(skipOf(structured('AZFW\u001b[2J'))).toBe('Category:AZFW\uFFFD[2J');
  });
});

describe('structured format', () => {
  it('NetworkRule with rule path', () => {
    const row = rowOf(
      structured('AZFWNetworkRule', {
        Protocol: 'TCP',
        SourceIp: '10.0.0.1',
        SourcePort: 1234,
        DestinationIp: '10.0.0.2',
        DestinationPort: 443,
        Action: 'Allow',
        ...RULE,
      }),
    );
    expect(row).toMatchObject({
      category: 'NetworkRule',
      protocol: 'TCP',
      sourceIp: '10.0.0.1',
      sourcePort: '1234',
      targetIp: '10.0.0.2',
      targetPort: '443',
      action: 'Allow',
      policy: 'pol»rcg»rc»r',
      fwPolicy: 'pol',
      ruleCollectionGroup: 'rcg',
      ruleCollection: 'rc',
      ruleName: 'r',
      resourceId: FW_ID,
    });
  });
  it('NetworkRule without a group shows the action reason; ICMP ports are "-"', () => {
    const row = rowOf(
      structured('AZFWNetworkRule', {
        Protocol: 'ICMP',
        Action: 'Deny',
        ActionReason: 'Default Action',
      }),
    );
    expect(row.policy).toBe('Default Action');
    expect(row.sourcePort).toBe('-');
    expect(row.targetPort).toBe('-');
  });
  it('AppRule: path, partial path, reason and policy fallbacks, tri-state flags', () => {
    const full = rowOf(
      structured('AZFWApplicationRule', {
        Protocol: 'HTTPS',
        SourceIp: '10.0.0.1',
        Fqdn: 'a.example',
        DestinationPort: 443,
        Action: 'Allow',
        TargetUrl: 'https://a.example/x',
        IsExplicitProxyRequest: true,
        IsTlsInspected: 'False',
        ...RULE,
      }),
    );
    expect(full).toMatchObject({
      category: 'AppRule',
      targetIp: 'a.example',
      policy: 'pol»rcg»rc»r',
      moreInfo: 'https://a.example/x',
      explicitProxy: 'yes',
      tlsInspected: 'no',
    });
    expect(
      rowOf(structured('AZFWApplicationRule', { Policy: 'p', Rule: 'only' }))
        .policy,
    ).toBe('p»only');
    expect(
      rowOf(
        structured('AZFWApplicationRule', {
          Policy: 'p',
          ActionReason: 'No rule matched',
        }),
      ).policy,
    ).toBe('No rule matched');
    expect(
      rowOf(structured('AZFWApplicationRule', { Policy: 'p' })).policy,
    ).toBe('p');
    const unknown = rowOf(
      structured('AZFWApplicationRule', {
        IsTlsInspected: 'maybe',
        IsExplicitProxyRequest: null,
      }),
    );
    expect(unknown.tlsInspected).toBe('');
    expect(unknown.explicitProxy).toBe('');
  });
  it('NatRule shows the translated target and keeps the public destination', () => {
    const row = rowOf(
      structured('AZFWNatRule', {
        Protocol: 'TCP',
        SourceIp: '1.2.3.4',
        SourcePort: 5,
        DestinationIp: '5.6.7.8',
        DestinationPort: 3389,
        TranslatedIp: '10.1.1.1',
        TranslatedPort: 3390,
        ...RULE,
      }),
    );
    expect(row).toMatchObject({
      category: 'NATRule',
      action: 'DNAT',
      targetIp: '10.1.1.1',
      targetPort: '3390',
      natDstIp: '5.6.7.8',
      natDstPort: '3389',
    });
  });
  it('DnsQuery: query type in Proto, no trailing dot, port 53, default action', () => {
    const row = rowOf(
      structured('AZFWDnsQuery', {
        SourceIp: 'fd10:3:5:1::4',
        SourcePort: 1,
        QueryType: 'AAAA',
        QueryName: 'ifconfig.me.',
        ResponseCode: 'NXDOMAIN',
      }),
    );
    expect(row).toMatchObject({
      category: 'DnsQuery',
      protocol: 'AAAA',
      targetIp: 'ifconfig.me',
      targetPort: '53',
      action: 'NXDOMAIN',
    });
    expect(rowOf(structured('AZFWDnsQuery', {})).action).toBe('Request');
  });
  it('IDPS capitalises the action and joins details', () => {
    const row = rowOf(
      structured('AZFWIdpsSignature', {
        Action: 'alert',
        Severity: 1,
        SignatureId: 2024,
        Category: 'trojan',
        Description: 'bad',
      }),
    );
    expect(row).toMatchObject({
      category: 'IDPS',
      action: 'Alert',
      moreInfo: 'SEV:1 · 2024 · trojan · bad',
    });
  });
  it('ThreatIntel prefers the FQDN over the address', () => {
    expect(
      rowOf(
        structured('AZFWThreatIntel', {
          Fqdn: 'evil.example',
          DestinationIp: '',
          Action: 'deny',
        }),
      ),
    ).toMatchObject({
      targetIp: 'evil.example',
      action: 'Deny',
    });
    expect(
      rowOf(structured('AZFWThreatIntel', { DestinationIp: '9.9.9.9' }))
        .targetIp,
    ).toBe('9.9.9.9');
  });
  it.each(['AZFWFqdnResolveFailure', 'AZFWInternalFqdnResolutionFailure'])(
    '%s is a DnsFailure',
    (c) => {
      expect(
        rowOf(
          structured(c, { Fqdn: 'nope.invalid', Error: 'NXDOMAIN', ...RULE }),
        ),
      ).toMatchObject({
        category: 'DnsFailure',
        action: 'ResolveFail',
        targetIp: 'nope.invalid',
        moreInfo: 'NXDOMAIN',
        policy: 'pol»rcg»rc»r',
      });
    },
  );
  it('FlowTrace puts the flag in Action and the direction in info, dropping the boilerplate', () => {
    const row = rowOf(
      structured('AZFWFlowTrace', {
        Flag: 'SYN-ACK',
        SourcePort: 443,
        DestinationPort: 50000,
        Action: 'Log Additional',
        ActionReason: 'TCP Log',
      }),
    );
    expect(row).toMatchObject({
      category: 'FlowTrace',
      action: 'SYN-ACK',
      moreInfo: 'server → client',
    });
    expect(
      rowOf(
        structured('AZFWFlowTrace', {
          Flag: 'RST',
          SourcePort: 50000,
          DestinationPort: 443,
          Action: 'Deny',
          ActionReason: 'x',
        }),
      ).moreInfo,
    ).toBe('client → server · Deny x');
    expect(rowOf(structured('AZFWFlowTrace', {})).action).toBe('-');
  });
  it('FatFlow formats the rate with three decimals below 1 Mbit/s', () => {
    expect(
      rowOf(structured('AZFWFatFlow', { FlowRate: '3.2930000000000001' }))
        .action,
    ).toBe('3.3 Mbps');
    expect(rowOf(structured('AZFWFatFlow', { FlowRate: '0.024' })).action).toBe(
      '0.024 Mbps',
    );
    expect(rowOf(structured('AZFWFatFlow', { FlowRate: 'abc' })).action).toBe(
      'abc Mbps',
    );
    expect(rowOf(structured('AZFWFatFlow', {})).action).toBe('-');
  });
});

describe('tcpDirection', () => {
  it('uses the flag first, then the higher port', () => {
    expect(tcpDirection('SYN', '1', '2')).toBe('client → server');
    expect(tcpDirection('syn-ack', '50000', '443')).toBe('server → client');
    expect(tcpDirection('FIN', '50000', '443')).toBe('client → server');
    expect(tcpDirection('FIN', '443', '50000')).toBe('server → client');
    expect(tcpDirection('FIN', '443', '443')).toBe('');
    expect(tcpDirection('FIN', '-', '443')).toBe('');
  });
});

describe('legacy format', () => {
  const net = (msg: string) =>
    rowOf(
      legacy('AzureFirewallNetworkRule', 'AzureFirewallNetworkRuleLog', msg),
    );

  it('network rule with rule path', () => {
    expect(
      net(
        'TCP request from 10.1.1.1:1234 to 10.2.2.2:80. Action: Allow. Rule Collection Group: rcg-x. Rule Collection: rc-y. Rule: r-z.',
      ),
    ).toMatchObject({
      category: 'NetworkRule',
      protocol: 'TCP',
      sourceIp: '10.1.1.1',
      sourcePort: '1234',
      targetIp: '10.2.2.2',
      targetPort: '80',
      action: 'Allow',
      policy: 'rcg-x»rc-y»r-z',
      ruleName: 'r-z',
    });
  });
  it('a rule-less deny is the default action; a rule-less allow is left unexplained', () => {
    const deny = net(
      'UDP request from 10.1.1.1:5000 to 10.2.2.2:123. Action: Deny.',
    );
    expect(deny).toMatchObject({
      policy: 'Default Action',
      targetPort: '123',
      ruleName: '',
    });
    expect(
      net('UDP request from 10.1.1.1:5000 to 10.2.2.2:123. Action: Allow.')
        .policy,
    ).toBe('');
  });
  it('keeps IPv6 endpoints intact (bare and bracketed)', () => {
    expect(
      net('TCP request from fd00::1:1234 to fd00::2:443. Action: Allow.'),
    ).toMatchObject({
      sourceIp: 'fd00::1',
      sourcePort: '1234',
      targetIp: 'fd00::2',
      targetPort: '443',
    });
    expect(
      net(
        'TCP request from [fd10:0003:0005:0001:0000:0000:0000:0004]:38238 to [2606:4700:4700:0000:0000:0000:0000:1111]:80. Action: Deny..',
      ),
    ).toMatchObject({
      sourceIp: 'fd10:3:5:1::4',
      sourcePort: '38238',
      targetIp: '2606:4700:4700::1111',
      targetPort: '80',
      action: 'Deny',
    });
  });
  it('application rule: FQDN keeps its dots, URL extracted, policy path', () => {
    const row = rowOf(
      legacy(
        'AzureFirewallApplicationRule',
        'AzureFirewallApplicationRuleLog',
        'HTTP request from 10.1.1.1:55583 to www.example.com:80. Url: example.com/path. Action: Allow. Policy: pol-hub. Rule Collection Group: rcg. Rule Collection: rc. Rule: r.',
      ),
    );
    expect(row).toMatchObject({
      category: 'AppRule',
      protocol: 'HTTP',
      targetIp: 'www.example.com',
      targetPort: '80',
      moreInfo: 'example.com/path',
      policy: 'pol-hub»rcg»rc»r',
      fwPolicy: 'pol-hub',
    });
  });
  it('application rule: "No rule matched" shows N/A, IPv6 client intact', () => {
    const row = rowOf(
      legacy(
        'AzureFirewallApplicationRule',
        'AzureFirewallApplicationRuleLog',
        'HTTPS request from fd00::1:55583 to example.com:443. Action: Deny. No rule matched. Proceeding with default action',
      ),
    );
    expect(row).toMatchObject({
      action: 'Deny',
      policy: 'N/A',
      sourceIp: 'fd00::1',
      sourcePort: '55583',
      targetIp: 'example.com',
    });
  });
  it('NAT rule', () => {
    const row = rowOf(
      legacy(
        'AzureFirewallNatRule',
        'AzureFirewallNatRuleLog',
        "TCP request from 1.2.3.4:1234 to 5.6.7.8:3389 was DNAT'ed to 10.1.1.1:3389",
      ),
    );
    expect(row).toMatchObject({
      category: 'NATRule',
      action: 'DNAT',
      sourceIp: '1.2.3.4',
      targetIp: '10.1.1.1',
      targetPort: '3389',
      natDstIp: '5.6.7.8',
      natDstPort: '3389',
    });
  });
  it('DNS proxy is normalised to DnsQuery, tolerating short messages', () => {
    const dns = (msg: string) =>
      rowOf(legacy('AzureFirewallDnsProxy', 'AzureFirewallDnsProxyLog', msg));
    expect(
      dns(
        'DNS Request: 10.2.0.6:5350 - 10407 A IN ifconfig.me. udp 40 false 1232 NOERROR qr,aa,rd,ra 56 0.000324423s',
      ),
    ).toMatchObject({
      category: 'DnsQuery',
      sourceIp: '10.2.0.6',
      sourcePort: '5350',
      protocol: 'A',
      targetIp: 'ifconfig.me',
      targetPort: '53',
      action: 'NOERROR',
    });
    expect(dns('DNS Request: 10.2.0.6:5350')).toMatchObject({
      sourceIp: '10.2.0.6',
      protocol: '-',
      action: '-',
    });
  });

  const FAIL = (msg: string) =>
    rowOf(
      legacy(
        'AzureFirewallNetworkRule',
        'AzureFirewallDNSResolutionFailureLog',
        msg,
      ),
    );
  it('DNS resolution failure (real lab record)', () => {
    const row = FAIL(
      'Failed to resolve FQDN ifconfig.me. Error lookup ifconfig.me on 127.0.0.53:53: read udp 10.2.0.6:48652->10.2.0.6:65053: read: connection refused; DNS resolution returned no IPv4 IPs. Rule Collection: fwp-hub-premium-gwc:cclab-network-rule-collection-group:priority-demo-net-rules. Rule: allow-ifconfig-me',
    );
    expect(row).toMatchObject({
      category: 'DnsFailure',
      action: 'ResolveFail',
      targetIp: 'ifconfig.me',
      fwPolicy: 'fwp-hub-premium-gwc',
      ruleCollectionGroup: 'cclab-network-rule-collection-group',
      ruleCollection: 'priority-demo-net-rules',
      ruleName: 'allow-ifconfig-me',
    });
    expect(row.moreInfo.startsWith('lookup ifconfig.me on 127.0.0.53:53')).toBe(
      true,
    );
    expect(row.moreInfo.endsWith('DNS resolution returned no IPv4 IPs')).toBe(
      true,
    );
  });
  it('DNS resolution failure without rule info or without error text', () => {
    expect(
      FAIL('Failed to resolve FQDN nope.invalid. Error NXDOMAIN.'),
    ).toMatchObject({
      targetIp: 'nope.invalid',
      moreInfo: 'NXDOMAIN',
      policy: '',
    });
    expect(
      FAIL(
        'Failed to resolve FQDN nope.invalid. Rule Collection: pol:rcg:rc. Rule: r',
      ),
    ).toMatchObject({ moreInfo: '', policy: 'pol»rcg»rc»r' });
  });
  it('counts malformed and unknown operations as parse errors', () => {
    expect(
      skipOf(
        legacy(
          'AzureFirewallNetworkRule',
          'AzureFirewallNetworkRuleLog',
          'garbage',
        ),
      ),
    ).toBe('ParseErr:AzureFirewallNetworkRuleLog');
    expect(
      skipOf(
        legacy(
          'AzureFirewallNetworkRule',
          'SomethingElse',
          'TCP request from a:1 to b:2. Action: Allow.',
        ),
      ),
    ).toBe('ParseErr:SomethingElse');
    expect(
      skipOf(
        legacy('AzureFirewallNatRule', 'AzureFirewallNatRuleLog', 'too short'),
      ),
    ).toBe('ParseErr:AzureFirewallNatRuleLog');
  });
});

describe('display safety', () => {
  const OSC52 = '\u001b]52;c;aGk=\u0007';
  const CSI = '\u009b2J';
  /* oxlint-disable no-control-regex */
  const unsafe =
    /[\u0000-\u0008\u000A-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/;
  /* oxlint-enable no-control-regex */

  it('replaces control and bidi characters, turns tabs into spaces, leaves text alone', () => {
    expect(displaySafe('a\u001bb\u009bc\u202Ed')).toBe(
      'a\uFFFDb\uFFFDc\uFFFDd',
    );
    expect(displaySafe('a\tb')).toBe('a b');
    expect(displaySafe('www.example.com/ü?x=1')).toBe('www.example.com/ü?x=1');
    expect(displaySafe('')).toBe('');
  });
  it('sanitises every string field of structured and legacy rows', () => {
    const records = [
      structured('AZFWApplicationRule', {
        Fqdn: `evil${OSC52}.example`,
        Rule: `R${CSI}`,
        TargetUrl: `https://e/${OSC52}`,
      }),
      legacy(
        'AzureFirewallApplicationRule',
        'AzureFirewallApplicationRuleLog',
        `HTTPS request from 10.1.1.1:5 to evil${OSC52}.example:443. Action: Allow. Rule: R${CSI}. Url: https://e/${OSC52}`,
      ),
      legacy(
        'AzureFirewallNetworkRule',
        'AzureFirewallDNSResolutionFailureLog',
        `Failed to resolve FQDN f${CSI}.example. Error ${OSC52} Rule Collection: p:g:rc. Rule: r`,
      ),
    ];
    for (const rec of records)
      for (const value of Object.values(rowOf(rec)))
        expect(value).not.toMatch(unsafe);
  });
});

describe('real dual-stack samples', () => {
  const dir = new URL('./__fixtures__/', import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith('.jsonl'));
  it('has fixtures', () => expect(files.length).toBe(4));
  it.each(files)('%s parses every record with no skips', (name) => {
    const records = readFileSync(new URL(name, dir), 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l));
    expect(records.length).toBeGreaterThan(0);
    for (const rec of records) {
      const row = rowOf(rec);
      // One spelling per address: no brackets and no expanded zero groups.
      for (const a of [row.sourceIp, row.targetIp]) {
        expect(a).not.toMatch(/[[\]]/);
        expect(a).not.toMatch(/(^|:)0{2,}\d*(:|$)/);
      }
    }
  });
  it('structured and legacy network rows agree on addresses', () => {
    const load = (n: string) =>
      readFileSync(new URL(n, dir), 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => rowOf(JSON.parse(l)));
    const a = load('AZFWNetworkRule.jsonl');
    const b = load('AzureFirewallNetworkRule.jsonl');
    const addrs = (rows: FirewallLogRow[]) =>
      new Set(rows.flatMap((r) => [r.sourceIp, r.targetIp]));
    for (const addr of addrs(a)) expect(addrs(b).has(addr)).toBe(true);
  });
});
