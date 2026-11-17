import { describe, expect, it } from 'vitest';
import {
  detectedHubs,
  eventHubCoverage,
  parseDiagnosticSettings,
  type DiagnosticSettingSummary,
  type FirewallLogging,
} from './logSources';

const NS_ID =
  '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-logs/providers/Microsoft.EventHub/namespaces/Contoso-FW';
const setting = (
  over: Partial<DiagnosticSettingSummary> = {},
): DiagnosticSettingSummary => ({
  name: 'to-eh',
  eventHubNamespaceId: NS_ID,
  eventHubName: 'firewall-logs',
  categories: [],
  allLogs: false,
  logAnalytics: false,
  storage: false,
  ...over,
});
const NINE = [
  'AZFWNetworkRule',
  'AZFWApplicationRule',
  'AZFWNatRule',
  'AZFWThreatIntel',
  'AZFWIdpsSignature',
  'AZFWDnsQuery',
  'AZFWFqdnResolveFailure',
  'AZFWFlowTrace',
  'AZFWFatFlow',
];

describe('parseDiagnosticSettings', () => {
  const response = {
    value: [
      {
        name: 'to-eh',
        properties: {
          eventHubAuthorizationRuleId: `${NS_ID}/authorizationrules/RootManageSharedAccessKey`,
          eventHubName: 'firewall-logs',
          workspaceId: '/subscriptions/x/workspaces/w',
          logs: [
            { category: 'AZFWNetworkRule', enabled: true },
            { category: 'AZFWNatRule', enabled: false },
            { categoryGroup: 'allLogs', enabled: true },
          ],
        },
      },
      {
        name: 'to-storage',
        properties: { storageAccountId: '/subscriptions/x/sa', logs: [] },
      },
    ],
  };
  it('reads the hub target, enabled categories and other destinations', () => {
    const [eh, st] = parseDiagnosticSettings(response);
    expect(eh).toMatchObject({
      name: 'to-eh',
      eventHubNamespaceId: NS_ID,
      eventHubName: 'firewall-logs',
      categories: ['AZFWNetworkRule'],
      allLogs: true,
      logAnalytics: true,
      storage: false,
    });
    expect(st).toMatchObject({ eventHubNamespaceId: undefined, storage: true });
  });
  it('survives junk from Azure', () => {
    for (const bad of [
      null,
      5,
      'x',
      {},
      { value: 'x' },
      { value: [null, 3, { properties: 7 }] },
    ])
      expect(() => parseDiagnosticSettings(bad)).not.toThrow();
    expect(
      parseDiagnosticSettings({
        value: [{ properties: { eventHubAuthorizationRuleId: 'nonsense' } }],
      })[0].eventHubNamespaceId,
    ).toBeUndefined();
  });
});

describe('eventHubCoverage', () => {
  it('none when nothing sends to the hub, and flags per-category hubs', () => {
    expect(eventHubCoverage([], 'contoso-fw', 'firewall-logs')).toMatchObject({
      state: 'none',
    });
    expect(
      eventHubCoverage(
        [setting({ eventHubName: 'other' })],
        'contoso-fw',
        'firewall-logs',
      ).state,
    ).toBe('none');
    expect(
      eventHubCoverage(
        [setting({ eventHubName: '' })],
        'contoso-fw',
        'firewall-logs',
      ),
    ).toMatchObject({
      state: 'none',
      perCategoryHubs: true,
    });
  });
  it('matches namespace and hub case-insensitively, FQDN or short name', () => {
    const s = [setting({ categories: NINE })];
    expect(
      eventHubCoverage(s, 'CONTOSO-FW.servicebus.windows.net', 'Firewall-Logs')
        .state,
    ).toBe('complete');
    expect(eventHubCoverage(s, 'contoso-fw', 'firewall-logs').state).toBe(
      'complete',
    );
  });
  it('complete needs the three rule categories; recommended ones are reported separately', () => {
    const c = eventHubCoverage(
      [
        setting({
          categories: ['AZFWNetworkRule', 'AZFWApplicationRule', 'AZFWNatRule'],
        }),
      ],
      'contoso-fw',
      'firewall-logs',
      'Standard',
    );
    expect(c).toMatchObject({ state: 'complete', missingCore: [] });
    expect(c.missingRecommended).toEqual([
      'ThreatIntel',
      'DnsQuery',
      'DnsFailure',
    ]); // IDPS is Premium-only
  });
  it('names missing core categories', () => {
    const c = eventHubCoverage(
      [setting({ categories: ['AZFWNetworkRule'] })],
      'contoso-fw',
      'firewall-logs',
    );
    expect(c).toMatchObject({
      state: 'incomplete',
      missingCore: ['AppRule', 'NATRule'],
    });
  });
  it('legacy rule categories count, but NAT only comes from the structured category', () => {
    const legacy = ['AzureFirewallNetworkRule', 'AzureFirewallApplicationRule'];
    const c = eventHubCoverage(
      [setting({ categories: legacy })],
      'contoso-fw',
      'firewall-logs',
    );
    expect(c).toMatchObject({ state: 'incomplete', missingCore: ['NATRule'] });
    expect(
      eventHubCoverage(
        [setting({ categories: [...legacy, 'AZFWNatRule'] })],
        'contoso-fw',
        'firewall-logs',
      ).state,
    ).toBe('complete');
  });
  it('allLogs covers everything', () => {
    expect(
      eventHubCoverage(
        [setting({ allLogs: true })],
        'contoso-fw',
        'firewall-logs',
        'Premium',
      ),
    ).toMatchObject({
      state: 'complete',
      missingRecommended: [],
      allLogs: true,
    });
  });
  it('several settings to the same hub add up', () => {
    const c = eventHubCoverage(
      [
        setting({ categories: ['AZFWNetworkRule'] }),
        setting({
          name: 'b',
          categories: ['AZFWApplicationRule', 'AZFWNatRule'],
        }),
      ],
      'contoso-fw',
      'firewall-logs',
    );
    expect(c.state).toBe('complete');
  });
  it('Premium firewalls are expected to carry IDPS; troubleshooting categories never count as missing', () => {
    const base = ['AZFWNetworkRule', 'AZFWApplicationRule', 'AZFWNatRule'];
    expect(
      eventHubCoverage(
        [setting({ categories: base })],
        'contoso-fw',
        'firewall-logs',
        'Premium',
      ).missingRecommended,
    ).toContain('IDPS');
    const all = eventHubCoverage(
      [setting({ categories: base })],
      'contoso-fw',
      'firewall-logs',
      'Premium',
    );
    expect([...all.missingCore, ...all.missingRecommended]).not.toContain(
      'FlowTrace',
    );
    expect([...all.missingCore, ...all.missingRecommended]).not.toContain(
      'FatFlow',
    );
  });
});

describe('detectedHubs', () => {
  const fw = (over: Partial<FirewallLogging>): FirewallLogging => ({
    firewallId:
      '/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw1',
    firewallName: 'fw1',
    settings: [],
    ...over,
  });
  it('lists one entry per firewall and distinct hub, skipping non-Event-Hub settings', () => {
    const hubs = detectedHubs([
      fw({
        settings: [
          setting({ categories: NINE }),
          setting({ name: 'dup', categories: NINE }),
          setting({
            name: 'law',
            eventHubNamespaceId: undefined,
            eventHubName: undefined,
            logAnalytics: true,
          }),
        ],
      }),
      fw({ firewallName: 'fw2', settings: [] }),
    ]);
    expect(hubs).toHaveLength(1);
    expect(hubs[0]).toMatchObject({
      firewallName: 'fw1',
      namespaceName: 'Contoso-FW',
      eventHub: 'firewall-logs',
    });
    expect(hubs[0].coverage.state).toBe('complete');
  });
});
