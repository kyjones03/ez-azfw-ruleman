import { describe, expect, it } from 'vitest';
import {
  buildEventHubTemplate,
  buildProvisionPlan,
  defaultCategories,
  destinationInfo,
  explainProvisionError,
  mergeDiagnosticSetting,
  parseProvisionRequest,
  planDiagnosticSetting,
  requiredPermissions,
  reviewLines,
  selectableCategories,
  stepLabels,
  uniqueSettingName,
  validateProvisionRequest,
  type ProvisionContext,
  type ProvisionRequest,
} from './logProvision';
import { nameError } from './naming';

// What a real Azure Firewall offers (from the spike).
const OFFERED = [
  'AzureFirewallApplicationRule',
  'AzureFirewallNetworkRule',
  'AzureFirewallDnsProxy',
  'AZFWNetworkRule',
  'AZFWApplicationRule',
  'AZFWNatRule',
  'AZFWThreatIntel',
  'AZFWIdpsSignature',
  'AZFWDnsQuery',
  'AZFWFqdnResolveFailure',
  'AZFWFatFlow',
  'AZFWFlowTrace',
  'AZFWApplicationRuleAggregation',
  'AZFWNetworkRuleAggregation',
  'AZFWNatRuleAggregation',
  'AZFWDnsAdditional',
];
const SUB = '00000000-0000-0000-0000-000000000000';
const FW_ID = `/subscriptions/${SUB}/resourceGroups/rg-fw/providers/Microsoft.Network/azureFirewalls/fw1`;
const NS_ID = `/subscriptions/${SUB}/resourceGroups/rg-logs/providers/Microsoft.EventHub/namespaces/contoso-logs`;
const RULE_ID = `${NS_ID}/authorizationRules/ez-azfw-logs-send`;
const DEFAULTS = defaultCategories(OFFERED);

const firewall = {
  id: FW_ID,
  name: 'fw1',
  location: 'eastus2',
  skuTier: 'Premium',
};
const newReq = (
  over: Partial<ProvisionRequest> = {},
  dest: object = {},
): ProvisionRequest => ({
  firewalls: [firewall],
  destination: {
    kind: 'new',
    subscriptionId: SUB,
    resourceGroup: 'rg-logs',
    createResourceGroup: false,
    namespaceName: 'contoso-logs',
    tier: 'Basic',
    eventHub: 'firewall-logs',
    retentionHours: 24,
    ...dest,
  } as ProvisionRequest['destination'],
  categories: DEFAULTS,
  settingName: 'ez-azfw-logs',
  grantRole: true,
  ...over,
});
const existingReq = (
  dest: object = {},
  over: Partial<ProvisionRequest> = {},
): ProvisionRequest => ({
  ...newReq(),
  ...over,
  destination: {
    kind: 'existing',
    namespaceId: NS_ID,
    namespaceLocation: 'eastus2',
    tier: 'Basic',
    eventHub: 'firewall-logs',
    createEventHub: false,
    retentionHours: 24,
    ...dest,
  } as ProvisionRequest['destination'],
});
const ctx = (settings: unknown[] = []): ProvisionContext => ({
  firewalls: [
    {
      firewallId: FW_ID,
      offeredCategories: OFFERED,
      existingSettings: settings,
    },
  ],
});

/** A setting as Azure returns it, nulls included. */
const azureSetting = (name: string, props: Record<string, unknown> = {}) => ({
  id: 'x',
  name,
  type: 'Microsoft.Insights/diagnosticSettings',
  properties: {
    eventHubAuthorizationRuleId: null,
    eventHubName: null,
    logAnalyticsDestinationType: null,
    logs: [],
    metrics: [],
    serviceBusRuleId: null,
    storageAccountId: null,
    workspaceId: null,
    ...props,
  },
});

describe('names', () => {
  it('namespace: 6-50 letters, digits, hyphens; starts with a letter; ends with letter or digit', () => {
    expect(nameError('eventHubNamespace', 'contoso-logs')).toBeUndefined();
    expect(nameError('eventHubNamespace', 'abc')).toMatch(/6-50/);
    expect(nameError('eventHubNamespace', '1contoso')).toMatch(
      /start with a letter/,
    );
    expect(nameError('eventHubNamespace', 'contoso-')).toMatch(
      /end with a letter or digit/,
    );
    expect(nameError('eventHubNamespace', 'contoso_logs')).toMatch(
      /can't contain "_"/,
    );
    expect(nameError('eventHubNamespace', 'a'.repeat(51))).toMatch(/6-50/);
  });
  it('event hub: letters, digits, _ . - ; starts and ends alphanumeric', () => {
    expect(nameError('eventHub', 'firewall-logs')).toBeUndefined();
    expect(nameError('eventHub', 'fw.logs_1')).toBeUndefined();
    expect(nameError('eventHub', '-x')).toMatch(/start/);
    expect(nameError('eventHub', 'x_')).toMatch(/end/);
    expect(nameError('eventHub', 'a b')).toMatch(/spaces/);
  });
  it('diagnostic setting: no reserved characters, no trailing space or period', () => {
    expect(nameError('diagnosticSetting', 'ez-azfw-logs')).toBeUndefined();
    expect(nameError('diagnosticSetting', 'my logs (eh)')).toBeUndefined();
    expect(nameError('diagnosticSetting', 'a/b')).toMatch(/can't contain/);
    expect(nameError('diagnosticSetting', 'a:b')).toMatch(/can't contain/);
    expect(nameError('diagnosticSetting', 'logs.')).toMatch(/end with/);
    expect(nameError('diagnosticSetting', '')).toMatch(/required/);
  });
  it('uniqueSettingName adds a number when the name is taken, ignoring case', () => {
    expect(uniqueSettingName('logs', [])).toBe('logs');
    expect(uniqueSettingName('logs', ['LOGS'])).toBe('logs-2');
    expect(uniqueSettingName('logs', ['logs', 'logs-2'])).toBe('logs-3');
  });
});

describe('categories', () => {
  it('offers the structured names in groups; legacy-only categories are used when that is all there is', () => {
    const s = selectableCategories(OFFERED);
    expect(s.core).toEqual([
      'AZFWNetworkRule',
      'AZFWApplicationRule',
      'AZFWNatRule',
    ]);
    expect(s.recommended).toEqual([
      'AZFWThreatIntel',
      'AZFWIdpsSignature',
      'AZFWDnsQuery',
      'AZFWFqdnResolveFailure',
    ]);
    expect(s.troubleshooting).toEqual(['AZFWFlowTrace', 'AZFWFatFlow']);
    expect(
      selectableCategories([
        'AzureFirewallNetworkRule',
        'AzureFirewallApplicationRule',
      ]).core,
    ).toEqual(['AzureFirewallNetworkRule', 'AzureFirewallApplicationRule']);
  });
  it('defaults leave out the noisy categories and the aggregation ones', () => {
    expect(DEFAULTS).toEqual([
      'AZFWNetworkRule',
      'AZFWApplicationRule',
      'AZFWNatRule',
      'AZFWThreatIntel',
      'AZFWIdpsSignature',
      'AZFWDnsQuery',
      'AZFWFqdnResolveFailure',
    ]);
    expect(
      DEFAULTS.some((c) => /Aggregation|Additional|Flow|Fat/.test(c)),
    ).toBe(false);
  });
});

describe('destinationInfo', () => {
  it('new Basic: $Default, no consumer group, rule and hub IDs under the new namespace', () => {
    const info = destinationInfo(newReq());
    expect(info).toMatchObject({
      namespaceId: NS_ID,
      ruleId: RULE_ID,
      hubId: `${NS_ID}/eventhubs/firewall-logs`,
      location: 'eastus2',
      consumerGroup: '$Default',
      createsConsumerGroup: false,
      createsNamespace: true,
      createsHub: true,
    });
  });
  it('new Standard gets its own consumer group', () => {
    expect(destinationInfo(newReq({}, { tier: 'Standard' }))).toMatchObject({
      consumerGroup: 'ruleman',
      createsConsumerGroup: true,
    });
  });
  it('existing namespace: derived from its ID; tier decides the consumer group', () => {
    expect(destinationInfo(existingReq())).toMatchObject({
      resourceGroup: 'rg-logs',
      namespaceName: 'contoso-logs',
      createsNamespace: false,
      createsHub: false,
      consumerGroup: '$Default',
    });
    expect(destinationInfo(existingReq({ tier: 'Premium' }))).toMatchObject({
      consumerGroup: 'ruleman',
    });
    expect(destinationInfo(existingReq({ tier: undefined }))).toMatchObject({
      consumerGroup: '$Default',
    });
  });
  it('normalises the region ("East US 2" is eastus2)', () => {
    expect(
      destinationInfo(
        newReq({ firewalls: [{ ...firewall, location: 'East US 2' }] }),
      ).location,
    ).toBe('eastus2');
  });
});

describe('buildEventHubTemplate', () => {
  const byType = (t: ReturnType<typeof buildEventHubTemplate>) =>
    Object.fromEntries(
      t.resources.map((r) => [String(r.type).split('/').slice(1).join('/'), r]),
    );

  it('new Basic namespace: TLS 1.2, local auth off, one partition, explicit retention, Send-only rule, no consumer group', () => {
    const t = buildEventHubTemplate(newReq());
    const r = byType(t);
    expect(Object.keys(r)).toEqual([
      'namespaces',
      'namespaces/eventhubs',
      'namespaces/authorizationRules',
    ]);
    expect(r['namespaces']).toMatchObject({
      name: 'contoso-logs',
      location: 'eastus2',
      sku: { name: 'Basic', tier: 'Basic', capacity: 1 },
      tags: { createdBy: 'EZ AzFW Manager' },
      properties: { minimumTlsVersion: '1.2', disableLocalAuth: true },
    });
    expect(r['namespaces/eventhubs']).toMatchObject({
      name: 'contoso-logs/firewall-logs',
      properties: {
        partitionCount: 1,
        retentionDescription: {
          cleanupPolicy: 'Delete',
          retentionTimeInHours: 24,
        },
      },
    });
    expect(r['namespaces/authorizationRules']).toMatchObject({
      name: 'contoso-logs/ez-azfw-logs-send',
      properties: { rights: ['Send'] },
    });
    expect(t.$schema).toContain('deploymentTemplate.json');
  });
  it('never grants Listen or Manage, and never reads keys', () => {
    expect(JSON.stringify(buildEventHubTemplate(newReq()))).not.toMatch(
      /"Listen"|"Manage"|listKeys/,
    );
  });
  it('Standard adds the consumer group after the hub', () => {
    const r = byType(buildEventHubTemplate(newReq({}, { tier: 'Standard' })));
    expect(r['namespaces/eventhubs/consumergroups']).toMatchObject({
      name: 'contoso-logs/firewall-logs/ruleman',
      dependsOn: [
        "[resourceId('Microsoft.EventHub/namespaces/eventhubs', 'contoso-logs', 'firewall-logs')]",
      ],
    });
  });
  it('existing namespace and hub: only the rule; the namespace is not redeclared', () => {
    const t = buildEventHubTemplate(existingReq());
    expect(t.resources.map((r) => r.type)).toEqual([
      'Microsoft.EventHub/namespaces/authorizationRules',
    ]);
    expect(t.resources[0]).not.toHaveProperty('dependsOn');
    expect(JSON.stringify(t)).not.toContain('disableLocalAuth');
  });
  it('existing Standard namespace with a new hub: hub, rule, consumer group', () => {
    const t = buildEventHubTemplate(
      existingReq({
        tier: 'Standard',
        createEventHub: true,
        retentionHours: 72,
      }),
    );
    expect(
      t.resources.map((r) => String(r.type).split('/').slice(1).join('/')),
    ).toEqual([
      'namespaces/eventhubs',
      'namespaces/authorizationRules',
      'namespaces/eventhubs/consumergroups',
    ]);
    expect(
      (
        t.resources[0].properties as {
          retentionDescription: { retentionTimeInHours: number };
        }
      ).retentionDescription.retentionTimeInHours,
    ).toBe(72);
  });
  it('is plain JSON (no undefined fields)', () => {
    const t = buildEventHubTemplate(newReq());
    expect(JSON.parse(JSON.stringify(t))).toEqual(t);
  });
});

describe('mergeDiagnosticSetting', () => {
  const target = { ruleId: RULE_ID, eventHub: 'firewall-logs' };

  it('builds a new setting from nothing', () => {
    const m = mergeDiagnosticSetting(undefined, target, [
      'AZFWNetworkRule',
      'AZFWNatRule',
    ]);
    expect(m.body.properties).toEqual({
      eventHubAuthorizationRuleId: RULE_ID,
      eventHubName: 'firewall-logs',
      logs: [
        { category: 'AZFWNetworkRule', enabled: true },
        { category: 'AZFWNatRule', enabled: true },
      ],
      metrics: [],
    });
    expect(m.changes).toEqual([
      'Send to event hub firewall-logs',
      'Turn on NetworkRule',
      'Turn on NATRule',
    ]);
    expect(m.noop).toBe(false);
  });

  it("keeps a real firewall's Log Analytics destination, allLogs group, metrics and destination type", () => {
    // Shape copied from a real firewall: allLogs to Log Analytics and an Event Hub.
    const real = azureSetting('FirewallPolicySettings', {
      eventHubAuthorizationRuleId:
        '/subscriptions/x/resourceGroups/r/providers/Microsoft.EventHub/namespaces/other/authorizationrules/RootManageSharedAccessKey',
      eventHubName: 'insights-logs-azurefirewall',
      workspaceId:
        '/subscriptions/x/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w',
      logAnalyticsDestinationType: 'Dedicated',
      logs: [
        {
          category: null,
          categoryGroup: 'allLogs',
          enabled: true,
          retentionPolicy: { days: 0, enabled: false },
        },
      ],
      metrics: [
        {
          category: 'AllMetrics',
          enabled: false,
          retentionPolicy: { days: 0, enabled: false },
        },
      ],
    });
    const m = mergeDiagnosticSetting(real, target, DEFAULTS);
    const p = m.body.properties;
    expect(p.workspaceId).toContain('workspaces/w');
    expect(p.logAnalyticsDestinationType).toBe('Dedicated');
    expect(p.metrics).toEqual(real.properties.metrics);
    // allLogs already covers every category: nothing is added next to it.
    expect(p.logs).toEqual([
      {
        categoryGroup: 'allLogs',
        enabled: true,
        retentionPolicy: { days: 0, enabled: false },
      },
    ]);
    expect(m.changes).toEqual([
      `Change the event hub from insights-logs-azurefirewall to firewall-logs`,
    ]);
    expect(p).not.toHaveProperty('storageAccountId'); // null values are dropped, not sent
    expect(JSON.stringify(p)).not.toContain('null');
  });

  it('turns on a category that is listed but off, and adds only the missing ones', () => {
    const s = azureSetting('s', {
      eventHubAuthorizationRuleId: RULE_ID,
      eventHubName: 'firewall-logs',
      storageAccountId: '/subscriptions/x/storage',
      logs: [
        { category: 'AZFWNetworkRule', categoryGroup: null, enabled: true },
        {
          category: 'AZFWApplicationRule',
          categoryGroup: null,
          enabled: false,
        },
        { category: 'AZFWFlowTrace', categoryGroup: null, enabled: true },
      ],
    });
    const m = mergeDiagnosticSetting(s, target, [
      'AZFWNetworkRule',
      'AZFWApplicationRule',
      'AZFWNatRule',
    ]);
    expect(m.changes).toEqual(['Turn on AppRule', 'Turn on NATRule']);
    expect(m.body.properties.logs).toEqual([
      { category: 'AZFWNetworkRule', enabled: true },
      { category: 'AZFWApplicationRule', enabled: true },
      { category: 'AZFWFlowTrace', enabled: true }, // someone else's choice is kept
      { category: 'AZFWNatRule', enabled: true },
    ]);
    expect(m.body.properties.storageAccountId).toBe('/subscriptions/x/storage');
  });

  it('is a no-op when everything is already as wanted (case-insensitive)', () => {
    const s = azureSetting('s', {
      eventHubAuthorizationRuleId: RULE_ID.toLowerCase(),
      eventHubName: 'FIREWALL-LOGS',
      logs: [{ category: 'azfwnetworkrule', enabled: true }],
    });
    const m = mergeDiagnosticSetting(s, target, ['AZFWNetworkRule']);
    expect(m.noop).toBe(true);
    expect(m.changes).toEqual([]);
  });

  it('never emits allLogs by itself and does not modify its input', () => {
    const s = azureSetting('s', {
      logs: [{ category: 'AZFWNetworkRule', enabled: false }],
    });
    const before = JSON.stringify(s);
    const m = mergeDiagnosticSetting(s, target, DEFAULTS);
    expect(JSON.stringify(s)).toBe(before);
    expect(JSON.stringify(m.body)).not.toMatch(/allLogs/i);
  });

  it('survives junk input', () => {
    for (const junk of [
      null,
      5,
      'x',
      [],
      { properties: 'x' },
      { properties: { logs: 'x' } },
    ])
      expect(() =>
        mergeDiagnosticSetting(junk, target, ['AZFWNetworkRule']),
      ).not.toThrow();
  });
});

describe('planDiagnosticSetting', () => {
  const desired = {
    settingName: 'ez-azfw-logs',
    ruleId: RULE_ID,
    eventHub: 'firewall-logs',
    categories: ['AZFWNetworkRule'],
  };

  it('creates a new setting when none exists', () => {
    const p = planDiagnosticSetting([], desired);
    expect(p).toMatchObject({ action: 'create', settingName: 'ez-azfw-logs' });
  });
  it('updates the setting that already owns the sink, whatever its name', () => {
    const owner = azureSetting('portal-made', {
      eventHubAuthorizationRuleId: RULE_ID.toUpperCase(),
      eventHubName: 'firewall-logs',
      logs: [{ category: 'AZFWNatRule', enabled: true }],
    });
    const p = planDiagnosticSetting([owner], desired);
    expect(p).toMatchObject({ action: 'update', settingName: 'portal-made' });
    expect(
      (p as unknown as { body: { properties: { logs: unknown[] } } }).body
        .properties.logs,
    ).toHaveLength(2);
  });
  it('does nothing when the owner already has everything', () => {
    const owner = azureSetting('x', {
      eventHubAuthorizationRuleId: RULE_ID,
      eventHubName: 'firewall-logs',
      logs: [{ category: 'AZFWNetworkRule', enabled: true }],
    });
    expect(planDiagnosticSetting([owner], desired).action).toBe('noop');
  });
  it('blocks instead of redirecting a setting that sends the same categories to another hub through the same rule', () => {
    const owner = azureSetting('theirs', {
      eventHubAuthorizationRuleId: RULE_ID,
      eventHubName: 'other-hub',
      logs: [{ category: 'AZFWNetworkRule', enabled: true }],
    });
    const p = planDiagnosticSetting([owner], desired);
    expect(p.action).toBe('blocked');
    expect((p as { reason: string }).reason).toMatch(
      /"theirs".*"other-hub".*only once/,
    );
    const allLogs = azureSetting('theirs', {
      eventHubAuthorizationRuleId: RULE_ID,
      eventHubName: 'other-hub',
      logs: [{ categoryGroup: 'allLogs', enabled: true }],
    });
    expect(planDiagnosticSetting([allLogs], desired).action).toBe('blocked');
  });
  it('creates a separate setting when the same rule is used for other categories only', () => {
    const owner = azureSetting('theirs', {
      eventHubAuthorizationRuleId: RULE_ID,
      eventHubName: 'other-hub',
      logs: [{ category: 'AZFWDnsQuery', enabled: true }],
    });
    expect(planDiagnosticSetting([owner], desired).action).toBe('create');
  });
  it("never reuses a setting name, and never redirects another sink's setting to take it over", () => {
    const taken = azureSetting('ez-azfw-logs', {
      workspaceId: '/subscriptions/x/workspaces/w',
      logs: [{ categoryGroup: 'allLogs', enabled: true }],
    });
    const p = planDiagnosticSetting([taken], desired);
    expect(p).toMatchObject({
      action: 'create',
      settingName: 'ez-azfw-logs-2',
    });
    expect(JSON.stringify((p as { body: unknown }).body)).not.toContain(
      'workspaces',
    );
  });
  it('blocks a sixth setting, and says what to do', () => {
    const five = Array.from({ length: 5 }, (_, i) =>
      azureSetting(`s${i}`, { workspaceId: `/w${i}` }),
    );
    const p = planDiagnosticSetting(five, desired);
    expect(p).toMatchObject({ action: 'blocked' });
    expect((p as { reason: string }).reason).toMatch(/5 diagnostic settings/);
    // Updating the owner needs no new slot, so it is still allowed at five.
    const owner = azureSetting('own', {
      eventHubAuthorizationRuleId: RULE_ID,
      eventHubName: 'firewall-logs',
    });
    expect(
      planDiagnosticSetting([...five.slice(0, 4), owner], desired).action,
    ).toBe('update');
  });
});

describe('validateProvisionRequest', () => {
  const check = (req: ProvisionRequest, c = ctx()) =>
    validateProvisionRequest(req, c);

  describe('namespace network access', () => {
    const withNetwork = (
      publicNetworkAccess?: string,
      namespaceId = NS_ID,
    ) => ({
      ...ctx(),
      destinationNetwork: { namespaceId, publicNetworkAccess },
    });
    it('warns, without blocking, when the existing namespace has public access disabled', () => {
      const result = check(existingReq(), withNetwork('Disabled'));
      expect(result.errors).toEqual([]);
      expect(result.warnings).toHaveLength(1);
      expect(result.warnings[0]).toMatch(/public network access disabled/);
    });
    it('matches the value and the namespace ID case-insensitively', () => {
      expect(
        check(existingReq(), withNetwork('disabled', NS_ID.toUpperCase()))
          .warnings,
      ).toHaveLength(1);
    });
    it.each(['Enabled', 'SecuredByPerimeter', undefined])(
      'does not warn when public access is %s',
      (value) => {
        expect(check(existingReq(), withNetwork(value)).warnings).toEqual([]);
      },
    );
    it('does not warn about another namespace, or when the setting was not read', () => {
      expect(
        check(existingReq(), withNetwork('Disabled', `${NS_ID}-other`))
          .warnings,
      ).toEqual([]);
      expect(check(existingReq()).warnings).toEqual([]);
    });
    it('never warns for a new namespace', () => {
      expect(check(newReq(), withNetwork('Disabled')).warnings).toEqual([]);
    });
  });

  it('accepts a good request for a new Basic namespace', () => {
    expect(check(newReq())).toEqual({ errors: [], warnings: [] });
  });
  it('requires firewalls, a destination and categories', () => {
    expect(check(newReq({ firewalls: [] })).errors).toEqual([
      'Choose at least one firewall.',
    ]);
    expect(check(newReq({ categories: [] })).errors).toContain(
      'Choose at least one log category.',
    );
    expect(
      check({ ...newReq(), destination: undefined as never }).errors,
    ).toEqual(['Choose where the logs should go.']);
  });
  it('explains name problems', () => {
    const e = check(
      newReq(
        { settingName: 'a/b' },
        { namespaceName: 'x', eventHub: '-h', resourceGroup: '' },
      ),
    ).errors.join(' ');
    expect(e).toMatch(/Event Hubs namespace name must be 6-50/);
    expect(e).toMatch(/Event hub name must start/);
    expect(e).toMatch(/Resource group name is required/);
    expect(e).toMatch(/Diagnostic setting name can't contain/);
  });
  it('rejects firewalls from different regions, naming them', () => {
    const e = check(
      newReq({
        firewalls: [
          firewall,
          {
            ...firewall,
            id: FW_ID.replace('fw1', 'fw2'),
            name: 'fw2',
            location: 'centralus',
          },
        ],
      }),
    ).errors[0];
    expect(e).toMatch(/different regions \(eastus2, centralus\)/);
  });
  it('rejects an existing namespace in another region', () => {
    expect(
      check(existingReq({ namespaceLocation: 'centralus' })).errors[0],
    ).toMatch(/in centralus, but the firewall is in eastus2/);
  });
  it('limits retention by tier', () => {
    expect(check(newReq({}, { retentionHours: 48 })).errors).toContain(
      'Retention must be 1 to 24 hours on the Basic tier.',
    );
    expect(
      check(newReq({}, { tier: 'Standard', retentionHours: 48 })).errors,
    ).toEqual([]);
    expect(
      check(newReq({}, { tier: 'Standard', retentionHours: 200 })).errors[0],
    ).toMatch(/1 to 168 hours/);
    // An existing hub keeps the retention it has.
    expect(check(existingReq({ retentionHours: 9999 })).errors).toEqual([]);
  });
  it("rejects categories the firewall doesn't offer", () => {
    const limited: ProvisionContext = {
      firewalls: [
        {
          firewallId: FW_ID,
          offeredCategories: ['AZFWNetworkRule'],
          existingSettings: [],
        },
      ],
    };
    expect(
      check(newReq({ categories: ['AZFWNetworkRule', 'AZFWNatRule'] }), limited)
        .errors,
    ).toEqual(["fw1 doesn't offer NATRule."]);
  });
  it('warns about missing rule categories and about noisy ones, without blocking', () => {
    const w = check(
      newReq({
        categories: ['AZFWNetworkRule', 'AZFWFlowTrace', 'AZFWFatFlow'],
      }),
    ).warnings;
    expect(w[0]).toMatch(/NetworkRule, AppRule, NATRule\) are not selected/);
    expect(w[1]).toMatch(/FlowTrace and FatFlow can produce a lot of data/);
    expect(
      check(newReq({ categories: [...DEFAULTS, 'AZFWFlowTrace'] })).warnings,
    ).toHaveLength(1);
  });
  it('surfaces a blocked firewall as an error', () => {
    const five = Array.from({ length: 5 }, (_, i) =>
      azureSetting(`s${i}`, { workspaceId: `/w${i}` }),
    );
    expect(check(newReq(), ctx(five)).errors[0]).toMatch(
      /^fw1: This firewall already has 5/,
    );
  });
});

describe('buildProvisionPlan', () => {
  it('orders: resource group, Event Hub resources, settings, role', () => {
    const plan = buildProvisionPlan(
      newReq({}, { createResourceGroup: true }),
      ctx(),
    );
    expect(plan.steps.map((s) => s.kind)).toEqual([
      'resourceGroup',
      'eventHubs',
      'diagnosticSetting',
      'role',
    ]);
    expect(plan.blocked).toEqual([]);
    expect(plan.steps[3]).toMatchObject({
      scope: `${NS_ID}/eventhubs/firewall-logs`,
      roleId: 'a638d3c7-ab3a-418d-83e6-5f17a39d4fde',
    });
  });
  it('skips the resource group and the role when not asked for', () => {
    const plan = buildProvisionPlan(newReq({ grantRole: false }), ctx());
    expect(plan.steps.map((s) => s.kind)).toEqual([
      'eventHubs',
      'diagnosticSetting',
    ]);
  });
  it('points the Logs view at the new hub, with the right consumer group', () => {
    expect(buildProvisionPlan(newReq(), ctx()).connect).toEqual({
      namespace: 'contoso-logs.servicebus.windows.net',
      eventHub: 'firewall-logs',
      consumerGroup: '$Default',
      startPosition: 'latest',
    });
    expect(
      buildProvisionPlan(newReq({}, { tier: 'Standard' }), ctx()).connect
        .consumerGroup,
    ).toBe('ruleman');
  });
  it('plans one setting per firewall and reports blocked ones', () => {
    const fw2 = { ...firewall, id: FW_ID.replace('fw1', 'fw2'), name: 'fw2' };
    const five = Array.from({ length: 5 }, (_, i) =>
      azureSetting(`s${i}`, { workspaceId: `/w${i}` }),
    );
    const c: ProvisionContext = {
      firewalls: [
        { firewallId: FW_ID, offeredCategories: OFFERED, existingSettings: [] },
        {
          firewallId: fw2.id,
          offeredCategories: OFFERED,
          existingSettings: five,
        },
      ],
    };
    const plan = buildProvisionPlan(newReq({ firewalls: [firewall, fw2] }), c);
    expect(
      plan.steps.filter((s) => s.kind === 'diagnosticSetting'),
    ).toHaveLength(1);
    expect(plan.blocked).toHaveLength(1);
    expect(plan.blocked[0]).toMatch(/^fw2:/);
  });
});

describe('review text', () => {
  it('lists every change in plain words, from the same steps that run', () => {
    const plan = buildProvisionPlan(
      newReq({}, { createResourceGroup: true, tier: 'Standard' }),
      ctx(),
    );
    expect(reviewLines(plan)).toEqual([
      'Create resource group rg-logs in eastus2',
      'Create Event Hubs namespace contoso-logs (Standard tier, eastus2, local authentication disabled)',
      'Create Event hub firewall-logs (1 partition, 24 hours retention)',
      'Create Access rule ez-azfw-logs-send on contoso-logs, with the Send right only',
      'Create Consumer group ruleman on firewall-logs',
      'fw1: create diagnostic setting "ez-azfw-logs": Send to event hub firewall-logs; Turn on NetworkRule; Turn on AppRule; Turn on NATRule; Turn on ThreatIntel; Turn on IDPS; Turn on DnsQuery; Turn on DnsFailure',
      'Give you the Azure Event Hubs Data Receiver role on event hub firewall-logs (this hub only)',
    ]);
  });
  it('says so when nothing needs to change on a firewall', () => {
    const owner = azureSetting('mine', {
      eventHubAuthorizationRuleId: RULE_ID,
      eventHubName: 'firewall-logs',
      logs: DEFAULTS.map((category) => ({ category, enabled: true })),
    });
    const lines = reviewLines(
      buildProvisionPlan(existingReq({}, { grantRole: false }), ctx([owner])),
    );
    expect(lines.at(-1)).toBe(
      'fw1: diagnostic setting "mine" already sends these logs; no change',
    );
  });
  it('names the permissions the steps need, and drops the ones that are not needed', () => {
    const all = requiredPermissions(buildProvisionPlan(newReq(), ctx())).map(
      (p) => p.what,
    );
    expect(all).toEqual([
      'Create the Event Hub resources',
      'Write the diagnostic settings',
      'Assign the Data Receiver role',
    ]);
    const owner = azureSetting('mine', {
      eventHubAuthorizationRuleId: RULE_ID,
      eventHubName: 'firewall-logs',
      logs: DEFAULTS.map((category) => ({ category, enabled: true })),
    });
    expect(
      requiredPermissions(
        buildProvisionPlan(existingReq({}, { grantRole: false }), ctx([owner])),
      ).map((p) => p.what),
    ).toEqual(['Create the Event Hub resources']);
  });
});

describe('explainProvisionError', () => {
  it('explains the errors Azure returned in the spike', () => {
    expect(
      explainProvisionError(
        'Bad Request({"code":"BadRequest","message":"Resources should be in the same region. Resource \'/subscriptions/x/…/nsg-central\' is in region \'centralus\' and resource \'…\' is in region \'eastus2\'"})',
      ),
    ).toMatch(/same region as the firewall/);
    expect(
      explainProvisionError(
        "Conflict: Data sink '/subscriptions/x/…/authorizationrules/ez-azfw-logs-send' is already used in diagnostic setting 't1' for category 'NetworkSecurityGroupEvent'. Data sinks can't be reused in different settings on the same category for the same resource.",
      ),
    ).toMatch(/diagnostic setting "t1".*only once per category/);
    expect(
      explainProvisionError(
        "The limit of 5 diagnostic settings was reached. To create new setting 't6', delete an existing one.",
      ),
    ).toMatch(/maximum of 5/);
    expect(
      explainProvisionError(
        "MessagingGatewayBadRequest: The operation cannot be perform on entity type 'ConsumerGroup' because the namespace 'x' is using 'Basic' tier.",
      ),
    ).toMatch(/Basic tier has no consumer groups/);
  });
  it('leaves other errors to the caller', () => {
    expect(explainProvisionError('AuthorizationFailed')).toBeUndefined();
    expect(explainProvisionError('')).toBeUndefined();
  });
});

describe('provider registration', () => {
  const withProviders = (
    providers: ProvisionContext['providers'],
  ): ProvisionContext => ({
    ...ctx(),
    providers,
  });
  it('adds a step per unregistered provider, once per subscription, first in the plan', () => {
    const plan = buildProvisionPlan(
      newReq(),
      withProviders([
        {
          subscriptionId: SUB,
          namespace: 'Microsoft.EventHub',
          registered: false,
        },
        {
          subscriptionId: SUB.toUpperCase(),
          namespace: 'Microsoft.Insights',
          registered: false,
        },
      ]),
    );
    expect(plan.steps.slice(0, 2)).toEqual([
      {
        kind: 'registerProvider',
        subscriptionId: SUB,
        namespace: 'Microsoft.EventHub',
      },
      {
        kind: 'registerProvider',
        subscriptionId: SUB,
        namespace: 'Microsoft.Insights',
      },
    ]);
    expect(reviewLines(plan)[0]).toMatch(
      /^Register Microsoft.EventHub in subscription/,
    );
    expect(requiredPermissions(plan)[0]).toEqual({
      what: 'Register a resource provider',
      permission: 'Contributor on the subscription',
    });
  });
  it('adds nothing when registered or not checked', () => {
    for (const providers of [
      undefined,
      [
        {
          subscriptionId: SUB,
          namespace: 'Microsoft.EventHub' as const,
          registered: true,
        },
      ],
    ])
      expect(
        buildProvisionPlan(newReq(), withProviders(providers)).steps.some(
          (s) => s.kind === 'registerProvider',
        ),
      ).toBe(false);
  });
});

describe('stepLabels', () => {
  it('gives one short row per step', () => {
    const plan = buildProvisionPlan(
      newReq({}, { createResourceGroup: true }),
      ctx(),
    );
    expect(stepLabels(plan)).toEqual([
      'Create resource group rg-logs',
      'Create Event Hub resources in rg-logs',
      'fw1: create diagnostic setting "ez-azfw-logs"',
      'Assign Azure Event Hubs Data Receiver',
    ]);
  });
});

describe('parseProvisionRequest', () => {
  const good = () => JSON.parse(JSON.stringify(newReq()));
  it('round-trips a valid request and drops unknown fields', () => {
    const raw = {
      ...good(),
      extra: 'x',
      destination: { ...good().destination, evil: 1 },
    };
    const parsed = parseProvisionRequest(raw);
    expect(parsed).toEqual(newReq());
    expect(JSON.stringify(parsed)).not.toContain('evil');
  });
  it('parses an existing destination', () => {
    const req = existingReq({ createEventHub: true });
    expect(parseProvisionRequest(JSON.parse(JSON.stringify(req)))).toEqual(req);
  });
  it('rejects anything of the wrong shape', () => {
    const bad = (mut: (r: Record<string, any>) => void) => {
      const r = good();
      mut(r);
      return () => parseProvisionRequest(r);
    };
    expect(() => parseProvisionRequest(null)).toThrow();
    expect(() => parseProvisionRequest('x')).toThrow();
    expect(bad((r) => (r.firewalls = []))).toThrow(/at least one firewall/);
    expect(bad((r) => (r.firewalls[0].id = 5))).toThrow(/firewall ID/);
    expect(bad((r) => (r.destination.kind = 'other'))).toThrow(
      /where the logs/,
    );
    expect(bad((r) => (r.destination.tier = 'Premium'))).toThrow(
      /Basic or Standard/,
    );
    expect(bad((r) => (r.destination.retentionHours = '24'))).toThrow(
      /retention/,
    );
    expect(bad((r) => (r.destination.retentionHours = 1.5))).toThrow(
      /retention/,
    );
    expect(bad((r) => (r.categories = 'x'))).toThrow(/categories/);
    expect(bad((r) => (r.categories = [1]))).toThrow(/log category/);
    expect(bad((r) => (r.settingName = 'a'.repeat(300)))).toThrow(
      /setting name/,
    );
  });
  it('only treats an explicit true as a yes', () => {
    expect(
      parseProvisionRequest({ ...good(), grantRole: 'yes' }).grantRole,
    ).toBe(false);
    expect(
      parseProvisionRequest({ ...good(), grantRole: true }).grantRole,
    ).toBe(true);
  });
});
