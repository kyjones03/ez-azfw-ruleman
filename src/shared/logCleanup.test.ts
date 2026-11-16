import { describe, expect, it } from 'vitest';
import { danglingSettings, namespaceIdOfRule, planCleanup } from './logCleanup';
import type { FirewallLogging } from './logSources';

const NS =
  '/subscriptions/s/resourceGroups/rg-scratch/providers/Microsoft.EventHub/namespaces/scratch-logs-namespace';
const RULE = `${NS}/authorizationRules/RootManageSharedAccessKey`;

const fw = (settings: FirewallLogging['settings']): FirewallLogging => ({
  firewallId:
    '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw-hub-eus2',
  firewallName: 'fw-hub-eus2',
  settings,
});
const setting = (
  name: string,
  namespaceId?: string,
  eventHubName?: string,
) => ({
  name,
  eventHubNamespaceId: namespaceId,
  eventHubName,
  categories: [],
  allLogs: false,
  logAnalytics: false,
  storage: false,
});

describe('namespaceIdOfRule', () => {
  it('cuts the rule off the namespace ID', () => {
    expect(namespaceIdOfRule(RULE)).toBe(NS);
  });
  it('returns nothing for text that is not a rule ID', () => {
    expect(namespaceIdOfRule('nope')).toBeUndefined();
    expect(namespaceIdOfRule(undefined)).toBeUndefined();
  });
});

describe('danglingSettings', () => {
  it('lists settings that send to a namespace confirmed gone, matching case-insensitively', () => {
    const found = danglingSettings(
      [fw([setting('old', NS, 'hub'), setting('live', '/other/ns')])],
      new Set([NS.toUpperCase()]),
    );
    expect(found).toEqual([
      expect.objectContaining({
        settingName: 'old',
        namespaceId: NS,
        eventHubName: 'hub',
        firewallName: 'fw-hub-eus2',
      }),
    ]);
  });
  it('lists nothing when no namespace was confirmed gone (unreadable ones are not offered)', () => {
    expect(danglingSettings([fw([setting('old', NS)])], new Set())).toEqual([]);
  });
  it('ignores settings with no event hub', () => {
    expect(danglingSettings([fw([setting('law')])], new Set([NS]))).toEqual([]);
  });
});

const existing = (props: Record<string, unknown>) => ({
  name: 'old',
  properties: props,
});

describe('planCleanup', () => {
  it('trims only the event hub destination and keeps the rest', () => {
    const before = existing({
      eventHubAuthorizationRuleId: RULE,
      eventHubName: 'hub',
      storageAccountId: '/subscriptions/s/storage',
      workspaceId: null,
      logs: [{ category: 'AZFWNetworkRule', enabled: true }],
      metrics: [{ category: 'AllMetrics', enabled: false }],
    });
    const copy = JSON.stringify(before);
    const plan = planCleanup(before, 'fw-hub-eus2', NS);
    expect(plan.action).toBe('trim');
    if (plan.action !== 'trim') return;
    expect(plan.body.properties).toEqual({
      storageAccountId: '/subscriptions/s/storage',
      logs: [{ category: 'AZFWNetworkRule', enabled: true }],
      metrics: [{ category: 'AllMetrics', enabled: false }],
    });
    expect(plan.kept).toEqual(['Storage']);
    expect(plan.lines[0]).toContain('keeps Storage');
    expect(JSON.stringify(before)).toBe(copy);
  });

  it('keeps allLogs and every other destination when trimming', () => {
    const plan = planCleanup(
      existing({
        eventHubAuthorizationRuleId: RULE,
        eventHubName: 'hub',
        workspaceId: '/subscriptions/s/law',
        logAnalyticsDestinationType: 'Dedicated',
        logs: [{ categoryGroup: 'allLogs', enabled: true }],
      }),
      'fw',
      NS,
    );
    expect(plan.action).toBe('trim');
    if (plan.action !== 'trim') return;
    expect(plan.body.properties.logs).toEqual([
      { categoryGroup: 'allLogs', enabled: true },
    ]);
    expect(plan.body.properties.logAnalyticsDestinationType).toBe('Dedicated');
    expect(plan.kept).toEqual(['Log Analytics']);
  });

  it('deletes the setting when the event hub was its only destination', () => {
    const plan = planCleanup(
      existing({
        eventHubAuthorizationRuleId: RULE,
        eventHubName: 'hub',
        workspaceId: null,
        storageAccountId: '',
        logs: [{ category: 'AZFWNetworkRule', enabled: true }],
      }),
      'fw-hub-eus2',
      NS,
    );
    expect(plan.action).toBe('delete');
    expect(plan.lines[0]).toContain('delete diagnostic setting "old"');
    expect(plan.lines[0]).toContain('scratch-logs-namespace');
  });

  it('does nothing when the setting no longer points at that namespace', () => {
    const plan = planCleanup(
      existing({
        eventHubAuthorizationRuleId:
          '/subscriptions/s/other/authorizationRules/x',
        eventHubName: 'hub',
        storageAccountId: '/s',
      }),
      'fw',
      NS,
    );
    expect(plan.action).toBe('noop');
  });

  it('does nothing for a setting with no event hub at all', () => {
    expect(
      planCleanup(existing({ workspaceId: '/law' }), 'fw', NS).action,
    ).toBe('noop');
  });
});
