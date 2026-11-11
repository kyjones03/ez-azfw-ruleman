import { describe, expect, it } from 'vitest';
import {
  allocationErrors,
  draftBaseline,
  firewallSettingsErrors,
  keyVaultSecretError,
  mergeSettings,
  policySettingsErrors,
  readPolicySettings,
  sanitizePolicySettings,
  FIREWALL_SETTING_KEYS,
  POLICY_SETTING_KEYS,
  type FirewallConfiguration,
  type PolicyAdvancedSettings,
} from './resourceSettings';

const ROOT =
  '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg';
const identity = `${ROOT}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/tls-identity`;
const initial = (): PolicyAdvancedSettings => ({
  dns: { inherit: true, enableProxy: false, servers: [] },
  allowlistIps: [],
  allowlistFqdns: [],
  autoLearnSnat: false,
  tls: { enabled: false, certificateName: '', secretId: '', identityIds: [] },
});
const firewall: FirewallConfiguration = {
  name: 'fw',
  routeServerId: '',
  minCapacity: null,
  maxCapacity: null,
  powerState: 'Running',
};

describe('advanced resource validation', () => {
  it('validates DNS server addresses and the actual 15-server maximum', () => {
    const config = initial();
    config.dns = {
      inherit: false,
      enableProxy: true,
      servers: Array.from({ length: 15 }, (_, i) => `10.0.0.${i + 1}`),
    };
    expect(policySettingsErrors(config, 'Standard')).toEqual([]);
    config.dns.servers.push('10.0.0.16');
    expect(policySettingsErrors(config, 'Standard')).toContain(
      'Custom DNS supports at most 15 servers.',
    );
    config.dns.servers = ['10.0.0.4/24'];
    expect(policySettingsErrors(config, 'Standard').join(' ')).toContain(
      'not a CIDR',
    );
    expect(policySettingsErrors(config, 'Basic').join(' ')).toContain(
      'Standard or Premium',
    );
  });

  it('reuses strict IP/CIDR/range and host-name validation for allowlists', () => {
    const config = initial();
    config.allowlistIps = [
      '192.0.2.1',
      '198.51.100.0/24',
      '203.0.113.1-203.0.113.20',
    ];
    config.allowlistFqdns = ['www.contoso.com'];
    expect(policySettingsErrors(config, 'Standard')).toEqual([]);
    config.allowlistIps = ['10.0.0.7/24', '999.0.0.1', '*'];
    config.allowlistFqdns = ['https://contoso.com/path'];
    const errors = policySettingsErrors(config, 'Standard').join(' ');
    expect(errors).toContain('host bits');
    expect(errors).toContain('above 255');
    expect(errors).toContain('Wildcards');
    expect(errors).toContain('scheme or path');
  });

  it('accepts Key Vault secret references, not private-key contents or other URLs', () => {
    expect(
      keyVaultSecretError(
        'https://demo-vault.vault.azure.net/secrets/intermediate-ca',
      ),
    ).toBeUndefined();
    expect(
      keyVaultSecretError(
        'https://demo-vault.vault.azure.net/secrets/intermediate-ca/0123456789abcdef0123456789abcdef',
      ),
    ).toBeUndefined();
    for (const uri of [
      '-----BEGIN PRIVATE KEY-----',
      'http://demo-vault.vault.azure.net/secrets/ca',
      'https://example.com/secrets/ca',
      'https://demo-vault.vault.azure.net/certificates/ca',
      'https://demo-vault.vault.azure.net/secrets/ca?token=x',
    ])
      expect(keyVaultSecretError(uri)).toBeTruthy();
    const config = initial();
    config.tls = {
      enabled: true,
      secretId: 'https://demo-vault.vault.azure.net/secrets/ca',
      certificateName: 'ca',
      identityIds: [identity],
    };
    expect(policySettingsErrors(config, 'Premium')).toEqual([]);
    expect(policySettingsErrors(config, 'Standard').join(' ')).toContain(
      'Premium',
    );
    config.tls.identityIds = [];
    expect(policySettingsErrors(config, 'Premium').join(' ')).toContain(
      'managed identity',
    );
  });

  it('enforces prescaling bounds, equality/gap rules and Basic limitations', () => {
    for (const [minCapacity, maxCapacity] of [
      [2, 2],
      [2, 4],
      [48, 50],
      [50, 50],
    ]) {
      expect(
        firewallSettingsErrors(
          { ...firewall, minCapacity, maxCapacity },
          'Standard',
          'AZFW_VNet',
        ),
      ).toEqual([]);
    }
    for (const [minCapacity, maxCapacity] of [
      [1, 4],
      [2, 51],
      [5, 6],
      [6, 4],
      [2.5, 8],
    ])
      expect(
        firewallSettingsErrors(
          { ...firewall, minCapacity, maxCapacity },
          'Standard',
          'AZFW_VNet',
        ).length,
      ).toBeGreaterThan(0);
    expect(
      firewallSettingsErrors(
        { ...firewall, minCapacity: 2, maxCapacity: 4 },
        'Basic',
        'AZFW_VNet',
      ).join(' '),
    ).toContain('Standard or Premium');
    expect(
      firewallSettingsErrors(
        { ...firewall, minCapacity: 2 },
        'Standard',
        'AZFW_VNet',
      ).join(' '),
    ).toContain('both');
    expect(
      firewallSettingsErrors(
        {
          ...firewall,
          minCapacity: 4,
          maxCapacity: 8,
          allocation: {
            skuName: 'AZFW_Hub',
            virtualHubId: `${ROOT}/providers/Microsoft.Network/virtualHubs/hub`,
            ipConfigurations: [
              {
                name: 'data',
                publicIPAddress: {
                  id: `${ROOT}/providers/Microsoft.Network/publicIPAddresses/pip`,
                },
              },
            ],
          },
        },
        'Standard',
        'AZFW_Hub',
        { ...firewall, minCapacity: 4, maxCapacity: 8, powerState: 'Stopped' },
      ).join(' '),
    ).toContain('customer-provided');
  });

  it('does not silently invent missing management or hub allocation details', () => {
    const allocation = {
      skuName: 'AZFW_VNet' as const,
      ipConfigurations: [
        {
          name: 'data',
          subnet: {
            id: `${ROOT}/providers/Microsoft.Network/virtualNetworks/vnet/subnets/AzureFirewallSubnet`,
          },
          publicIPAddress: {
            id: `${ROOT}/providers/Microsoft.Network/publicIPAddresses/pip`,
          },
        },
      ],
    };
    expect(allocationErrors(allocation, 'Standard')).toEqual([]);
    expect(allocationErrors(allocation, 'Basic').join(' ')).toContain(
      'management',
    );
    expect(
      allocationErrors(
        {
          skuName: 'AZFW_Hub',
          ipConfigurations: [],
          virtualHubId: `${ROOT}/providers/Microsoft.Network/virtualHubs/hub`,
        },
        'Standard',
      ).join(' '),
    ).toContain('count');
  });

  it('merges unrelated concurrent changes and rejects conflicts in edited fields', () => {
    const before = initial();
    const desired = initial();
    desired.dns.enableProxy = true;
    desired.dns.inherit = false;
    const current = initial();
    current.allowlistFqdns = ['existing.contoso.com'];
    expect(
      mergeSettings(before, desired, current, POLICY_SETTING_KEYS)
        .allowlistFqdns,
    ).toEqual(['existing.contoso.com']);
    current.dns.servers = ['10.0.0.9'];
    expect(() =>
      mergeSettings(before, desired, current, POLICY_SETTING_KEYS),
    ).toThrow('changed in Azure');
    const baseline = draftBaseline(
      before,
      desired,
      { ...before, allowlistIps: ['192.0.2.2'] },
      POLICY_SETTING_KEYS,
    );
    expect(baseline.allowlistIps).toEqual(['192.0.2.2']);
    expect(baseline.dns).toEqual(before.dns);
    expect(
      mergeSettings(
        firewall,
        { ...firewall, minCapacity: 2, maxCapacity: 4 },
        { ...firewall, routeServerId: 'new-route-server' },
        FIREWALL_SETTING_KEYS,
      ).routeServerId,
    ).toBe('new-route-server');
  });

  it('parses only valid payload shapes and preserves default/inherited DNS semantics', () => {
    expect(readPolicySettings({})).toEqual(initial());
    expect(sanitizePolicySettings(initial())).toEqual(initial());
    expect(() =>
      sanitizePolicySettings({ ...initial(), allowlistIps: '10.0.0.1' }),
    ).toThrow('allowlist');
    expect(() =>
      readPolicySettings({ dnsSettings: { enableProxy: 'true' } }),
    ).toThrow('proxy');
    expect(() =>
      readPolicySettings({ snat: { autoLearnPrivateRanges: 'unexpected' } }),
    ).toThrow('Unsupported');
    expect(
      readPolicySettings({
        transportSecurity: {
          certificateAuthority: {
            keyVaultSecretId:
              'https://demo-vault.vault.azure.net/secrets/existing-ca',
          },
        },
      }).tls,
    ).toMatchObject({
      enabled: true,
      certificateName: 'existing-ca',
    });
  });
});
