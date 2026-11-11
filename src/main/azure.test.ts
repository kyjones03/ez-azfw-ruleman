import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }));
vi.mock('./auth', () => ({ getCredential: () => ({}), onSignOut: () => {} }));
vi.mock('@azure/arm-network', () => ({
  NetworkManagementClient: class {
    firewallPolicies = { get: mocks.get, createOrUpdate: mocks.put };
  },
}));
const { getPolicyMode, putPolicyMode } = await import('./azure');
const POLICY =
  '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/fp';
const raw = {
  name: 'fp',
  location: 'eastus',
  threatIntelMode: 'Alert',
  etag: 'etag-current',
  sku: { tier: 'Premium' },
  tags: { env: 'prod' },
  dnsSettings: { enableProxy: true, servers: ['10.0.0.4'] },
  threatIntelWhitelist: { ipAddresses: ['192.0.2.1'] },
  intrusionDetection: { mode: 'Deny' },
  identity: {
    type: 'UserAssigned',
    userAssignedIdentities: { 'identity-id': {} },
  },
};

beforeEach(() => {
  vi.resetAllMocks();
  mocks.get.mockResolvedValue(structuredClone(raw));
  mocks.put.mockResolvedValue({ ...raw, threatIntelMode: 'Deny' });
});

describe('Azure policy mode updates', () => {
  it('changes only the requested field while preserving the latest full policy', async () => {
    await putPolicyMode(POLICY, 'Alert', 'Deny');
    expect(mocks.put).toHaveBeenCalledWith(
      'rg',
      'fp',
      {
        ...raw,
        threatIntelMode: 'Deny',
      },
      { requestOptions: { headers: { 'If-Match': 'etag-current' } } },
    );
    expect(raw.threatIntelMode).toBe('Alert');
  });

  it('refuses concurrent mode changes without overwriting Azure', async () => {
    mocks.get.mockResolvedValue({ ...raw, threatIntelMode: 'Off' });
    await expect(putPolicyMode(POLICY, 'Alert', 'Deny')).rejects.toMatchObject({
      code: 'PolicyModeConflict',
    });
    expect(mocks.put).not.toHaveBeenCalled();
  });

  it('recognizes an already applied change without writing it again', async () => {
    mocks.get.mockResolvedValue({ ...raw, threatIntelMode: 'Deny' });
    await putPolicyMode(POLICY, 'Alert', 'Deny');
    expect(mocks.put).not.toHaveBeenCalled();
  });

  it('rejects unsupported and inherited weaker modes before any write', async () => {
    mocks.get.mockResolvedValueOnce({ ...raw, sku: { tier: 'Basic' } });
    await expect(putPolicyMode(POLICY, 'Alert', 'Deny')).rejects.toThrow(
      'Basic',
    );
    mocks.get.mockImplementation(async (_group: string, name: string) =>
      name === 'parent'
        ? { ...raw, name, threatIntelMode: 'Deny' }
        : {
            ...raw,
            threatIntelMode: 'Deny',
            basePolicy: { id: POLICY.replace('/fp', '/parent') },
          },
    );
    await expect(putPolicyMode(POLICY, 'Deny', 'Alert')).rejects.toThrow(
      'less strict',
    );
    expect(mocks.put).not.toHaveBeenCalled();
  });

  it('surfaces missing modes and Azure write failures instead of guessing success', async () => {
    mocks.get.mockResolvedValueOnce({ ...raw, threatIntelMode: undefined });
    await expect(getPolicyMode(POLICY)).rejects.toThrow('supported');
    mocks.put.mockRejectedValueOnce(new Error('Permission denied'));
    await expect(putPolicyMode(POLICY, 'Alert', 'Deny')).rejects.toThrow(
      'Permission denied',
    );
  });
});
