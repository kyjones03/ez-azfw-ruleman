import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  getPolicy: vi.fn(),
  listGroups: vi.fn(),
  lookups: vi.fn(),
  importCsv: vi.fn(),
  view: vi.fn(),
}));
vi.mock('./azure', () => ({
  getPolicy: mocks.getPolicy,
  listRuleCollectionGroups: mocks.listGroups,
}));
vi.mock('./lookups', () => ({ getRuleLookups: mocks.lookups }));
vi.mock('./candidate', () => ({
  candidate: { importRulesCsv: mocks.importCsv, view: mocks.view },
}));
const { importRulesCsv } = await import('./ruleImport');
const POLICY =
  '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/child';
const PARENT = `${POLICY}-parent`;

beforeEach(() => {
  vi.resetAllMocks();
  mocks.getPolicy.mockImplementation(async (id: string) => ({
    id,
    subscriptionId: '00000000-1111-2222-3333-444444444444',
    location: 'East US',
    basePolicyId: id === POLICY ? PARENT : undefined,
  }));
  mocks.listGroups.mockResolvedValue([]);
  mocks.lookups.mockResolvedValue({
    ipGroups: [],
    serviceTags: [],
    fqdnTags: [],
    webCategories: [],
    errors: [],
  });
  mocks.view.mockReturnValue([]);
  mocks.importCsv.mockReturnValue({ ruleCount: 1 });
});

describe('CSV import Azure preflight', () => {
  it('re-reads running and parent rules and reuses the editor lookup validation', async () => {
    const parentGroup = {
      id: 'parent-group',
      name: 'Inherited',
      priority: 100,
      ruleCollections: [],
    };
    mocks.view.mockReturnValue([{ group: parentGroup }]);
    mocks.lookups.mockResolvedValue({
      ipGroups: [{ id: 'GROUP-ID', addresses: ['10.0.0.0/24'] }],
      serviceTags: [{ name: 'AzureCloud' }],
      fqdnTags: [],
      webCategories: [],
      errors: [],
    });
    const choices = { 2: { action: 'import' as const, token: 'reviewed' } };
    await expect(importRulesCsv(POLICY, 'csv', choices)).resolves.toEqual({
      ruleCount: 1,
    });
    expect(mocks.getPolicy).toHaveBeenCalledWith(PARENT);
    expect(mocks.listGroups).toHaveBeenCalledWith(POLICY);
    expect(mocks.listGroups).toHaveBeenCalledWith(PARENT);
    expect(mocks.lookups).toHaveBeenCalledWith(
      '00000000-1111-2222-3333-444444444444',
      'eastus',
    );
    expect(mocks.importCsv).toHaveBeenCalledWith(POLICY, 'csv', choices, [], {
      inheritedGroups: [parentGroup],
      known: {
        ipGroups: new Set(['group-id']),
        serviceTags: new Set(['azurecloud']),
        fqdnTags: undefined,
        webCategories: undefined,
      },
      ipGroups: new Map([['group-id', ['10.0.0.0/24']]]),
    });
  });

  it('does not stage when a parent cannot be read', async () => {
    mocks.getPolicy.mockImplementation(async (id: string) => {
      if (id === PARENT) throw new Error('Read denied');
      return {
        location: 'eastus',
        subscriptionId: 'sub',
        basePolicyId: PARENT,
      };
    });
    await expect(importRulesCsv(POLICY, 'csv', {})).rejects.toThrow(
      'Read denied',
    );
    expect(mocks.importCsv).not.toHaveBeenCalled();
  });

  it('rejects cyclic parent policies instead of staging with incomplete conflict checks', async () => {
    mocks.getPolicy.mockResolvedValue({
      location: 'eastus',
      subscriptionId: 'sub',
      basePolicyId: POLICY,
    });
    await expect(importRulesCsv(POLICY, 'csv', {})).rejects.toThrow(
      'could not be resolved safely',
    );
    expect(mocks.importCsv).not.toHaveBeenCalled();
  });
});
