import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CreateIpGroupRequest } from '../shared/ipGroups';

const mocks = vi.hoisted(() => ({
  graph: vi.fn(),
  get: vi.fn(),
  create: vi.fn(),
  providers: vi.fn(),
  resourceGroups: vi.fn(),
  signOut: () => {},
}));
vi.mock('./auth', () => ({
  getCredential: () => ({}),
  onSignOut: (callback: () => void) => {
    mocks.signOut = callback;
  },
}));
vi.mock('./azure', () => ({
  graphQuery: mocks.graph,
  network: () => ({
    ipGroups: { get: mocks.get, createOrUpdate: mocks.create },
  }),
}));
vi.mock('@azure/arm-resources', () => ({
  ResourceManagementClient: class {
    resourceGroups = { list: mocks.resourceGroups };
    providers = { get: mocks.providers };
  },
}));

const { discoverIpGroups, createIpGroup, getIpGroupContext } =
  await import('./ipGroups');
const request: CreateIpGroupRequest = {
  subscriptionId: '00000000-1111-2222-3333-444444444444',
  resourceGroup: 'rg-network',
  location: 'eastus',
  name: 'ipg-office',
  addresses: ['10.0.0.1', '10.1.0.0/24'],
};
const id = `/subscriptions/${request.subscriptionId}/resourceGroups/${request.resourceGroup}/providers/Microsoft.Network/ipGroups/${request.name}`;

beforeEach(() => {
  mocks.signOut();
  vi.resetAllMocks();
  mocks.graph.mockResolvedValue([]);
  mocks.get.mockRejectedValue({ statusCode: 404 });
  mocks.create.mockResolvedValue({
    id,
    name: request.name,
    location: request.location,
    ipAddresses: request.addresses,
    provisioningState: 'Succeeded',
  });
});

describe('IP group Azure operations', () => {
  it('creates a validated group and keeps it available until Resource Graph catches up', async () => {
    const created = await createIpGroup(request);
    expect(mocks.create).toHaveBeenCalledWith(
      request.resourceGroup,
      request.name,
      {
        location: request.location,
        ipAddresses: request.addresses,
      },
    );
    expect(await discoverIpGroups()).toEqual([created]);
    mocks.graph.mockResolvedValueOnce([
      { ...created, addresses: ['10.9.0.0/16'] },
    ]);
    expect((await discoverIpGroups())[0].addresses).toEqual(['10.9.0.0/16']);
    expect(await discoverIpGroups()).toEqual([]);
  });

  it('does not overwrite an existing group or treat permission errors as missing resources', async () => {
    mocks.get.mockResolvedValueOnce({ id });
    await expect(createIpGroup(request)).rejects.toThrow('already exists');
    mocks.get.mockRejectedValueOnce({ statusCode: 403 });
    await expect(createIpGroup(request)).rejects.toMatchObject({
      statusCode: 403,
    });
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it('rejects invalid addresses and names before any Azure operation', async () => {
    await expect(
      createIpGroup({ ...request, addresses: ['10.0.0.7/24'] }),
    ).rejects.toThrow('host bits');
    await expect(
      createIpGroup({ ...request, name: 'bad name' }),
    ).rejects.toThrow("can't contain spaces");
    expect(mocks.get).not.toHaveBeenCalled();
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it('reports failed provisioning and Azure write failures instead of returning success', async () => {
    mocks.create.mockResolvedValueOnce({ id, provisioningState: 'Failed' });
    await expect(createIpGroup(request)).rejects.toThrow(
      'did not finish provisioning',
    );
    mocks.create.mockRejectedValueOnce(new Error('Azure write denied'));
    await expect(createIpGroup(request)).rejects.toThrow('Azure write denied');
    expect(await discoverIpGroups()).toEqual([]);
  });

  it('normalizes empty address lists and surfaces discovery failures', async () => {
    mocks.graph.mockResolvedValueOnce([{ id, name: request.name }]);
    expect((await discoverIpGroups())[0].addresses).toEqual([]);
    mocks.graph.mockRejectedValueOnce(new Error('Reader access required'));
    await expect(discoverIpGroups()).rejects.toThrow('Reader access required');
  });

  it('clears recent groups on sign-out, including a creation finishing after sign-out', async () => {
    await createIpGroup(request);
    mocks.signOut();
    expect(await discoverIpGroups()).toEqual([]);
    mocks.create.mockImplementationOnce(async () => {
      mocks.signOut();
      return { id, provisioningState: 'Succeeded' };
    });
    await createIpGroup(request);
    expect(await discoverIpGroups()).toEqual([]);
  });

  it('loads all resource groups and IP group locations, not firewall locations', async () => {
    mocks.resourceGroups.mockImplementation(async function* () {
      yield { name: 'rg-z' };
      yield { name: 'rg-a' };
    });
    mocks.providers.mockResolvedValue({
      resourceTypes: [
        { resourceType: 'azureFirewalls', locations: ['West US'] },
        { resourceType: 'ipGroups', locations: ['East US', 'North Europe'] },
      ],
    });
    expect(await getIpGroupContext(request.subscriptionId)).toEqual({
      resourceGroups: ['rg-a', 'rg-z'],
      locations: [
        { name: 'eastus', displayName: 'East US' },
        { name: 'northeurope', displayName: 'North Europe' },
      ],
    });
  });
});
