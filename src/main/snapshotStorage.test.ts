import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  CommitRecord,
  PolicySnapshot,
  SnapshotStorageConfig,
} from '../shared/types';

const mocks = vi.hoisted(() => ({
  state: {} as { snapshotStorage?: SnapshotStorageConfig },
  graph: vi.fn(),
  armToken: vi.fn(),
  storageToken: vi.fn(),
  principal: vi.fn(),
  fetch: vi.fn(),
}));
vi.mock('./store', () => ({
  loadState: () => mocks.state,
  updateState: (fn: (s: typeof mocks.state) => void) => fn(mocks.state),
}));
vi.mock('./auth', () => ({
  getCredential: () => ({ getToken: mocks.armToken }),
  getStorageToken: mocks.storageToken,
  getPrincipal: mocks.principal,
}));
vi.mock('./azure', () => ({
  graphQuery: mocks.graph,
  describeAzureError: (e: Error) => e.message,
}));
vi.mock('@azure/arm-resources', () => ({
  ResourceManagementClient: class {
    providers = {
      get: async () => ({ registrationState: 'Registered' }),
      register: async () => undefined,
    };
    resourceGroups = { createOrUpdate: async () => undefined };
  },
}));

const SUB = '00000000-1111-2222-3333-444444444444';
const ACCOUNT = `/subscriptions/${SUB}/resourceGroups/qa/providers/Microsoft.Storage/storageAccounts/qasnapshots`;
const config: SnapshotStorageConfig = {
  storageAccountId: ACCOUNT,
  storageAccountName: 'qasnapshots',
  subscriptionId: SUB,
  resourceGroup: 'qa',
  location: 'eastus',
  skuName: 'Standard_GRS',
  containerName: 'ez-azfw-snapshots',
};
const policyId = (name: string) =>
  `/subscriptions/${SUB}/resourceGroups/qa/providers/Microsoft.Network/firewallPolicies/${name}`;

function snapshot(
  id: string,
  policy = 'fp',
  time = '2026-11-03T12:00:00.000Z',
): PolicySnapshot {
  return {
    id,
    policyId: policyId(policy),
    policyName: policy,
    time,
    description: 'test',
    groups: [],
  };
}

const listXml = (names: string[], next = '') =>
  `<EnumerationResults><Blobs>${names.map((n) => `<Blob><Name>${n}</Name></Blob>`).join('')}</Blobs><NextMarker>${next}</NextMarker></EnumerationResults>`;

/** Serves a fake blob container; `pages` splits the listing to exercise continuation markers. */
function serveBlobs(blobs: Record<string, unknown>, pageSize = 1000) {
  mocks.fetch.mockImplementation(async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    if (url.searchParams.get('comp') === 'list') {
      const all = Object.keys(blobs).sort();
      const start = Number(url.searchParams.get('marker') ?? 0);
      const max = Number(url.searchParams.get('maxresults') ?? pageSize);
      const size = Math.min(max, pageSize);
      const page = all.slice(start, start + size);
      const more =
        start + size < all.length && !url.searchParams.get('maxresults');
      return new Response(listXml(page, more ? String(start + size) : ''));
    }
    if (init?.method === 'PUT') return new Response(null, { status: 201 });
    const name = decodeURIComponent(url.pathname).replace(
      `/${config.containerName}/`,
      '',
    );
    return name in blobs
      ? Response.json(blobs[name])
      : new Response('missing', { status: 404 });
  });
}

async function storage() {
  vi.resetModules();
  return import('./snapshotStorage');
}

beforeEach(() => {
  mocks.state = { snapshotStorage: { ...config } };
  mocks.graph.mockReset().mockResolvedValue([]);
  mocks.armToken.mockReset().mockResolvedValue({ token: 'arm-token' });
  mocks.storageToken.mockReset().mockResolvedValue('storage-token');
  mocks.principal
    .mockReset()
    .mockResolvedValue({ objectId: 'user-oid', type: 'User' });
  mocks.fetch.mockReset();
  vi.stubGlobal('fetch', mocks.fetch);
  serveBlobs({});
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('discovering storage accounts', () => {
  it('uses a plain Resource Graph query and derives the SKU and names in code', async () => {
    mocks.graph.mockImplementation(async (kql: string) =>
      kql.includes('resourcecontainers')
        ? [{ subscriptionId: SUB, subscriptionName: 'Prod' }]
        : [
            {
              id: ACCOUNT,
              name: 'qasnapshots',
              subscriptionId: SUB,
              resourceGroup: 'qa',
              location: 'eastus',
              sku: { name: 'Standard_GRS' },
              kind: 'StorageV2',
              tags: { 'ez-azfw-ruleman-snapshots': 'true' },
            },
          ],
    );
    const [account] = await (await storage()).listSnapshotStorageAccounts();
    expect(account).toMatchObject({
      skuName: 'Standard_GRS',
      isGRS: true,
      isAppTagged: true,
      subscriptionName: 'Prod',
      kind: 'StorageV2',
    });
    const accountQuery = mocks.graph.mock.calls
      .map(([q]) => q as string)
      .find((q) => q.includes('storageaccounts'))!;
    expect(accountQuery).not.toMatch(/join|extend/);
  });

  it('still lists accounts when subscription names are unavailable', async () => {
    mocks.graph.mockImplementation(async (kql: string) => {
      if (kql.includes('resourcecontainers')) throw new Error('denied');
      return [
        {
          id: ACCOUNT,
          name: 'qasnapshots',
          subscriptionId: SUB,
          resourceGroup: 'qa',
          location: 'eastus',
          sku: { name: 'Standard_LRS' },
        },
      ];
    });
    const accounts = await (await storage()).listSnapshotStorageAccounts();
    expect(accounts).toHaveLength(1);
    expect(accounts[0].subscriptionName).toBeUndefined();
  });

  it('surfaces discovery failures instead of reporting no storage', async () => {
    mocks.state = {};
    mocks.graph.mockRejectedValue(new Error('BadRequest'));
    await expect((await storage()).getSnapshotStorageConfig()).rejects.toThrow(
      'BadRequest',
    );
  });

  it('adopts a team-tagged account and remembers it', async () => {
    mocks.state = {};
    mocks.graph.mockImplementation(async (kql: string) =>
      kql.includes('resourcecontainers')
        ? []
        : [
            {
              id: ACCOUNT,
              name: 'qasnapshots',
              subscriptionId: SUB,
              resourceGroup: 'qa',
              location: 'eastus',
              sku: { name: 'Standard_GRS' },
              tags: {
                'ez-azfw-ruleman-snapshots': 'true',
                'ez-azfw-ruleman-container': 'team-snaps',
              },
            },
          ],
    );
    const cfg = await (await storage()).getSnapshotStorageConfig();
    expect(cfg).toMatchObject({
      storageAccountId: ACCOUNT,
      containerName: 'team-snaps',
    });
    expect(mocks.state.snapshotStorage).toEqual(cfg);
  });
});

describe('blob access', () => {
  it('authorizes with the signed-in user, never with account keys', async () => {
    serveBlobs({ 'fp/a.json': snapshot('a') });
    const mod = await storage();
    await mod.listSnapshotsFromCentralStorage();
    await mod.saveSnapshotToCentralStorage(snapshot('b'));
    for (const [url, init] of mocks.fetch.mock.calls) {
      expect(url).not.toContain('listKeys');
      expect(init.headers.Authorization).toBe('Bearer storage-token');
    }
  });

  it('uploads the snapshot JSON as a block blob', async () => {
    const mod = await storage();
    const value = { ...snapshot('b'), description: 'caf\u00e9 \u2603' };
    await mod.saveSnapshotToCentralStorage(value);
    const [url, init] = mocks.fetch.mock.calls.find(
      ([, i]) => i.method === 'PUT',
    )!;
    expect(url).toContain(
      '/ez-azfw-snapshots/fp/2026-11-03T12-00-00-000Z-b.json',
    );
    expect(init.headers['x-ms-blob-type']).toBe('BlockBlob');
    expect(JSON.parse(init.body)).toEqual(value);
  });

  it('explains which role is missing when Azure reports a permission mismatch', async () => {
    mocks.fetch.mockImplementation(
      async () =>
        new Response('denied', {
          status: 403,
          headers: { 'x-ms-error-code': 'AuthorizationPermissionMismatch' },
        }),
    );
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const mod = await storage();
    await expect(mod.requireSnapshotStorageConfigured()).rejects.toThrow(
      /Storage Blob Data Contributor.*AuthorizationPermissionMismatch/,
    );
    await expect(mod.listSnapshotsFromCentralStorage()).rejects.toThrow(
      /Storage Blob Data Contributor/,
    );
    await expect(
      mod.saveSnapshotToCentralStorage(snapshot('x')),
    ).rejects.toThrow(/Storage Blob Data Contributor/);
  });

  it('does not blame roles when Azure refuses the request for another reason', async () => {
    mocks.fetch.mockImplementation(async (input: string) =>
      input.includes('management.azure.com')
        ? Response.json({
            properties: {
              publicNetworkAccess: 'Disabled',
              networkAcls: { defaultAction: 'Deny' },
            },
          })
        : new Response(
            '<Error><Code>AuthorizationFailure</Code><Message>This request is not authorized to perform this operation.\nRequestId:1</Message></Error>',
            {
              status: 403,
              headers: { 'x-ms-error-code': 'AuthorizationFailure' },
            },
          ),
    );
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const error = await (
      await storage()
    )
      .requireSnapshotStorageConfigured()
      .catch((e: Error) => e);
    expect((error as Error).message).toMatch(
      /HTTP 403, AuthorizationFailure.*networking blocks this computer.*public network access: Disabled.*firewall default action: Deny.*This request is not authorized/s,
    );
    expect((error as Error).message).not.toMatch(/Assign yourself/);
  });

  it('reports a rejected sign-in token separately', async () => {
    mocks.fetch.mockImplementation(
      async () =>
        new Response('', {
          status: 401,
          headers: { 'x-ms-error-code': 'InvalidAuthenticationInfo' },
        }),
    );
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await expect(
      (await storage()).requireSnapshotStorageConfigured(),
    ).rejects.toThrow(/rejected your sign-in token.*InvalidAuthenticationInfo/);
  });

  it('checks reachability before a commit can start', async () => {
    mocks.fetch.mockRejectedValue(new Error('unreachable'));
    await expect(
      (await storage()).requireSnapshotStorageConfigured(),
    ).rejects.toThrow('unreachable');
  });

  it('refuses commits when no storage is configured', async () => {
    mocks.state = {};
    await expect(
      (await storage()).requireSnapshotStorageConfigured(),
    ).rejects.toThrow(/required/);
  });
});

describe('listing snapshots', () => {
  it('follows continuation markers', async () => {
    serveBlobs(
      {
        'a/1.json': snapshot('one'),
        'a/2.json': snapshot('two'),
        'a/3.json': snapshot('three'),
      },
      1,
    );
    const ids = (await (await storage()).listSnapshotsFromCentralStorage())
      .map((s) => s.id)
      .sort();
    expect(ids).toEqual(['one', 'three', 'two']);
  });

  it("keeps each policy's newest snapshot when the cap applies", async () => {
    const blobs: Record<string, unknown> = {
      'a-policy/2026-11-03T12-00-00-000Z-newest.json': snapshot(
        'newest',
        'a-policy',
      ),
    };
    for (let i = 0; i < 200; i++) {
      const time = `2026-11-01T00-00-00-${String(i).padStart(3, '0')}Z`;
      blobs[`z-policy/${time}-old${i}.json`] = snapshot(
        `old${i}`,
        'z-policy',
        '2026-11-01T00:00:00.000Z',
      );
    }
    serveBlobs(blobs);
    const ids = (await (await storage()).listSnapshotsFromCentralStorage()).map(
      (s) => s.id,
    );
    expect(ids[0]).toBe('newest');
    expect(ids).toHaveLength(200);
  });

  it('finds a snapshot by id even beyond the list cap', async () => {
    const blobs: Record<string, unknown> = {
      'a/2020-01-01T00-00-00-000Z-wanted.json': snapshot('wanted'),
    };
    for (let i = 0; i < 250; i++)
      blobs[`z/2026-11-01T00-00-00-${String(i).padStart(3, '0')}Z-x${i}.json`] =
        snapshot(`x${i}`, 'z');
    serveBlobs(blobs);
    const mod = await storage();
    expect(await mod.getSnapshotFromCentralStorage('wanted')).toEqual(
      snapshot('wanted'),
    );
    expect(await mod.getSnapshotFromCentralStorage('missing')).toBeUndefined();
  });

  it('skips malformed snapshots, including groups that would break the UI', async () => {
    serveBlobs({
      'fp/good.json': snapshot('good'),
      'fp/bad-groups.json': {
        ...snapshot('bad'),
        groups: [{ id: 'g', name: 'g', priority: 1 }],
      },
      'fp/no-time.json': { id: 'x', policyId: policyId('fp'), groups: [] },
    });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(
      (await (await storage()).listSnapshotsFromCentralStorage()).map(
        (s) => s.id,
      ),
    ).toEqual(['good']);
  });

  it('fails the listing, rather than showing none, when a blob is unreadable', async () => {
    serveBlobs({ 'fp/a.json': snapshot('a') });
    const serve = mocks.fetch.getMockImplementation()!;
    mocks.fetch.mockImplementation(async (url: string, init?: RequestInit) =>
      url.endsWith('/fp/a.json')
        ? new Response('denied', {
            status: 403,
            headers: { 'x-ms-error-code': 'AuthorizationPermissionMismatch' },
          })
        : serve(url, init),
    );
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await expect(
      (await storage()).listSnapshotsFromCentralStorage(),
    ).rejects.toThrow(/Storage Blob Data Contributor/);
  });
});

describe('shared commit history', () => {
  const commit = (id: string, time: string, user = 'alice@contoso.com') =>
    ({
      id,
      time,
      user,
      description: `change ${id}`,
      changeCount: 1,
      results: [
        {
          groupId: `${policyId('fp')}/ruleCollectionGroups/g`,
          groupName: 'g',
          policyName: 'fp',
          ok: true,
        },
      ],
    }) satisfies CommitRecord;

  /** Fake history container: blob name -> JSON, served from the history container only. */
  function serveHistory(blobs: Record<string, unknown>) {
    mocks.fetch.mockImplementation(async (input: string) => {
      const url = new URL(input);
      if (url.searchParams.get('comp') === 'list')
        return new Response(listXml(Object.keys(blobs)));
      const name = decodeURIComponent(url.pathname).replace(
        '/ez-azfw-history/',
        '',
      );
      return name in blobs
        ? Response.json(blobs[name])
        : new Response('missing', { status: 404 });
    });
  }

  it('saves a commit to the history container, without this device’s transient notices', async () => {
    const mod = await storage();
    await mod.saveCommitToCentralHistory({
      ...commit('c1', '2026-11-03T12:00:00.000Z'),
      snapshotError: 'snapshot failed',
      historyError: 'history failed',
    });
    const [url, init] = mocks.fetch.mock.calls.find(
      ([, i]) => i.method === 'PUT',
    )!;
    expect(url).toContain('/ez-azfw-history/2026-11-03T12-00-00-000Z-c1.json');
    expect(url).not.toContain('/ez-azfw-snapshots/');
    expect(init.headers.Authorization).toBe('Bearer storage-token');
    const saved = JSON.parse(init.body);
    expect(saved).toMatchObject({ id: 'c1', user: 'alice@contoso.com' });
    expect(saved).not.toHaveProperty('snapshotError');
    expect(saved).not.toHaveProperty('historyError');
  });

  it('creates the history container on the fly for accounts set up earlier', async () => {
    let created = false;
    mocks.fetch.mockImplementation(
      async (input: string, init?: RequestInit) => {
        if (input.includes('/containers/ez-azfw-history')) {
          created = true;
          return Response.json({});
        }
        return init?.method === 'PUT' && !created
          ? new Response('no container', { status: 404 })
          : new Response(null, { status: 201 });
      },
    );
    await (
      await storage()
    ).saveCommitToCentralHistory(commit('c1', '2026-11-03T12:00:00.000Z'));
    expect(created).toBe(true);
  });

  it('lists everyone’s commits newest first and flags ones only on this device', async () => {
    const shared = commit(
      'shared',
      '2026-11-02T12:00:00.000Z',
      'bob@contoso.com',
    );
    const newest = commit('newest', '2026-11-03T12:00:00.000Z');
    serveHistory({
      '2026-11-02T12-00-00-000Z-shared.json': shared,
      '2026-11-03T12-00-00-000Z-newest.json': newest,
      '2026-11-01T12-00-00-000Z-junk.json': { nope: true },
    });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const unsent = commit('unsent', '2026-11-03T13:00:00.000Z');
    const list = await (
      await storage()
    ).listCommitHistoryFromCentralStorage([shared, unsent]);
    expect(list.map((r) => r.id)).toEqual(['unsent', 'newest', 'shared']);
    expect(list.find((r) => r.id === 'unsent')?.localOnly).toBe(true);
    expect(list.find((r) => r.id === 'shared')?.localOnly).toBeUndefined();
    expect(list.find((r) => r.id === 'shared')?.user).toBe('bob@contoso.com');
  });

  it('writes and reads the history in the container chosen for it', async () => {
    mocks.state = {
      snapshotStorage: { ...config, historyContainerName: 'audit-log' },
    };
    const names = ['2026-11-03T12-00-00-000Z-c1.json'];
    mocks.fetch.mockImplementation(
      async (input: string, init?: RequestInit) => {
        const url = new URL(input);
        expect(url.pathname).toMatch(/^\/audit-log(\/|$)/);
        if (init?.method === 'PUT') return new Response(null, { status: 201 });
        if (url.searchParams.get('comp') === 'list')
          return new Response(listXml(names));
        return Response.json({
          id: 'c1',
          time: '2026-11-03T12:00:00.000Z',
          description: 'd',
          changeCount: 0,
          results: [],
        });
      },
    );
    const mod = await storage();
    await mod.saveCommitToCentralHistory({
      id: 'c1',
      time: '2026-11-03T12:00:00.000Z',
      description: 'd',
      changeCount: 0,
      results: [],
    });
    expect(
      (await mod.listCommitHistoryFromCentralStorage([])).map((r) => r.id),
    ).toEqual(['c1']);
  });

  it('refuses to use the snapshot container for the history', async () => {
    mocks.state = {
      snapshotStorage: {
        ...config,
        containerName: 'shared-blobs',
        historyContainerName: 'Shared-Blobs',
      },
    };
    const mod = await storage();
    await expect(
      mod.saveCommitToCentralHistory({
        id: 'c1',
        time: '2026-11-03T12:00:00.000Z',
        description: 'd',
        changeCount: 0,
        results: [],
      }),
    ).rejects.toThrow(/different blob container than snapshots/);
    await expect(mod.listCommitHistoryFromCentralStorage([])).rejects.toThrow(
      /different blob container than snapshots/,
    );
    expect(mocks.fetch).not.toHaveBeenCalled();
  });

  it('reports when no shared storage is configured', async () => {
    mocks.state = {};
    await expect(
      (await storage()).listCommitHistoryFromCentralStorage([]),
    ).rejects.toThrow(/not configured/);
  });

  it('keeps snapshots and commit history out of each other’s listings', async () => {
    serveBlobs({ 'fp/a.json': snapshot('a') });
    const snapshots = await (await storage()).listSnapshotsFromCentralStorage();
    expect(snapshots.map((s) => s.id)).toEqual(['a']);
    const listCalls = mocks.fetch.mock.calls
      .map(([u]) => u as string)
      .filter((u) => u.includes('comp=list'));
    expect(listCalls.every((u) => u.includes('/ez-azfw-snapshots?'))).toBe(
      true,
    );
  });
});

describe('choosing containers', () => {
  it.each([
    ['same name', 'shared', 'shared'],
    ['different case', 'shared', 'SHARED'],
    ['surrounding spaces', 'shared', ' shared '],
  ])('rejects %s for snapshots and history', async (_label, snap, hist) => {
    expect((await storage()).validateContainerChoice(snap, hist)).toMatch(
      /different blob container than snapshots/,
    );
  });

  it('accepts two valid, different containers and flags invalid names', async () => {
    const mod = await storage();
    expect(mod.validateContainerChoice('snapshots', 'history')).toBeUndefined();
    expect(mod.validateContainerChoice('snapshots', 'Bad_Name')).toMatch(
      /Commit history container/,
    );
    expect(mod.validateContainerChoice('x', 'history')).toMatch(
      /Snapshot container/,
    );
  });

  it('will not connect an existing account with the same container for both', async () => {
    await expect(
      (await storage()).setSnapshotStorageAccount(ACCOUNT, 'shared', 'shared'),
    ).rejects.toThrow(/different blob container than snapshots/);
    expect(mocks.fetch).not.toHaveBeenCalled();
  });

  it('connects an existing account with separate containers and remembers both', async () => {
    mocks.fetch.mockImplementation(async () =>
      Response.json({ location: 'eastus', sku: { name: 'Standard_GRS' } }),
    );
    const cfg = await (
      await storage()
    ).setSnapshotStorageAccount(ACCOUNT, 'snaps', 'audit-log');
    expect(cfg).toMatchObject({
      containerName: 'snaps',
      historyContainerName: 'audit-log',
    });
    expect(mocks.state.snapshotStorage).toMatchObject({
      historyContainerName: 'audit-log',
    });
    const created = mocks.fetch.mock.calls
      .map(([u]) => u as string)
      .filter((u) => u.includes('/containers/'))
      .map((u) => /containers\/([^?]+)/.exec(u)![1]);
    expect(created).toEqual(['snaps', 'audit-log']);
    const tagPatch = mocks.fetch.mock.calls.find(
      ([, i]) => i?.method === 'PATCH',
    )!;
    expect(JSON.parse(tagPatch[1].body).tags).toMatchObject({
      'ez-azfw-ruleman-container': 'snaps',
      'ez-azfw-ruleman-history-container': 'audit-log',
    });
  });

  it('will not create an account that uses one container for both', async () => {
    await expect(
      (await storage()).createSnapshotStorageAccount({
        subscriptionId: SUB,
        resourceGroup: 'qa',
        location: 'eastus',
        storageAccountName: 'qasnapshots',
        containerName: 'shared',
        historyContainerName: 'SHARED',
      }),
    ).rejects.toThrow(/different blob container than snapshots/);
    expect(mocks.fetch).not.toHaveBeenCalled();
  });

  it('discovers both container names from the account tags', async () => {
    mocks.state = {};
    mocks.graph.mockImplementation(async (kql: string) =>
      kql.includes('resourcecontainers')
        ? []
        : [
            {
              id: ACCOUNT,
              name: 'qasnapshots',
              subscriptionId: SUB,
              resourceGroup: 'qa',
              location: 'eastus',
              sku: { name: 'Standard_GRS' },
              tags: {
                'ez-azfw-ruleman-snapshots': 'true',
                'ez-azfw-ruleman-container': 'snaps',
                'ez-azfw-ruleman-history-container': 'audit-log',
              },
            },
          ],
    );
    expect(await (await storage()).getSnapshotStorageConfig()).toMatchObject({
      containerName: 'snaps',
      historyContainerName: 'audit-log',
    });
  });
});

describe('creating a storage account', () => {
  const request = {
    subscriptionId: SUB,
    resourceGroup: 'qa',
    location: 'eastus',
    storageAccountName: 'QASnapshots',
  };

  function serveArm(roleAssignment: () => Response) {
    mocks.fetch.mockImplementation(
      async (input: string, init?: RequestInit) => {
        if (input.includes('/roleAssignments/')) return roleAssignment();
        if (init?.method === 'PUT' && !input.includes('blobServices'))
          return Response.json({
            properties: { provisioningState: 'Succeeded' },
          });
        return Response.json({
          location: 'eastus',
          sku: { name: 'Standard_GRS' },
        });
      },
    );
  }

  it('assigns the signed-in user Storage Blob Data Contributor on the account', async () => {
    serveArm(() => Response.json({}));
    const result = await (
      await storage()
    ).createSnapshotStorageAccount(request);
    const accountPut = mocks.fetch.mock.calls.find(
      ([u, i]) =>
        u.includes('/storageAccounts/qasnapshots?') && i.method === 'PUT',
    )!;
    expect(JSON.parse(accountPut[1].body).properties).toMatchObject({
      allowBlobPublicAccess: false,
      publicNetworkAccess: 'Enabled',
      networkAcls: { defaultAction: 'Allow' },
    });
    expect(result).toMatchObject({
      storageAccountName: 'qasnapshots',
      roleAssigned: true,
    });
    const [url, init] = mocks.fetch.mock.calls.find(([u]) =>
      u.includes('/roleAssignments/'),
    )!;
    expect(url).toContain(
      `${ACCOUNT}/providers/Microsoft.Authorization/roleAssignments/`,
    );
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body).properties).toEqual({
      roleDefinitionId: `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe`,
      principalId: 'user-oid',
      principalType: 'User',
    });
  });

  it('also creates the commit history container', async () => {
    serveArm(() => Response.json({}));
    await (await storage()).createSnapshotStorageAccount(request);
    const containers = mocks.fetch.mock.calls
      .map(([u]) => u as string)
      .filter((u) => u.includes('/containers/'))
      .map((u) => /containers\/([^?]+)/.exec(u)![1]);
    expect(containers).toEqual(['ez-azfw-snapshots', 'ez-azfw-history']);
  });

  it('uses the same assignment name each time, so retries are harmless', async () => {
    serveArm(() => Response.json({}));
    const mod = await storage();
    await mod.createSnapshotStorageAccount(request);
    await mod.createSnapshotStorageAccount(request);
    const names = mocks.fetch.mock.calls
      .map(([u]) => u as string)
      .filter((u) => u.includes('/roleAssignments/'))
      .map((u) => /roleAssignments\/([^?]+)/.exec(u)![1]);
    expect(names).toHaveLength(2);
    expect(names[0]).toBe(names[1]);
    expect(names[0]).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('treats an existing assignment as success', async () => {
    serveArm(() =>
      Response.json(
        { error: { code: 'RoleAssignmentExists' } },
        { status: 409 },
      ),
    );
    expect(
      (await (await storage()).createSnapshotStorageAccount(request))
        .roleAssigned,
    ).toBe(true);
  });

  it('keeps the new account and says what to do when it cannot assign the role', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    serveArm(() =>
      Response.json(
        { error: { code: 'AuthorizationFailed', message: 'no write access' } },
        { status: 403 },
      ),
    );
    const result = await (
      await storage()
    ).createSnapshotStorageAccount(request);
    expect(result.roleAssigned).toBe(false);
    expect(result.roleAssignmentError).toBe(
      'Assign yourself the "Storage Blob Data Contributor" role on qasnapshots before you can view or save snapshots.',
    );
    expect(mocks.state.snapshotStorage?.storageAccountName).toBe('qasnapshots');
  });
});
