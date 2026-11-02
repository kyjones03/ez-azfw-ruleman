import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CommitProgress, RuleCollectionGroup } from '../shared/types';

// The candidate module touches disk (store) and Azure (azure); stub both.
const azure = vi.hoisted(() => ({
  getRuleCollectionGroup: vi.fn(),
  listRuleCollectionGroups: vi.fn(),
  putRuleCollectionGroup: vi.fn(),
}));
const snapshotStorage = vi.hoisted(() => ({
  requireSnapshotStorageConfigured: vi.fn(),
  saveSnapshotToCentralStorage: vi.fn(),
}));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const store = vi.hoisted(() => ({ state: {} as any }));
vi.mock('./store', () => ({
  loadState: () => store.state,
  updateState: (mutate: (s: unknown) => void) => mutate(store.state),
}));
vi.mock('./snapshotStorage', () => snapshotStorage);
beforeEach(() => {
  store.state = {
    candidate: [],
    history: [],
    activeCommits: [],
  };
  azure.listRuleCollectionGroups.mockReset();
  azure.listRuleCollectionGroups.mockResolvedValue([]);
  snapshotStorage.requireSnapshotStorageConfigured.mockReset();
  snapshotStorage.requireSnapshotStorageConfigured.mockResolvedValue({
    storageAccountId:
      '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stsnap',
    storageAccountName: 'stsnap',
    containerName: 'ez-azfw-snapshots',
    configuredAt: '2026-01-01T00:00:00.000Z',
  });
  snapshotStorage.saveSnapshotToCentralStorage.mockReset();
  snapshotStorage.saveSnapshotToCentralStorage.mockResolvedValue(undefined);
});
vi.mock('./azure', () => ({
  ...azure,
  describeAzureError: (e: Error) => e.message,
}));

const POLICY =
  '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/fp';
const running: RuleCollectionGroup[] = [
  {
    id: `${POLICY}/ruleCollectionGroups/Platform`,
    name: 'Platform',
    priority: 100,
    etag: 'e1',
    ruleCollections: [],
  },
];
const NEW_ID = `${POLICY}/ruleCollectionGroups/rcg-new`;
const notFound = Object.assign(new Error('Not found'), { statusCode: 404 });

async function freshCandidate() {
  vi.resetModules();
  const mod = await import('./candidate');
  mod.Candidate.pollMs = 1;
  return mod.candidate;
}

describe('drafting new rule collection groups', () => {
  beforeEach(() => {
    azure.getRuleCollectionGroup.mockReset();
    azure.putRuleCollectionGroup.mockReset();
  });

  it('drafts an empty group that shows in the view and as a pending change', async () => {
    const c = await freshCandidate();
    const status = c.create(POLICY, 'rcg-new', 200, running);
    expect(status.pending).toEqual([
      expect.objectContaining({
        groupId: NEW_ID,
        groupName: 'rcg-new',
        changes: [
          {
            kind: 'added',
            target: 'group',
            detail: 'new group, priority 200',
          },
        ],
      }),
    ]);
    const view = c.view(POLICY, running);
    expect(view.map((v) => [v.group.name, v.isNew ?? false])).toEqual([
      ['Platform', false],
      ['rcg-new', true],
    ]);
    // Other policies don't see it.
    expect(c.view(`${POLICY}-other`, [])).toEqual([]);
  });

  it('rejects duplicate names/priorities, including other drafted groups', async () => {
    const c = await freshCandidate();
    expect(() => c.create(POLICY, 'PLATFORM', 300, running)).toThrow(
      /already has a rule collection group/,
    );
    expect(() => c.create(POLICY, 'rcg-x', 100, running)).toThrow(
      /already used by "Platform"/,
    );
    c.create(POLICY, 'rcg-new', 200, running);
    expect(() => c.create(POLICY, 'rcg-other', 200, running)).toThrow(
      /already used by "rcg-new"/,
    );
  });

  it('stages edits to a drafted group without Azure, and keeps it when emptied', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    const edited: RuleCollectionGroup = {
      id: NEW_ID,
      name: 'rcg-new',
      priority: 200,
      ruleCollections: [
        {
          ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
          name: 'allow-dns',
          priority: 100,
          action: { type: 'Allow' },
          rules: [],
        },
      ],
    };
    const status = c.stage(POLICY, edited, undefined);
    expect(status.pending[0].changes.map((x) => x.target)).toEqual([
      'group',
      'collection',
    ]);
    // Removing everything again leaves the new (empty) group drafted.
    const emptied = c.stage(
      POLICY,
      { ...edited, ruleCollections: [] },
      undefined,
    );
    expect(emptied.pending).toHaveLength(1);
    expect(azure.getRuleCollectionGroup).not.toHaveBeenCalled();
  });

  it('discarding a drafted group removes it', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    expect(c.revert([NEW_ID]).pending).toEqual([]);
    expect(c.view(POLICY, running)).toHaveLength(1);
  });

  it('creates the group in Azure on commit when it still does not exist', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    azure.getRuleCollectionGroup
      .mockRejectedValueOnce(notFound)
      .mockResolvedValue({ ...running[0], id: NEW_ID });
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const record = await c.commit([NEW_ID], 'add group', 'me', () => {});
    expect(record.results).toEqual([
      expect.objectContaining({ groupId: NEW_ID, ok: true }),
    ]);
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledWith(
      expect.objectContaining({ id: NEW_ID, priority: 200 }),
    );
    expect(c.status().pending).toEqual([]);
    // The history records what was done, not just that it worked.
    expect(record.results[0]).toMatchObject({
      action: 'create',
      changes: [
        {
          kind: 'added',
          target: 'group',
          detail: 'new group, priority 200',
        },
      ],
    });
  });

  it('refuses to overwrite a same-named group created in Azure meanwhile', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    azure.getRuleCollectionGroup.mockResolvedValue({ ...running[0] });
    const record = await c.commit([NEW_ID], 'add group', 'me', () => {});
    expect(record.results[0]).toMatchObject({ ok: false, conflict: true });
    expect(azure.putRuleCollectionGroup).not.toHaveBeenCalled();
    // It stays drafted, flagged as conflicting once Azure lists it.
    const view = c.view(POLICY, [
      ...running,
      { ...running[0], id: NEW_ID, name: 'rcg-new', priority: 200 },
    ]);
    expect(view.find((v) => v.group.id === NEW_ID)).toMatchObject({
      isNew: true,
      drift: true,
    });
  });
});

describe('committing edits to existing groups', () => {
  beforeEach(() => {
    azure.getRuleCollectionGroup.mockReset();
    azure.putRuleCollectionGroup.mockReset();
  });
  const edited = (): RuleCollectionGroup => ({
    ...running[0],
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
        name: 'net-allow-core',
        priority: 100,
        action: { type: 'Allow' },
        rules: [],
      },
    ],
  });

  it('commits when only the etag changed (e.g. Azure finished provisioning)', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    // Same contents, new etag.
    azure.getRuleCollectionGroup.mockResolvedValue({
      ...running[0],
      etag: 'e2',
    });
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const events: CommitProgress[] = [];
    const record = await c.commit([running[0].id], 'x', 'me', (p) =>
      events.push(p),
    );
    expect(record.results[0]).toMatchObject({ ok: true });
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledWith(
      expect.objectContaining({ etag: 'e2' }),
    );
    expect(events.map((e) => e.groups[0].state)).toEqual([
      'checking',
      'updating',
      'succeeded',
      'succeeded',
    ]);
    expect(events.at(-1)).toMatchObject({ done: true, commitId: record.id });
    // The draft view doesn't call this a conflict either.
    expect(c.view(POLICY, [{ ...running[0], etag: 'e3' }])[0].drift).toBe(
      false,
    );
  });

  it('merges a draft onto unrelated changes made in Azure', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    const theirs = { ...running[0], etag: 'e2', priority: 150 };
    azure.getRuleCollectionGroup.mockResolvedValue(theirs);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const record = await c.commit([running[0].id], 'x', 'me', () => {});
    expect(record.results[0]).toMatchObject({ ok: true });
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledWith(
      expect.objectContaining({
        etag: 'e2',
        priority: 150,
        ruleCollections: edited().ruleCollections,
      }),
    );
  });

  it('refuses when Azure changed the same thing differently', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    const theirs = {
      ...running[0],
      etag: 'e2',
      ruleCollections: [{ ...edited().ruleCollections[0], priority: 300 }],
    };
    azure.getRuleCollectionGroup.mockResolvedValue(theirs);
    const events: CommitProgress[] = [];
    const record = await c.commit([running[0].id], 'x', 'me', (p) =>
      events.push(p),
    );
    expect(record.results[0]).toMatchObject({ ok: false, conflict: true });
    expect(azure.putRuleCollectionGroup).not.toHaveBeenCalled();
    expect(events.at(-1)?.groups[0].state).toBe('conflict');
    const view = c.view(POLICY, [theirs])[0];
    expect(view.drift).toBe(true);
    expect(view.conflicts?.[0]).toMatch(/net-allow-core/);
  });

  it('moves a saved draft onto Azure’s version when they don’t overlap', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    c.save();
    const theirs = { ...running[0], etag: 'e2', priority: 150 };
    const view = c.view(POLICY, [theirs])[0];
    expect(view).toMatchObject({ staged: true, drift: false });
    expect(view.group.priority).toBe(150);
    expect(view.baseline?.etag).toBe('e2');
  });

  it('marks groups as committing and refuses a second commit of them meanwhile', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    let finish!: () => void;
    azure.putRuleCollectionGroup.mockReturnValue(
      new Promise((r) => (finish = () => r({}))),
    );
    const first = c.commit([running[0].id], 'x', 'me', () => {});
    expect(c.status().pending[0].committing).toBe(true);
    await expect(
      c.commit([running[0].id], 'again', 'me', () => {}),
    ).rejects.toThrow(/already being committed/);
    expect(() => c.stage(POLICY, edited(), running[0])).toThrow(
      /being committed/,
    );
    await vi.waitFor(() =>
      expect(azure.putRuleCollectionGroup).toHaveBeenCalled(),
    );
    finish();
    expect((await first).results[0].ok).toBe(true);
    expect(c.status().pending).toEqual([]);
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledTimes(1);
  });

  it('waits for Azure to finish earlier and current changes before reporting success', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    const updating = { ...running[0], provisioningState: 'Updating' };
    const done = { ...edited(), etag: 'e3', provisioningState: 'Succeeded' };
    azure.getRuleCollectionGroup
      .mockResolvedValueOnce(updating)
      .mockResolvedValueOnce({ ...running[0], provisioningState: 'Succeeded' })
      .mockResolvedValueOnce({ ...done, provisioningState: 'Updating' })
      .mockResolvedValueOnce(done);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const events: CommitProgress[] = [];
    const record = await c.commit([running[0].id], 'x', 'me', (p) =>
      events.push(p),
    );
    expect(record.results[0].ok).toBe(true);
    expect(events.map((e) => e.groups[0].state)).toEqual([
      'checking',
      'waiting',
      'checking',
      'updating',
      'succeeded',
      'succeeded',
    ]);
    expect(azure.getRuleCollectionGroup).toHaveBeenCalledTimes(4);
    expect(store.state.activeCommits).toEqual([]);
  });

  it('retries when Azure says the group is still busy', async () => {
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    azure.putRuleCollectionGroup
      .mockRejectedValueOnce(
        Object.assign(new Error('busy'), {
          code: 'FirewallPolicyRuleCollectionGroupUpdateNotAllowedWhenUpdatingOrDeleting',
        }),
      )
      .mockResolvedValueOnce({});
    const record = await c.commit([running[0].id], 'x', 'me', () => {});
    expect(record.results[0].ok).toBe(true);
    expect(azure.putRuleCollectionGroup).toHaveBeenCalledTimes(2);
  });

  it('resumes a commit interrupted by closing the app', async () => {
    const other = { ...running[0], id: `${POLICY}/ruleCollectionGroups/Other` };
    store.state.candidate = [
      {
        groupId: running[0].id,
        policyId: POLICY,
        policyName: 'fp',
        stagedAt: '',
        baseline: running[0],
        candidate: edited(),
      },
      {
        groupId: other.id,
        policyId: POLICY,
        policyName: 'fp',
        stagedAt: '',
        baseline: other,
        candidate: { ...edited(), id: other.id },
      },
    ];
    const group = (id: string, state: string) => ({
      groupId: id,
      groupName: 'g',
      policyName: 'fp',
      action: 'update' as const,
      state: state as never,
    });
    store.state.activeCommits = [
      {
        changeCount: 2,
        results: [],
        written: { [running[0].id.toLowerCase()]: edited() },
        progress: {
          commitId: 'c1',
          startedAt: '',
          description: 'interrupted',
          index: 0,
          total: 2,
          groupName: 'g',
          policyName: 'fp',
          groups: [
            group(running[0].id, 'updating'),
            group(other.id, 'pending'),
          ],
        },
      },
    ];
    const c = await freshCandidate();
    azure.getRuleCollectionGroup
      .mockResolvedValueOnce({ ...edited(), provisioningState: 'Updating' })
      .mockResolvedValueOnce({ ...edited(), provisioningState: 'Succeeded' });
    const events: CommitProgress[] = [];
    const snapshot = c.resume((p) => events.push(p));
    expect(snapshot?.commitId).toBe('c1');
    expect(c.status().pending.every((p) => p.committing)).toBe(true);
    await vi.waitFor(() => expect(events.at(-1)?.done).toBe(true));
    expect(events.at(-1)?.groups.map((g) => g.state)).toEqual([
      'succeeded',
      'failed',
    ]);
    expect(store.state.history[0]).toMatchObject({ id: 'c1' });
    expect(store.state.activeCommits).toEqual([]);
    // The written group left the draft; the unsent one is still there.
    expect(c.status().pending.map((p) => p.groupId)).toEqual([other.id]);
    expect(c.resume(() => {})).toBeNull();
  });

  it('reports "creating" for new groups', async () => {
    const c = await freshCandidate();
    c.create(POLICY, 'rcg-new', 200, running);
    azure.getRuleCollectionGroup
      .mockRejectedValueOnce(notFound)
      .mockResolvedValue({ ...running[0], id: NEW_ID });
    azure.putRuleCollectionGroup.mockResolvedValue({});
    const events: CommitProgress[] = [];
    await c.commit([NEW_ID], 'x', 'me', (p) => events.push(p));
    expect(events.map((e) => e.groups[0].state)).toContain('creating');
    expect(events[0].groups[0].action).toBe('create');
  });

  it('keeps every concurrently running commit on disk until it finishes', async () => {
    const other = { ...running[0], id: `${POLICY}/ruleCollectionGroups/Other` };
    const c = await freshCandidate();
    c.stage(POLICY, edited(), running[0]);
    c.stage(POLICY, { ...edited(), id: other.id }, other);
    azure.getRuleCollectionGroup.mockImplementation(async (id: string) =>
      id === other.id ? other : running[0],
    );
    const finishers: (() => void)[] = [];
    azure.putRuleCollectionGroup.mockImplementation(
      () => new Promise((r) => finishers.push(() => r({}))),
    );
    const first = c.commit([running[0].id], 'one', 'me', () => {});
    const second = c.commit([other.id], 'two', 'me', () => {});
    await vi.waitFor(() => expect(finishers).toHaveLength(2));
    expect(store.state.activeCommits).toHaveLength(2);
    finishers[0]();
    const firstRecord = await first;
    // The second commit is still running, so it must still be resumable.
    expect(
      store.state.activeCommits.map(
        (a: { progress: CommitProgress }) => a.progress.description,
      ),
    ).toEqual(['two']);
    finishers[1]();
    const secondRecord = await second;
    expect(store.state.activeCommits).toEqual([]);
    expect(store.state.history.map((h: { id: string }) => h.id).sort()).toEqual(
      [firstRecord.id, secondRecord.id].sort(),
    );
  });

  it('drops groups that succeeded before the app closed from the draft on resume', async () => {
    const other = { ...running[0], id: `${POLICY}/ruleCollectionGroups/Other` };
    const staged = (g: RuleCollectionGroup) => ({
      groupId: g.id,
      policyId: POLICY,
      policyName: 'fp',
      stagedAt: '',
      baseline: g,
      candidate: { ...edited(), id: g.id },
    });
    store.state.candidate = [staged(running[0]), staged(other)];
    const group = (id: string, state: string) => ({
      groupId: id,
      groupName: 'g',
      policyName: 'fp',
      action: 'update' as const,
      state: state as never,
    });
    const interrupted = (
      commitId: string,
      groups: ReturnType<typeof group>[],
    ) => ({
      changeCount: groups.length,
      results: [],
      written: {},
      progress: {
        commitId,
        startedAt: '',
        description: commitId,
        index: 0,
        total: groups.length,
        groupName: 'g',
        policyName: 'fp',
        groups,
      },
    });
    store.state.activeCommits = [
      interrupted('c1', [group(running[0].id, 'succeeded')]),
      interrupted('c2', [group(other.id, 'pending')]),
    ];
    const c = await freshCandidate();
    const events: CommitProgress[] = [];
    expect(c.resume((p) => events.push(p))?.commitId).toBe('c1');
    await vi.waitFor(() => expect(store.state.activeCommits).toEqual([]));
    expect(
      events
        .filter((e) => e.done)
        .map((e) => e.commitId)
        .sort(),
    ).toEqual(['c1', 'c2']);
    expect(c.status().pending.map((p) => p.groupId)).toEqual([other.id]);
    expect(azure.getRuleCollectionGroup).not.toHaveBeenCalled();
  });

  it('records one cumulative snapshot in central storage only when a commit completes, and restores a former snapshot', async () => {
    const c = await freshCandidate();
    // Viewing or staging draft changes must never create snapshots.
    c.view(POLICY, running);
    const nextGroup = edited();
    c.stage(POLICY, nextGroup, running[0]);
    expect(snapshotStorage.saveSnapshotToCentralStorage).not.toHaveBeenCalled();

    // Committing records a single cumulative snapshot for the policy in centralized storage.
    azure.getRuleCollectionGroup.mockResolvedValue(running[0]);
    azure.putRuleCollectionGroup.mockResolvedValue({});
    azure.listRuleCollectionGroups.mockResolvedValue([nextGroup]);
    await c.commit([running[0].id], 'CHG001 cumulative update', 'me', () => {});
    expect(
      snapshotStorage.requireSnapshotStorageConfigured,
    ).toHaveBeenCalledTimes(1);
    expect(snapshotStorage.saveSnapshotToCentralStorage).toHaveBeenCalledTimes(
      1,
    );
    const savedSnapshot =
      snapshotStorage.saveSnapshotToCentralStorage.mock.calls[0][0];
    expect(savedSnapshot).toMatchObject({
      policyId: POLICY,
      policyName: 'fp',
      user: 'me',
      description: 'CHG001 cumulative update',
    });

    // Restoring a prior snapshot stages the rollback over the modified running state.
    const initialSnapshot = {
      ...savedSnapshot,
      groups: running,
    };
    const restoredStatus = c.restoreSnapshot(initialSnapshot, [nextGroup]);
    expect(restoredStatus.pending).toHaveLength(1);
    expect(restoredStatus.pending[0].changes).toEqual([
      expect.objectContaining({
        kind: 'removed',
        target: 'collection',
        collection: 'net-allow-core',
      }),
    ]);
  });
});
