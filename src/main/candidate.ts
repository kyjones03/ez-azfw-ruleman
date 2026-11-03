import { randomUUID } from 'node:crypto';
import {
  loadState,
  updateState,
  type ActiveCommit,
  type StagedGroup,
} from './store';
import {
  getRuleCollectionGroup,
  listRuleCollectionGroups,
  putRuleCollectionGroup,
  describeAzureError,
} from './azure';
import {
  requireSnapshotStorageConfigured,
  saveCommitToCentralHistory,
  saveSnapshotToCentralStorage,
} from './snapshotStorage';
import {
  diffGroups,
  groupsEqual,
  newGroupErrors,
  validateGroup,
} from '../shared/rules';
import { resourceName, sameResourceId } from '../shared/resourceId';
import { changeWarnings } from '../shared/risk';
import { mergeGroup } from '../shared/merge';
import type {
  CandidateStatus,
  ChangeItem,
  CommitGroupState,
  CommitProgress,
  CommitRecord,
  CommitResult,
  GroupView,
  PolicySnapshot,
  RuleCollectionGroup,
} from '../shared/types';

/**
 * The candidate configuration: locally edited copies of rule collection groups.
 * Edits are held in memory until saved to disk, and only reach Azure on commit.
 */
export class Candidate {
  /** How often to poll Azure while it applies a change. */
  static pollMs = 5000;

  private staged = new Map<string, StagedGroup>();
  private dirty = false;
  /** Groups a commit is writing right now (lower-cased IDs). */
  private inFlight = new Set<string>();

  private lastKnownRunning = new Map<string, RuleCollectionGroup[]>();

  private assertNotCommitting(groupId: string) {
    if (this.inFlight.has(key(groupId)))
      throw new Error(
        'This group is being committed to Azure right now. Wait for that to finish (see the activity bell), then make more changes.',
      );
  }

  constructor() {
    for (const s of loadState().candidate) this.staged.set(key(s.groupId), s);
  }

  get unsaved(): boolean {
    return this.dirty;
  }

  /** Merges running groups with staged edits (and draft-only new groups) for display. */
  view(policyId: string, running: RuleCollectionGroup[]): GroupView[] {
    this.lastKnownRunning.set(key(policyId), running);
    let rebased = false;
    const views: GroupView[] = running.map((group) => {
      let s = this.staged.get(key(group.id));
      if (!s) return { group, staged: false, drift: false };
      // Mid-commit, Azure's copy is in flux; the commit itself checks for conflicts.
      if (this.inFlight.has(key(group.id)))
        return {
          group: s.candidate,
          staged: true,
          drift: false,
          baseline: s.baseline,
        };
      // A drafted "new" group that now exists in Azure was created by someone else.
      if (s.created)
        return {
          group: s.candidate,
          staged: true,
          drift: true,
          conflicts: [
            'A group with this name was created in Azure after you drafted it',
          ],
          isNew: true,
          baseline: s.baseline,
        };
      let conflicts: string[] = [];
      if (!groupsEqual(s.baseline, group)) {
        // Azure moved on (someone's edit, or just Azure re-saving it): carry the draft's own
        // edits over to the current version unless both touched the same thing.
        const m = mergeGroup(s.baseline, s.candidate, group);
        conflicts = m.conflicts;
        if (!conflicts.length) {
          s = this.rebase(s, group, m.merged);
          rebased = true;
          if (!s) return { group, staged: false, drift: false };
        }
      }
      return {
        group: s.candidate,
        staged: true,
        drift: conflicts.length > 0,
        conflicts: conflicts.length ? conflicts : undefined,
        baseline: s.baseline,
      };
    });
    // Keep a saved draft in step on disk; unsaved edits stay unsaved.
    if (rebased && !this.dirty) this.persist();
    for (const s of this.staged.values()) {
      if (
        s.created &&
        sameResourceId(s.policyId, policyId) &&
        !running.some((g) => sameResourceId(g.id, s.groupId))
      ) {
        views.push({
          group: s.candidate,
          staged: true,
          drift: false,
          isNew: true,
        });
      }
    }
    return views.sort((a, b) => a.group.priority - b.group.priority);
  }

  isCreated(groupId: string): boolean {
    return !!this.staged.get(key(groupId))?.created;
  }

  /** Drafts a new, empty rule collection group. It's created in Azure on commit. */
  create(
    policyId: string,
    name: string,
    priority: number,
    running: RuleCollectionGroup[],
  ): CandidateStatus {
    const others = [
      ...running.map((g) => this.staged.get(key(g.id))?.candidate ?? g),
      ...[...this.staged.values()]
        .filter(
          (s) =>
            s.created &&
            sameResourceId(s.policyId, policyId) &&
            !running.some((g) => sameResourceId(g.id, s.groupId)),
        )
        .map((s) => s.candidate),
    ];
    const problems = newGroupErrors(name, priority, others);
    const message = [problems.name, problems.priority].filter(Boolean);
    if (message.length) throw new Error(message.join('\n'));

    const group: RuleCollectionGroup = {
      id: `${policyId}/ruleCollectionGroups/${name}`,
      name,
      priority,
      ruleCollections: [],
    };
    this.staged.set(key(group.id), {
      groupId: group.id,
      policyId,
      policyName: resourceName(policyId),
      stagedAt: new Date().toISOString(),
      created: true,
      baseline: { ...group, ruleCollections: [] },
      candidate: group,
    });
    this.dirty = true;
    return this.status();
  }

  stage(
    policyId: string,
    edited: RuleCollectionGroup,
    running: RuleCollectionGroup | undefined,
  ): CandidateStatus {
    const k = key(edited.id);
    this.assertNotCommitting(edited.id);
    const existing = this.staged.get(k);
    // Draft-only groups have no running copy; their empty baseline stands in for it.
    const reference = existing?.created ? existing.baseline : running;
    if (!reference) throw new Error('Rule collection group not found.');
    if (!sameResourceId(edited.id, reference.id))
      throw new Error('Rule collection group mismatch.');
    const errors = validateGroup(edited);
    if (errors.length)
      throw new Error(`Validation failed:\n• ${errors.join('\n• ')}`);

    const baseline = existing?.baseline ?? reference;
    const candidate: RuleCollectionGroup = {
      ...edited,
      id: reference.id,
      name: reference.name,
      etag: baseline.etag,
    };

    // A new group stays drafted even if empty: creating it is itself the change.
    if (!existing?.created && groupsEqual(baseline, candidate)) {
      this.staged.delete(k);
    } else {
      this.staged.set(k, {
        groupId: reference.id,
        policyId,
        policyName: resourceName(policyId),
        stagedAt: existing?.stagedAt ?? new Date().toISOString(),
        created: existing?.created,
        baseline,
        candidate,
      });
    }
    this.dirty = true;
    return this.status();
  }

  status(): CandidateStatus {
    return {
      unsaved: this.dirty,
      pending: [...this.staged.values()].map((s) => ({
        groupId: s.groupId,
        groupName: s.candidate.name,
        policyId: s.policyId,
        policyName: s.policyName,
        stagedAt: s.stagedAt,
        changes: changesOf(s),
        warnings: changeWarnings(s.baseline, s.candidate),
        committing: this.inFlight.has(key(s.groupId)) || undefined,
      })),
    };
  }

  revert(groupIds?: string[]): CandidateStatus {
    // Groups being committed stay; their commit decides what happens to them.
    if (!groupIds) {
      for (const k of this.staged.keys())
        if (!this.inFlight.has(k)) this.staged.delete(k);
    } else {
      for (const id of groupIds) this.assertNotCommitting(id);
      for (const id of groupIds) this.staged.delete(key(id));
    }
    this.dirty = true;
    return this.status();
  }

  save(): CandidateStatus {
    this.persist();
    this.dirty = false;
    return this.status();
  }

  /** Stages a former policy snapshot onto the current running groups so the user can review or commit it. */
  restoreSnapshot(
    snapshot: PolicySnapshot,
    running: RuleCollectionGroup[],
  ): CandidateStatus {
    for (const r of running) this.assertNotCommitting(r.id);
    for (const g of snapshot.groups) this.assertNotCommitting(g.id);

    // Clear existing staged drafts for this policy before staging the snapshot state.
    for (const [k, s] of this.staged.entries()) {
      if (sameResourceId(s.policyId, snapshot.policyId)) {
        this.staged.delete(k);
      }
    }

    const runningByName = new Map(
      running.map((g) => [g.name.toLowerCase(), g]),
    );
    const snapshotNames = new Set(
      snapshot.groups.map((g) => g.name.toLowerCase()),
    );

    for (const snapGroup of snapshot.groups) {
      const live = runningByName.get(snapGroup.name.toLowerCase());
      if (live) {
        const candidateGroup: RuleCollectionGroup = {
          ...structuredClone(snapGroup),
          id: live.id,
          name: live.name,
          etag: live.etag,
        };
        if (!groupsEqual(live, candidateGroup)) {
          this.staged.set(key(live.id), {
            groupId: live.id,
            policyId: snapshot.policyId,
            policyName: snapshot.policyName,
            stagedAt: new Date().toISOString(),
            baseline: live,
            candidate: candidateGroup,
          });
        }
      } else {
        const id = `${snapshot.policyId}/ruleCollectionGroups/${snapGroup.name}`;
        const candidateGroup: RuleCollectionGroup = {
          ...structuredClone(snapGroup),
          id,
        };
        this.staged.set(key(id), {
          groupId: id,
          policyId: snapshot.policyId,
          policyName: snapshot.policyName,
          stagedAt: new Date().toISOString(),
          created: true,
          baseline: { ...candidateGroup, ruleCollections: [] },
          candidate: candidateGroup,
        });
      }
    }

    // Any running group that wasn't in the snapshot is emptied so its rules are rolled back too.
    for (const live of running) {
      if (!snapshotNames.has(live.name.toLowerCase())) {
        const emptied: RuleCollectionGroup = {
          ...live,
          ruleCollections: [],
        };
        if (!groupsEqual(live, emptied)) {
          this.staged.set(key(live.id), {
            groupId: live.id,
            policyId: snapshot.policyId,
            policyName: snapshot.policyName,
            stagedAt: new Date().toISOString(),
            baseline: live,
            candidate: emptied,
          });
        }
      }
    }

    this.dirty = true;
    return this.status();
  }

  private persist() {
    updateState((state) => {
      state.candidate = [...this.staged.values()];
    });
  }

  /**
   * Moves a drafted group onto Azure's current version. Returns undefined when the draft has
   * nothing left to change (Azure already matches it), in which case it leaves the draft.
   */
  private rebase(
    s: StagedGroup,
    current: RuleCollectionGroup,
    merged: RuleCollectionGroup,
  ): StagedGroup | undefined {
    const k = key(s.groupId);
    if (groupsEqual(current, merged)) {
      this.staged.delete(k);
      return undefined;
    }
    const next: StagedGroup = {
      ...s,
      baseline: current,
      candidate: { ...merged, etag: current.etag },
    };
    this.staged.set(k, next);
    return next;
  }

  async commit(
    groupIds: string[],
    description: string,
    user: string | undefined,
    onProgress: (p: CommitProgress) => void,
  ): Promise<CommitRecord> {
    const selected = groupIds
      .map((id) => this.staged.get(key(id)))
      .filter((s): s is StagedGroup => !!s)
      // A second commit must not write a group the first is still writing.
      .filter((s) => !this.inFlight.has(key(s.groupId)))
      // Azure rejects concurrent writes to the same policy, so commit one group at a time.
      .sort(
        (a, b) =>
          a.policyId.localeCompare(b.policyId) ||
          a.candidate.priority - b.candidate.priority,
      );
    if (!selected.length)
      throw new Error(
        groupIds.some((id) => this.inFlight.has(key(id)))
          ? 'These changes are already being committed. Follow their progress in the activity bell.'
          : 'There are no staged changes to commit.',
      );
    for (const s of selected) this.inFlight.add(key(s.groupId));
    try {
      await requireSnapshotStorageConfigured();
      return await this.write(selected, description, user, onProgress);
    } finally {
      for (const s of selected) this.inFlight.delete(key(s.groupId));
    }
  }

  private async write(
    selected: StagedGroup[],
    description: string,
    user: string | undefined,
    onProgress: (p: CommitProgress) => void,
  ): Promise<CommitRecord> {
    const active: ActiveCommit = {
      user,
      changeCount: selected.reduce((n, s) => n + changesOf(s).length, 0),
      results: [],
      written: {},
      progress: {
        commitId: randomUUID(),
        startedAt: new Date().toISOString(),
        description: description.trim(),
        index: 0,
        total: selected.length,
        groupName: selected[0].candidate.name,
        policyName: selected[0].policyName,
        groups: selected.map((s) => ({
          groupId: s.groupId,
          groupName: s.candidate.name,
          policyName: s.policyName,
          action: s.created ? 'create' : 'update',
          state: 'pending',
          changes: changesOf(s),
        })),
      },
    };
    const { progress, results } = active;
    const emit = this.tracker(active, onProgress);
    const setState = (
      index: number,
      state: CommitGroupState,
      error?: string,
    ) => {
      Object.assign(progress.groups[index], { state, error });
      emit();
    };

    for (const [index, s] of selected.entries()) {
      Object.assign(progress, {
        index,
        groupName: s.candidate.name,
        policyName: s.policyName,
      });
      setState(index, 'checking');
      const base = resultBase(progress.groups[index]);
      const fail = (error: string, conflict = false) => {
        results.push({
          ...base,
          ok: false,
          conflict: conflict || undefined,
          error,
        });
        setState(index, conflict ? 'conflict' : 'failed', error);
      };
      const succeed = () => {
        this.staged.delete(key(s.groupId));
        results.push({ ...base, ok: true });
        setState(index, 'succeeded');
      };
      const waiting = () => {
        if (progress.groups[index].state !== 'waiting')
          setState(index, 'waiting');
      };
      try {
        const started = Date.now();
        // Azure refuses writes while a group (or its policy) is still applying an earlier change;
        // wait for that and try again rather than failing the commit.
        for (;;) {
          let toWrite = s.candidate;
          if (s.created) {
            // Never overwrite a group someone else created with the same name meanwhile.
            if (await groupExists(s.groupId)) {
              fail(
                'A rule collection group with this name was created in Azure after you drafted it. Discard this draft and edit the existing group instead.',
                true,
              );
              break;
            }
          } else {
            const current = await waitUntilSettled(s.groupId, waiting);
            if (progress.groups[index].state === 'waiting')
              setState(index, 'checking');
            if (!groupsEqual(current, s.baseline)) {
              // Azure moved on since the draft started; keep both sides' edits when they don't overlap.
              const m = mergeGroup(s.baseline, s.candidate, current);
              if (m.conflicts.length) {
                fail(
                  `Changed in Azure after you started editing: ${m.conflicts.join('; ')}. Discard your changes to this group to load the latest version, then make them again.`,
                  true,
                );
                break;
              }
              toWrite = m.merged;
              if (groupsEqual(current, toWrite)) {
                // Azure already has everything the draft would write.
                succeed();
                break;
              }
            }
            toWrite = { ...toWrite, etag: current.etag };
          }
          active.written[key(s.groupId)] = toWrite;
          setState(index, s.created ? 'creating' : 'updating');
          try {
            await putRuleCollectionGroup(toWrite);
          } catch (err) {
            if (isBusy(err) && Date.now() - started < SETTLE_TIMEOUT_MS) {
              delete active.written[key(s.groupId)];
              waiting();
              await sleep(Candidate.pollMs);
              continue;
            }
            throw err;
          }
          // The write is accepted before Azure finishes applying it to the firewall; the group
          // stays "Updating" until then, and only then is the change in effect.
          const settled = await waitUntilSettled(s.groupId);
          if (settled.provisioningState?.toLowerCase() === 'failed') {
            fail(
              'Azure accepted the change but failed to apply it (provisioning state Failed). Check the policy in the Azure portal.',
            );
          } else {
            active.written[key(s.groupId)] = settled;
            succeed();
          }
          break;
        }
      } catch (err) {
        fail(describeAzureError(err));
      }
    }
    const snapshotError = await this.captureCommittedSnapshots(active);
    const record = this.finish(active, emit, snapshotError);
    const historyError = await shareCommitRecord(record);
    if (historyError) record.historyError = historyError;
    return record;
  }

  /** Emits progress and keeps it on disk, so a commit interrupted by closing the app can resume. */
  private tracker(
    active: ActiveCommit,
    onProgress: (p: CommitProgress) => void,
  ) {
    const { commitId } = active.progress;
    return () => {
      updateState((state) => {
        const i = state.activeCommits.findIndex(
          (c) => c.progress.commitId === commitId,
        );
        if (i >= 0) state.activeCommits[i] = active;
        else state.activeCommits.push(active);
      });
      onProgress({
        ...active.progress,
        groups: active.progress.groups.map((g) => ({ ...g })),
      });
    };
  }

  private finish(
    active: ActiveCommit,
    emit: () => void,
    snapshotError?: string,
  ): CommitRecord {
    const { progress } = active;
    const record: CommitRecord = {
      id: progress.commitId,
      time: new Date().toISOString(),
      user: active.user,
      description: progress.description,
      changeCount: active.changeCount,
      results: active.results,
      ...(snapshotError ? { snapshotError } : {}),
    };
    progress.done = true;
    emit();
    // Committed groups leave the candidate; persist that along with the history entry.
    // Unrelated unsaved edits are persisted too, since the file must stay consistent with Azure.
    updateState((state) => {
      state.candidate = [...this.staged.values()];
      state.history.unshift(record);
      state.activeCommits = state.activeCommits.filter(
        (c) => c.progress.commitId !== progress.commitId,
      );
    });
    this.dirty = false;
    return record;
  }

  /**
   * Saves one cumulative snapshot per policy once a commit has finished, from what the commit
   * itself wrote. Runs for completed and resumed commits alike (never for draft saves), and a
   * failure is reported rather than thrown: the change is already in Azure and the commit
   * must still be finalized. Returns the failure message, if any.
   */
  private async captureCommittedSnapshots(
    active: ActiveCommit,
  ): Promise<string | undefined> {
    const byPolicy = new Map<
      string,
      { policyId: string; results: CommitResult[] }
    >();
    for (const r of active.results) {
      if (!r.ok) continue;
      const policyId = r.groupId.replace(/\/ruleCollectionGroups\/[^/]+$/i, '');
      const entry = byPolicy.get(key(policyId)) ?? { policyId, results: [] };
      entry.results.push(r);
      byPolicy.set(key(policyId), entry);
    }

    const errors: string[] = [];
    for (const { policyId, results } of byPolicy.values()) {
      try {
        let liveGroups: RuleCollectionGroup[] | undefined;
        try {
          liveGroups = await listRuleCollectionGroups(policyId);
        } catch {
          // Fall back to merging the known running groups with the committed groups.
        }
        const merged = new Map<string, RuleCollectionGroup>(
          (liveGroups?.length
            ? liveGroups
            : (this.lastKnownRunning.get(key(policyId)) ?? [])
          ).map((g) => [key(g.id), g]),
        );
        // Ensure the newly written state is reflected even if list lags behind get.
        for (const r of results) {
          const written = active.written[key(r.groupId)];
          if (written) merged.set(key(r.groupId), written);
        }
        const names = results.map((r) => r.groupName).join(', ');
        await recordCommittedPolicySnapshot(policyId, [...merged.values()], {
          user: active.user,
          description:
            active.progress.description ||
            summarizeCommitChanges(
              names,
              results.flatMap((r) => r.changes ?? []),
            ),
        });
      } catch (err) {
        console.error(
          `[commit] Couldn't save the snapshot for ${resourceName(policyId)}:`,
          err,
        );
        errors.push(`${resourceName(policyId)}: ${describeAzureError(err)}`);
      }
    }
    return errors.length
      ? `The commit succeeded, but its snapshot wasn't saved. ${errors.join('; ')}`
      : undefined;
  }

  /**
   * Picks up commits that were running when the app closed. Groups already sent to Azure are
   * followed until Azure finishes and then checked against what was sent; groups not sent yet
   * stay in the draft. Returns the progress of the first one (null when there's nothing to
   * resume) and reports the rest through `onProgress`.
   */
  resume(onProgress: (p: CommitProgress) => void): CommitProgress | null {
    let first: CommitProgress | null = null;
    for (const active of loadState().activeCommits) {
      const progress = this.resumeCommit(active, onProgress);
      first ??= progress;
    }
    return first;
  }

  private resumeCommit(
    active: ActiveCommit,
    onProgress: (p: CommitProgress) => void,
  ): CommitProgress {
    const { groups } = active.progress;
    const open = active.progress.done
      ? []
      : groups.filter((g) => !FINAL_STATES.includes(g.state));
    // Already being resumed (e.g. the window was reloaded): just report where it is.
    if (open.some((g) => this.inFlight.has(key(g.groupId))))
      return structuredClone(active.progress);
    // Groups that made it before the app closed leave the draft, as they would have then.
    for (const g of groups)
      if (g.state === 'succeeded') this.staged.delete(key(g.groupId));
    for (const g of open) this.inFlight.add(key(g.groupId));
    const emit = this.tracker(active, onProgress);
    void (async () => {
      try {
        for (const g of open) await this.resumeGroup(active, g, emit);
        // A commit that finished across a restart still gets its snapshot.
        const snapshotError = await this.captureCommittedSnapshots(active);
        await shareCommitRecord(this.finish(active, emit, snapshotError));
      } catch (err) {
        console.error(
          `[commit] Couldn't finish resuming commit ${active.progress.commitId}:`,
          err,
        );
      } finally {
        for (const g of open) this.inFlight.delete(key(g.groupId));
      }
    })();
    return structuredClone(active.progress);
  }

  private async resumeGroup(
    active: ActiveCommit,
    g: CommitProgress['groups'][number],
    emit: () => void,
  ): Promise<void> {
    const result = (ok: boolean, error?: string) => {
      active.results.push({ ...resultBase(g), ok, error });
      Object.assign(g, { state: ok ? 'succeeded' : 'failed', error });
      if (ok) this.staged.delete(key(g.groupId));
      emit();
    };
    active.progress.index = active.progress.groups.indexOf(g);
    const written = active.written[key(g.groupId)];
    if (!written) {
      result(
        false,
        'Not committed: the app closed before this group was sent to Azure. It is still in your draft.',
      );
      return;
    }
    emit();
    try {
      const live = await waitUntilSettled(g.groupId);
      const ok =
        live.provisioningState?.toLowerCase() !== 'failed' &&
        groupsEqual(live, written);
      result(
        ok,
        ok
          ? undefined
          : 'The app closed while Azure was applying this change, and Azure’s copy doesn’t match what was sent. It is still in your draft.',
      );
    } catch (err) {
      result(false, describeAzureError(err));
    }
  }
}

/**
 * Adds a finished commit to the shared history. Like snapshots, this never undoes or blocks the
 * commit: a failure is returned as a message for the user instead.
 */
async function shareCommitRecord(
  record: CommitRecord,
): Promise<string | undefined> {
  try {
    await saveCommitToCentralHistory(record);
  } catch (err) {
    console.error(
      "[commit] Couldn't add the commit to the shared history:",
      err,
    );
    return `The commit succeeded, but it wasn't added to the shared commit history. ${describeAzureError(err)}`;
  }
}

const FINAL_STATES: CommitGroupState[] = ['succeeded', 'failed', 'conflict'];
/** How long to wait for Azure to finish applying a change before giving up. */
const SETTLE_TIMEOUT_MS = 20 * 60_000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Azure's answer when a group or its policy is still applying an earlier change. */
function isBusy(err: unknown): boolean {
  const e = err as { code?: string; message?: string };
  return /UpdateNotAllowedWhenUpdatingOrDeleting|AnotherOperationInProgress|InProgress|Conflict.*Updating/i.test(
    `${e?.code ?? ''} ${e?.message ?? ''}`,
  );
}

function summarizeCommitChanges(
  groupNames: string,
  changes: ChangeItem[],
): string {
  if (!changes.length) return `Committed ${groupNames}`;
  const added = changes.filter((c) => c.kind === 'added').length;
  const modified = changes.filter((c) => c.kind === 'modified').length;
  const removed = changes.filter((c) => c.kind === 'removed').length;
  const parts: string[] = [];
  if (added) parts.push(`+${added} added`);
  if (modified) parts.push(`~${modified} updated`);
  if (removed) parts.push(`−${removed} deleted`);
  return `Committed ${groupNames} (${parts.join(', ')})`;
}

/**
 * Uploads a single cumulative policy snapshot to the centralized Azure Blob Storage container
 * when a commit finishes. Snapshots are never saved to local disk.
 */
export async function recordCommittedPolicySnapshot(
  policyId: string,
  groups: RuleCollectionGroup[],
  options?: { user?: string; description?: string },
): Promise<PolicySnapshot> {
  const sortedGroups = structuredClone(groups).sort(
    (a, b) => a.priority - b.priority || a.name.localeCompare(b.name),
  );
  const snapshot: PolicySnapshot = {
    id: randomUUID(),
    policyId,
    policyName: resourceName(policyId),
    time: new Date().toISOString(),
    user: options?.user,
    description: options?.description || 'Committed policy changes',
    groups: sortedGroups,
  };
  await saveSnapshotToCentralStorage(snapshot);
  return snapshot;
}

/** Polls a group until Azure has finished applying changes to it. */
async function waitUntilSettled(
  groupId: string,
  onWaiting?: () => void,
): Promise<RuleCollectionGroup> {
  const started = Date.now();
  for (;;) {
    let g: RuleCollectionGroup;
    try {
      g = await getRuleCollectionGroup(groupId);
    } catch (err) {
      // A group that was just created can take a moment to be readable.
      if (
        (err as { statusCode?: number }).statusCode === 404 &&
        Date.now() - started < 60_000
      ) {
        await sleep(Candidate.pollMs);
        continue;
      }
      throw err;
    }
    const state = g.provisioningState?.toLowerCase();
    if (!['updating', 'creating', 'deleting', 'accepted'].includes(state ?? ''))
      return g;
    if (Date.now() - started > SETTLE_TIMEOUT_MS)
      throw new Error(
        'Azure has been applying a change to this group for over 20 minutes. Check the policy in the Azure portal, then try again.',
      );
    onWaiting?.();
    await sleep(Candidate.pollMs);
  }
}

function resultBase(g: CommitProgress['groups'][number]) {
  return {
    groupId: g.groupId,
    groupName: g.groupName,
    policyName: g.policyName,
    action: g.action,
    changes: g.changes,
  };
}

const key = (id: string) => id.toLowerCase();

/** Changes in a drafted group; a new group starts with an "added group" entry. */
function changesOf(s: StagedGroup): ChangeItem[] {
  const diff = diffGroups(s.baseline, s.candidate).filter(
    // The new group's priority is part of creating it, not a separate change.
    (c) => !(s.created && c.target === 'group'),
  );
  return s.created
    ? [
        {
          kind: 'added',
          target: 'group',
          detail: `new group, priority ${s.candidate.priority}`,
        },
        ...diff,
      ]
    : diff;
}

async function groupExists(groupId: string): Promise<boolean> {
  try {
    await getRuleCollectionGroup(groupId);
    return true;
  } catch (err) {
    if ((err as { statusCode?: number }).statusCode === 404) return false;
    throw err;
  }
}

export const candidate = new Candidate();
