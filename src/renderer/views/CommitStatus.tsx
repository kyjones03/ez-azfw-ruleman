import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  Loader2,
  XCircle,
} from 'lucide-react';
import { Modal } from '../components/Modal';
import { Badge } from '../components/ui';
import { ChangeList } from '../components/ChangeList';
import type {
  CommitGroupState,
  CommitProgress,
  CommitRecord,
} from '../../shared/types';

interface CommitStatusData {
  progress?: CommitProgress;
  record?: CommitRecord;
  /** The app was closed while this commit was running. */
  stale?: boolean;
}

const STATE_LABEL: Record<CommitGroupState, string> = {
  pending: 'Waiting',
  checking: 'Checking for changes in Azure',
  waiting: 'Waiting for Azure to finish an earlier change',
  creating: 'Creating',
  updating: 'Updating',
  succeeded: 'Saved to Azure',
  failed: 'Failed',
  conflict: 'Conflict',
};

function StateIcon({ state }: { state: CommitGroupState }) {
  if (state === 'succeeded')
    return <CheckCircle2 size={16} className="text-allow" />;
  if (state === 'failed') return <XCircle size={16} className="text-deny" />;
  if (state === 'conflict')
    return <AlertTriangle size={16} className="text-candidate" />;
  if (state === 'pending')
    return <Circle size={16} className="text-fg-faint" />;
  return <Loader2 size={16} className="animate-spin text-azure" />;
}

/** Normalizes live progress or a history record into one list of group outcomes. */
function commitGroups(data: CommitStatusData) {
  if (data.progress) return data.progress.groups;
  return (data.record?.results ?? []).map((r) => ({
    target: r.target,
    groupId: r.groupId,
    groupName: r.groupName,
    policyName: r.policyName,
    action: r.action,
    state: (r.ok
      ? 'succeeded'
      : r.conflict
        ? 'conflict'
        : 'failed') as CommitGroupState,
    error: r.error,
    changes: r.changes,
  }));
}

function commitSummary(data: CommitStatusData) {
  const groups = commitGroups(data);
  const done = data.record ? true : !!data.progress?.done;
  const failed = groups.filter(
    (g) => g.state === 'failed' || g.state === 'conflict',
  ).length;
  const succeeded = groups.filter((g) => g.state === 'succeeded').length;
  const current = data.progress?.groups.find(
    (g) =>
      g.state === 'checking' ||
      g.state === 'waiting' ||
      g.state === 'creating' ||
      g.state === 'updating',
  );
  return { groups, done, failed, succeeded, current };
}

/** Live (or finished) status of a commit, opened from the progress bell. */
export function CommitStatus({
  data,
  onClose,
}: {
  data: CommitStatusData;
  onClose: () => void;
}) {
  const { groups, done, failed, succeeded, current } = commitSummary(data);
  const description = data.progress?.description ?? data.record?.description;
  const started = data.progress?.startedAt ?? data.record?.time;
  const title = data.stale
    ? 'Commit interrupted'
    : !done
      ? `Committing ${groups.length} ${groups.some((g) => !!g.target) ? (groups.length === 1 ? 'resource' : 'resources') : groups.length === 1 ? 'group' : 'groups'}…`
      : failed
        ? `Commit finished with ${failed} ${failed === 1 ? 'problem' : 'problems'}`
        : 'Commit succeeded';

  return (
    <Modal
      title={title}
      subtitle={[
        description || 'No description',
        started && new Date(started).toLocaleString(),
      ]
        .filter(Boolean)
        .join(' · ')}
      onClose={onClose}
      widthClass="max-w-2xl"
      footer={
        <button className="btn-primary" onClick={onClose}>
          {done || data.stale ? 'Close' : 'Hide — keep running'}
        </button>
      }
    >
      {data.stale && (
        <div className="mb-3 flex gap-2 border border-candidate/40 bg-candidate/10 p-3 text-xs text-candidate">
          <AlertTriangle size={16} className="shrink-0" />
          <p>
            EZ AzFW Manager was closed while this commit was running. Resources
            marked as in progress may or may not have been saved; reload the
            policy to see what's in Azure.
          </p>
        </div>
      )}
      {!done && !data.stale && current && (
        <p className="mb-3 text-sm text-fg-muted">
          {STATE_LABEL[current.state]} {current.groupName}… Resources are
          written one at a time.
        </p>
      )}
      <ul className="divide-y divide-line border border-line">
        {groups.map((g) => (
          <li key={g.groupId} className="flex items-start gap-3 px-3 py-2">
            <span className="mt-0.5 shrink-0">
              <StateIcon
                state={
                  data.stale &&
                  !['succeeded', 'failed', 'conflict'].includes(g.state)
                    ? 'conflict'
                    : g.state
                }
              />
            </span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium text-fg">
                {g.target === 'firewall' ? g.groupName : g.policyName}{' '}
                <span className="text-fg-faint">/</span>{' '}
                {g.target === 'policy'
                  ? 'Policy settings'
                  : g.target === 'firewall'
                    ? 'Firewall settings'
                    : g.groupName}
              </p>
              {g.error && (
                <p className="mt-0.5 whitespace-pre-line text-xs text-fg-muted">
                  {g.error}
                </p>
              )}
              {!!g.changes?.length && (
                <div className="mt-1.5">
                  <ChangeList changes={g.changes} />
                </div>
              )}
            </div>
            <span className="flex shrink-0 items-center gap-2">
              {g.action && (
                <span className="text-xs text-fg-faint">
                  {g.action === 'create' ? 'New group' : 'Edit'}
                </span>
              )}
              <Badge
                tone={
                  g.state === 'succeeded'
                    ? 'green'
                    : g.state === 'failed'
                      ? 'red'
                      : g.state === 'conflict'
                        ? 'candidate'
                        : 'blue'
                }
              >
                {data.stale &&
                !['succeeded', 'failed', 'conflict'].includes(g.state)
                  ? 'Unknown'
                  : STATE_LABEL[g.state]}
              </Badge>
            </span>
          </li>
        ))}
      </ul>
      {done && (
        <p className="mt-3 text-xs text-fg-faint">
          {succeeded} of {groups.length} saved to Azure.
        </p>
      )}
    </Modal>
  );
}
