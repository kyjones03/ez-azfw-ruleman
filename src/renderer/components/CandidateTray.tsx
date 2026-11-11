import { Loader2 } from 'lucide-react';
import type { CandidateStatus } from '../../shared/types';

/**
 * The candidate tray: appears whenever the local candidate differs from Azure. It is the
 * one place amber is used in bulk, so uncommitted work is impossible to miss.
 */
export function CandidateTray({
  status,
  saving,
  onSave,
  onDiscard,
  onReview,
  onShowActivity,
}: {
  status: CandidateStatus;
  saving: boolean;
  onSave: () => void;
  onDiscard: () => void;
  onReview: () => void;
  /** Opens the activity bell, where commit progress is shown. */
  onShowActivity: () => void;
}) {
  const waiting = status.pending.filter((p) => !p.committing);
  const committing = status.pending.length - waiting.length;
  const changes = waiting.reduce((n, p) => n + p.changes.length, 0);
  const groups = waiting.length;
  const policies = waiting.filter((p) => p.target === 'policy').length;
  const firewalls = waiting.filter((p) => p.target === 'firewall').length;
  const groupCount = groups - policies - firewalls;
  const scope = [
    groupCount
      ? `${groupCount} rule collection ${groupCount === 1 ? 'group' : 'groups'}`
      : '',
    policies ? `${policies} ${policies === 1 ? 'policy' : 'policies'}` : '',
    firewalls
      ? `${firewalls} ${firewalls === 1 ? 'firewall' : 'firewalls'}`
      : '',
  ]
    .filter(Boolean)
    .join(' and ');
  if (!status.pending.length && !status.unsaved) return null;

  const summary = groups
    ? `${changes} ${changes === 1 ? 'change' : 'changes'} not committed in ${scope}`
    : committing
      ? ''
      : 'Your edits cancel out; nothing differs from Azure';

  return (
    <div
      role="region"
      aria-label="Uncommitted changes"
      className={`flex h-12 shrink-0 animate-tray-in items-center gap-3 border-t-2 pl-4 pr-3 ${groups ? 'border-candidate bg-[#221B10]' : 'border-azure/60 bg-ink-900'}`}
    >
      {groups > 0 && (
        <span
          className="h-2 w-2 shrink-0 rounded-full bg-candidate"
          aria-hidden
        />
      )}
      <p className="min-w-0 flex-1 truncate text-sm text-fg">
        {summary && (
          <button
            type="button"
            className="hover:underline disabled:no-underline"
            onClick={onReview}
            disabled={!groups}
            title="See every drafted change"
          >
            {summary}
          </button>
        )}
        {groups > 0 && (
          <span
            className="ml-2 text-fg-muted"
            title={
              status.unsaved
                ? 'Save the draft to keep these edits if the app closes.'
                : 'Saved drafts are kept in this app’s data folder on this device and restored the next time you open it. Azure is unchanged until you commit.'
            }
          >
            {status.unsaved
              ? 'Draft has unsaved edits.'
              : 'Draft saved on this device.'}
          </span>
        )}
        {committing > 0 && (
          <button
            type="button"
            onClick={onShowActivity}
            className={`inline-flex items-center gap-1.5 text-azure hover:underline ${summary ? 'ml-3' : ''}`}
          >
            <Loader2 size={13} className="animate-spin" />
            Committing {committing}{' '}
            {status.pending.some((p) => !!p.target && p.committing)
              ? committing === 1
                ? 'resource'
                : 'resources'
              : committing === 1
                ? 'group'
                : 'groups'}{' '}
            to Azure — progress is in the activity bell
          </button>
        )}
      </p>
      {(groups > 0 || (status.unsaved && !committing)) && (
        <>
          <button className="btn-ghost" onClick={onDiscard} disabled={!groups}>
            Discard all
          </button>
          <button
            className="btn-outline"
            onClick={onSave}
            disabled={!status.unsaved || saving}
          >
            Save draft
          </button>
          <button
            className="btn-candidate"
            onClick={onReview}
            disabled={!groups}
          >
            Review and commit
          </button>
        </>
      )}
    </div>
  );
}
