import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  GitCommitHorizontal,
  Loader2,
  XCircle,
} from 'lucide-react';
import type { CommitRecord } from '../../shared/types';
import {
  isFinished,
  timeAgo,
  type CommitActivity,
  type DeployActivity,
} from '../activity';

const MAX_COMMITS = 10;

type Item =
  | { kind: 'deploy'; time: string; unreadAt: string; deploy: DeployActivity }
  | { kind: 'commit'; time: string; unreadAt: string; commit: CommitRecord }
  | {
      kind: 'live-commit';
      time: string;
      unreadAt: string;
      live: CommitActivity;
    };

const commitRunning = (c: CommitActivity) => !c.stale && !c.progress.done;
const isRunning = (i: Item) =>
  (i.kind === 'deploy' && running(i.deploy)) ||
  (i.kind === 'live-commit' && commitRunning(i.live));

/**
 * Title-bar bell with a dropdown of current and recent activity (deployments and commits),
 * like the Azure portal's notifications. Clicking an item reopens it.
 */
export function ActivityMenu({
  deployments,
  commits,
  liveCommits,
  seenAt,
  clearedAt,
  onSeen,
  onClear,
  onOpenDeploy,
  onOpenCommit,
}: {
  deployments: DeployActivity[];
  commits: CommitRecord[];
  /** Commits in progress (or interrupted) that aren't in the history yet. */
  liveCommits: CommitActivity[];
  seenAt: string;
  clearedAt?: string;
  onSeen: () => void;
  onClear: () => void;
  onOpenDeploy: (key: string) => void;
  onOpenCommit: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  // Unread highlighting uses the "seen" time from before this opening.
  const [highlightAfter, setHighlightAfter] = useState(seenAt);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  const items: Item[] = [
    ...deployments.map(
      (d): Item => ({
        kind: 'deploy',
        time: d.progress.startedAt,
        unreadAt: d.updatedAt,
        deploy: d,
      }),
    ),
    ...commits
      .filter((c) => !clearedAt || c.time > clearedAt)
      .slice(0, MAX_COMMITS)
      .map(
        (c): Item => ({
          kind: 'commit',
          time: c.time,
          unreadAt: c.time,
          commit: c,
        }),
      ),
    // Live commits until they land in the history (interrupted ones stay as a warning).
    ...liveCommits
      .filter(
        (c) =>
          !commits.some((r) => r.id === c.key) && (!c.progress.done || c.stale),
      )
      .map(
        (c): Item => ({
          kind: 'live-commit',
          time: c.progress.startedAt,
          unreadAt: c.updatedAt,
          live: c,
        }),
      ),
  ].sort((a, b) => {
    // Running work first, then newest first.
    return (
      Number(isRunning(b)) - Number(isRunning(a)) ||
      b.time.localeCompare(a.time)
    );
  });

  const runningCount =
    deployments.filter(running).length +
    liveCommits.filter(commitRunning).length;
  const unreadCount = items.filter(
    (i) => i.unreadAt > seenAt && !isRunning(i),
  ).length;

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        button.current?.focus();
      }
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const toggle = () => {
    if (!open) {
      setHighlightAfter(seenAt);
      onSeen();
    }
    setOpen((o) => !o);
  };

  const choose = (item: Item) => {
    setOpen(false);
    if (item.kind === 'deploy') onOpenDeploy(item.deploy.key);
    else if (item.kind === 'live-commit') onOpenCommit(item.live.key);
    else onOpenCommit(item.commit.id);
  };

  const label = runningCount
    ? `Activity: ${runningCount} running`
    : unreadCount
      ? `Activity: ${unreadCount} new`
      : 'Activity';

  return (
    <div className="no-drag relative" ref={root}>
      <button
        ref={button}
        type="button"
        onClick={toggle}
        aria-label={label}
        title={label}
        aria-haspopup="dialog"
        aria-expanded={open}
        className={`relative flex h-9 w-11 items-center justify-center hover:bg-ink-800 hover:text-fg ${open ? 'bg-ink-800 text-fg' : 'text-fg-muted'}`}
      >
        <Bell size={16} />
        {runningCount > 0 ? (
          <Loader2
            size={10}
            className="absolute right-2 top-1.5 animate-spin text-azure"
            aria-hidden
          />
        ) : unreadCount > 0 ? (
          <span
            className="absolute right-1.5 top-1 flex h-3.5 min-w-3.5 items-center justify-center rounded-full bg-azure px-1 text-[9px] font-bold leading-none text-ink-950"
            aria-hidden
          >
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        ) : null}
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="Activity"
          className="absolute right-0 top-full z-50 mt-px flex max-h-[min(28rem,calc(100vh-4rem))] w-96 flex-col border border-line bg-ink-850 shadow-[0_16px_40px_rgba(4,10,20,0.55)]"
        >
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <h2 className="text-sm font-semibold text-fg">Activity</h2>
            {items.some((i) => !isRunning(i)) && (
              <button
                type="button"
                className="btn-ghost h-6 px-2 text-xs"
                onClick={onClear}
              >
                Clear
              </button>
            )}
          </div>
          {items.length === 0 ? (
            <p className="px-3 py-6 text-center text-sm text-fg-faint">
              No recent activity. Deployments and commits show up here.
            </p>
          ) : (
            <ul className="min-h-0 flex-1 overflow-y-auto py-1">
              {items.map((item) => {
                const unread =
                  item.unreadAt > highlightAfter && !isRunning(item);
                const { icon, title, detail } = describe(item);
                return (
                  <li
                    key={`${item.kind}:${item.kind === 'deploy' ? item.deploy.key : item.kind === 'live-commit' ? item.live.key : item.commit.id}`}
                  >
                    <button
                      type="button"
                      onClick={() => choose(item)}
                      className={`flex w-full gap-2.5 border-l-2 px-3 py-2 text-left hover:bg-ink-800 ${unread ? 'border-azure bg-azure/[0.06]' : 'border-transparent'}`}
                    >
                      <span className="mt-0.5 shrink-0">{icon}</span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-baseline gap-2">
                          <span className="min-w-0 flex-1 truncate text-sm font-medium text-fg">
                            {title}
                          </span>
                          <span className="shrink-0 text-xs text-fg-faint">
                            {timeAgo(item.time)}
                          </span>
                        </span>
                        <span className="mt-0.5 line-clamp-2 block text-xs text-fg-muted">
                          {detail}
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function running(d: DeployActivity) {
  return !d.stale && !isFinished(d.progress);
}

const VERB: Record<string, string> = {
  pending: 'Waiting to commit',
  checking: 'Checking',
  waiting: 'Waiting for Azure to finish an earlier change to',
  creating: 'Creating',
  updating: 'Updating',
};

function describe(item: Item) {
  if (item.kind === 'live-commit') {
    const p = item.live.progress;
    if (item.live.stale)
      return {
        icon: <AlertTriangle size={16} className="text-candidate" />,
        title: 'Commit interrupted',
        detail:
          'EZ AzFW Rule Manager was closed while this commit ran. Reload the policy to see what was saved.',
      };
    const current = p.groups[p.index];
    // Groups whose state has a verb here are still waiting or in progress.
    const doneCount = p.groups.filter(
      (g) => !Object.hasOwn(VERB, g.state),
    ).length;
    return {
      icon: <Loader2 size={16} className="animate-spin text-azure" />,
      title: `${VERB[current?.state] ?? 'Committing'} ${current?.groupName ?? ''} (${Math.min(doneCount + 1, p.total)} of ${p.total})`,
      detail: p.description || 'Committing to Azure…',
    };
  }
  if (item.kind === 'commit') {
    const c = item.commit;
    const failed = c.results.filter((r) => !r.ok).length;
    return {
      icon: failed ? (
        <XCircle size={16} className="text-deny" />
      ) : (
        <GitCommitHorizontal size={16} className="text-allow" />
      ),
      title: failed
        ? `Commit partly failed (${failed} of ${c.results.length})`
        : `Committed ${c.changeCount} ${c.changeCount === 1 ? 'change' : 'changes'}`,
      detail: c.description || 'No description',
    };
  }
  const { progress: p, stale } = item.deploy;
  if (stale) {
    return {
      icon: <AlertTriangle size={16} className="text-candidate" />,
      title: `Deployment of ${p.firewallName}`,
      detail:
        'EZ AzFW Rule Manager was closed while this ran. Check the result in the Azure portal.',
    };
  }
  if (p.phase === 'succeeded')
    return {
      icon: <CheckCircle2 size={16} className="text-allow" />,
      title: `Deployed ${p.firewallName}`,
      detail: p.message,
    };
  if (p.phase === 'failed')
    return {
      icon: <XCircle size={16} className="text-deny" />,
      title: `Deployment of ${p.firewallName} failed`,
      detail: p.error?.split('\n')[0] ?? p.message,
    };
  return {
    icon: <Loader2 size={16} className="animate-spin text-azure" />,
    title: `Deploying ${p.firewallName}`,
    detail: p.message,
  };
}
