import { Fragment, useEffect, useState } from 'react';
import {
  History as HistoryIcon,
  ChevronRight,
  CheckCircle2,
  Database,
  Settings2,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import { Badge, EmptyState, Notice, Spinner } from '../components/ui';
import { ChangeList, ChangeSummary } from '../components/ChangeList';
import { errorMessage } from '../components/Toast';
import type {
  CommitHistoryEntry,
  SnapshotStorageConfig,
} from '../../shared/types';

const DEFAULT_HISTORY_CONTAINER = 'ez-azfw-history';

export function CommitHistory({
  refreshKey,
  onOpenStorage,
}: {
  refreshKey: number;
  /** Opens the Snapshots tab, where the shared storage (and the history container) is set up. */
  onOpenStorage: () => void;
}) {
  const [records, setRecords] = useState<CommitHistoryEntry[] | null>(null);
  const [error, setError] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const [storage, setStorage] = useState<SnapshotStorageConfig | null>(null);

  useEffect(() => {
    let cancelled = false;
    window.api
      .getSnapshotStorageConfig()
      .then((cfg) => !cancelled && setStorage(cfg))
      .catch(() => !cancelled && setStorage(null));
    window.api
      .getCentralHistory()
      .then((history) => {
        if (cancelled) return;
        setRecords(history);
        setError('');
      })
      .catch(async (err) => {
        if (cancelled) return;
        // Shared history isn't reachable: still show what this device recorded.
        setError(errorMessage(err));
        const local = await window.api.getHistory().catch(() => []);
        if (!cancelled)
          setRecords(local.map((r) => ({ ...r, localOnly: true })));
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  if (!records)
    return (
      <div className="p-6">
        <Spinner label="Loading shared commit history…" />
      </div>
    );
  const problem = error && (
    <div className="px-6 pt-4">
      <Notice
        tone="error"
        title="Couldn't load the shared commit history"
        action={
          <button type="button" className="btn-outline" onClick={onOpenStorage}>
            <Settings2 size={14} />
            Open storage settings
          </button>
        }
      >
        {error}
      </Notice>
    </div>
  );
  if (!records.length) {
    return (
      <div className="flex h-full flex-col">
        {problem}
        <EmptyState icon={<HistoryIcon size={22} />} title="No commits yet">
          Commits made by you or your teammates are listed here with who made
          them and what changed.
        </EmptyState>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-6 pb-4 pt-5">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 className="text-xl font-semibold">Commit history</h1>
          {storage && (
            <span className="inline-flex items-center gap-1.5 rounded border border-line bg-ink-900 px-2.5 py-0.5 text-xs text-fg-muted">
              <Database size={12} className="text-azure" />
              <span className="font-mono text-fg">
                {storage.storageAccountName}/
                {storage.historyContainerName ?? DEFAULT_HISTORY_CONTAINER}
              </span>
            </span>
          )}
          <button
            type="button"
            className="btn-ghost h-7 px-2 text-xs"
            onClick={onOpenStorage}
          >
            <Settings2 size={13} />
            Change storage
          </button>
        </div>
        <p className="mt-1 text-sm text-fg-muted">
          Commits made by you and your teammates, saved in shared Azure Blob
          Storage, newest first.
        </p>
      </div>
      {problem}
      <div className="min-h-0 flex-1 overflow-y-auto">
        <table className="w-full table-fixed text-left text-sm">
          <thead className="sticky top-0 bg-ink-900 text-xs text-fg-muted">
            <tr className="border-b border-line">
              <th className="w-12 py-2 pl-6" />
              <th className="w-48 px-3 py-2 font-medium">Time</th>
              <th className="w-56 px-3 py-2 font-medium">User</th>
              <th className="px-3 py-2 font-medium">Description</th>
              <th className="w-56 px-3 py-2 font-medium">Changes</th>
              <th className="w-44 px-3 py-2 font-medium">Result</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r) => {
              const ok = r.results.filter((x) => x.ok).length;
              const failed = r.results.length - ok;
              const expanded = open === r.id;
              return (
                <Fragment key={r.id}>
                  <tr
                    className="cursor-pointer border-b border-line/60 hover:bg-ink-850"
                    onClick={() => setOpen(expanded ? null : r.id)}
                  >
                    <td className="py-2 pl-6 text-fg-muted">
                      {/* The row is clickable too; this button makes it reachable by keyboard. */}
                      <button
                        type="button"
                        className="flex hover:text-fg"
                        aria-expanded={expanded}
                        aria-label={`Details of the commit from ${new Date(r.time).toLocaleString()}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          setOpen(expanded ? null : r.id);
                        }}
                      >
                        <ChevronRight
                          size={14}
                          className={`transition-transform ${expanded ? 'rotate-90' : ''}`}
                        />
                      </button>
                    </td>
                    <td className="px-3 py-2 text-fg-muted">
                      {new Date(r.time).toLocaleString()}
                    </td>
                    <td
                      className="truncate px-3 py-2 text-fg-muted"
                      title={r.user}
                    >
                      {r.user ?? '—'}
                    </td>
                    <td className="truncate px-3 py-2" title={r.description}>
                      {r.description || (
                        <span className="text-fg-faint">No description</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {r.results.some((x) => x.changes) ? (
                        <ChangeSummary
                          changes={r.results.flatMap((x) => x.changes ?? [])}
                        />
                      ) : (
                        r.changeCount
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span className="flex flex-wrap gap-1">
                        {ok > 0 && <Badge tone="green">{ok} succeeded</Badge>}
                        {failed > 0 && (
                          <Badge tone="red">{failed} failed</Badge>
                        )}
                        {r.localOnly && (
                          <Badge
                            tone="neutral"
                            title="Only recorded on this device: it isn't in the shared history."
                          >
                            This device only
                          </Badge>
                        )}
                      </span>
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="border-b border-line/60 bg-ink-950">
                      <td />
                      <td colSpan={5} className="px-3 py-3">
                        <ul className="space-y-3">
                          {r.results.map((x) => (
                            <li key={x.groupId}>
                              <div className="flex items-start gap-2 text-sm">
                                {x.ok ? (
                                  <CheckCircle2
                                    size={15}
                                    className="mt-0.5 shrink-0 text-allow"
                                  />
                                ) : x.conflict ? (
                                  <AlertTriangle
                                    size={15}
                                    className="mt-0.5 shrink-0 text-candidate"
                                  />
                                ) : (
                                  <XCircle
                                    size={15}
                                    className="mt-0.5 shrink-0 text-deny"
                                  />
                                )}
                                <span className="min-w-0">
                                  <span className="font-medium text-fg">
                                    {x.policyName} / {x.groupName}
                                  </span>{' '}
                                  <span className="text-xs text-fg-muted">
                                    {x.ok
                                      ? x.action === 'create'
                                        ? 'created in Azure'
                                        : 'updated in Azure'
                                      : x.conflict
                                        ? 'not saved (conflict)'
                                        : 'not saved (failed)'}
                                  </span>
                                  {x.error && (
                                    <span className="block text-xs text-fg-muted">
                                      {x.error}
                                    </span>
                                  )}
                                </span>
                              </div>
                              <div className="ml-[23px] mt-1">
                                {x.changes?.length ? (
                                  <ChangeList changes={x.changes} />
                                ) : (
                                  <p className="text-xs text-fg-faint">
                                    {x.changes
                                      ? 'No rule changes.'
                                      : 'Change details weren’t recorded for commits made before this version.'}
                                  </p>
                                )}
                              </div>
                            </li>
                          ))}
                        </ul>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
