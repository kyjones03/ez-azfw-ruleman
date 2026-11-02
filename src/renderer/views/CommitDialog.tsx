import { useEffect, useState } from 'react';
import { AlertTriangle, Database, Undo2 } from 'lucide-react';
import { Modal } from '../components/Modal';
import { Notice } from '../components/ui';
import { errorMessage, useToast } from '../components/Toast';
import type {
  CandidateStatus,
  ChangeItem,
  SnapshotStorageConfig,
} from '../../shared/types';

const GLYPH = { added: '+', modified: '~', removed: '−' };

function describe(c: ChangeItem) {
  const what =
    c.target === 'group'
      ? 'Group settings'
      : c.target === 'collection'
        ? `Collection ${c.collection}`
        : `Rule ${c.collection} / ${c.rule}`;
  return `${what}${c.detail ? `: ${c.detail}` : ''}`;
}

export function CommitDialog({
  status,
  onStatus,
  onClose,
  onCommit,
}: {
  status: CandidateStatus;
  onStatus: (s: CandidateStatus) => void;
  onClose: () => void;
  /** Starts the commit; the dialog closes and progress continues in the activity bell. */
  onCommit: (groupIds: string[], description: string) => void;
}) {
  const toast = useToast();
  // Groups another commit is writing right now can't be committed again.
  const pending = status.pending.filter((p) => !p.committing);
  const [selected, setSelected] = useState(
    () => new Set(pending.map((p) => p.groupId)),
  );
  const [description, setDescription] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [storageConfig, setStorageConfig] = useState<
    SnapshotStorageConfig | null | undefined
  >(undefined);
  // Groups can leave the list while the dialog is open (e.g. another commit picked them up).
  const chosen = pending.filter((p) => selected.has(p.groupId));
  const riskyCount = chosen.reduce((n, p) => n + (p.warnings?.length ?? 0), 0);
  // A different set of risky changes needs a fresh acknowledgement.
  useEffect(() => setAcknowledged(false), [riskyCount]);

  useEffect(() => {
    let cancelled = false;
    window.api
      .getSnapshotStorageConfig()
      .then((cfg) => {
        if (!cancelled) setStorageConfig(cfg);
      })
      .catch(() => {
        if (!cancelled) setStorageConfig(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const revert = async (groupId: string) => {
    try {
      const next = await window.api.revert([groupId]);
      onStatus(next);
    } catch (err) {
      toast('error', errorMessage(err));
    }
  };

  const commit = () => {
    onCommit(
      chosen.map((p) => p.groupId),
      description,
    );
    onClose();
  };
  return (
    <Modal
      title="Commit to Azure"
      subtitle="Groups are written to Azure one at a time. Each is checked for changes made in Azure since you started editing."
      onClose={onClose}
      widthClass="max-w-3xl"
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-candidate"
            onClick={commit}
            disabled={
              !chosen.length ||
              !storageConfig ||
              (riskyCount > 0 && !acknowledged)
            }
          >
            Commit {chosen.length} group
            {chosen.length === 1 ? '' : 's'}
          </button>
        </>
      }
    >
      {!pending.length ? (
        <p className="text-sm text-fg-muted">
          Nothing to commit. Your draft matches Azure.
        </p>
      ) : (
        <div className="space-y-3">
          {storageConfig === null && (
            <Notice
              tone="warn"
              title="Centralized snapshot storage is required before committing"
            >
              Open the <strong className="text-fg">Snapshots</strong> tab to
              select an existing Azure Storage account or create a new
              geo-redundant (GRS) Blob Storage account. A cumulative snapshot is
              saved there automatically on every commit.
            </Notice>
          )}
          {storageConfig && (
            <div className="flex items-center gap-2 border border-line bg-ink-900 px-3 py-2 text-xs text-fg-muted">
              <Database size={13} className="shrink-0 text-azure" />
              <span>
                Cumulative commit snapshot will be saved to{' '}
                <span className="font-mono text-fg">
                  {storageConfig.storageAccountName}/
                  {storageConfig.containerName}
                </span>
              </span>
            </div>
          )}
          {pending.map((p) => (
            <div key={p.groupId} className="border border-line">
              <div className="flex items-center gap-3 border-b border-line bg-ink-800 px-3 py-2">
                <input
                  type="checkbox"
                  className="accent-azure"
                  aria-label={`Include ${p.groupName}`}
                  checked={selected.has(p.groupId)}
                  onChange={(e) =>
                    setSelected((s) => {
                      const next = new Set(s);
                      if (e.target.checked) next.add(p.groupId);
                      else next.delete(p.groupId);
                      return next;
                    })
                  }
                />
                <span
                  className="min-w-0 flex-1 truncate text-sm font-medium text-fg"
                  title={`${p.policyName} / ${p.groupName}`}
                >
                  {p.policyName} <span className="text-fg-faint">/</span>{' '}
                  {p.groupName}
                </span>
                <span className="text-xs text-fg-faint">
                  {p.changes.length} change{p.changes.length === 1 ? '' : 's'}
                </span>
                <button
                  className="btn-ghost h-7 px-2"
                  onClick={() => revert(p.groupId)}
                >
                  <Undo2 size={14} /> Discard
                </button>
              </div>
              <ul className="max-h-48 space-y-1 overflow-y-auto px-3 py-2">
                {p.changes.map((c, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-2 text-sm text-fg-muted"
                  >
                    <span
                      className={`w-3 shrink-0 font-mono ${c.kind === 'added' ? 'text-allow' : c.kind === 'removed' ? 'text-deny' : 'text-candidate'}`}
                      aria-label={c.kind}
                    >
                      {GLYPH[c.kind]}
                    </span>
                    <span className="min-w-0 break-words font-mono text-xs leading-5">
                      {describe(c)}
                    </span>
                  </li>
                ))}
              </ul>
              {!!p.warnings?.length && (
                <ul className="space-y-1 border-t border-candidate/40 bg-candidate/10 px-3 py-2">
                  {p.warnings.map((w) => (
                    <li
                      key={w}
                      className="flex items-start gap-2 text-xs text-candidate"
                    >
                      <AlertTriangle size={13} className="mt-0.5 shrink-0" />
                      <span>{w}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
          {riskyCount > 0 && (
            <label className="flex items-start gap-2 border border-candidate/50 bg-candidate/10 px-3 py-2 text-sm text-fg">
              <input
                type="checkbox"
                className="mt-0.5 accent-candidate"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
              />
              <span>
                I've reviewed the {riskyCount} risky{' '}
                {riskyCount === 1 ? 'change' : 'changes'} flagged above and want
                to commit {riskyCount === 1 ? 'it' : 'them'}.
              </span>
            </label>
          )}
          <div>
            <label className="label" htmlFor="commit-desc">
              Description
            </label>
            <textarea
              id="commit-desc"
              className="input"
              rows={2}
              maxLength={1000}
              placeholder="Change ticket and reason, for example CHG0012345 allow app tier to reach SQL"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          {status.unsaved && (
            <p className="text-xs text-fg-faint">
              Committing also saves the rest of your draft on this device.
            </p>
          )}
        </div>
      )}
    </Modal>
  );
}
