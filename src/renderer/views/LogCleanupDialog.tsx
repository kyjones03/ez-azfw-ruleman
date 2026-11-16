import { useEffect, useState } from 'react';
import { Trash2 } from 'lucide-react';
import { Modal } from '../components/Modal';
import { Spinner } from '../components/ui';
import { errorMessage, useToast } from '../components/Toast';
import type { CleanupReview, DanglingSetting } from '../../shared/logCleanup';

/**
 * Review and apply the cleanup of one diagnostic setting whose Event Hubs namespace was deleted.
 * The review is read from Azure when the dialog opens; nothing changes until the button is pressed.
 */
export function LogCleanupDialog({
  target,
  onClose,
}: {
  target: DanglingSetting;
  /** `changed` is true when Azure was modified, so the caller reads its lists again. */
  onClose: (changed: boolean) => void;
}) {
  const toast = useToast();
  const [review, setReview] = useState<CleanupReview>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    window.api
      .reviewLogCleanup(target.firewallId, target.settingName)
      .then((r) => !cancelled && setReview(r))
      .catch((err) => !cancelled && setError(errorMessage(err)));
    return () => {
      cancelled = true;
    };
  }, [target.firewallId, target.settingName]);

  const apply = async () => {
    if (!review) return;
    setBusy(true);
    setError('');
    try {
      const { action } = await window.api.applyLogCleanup(
        target.firewallId,
        target.settingName,
        review.hash,
      );
      toast(
        'success',
        action === 'delete'
          ? `Deleted diagnostic setting ${target.settingName}.`
          : `Removed the Event Hub destination from ${target.settingName}.`,
      );
      onClose(true);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Clean up a diagnostic setting?"
      onClose={() => !busy && onClose(false)}
      widthClass="max-w-xl"
      footer={
        <>
          <button
            className="btn-ghost"
            disabled={busy}
            onClick={() => onClose(false)}
          >
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={!review || busy}
            onClick={() => void apply()}
          >
            {busy ? <Spinner size={14} /> : <Trash2 size={14} />}
            {review?.action === 'delete'
              ? 'Delete the setting'
              : 'Remove the event hub'}
          </button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-fg-muted">
        <p>
          <strong className="text-fg">This changes Azure directly</strong>, not
          your draft.
        </p>
        {!review && !error && (
          <Spinner label="Checking the setting in Azure…" size={14} />
        )}
        {review && (
          <>
            <ul className="list-disc space-y-1 pl-5 text-fg">
              {review.lines.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
            <p className="text-xs">
              You need: {review.permission}.
              {review.action === 'delete' &&
                ' Deleting it also frees one of the five diagnostic settings a firewall can have.'}
            </p>
          </>
        )}
        {error && (
          <p role="alert" className="text-deny">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}
