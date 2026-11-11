import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Loader2,
  XCircle,
  Clock,
} from 'lucide-react';
import { Modal } from '../components/Modal';
import { Badge } from '../components/ui';
import { errorMessage, useToast } from '../components/Toast';
import type { DeployProgress } from '../../shared/deploy';

const PHASES = ['preparing', 'validating', 'deploying', 'succeeded'] as const;
const LABEL = {
  preparing: 'Prepare',
  validating: 'Validate',
  deploying: 'Deploy',
  succeeded: 'Done',
};

function stateTone(state: string) {
  if (state === 'Succeeded') return 'green';
  if (state === 'Failed' || state === 'Canceled') return 'red';
  return 'blue';
}

export function DeployStatus({
  progress,
  stale,
  onClose,
}: {
  progress: DeployProgress;
  /** The app was closed mid-deployment, so this snapshot's final state is unknown. */
  stale?: boolean;
  onClose: () => void;
}) {
  const toast = useToast();
  const done =
    stale || progress.phase === 'succeeded' || progress.phase === 'failed';
  const current =
    progress.phase === 'failed' ? -1 : PHASES.indexOf(progress.phase);
  const elapsed = Math.round(
    (Date.now() - new Date(progress.startedAt).getTime()) / 60000,
  );

  return (
    <Modal
      title={`${done && progress.phase === 'succeeded' ? 'Deployed' : 'Deploying'} ${progress.firewallName}`}
      subtitle={
        stale
          ? `Started ${new Date(progress.startedAt).toLocaleString()}`
          : done
            ? progress.message
            : `${progress.message} (${elapsed} min elapsed)`
      }
      onClose={onClose}
      widthClass="max-w-2xl"
      footer={
        <>
          {progress.deploymentId && (
            <button
              className="btn-ghost mr-auto"
              onClick={() =>
                window.api
                  .openInPortal(progress.deploymentId!)
                  .catch((err) => toast('error', errorMessage(err)))
              }
            >
              <ExternalLink size={14} /> View deployment in Azure portal
            </button>
          )}
          <button className="btn-primary" onClick={onClose}>
            {done ? 'Close' : 'Hide — keep running'}
          </button>
        </>
      }
    >
      <ol className="-mx-5 -mt-4 mb-4 flex border-b border-line px-5 text-sm">
        {PHASES.map((p, i) => {
          const complete = progress.phase === 'succeeded' || i < current;
          const active = i === current && !done;
          return (
            <li
              key={p}
              aria-current={active ? 'step' : undefined}
              className={`-mb-px flex h-10 items-center gap-2 border-b-2 pr-6 ${
                active
                  ? 'border-azure text-fg'
                  : complete
                    ? 'border-transparent text-fg-muted'
                    : 'border-transparent text-fg-faint'
              }`}
            >
              {complete ? (
                <CheckCircle2 size={14} className="text-allow" />
              ) : active ? (
                <Loader2 size={14} className="animate-spin text-azure" />
              ) : (
                <Clock size={14} />
              )}
              {LABEL[p]}
            </li>
          );
        })}
      </ol>

      {stale && (
        <div className="mb-4 flex gap-2 border border-candidate/40 bg-candidate/10 p-3 text-xs text-candidate">
          <AlertTriangle size={16} className="shrink-0" />
          <p>
            EZ AzFW Manager was closed while this deployment was running, so
            this is its last known state. Azure kept running it — check the
            final result in the Azure portal.
          </p>
        </div>
      )}
      {progress.phase === 'failed' && (
        <div className="mb-4 flex gap-2 border border-deny/40 bg-deny/10 p-3 text-xs text-deny">
          <XCircle size={16} className="shrink-0 text-deny" />
          <p className="whitespace-pre-line break-words">{progress.error}</p>
        </div>
      )}
      {progress.phase === 'succeeded' && (
        <div className="mb-4 flex gap-2 border border-allow/40 bg-allow/15 p-3 text-xs text-allow">
          <CheckCircle2 size={16} className="shrink-0 text-allow" />
          <p>
            The firewall is ready. It can take a minute to appear in discovery;
            use Refresh if it isn't listed yet.
          </p>
        </div>
      )}

      {progress.operations.length > 0 && (
        <table className="w-full table-fixed text-left text-xs">
          <thead className="text-xs text-fg-faint">
            <tr>
              <th className="py-1">Resource</th>
              <th className="w-56 py-1">Type</th>
              <th className="w-24 py-1">State</th>
            </tr>
          </thead>
          <tbody>
            {progress.operations.map((op) => (
              <tr
                key={`${op.resourceType}/${op.resourceName}`}
                className="border-t border-line align-top"
              >
                <td className="py-1.5 pr-2">
                  <span
                    className="block truncate text-fg"
                    title={op.resourceName}
                  >
                    {op.resourceName}
                  </span>
                  {op.error && (
                    <span className="block whitespace-pre-line text-deny">
                      {op.error}
                    </span>
                  )}
                </td>
                <td
                  className="truncate py-1.5 text-fg-muted"
                  title={op.resourceType}
                >
                  {op.resourceType.replace('Microsoft.Network/', '')}
                </td>
                <td className="py-1.5">
                  <Badge tone={stateTone(op.state)}>{op.state}</Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}
