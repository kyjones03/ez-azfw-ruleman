import type { ChangeItem } from '../../shared/types';

const VERB = {
  firewall: {
    added: 'Added firewall settings',
    modified: 'Changed firewall settings',
    removed: 'Removed firewall settings',
  },
  policy: {
    added: 'Added policy settings',
    modified: 'Changed policy settings',
    removed: 'Removed policy settings',
  },
  group: {
    added: 'Created group',
    modified: 'Changed group',
    removed: 'Deleted group',
  },
  collection: {
    added: 'Added collection',
    modified: 'Changed collection',
    removed: 'Deleted collection',
  },
  rule: {
    added: 'Added rule',
    modified: 'Updated rule',
    removed: 'Deleted rule',
  },
} as const;

const TONE = {
  added: 'text-allow',
  modified: 'text-candidate',
  removed: 'text-deny',
} as const;

const GLYPH = { added: '+', modified: '~', removed: '−' } as const;

/** Counts of added / changed / removed items, e.g. for a summary column. */
function countChanges(changes: ChangeItem[] = []) {
  return {
    added: changes.filter((c) => c.kind === 'added').length,
    changed: changes.filter((c) => c.kind === 'modified').length,
    removed: changes.filter((c) => c.kind === 'removed').length,
  };
}

export function ChangeSummary({ changes }: { changes?: ChangeItem[] }) {
  const { added, changed, removed } = countChanges(changes);
  const parts = [
    added && <span className="text-allow">{added} added</span>,
    changed && <span className="text-candidate">{changed} changed</span>,
    removed && <span className="text-deny">{removed} removed</span>,
  ].filter(Boolean);
  if (!parts.length) return <span className="text-fg-faint">—</span>;
  return (
    <span className="flex flex-wrap gap-x-2 text-xs">
      {parts.map((p, i) => (
        <span key={i}>{p}</span>
      ))}
    </span>
  );
}

/** What was done, line by line: "Added rule net-allow-core / dns: 10.0.0.0/8 → UDP 53 → …". */
export function ChangeList({ changes }: { changes: ChangeItem[] }) {
  return (
    <ul className="space-y-0.5">
      {changes.map((c, i) => {
        const what =
          c.target === 'group' ||
          c.target === 'policy' ||
          c.target === 'firewall'
            ? ''
            : c.target === 'collection'
              ? c.collection
              : `${c.collection} / ${c.rule}`;
        return (
          <li key={i} className="flex items-start gap-2 text-xs leading-5">
            <span
              className={`w-3 shrink-0 text-center font-mono font-bold ${TONE[c.kind]}`}
              aria-hidden
            >
              {GLYPH[c.kind]}
            </span>
            <span className="min-w-0">
              <span className={`font-medium ${TONE[c.kind]}`}>
                {VERB[c.target][c.kind]}
              </span>
              {what && <span className="font-medium text-fg"> {what}</span>}
              {c.detail && (
                <span className="break-words font-mono text-fg-muted">
                  {what ? ': ' : ' '}
                  {c.detail}
                </span>
              )}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
