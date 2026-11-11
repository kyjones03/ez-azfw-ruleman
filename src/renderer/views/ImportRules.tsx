import { useMemo, useRef, useState, type ChangeEvent } from 'react';
import { Download, Upload } from 'lucide-react';
import { Modal } from '../components/Modal';
import { SelectMenu } from '../components/Dropdown';
import { Notice, Spinner } from '../components/ui';
import { errorMessage, useToast } from '../components/Toast';
import { useRuleLookups } from '../lookups';
import { nextGroupPriority, summarizeRule } from '../../shared/rules';
import {
  MAX_RULE_IMPORT_BYTES,
  planRuleImport,
  ruleImportTemplate,
  type RuleImportChoices,
  type RuleImportResult,
} from '../../shared/ruleImport';
import type { PolicyView } from '../../shared/types';

const PAGE_SIZE = 25;

export function ImportRules({
  view,
  parents,
  parentError,
  onClose,
  onRefresh,
  onImported,
}: {
  view: PolicyView;
  parents: PolicyView[];
  parentError: string;
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onImported: (result: RuleImportResult) => Promise<void>;
}) {
  const { known, ipGroupMembers, loading, lookups } = useRuleLookups();
  const [csv, setCsv] = useState<string>();
  const [fileName, setFileName] = useState('');
  const [choices, setChoices] = useState<RuleImportChoices>({});
  const [error, setError] = useState('');
  const [reading, setReading] = useState(false);
  const [importing, setImporting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [page, setPage] = useState(0);
  const readSequence = useRef(0);
  const toast = useToast();
  const busy = reading || importing || refreshing;
  const plan = useMemo(
    () =>
      csv === undefined
        ? undefined
        : planRuleImport(
            csv,
            {
              policyId: view.policy.id,
              groups: view.groups.map((g) => g.group),
              inheritedGroups: parents.flatMap((p) =>
                p.groups.map((g) => g.group),
              ),
              known,
              ipGroups: ipGroupMembers,
            },
            choices,
          ),
    [csv, view, parents, known, ipGroupMembers, choices],
  );
  const blockedGroups =
    plan?.groups.filter((g) =>
      view.groups.some(
        (v) => v.drift && v.group.id.toLowerCase() === g.id.toLowerCase(),
      ),
    ) ?? [];
  const close = () => {
    if (!busy) onClose();
  };
  const chooseFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const sequence = ++readSequence.current;
    setCsv(undefined);
    setFileName(file.name);
    setError('');
    setChoices({});
    setPage(0);
    if (file.size > MAX_RULE_IMPORT_BYTES) {
      setError('Select a CSV file no larger than 5 MB.');
      return;
    }
    setReading(true);
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(
        await file.arrayBuffer(),
      );
      if (sequence === readSequence.current) setCsv(text);
    } catch (err) {
      if (sequence === readSequence.current)
        setError(
          `Couldn't read the file. Save it as UTF-8 CSV and try again: ${errorMessage(err)}`,
        );
    } finally {
      if (sequence === readSequence.current) setReading(false);
    }
  };
  const downloadTemplate = async () => {
    const groups = view.groups.map((g) => g.group);
    let name = 'rcg-csv-import';
    let suffix = 2;
    while (groups.some((g) => g.name.toLowerCase() === name.toLowerCase()))
      name = `rcg-csv-import-${suffix++}`;
    try {
      const saved = await window.api.saveCsv(
        'firewall-rules-import-template.csv',
        ruleImportTemplate(name, nextGroupPriority(groups)),
      );
      if (saved) toast('success', `Template saved to ${saved}`);
    } catch (err) {
      toast('error', errorMessage(err));
    }
  };
  const submit = async () => {
    if (
      !plan ||
      !csv ||
      plan.errors.length ||
      !plan.ruleCount ||
      busy ||
      loading ||
      parentError ||
      blockedGroups.length
    )
      return;
    setImporting(true);
    setError('');
    try {
      const result = await window.api.importRulesCsv(
        view.policy.id,
        csv,
        Object.fromEntries(
          plan.rows.map((row) => [
            String(row.line),
            { action: row.choice, token: row.token },
          ]),
        ),
      );
      await onImported(result);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setImporting(false);
    }
  };
  const refresh = async () => {
    setRefreshing(true);
    setError('');
    setChoices({});
    try {
      await onRefresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setRefreshing(false);
    }
  };
  const conflictRows = plan?.rows.filter((r) => r.conflicts.length).length ?? 0;
  const pages = Math.max(1, Math.ceil((plan?.rows.length ?? 0) / PAGE_SIZE));
  const shownPage = Math.min(page, pages - 1);
  return (
    <Modal
      title="Import rules from CSV"
      subtitle={`Into ${view.policy.name}. Changes stay in your local draft until you commit.`}
      widthClass="max-w-6xl"
      onClose={close}
      footer={
        <>
          {plan && (
            <span className="mr-auto text-sm text-fg-muted">
              {plan.ruleCount} selected · {plan.skippedCount} skipped
            </span>
          )}
          <button className="btn-ghost" disabled={busy} onClick={close}>
            Cancel
          </button>
          <button
            className="btn-primary"
            onClick={submit}
            disabled={
              busy ||
              loading ||
              !plan?.ruleCount ||
              !!plan?.errors.length ||
              !!parentError ||
              !!blockedGroups.length
            }
          >
            {importing ? (
              <Spinner label="Importing…" />
            ) : (
              'Import selected rules to draft'
            )}
          </button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="flex items-start gap-4">
          <div className="flex-1 text-sm text-fg-muted">
            <p>
              One row per rule. Repeat group and collection settings on each
              row. New groups and collections are created in the draft; existing
              settings must match.
            </p>
            <p className="mt-1">
              Use semicolons between list entries and full resource IDs for IP
              Groups. The template includes Network, Application, DNAT and IP
              Group examples: replace or remove them before importing.
            </p>
          </div>
          <button
            className="btn-outline shrink-0"
            disabled={busy}
            onClick={downloadTemplate}
          >
            <Download size={15} /> Download template
          </button>
        </div>
        <label className="block">
          <span className="label">
            <Upload size={14} className="mr-1 inline" /> CSV file (UTF-8, up to
            5 MB)
          </span>
          <input
            type="file"
            accept=".csv,text/csv"
            className="input h-auto"
            disabled={busy}
            onChange={(e) => void chooseFile(e)}
          />
        </label>
        {reading && <Spinner label="Reading CSV…" />}
        {loading && <Spinner label="Loading rule validation data…" />}
        {lookups?.errors.length ? (
          <Notice tone="info" title="Some Azure lookup data is unavailable">
            {lookups.errors.join('\n')} Syntactic validation still applies;
            unresolved overlaps are marked as potential.
          </Notice>
        ) : null}
        {parentError && (
          <Notice
            tone="error"
            title="Parent policies must be loaded before importing"
          >
            {parentError}
          </Notice>
        )}
        {!!blockedGroups.length && (
          <Notice tone="error" title="Resolve existing draft conflicts first">
            {blockedGroups.map((g) => g.name).join(', ')}
          </Notice>
        )}
        {error && (
          <Notice
            tone="error"
            title="Couldn't import rules"
            action={
              <button className="btn-outline" disabled={busy} onClick={refresh}>
                Refresh rules and preview
              </button>
            }
          >
            {error}
          </Notice>
        )}
        {plan && (
          <>
            <p className="text-sm text-fg-muted">
              {fileName}: {plan.rows.length} validated{' '}
              {plan.rows.length === 1 ? 'row' : 'rows'}. Selected rules affect{' '}
              {plan.groups.length}{' '}
              {plan.groups.length === 1 ? 'group' : 'groups'}, including{' '}
              {plan.newGroupCount} new{' '}
              {plan.newGroupCount === 1 ? 'group' : 'groups'} and{' '}
              {plan.newCollectionCount} new{' '}
              {plan.newCollectionCount === 1 ? 'collection' : 'collections'}.
            </p>
            {!!plan.errors.length && (
              <Notice
                tone="error"
                title={`${plan.errors.length} ${plan.errors.length === 1 ? 'problem' : 'problems'} to fix before importing`}
              >
                <ul className="list-inside list-disc">
                  {plan.errors.slice(0, 100).map((e, i) => (
                    <li key={i}>
                      Line {e.line}: {e.message}
                    </li>
                  ))}
                </ul>
                {plan.errors.length > 100 && (
                  <p>
                    Showing the first 100 problems. The entire file must
                    validate before any rules are staged.
                  </p>
                )}
              </Notice>
            )}
            {conflictRows > 0 && (
              <Notice
                tone="info"
                title={`${conflictRows} ${conflictRows === 1 ? 'rule needs' : 'rules need'} review`}
              >
                Duplicate, same-name and overlapping rules are skipped by
                default. Choose Import anyway or Replace for individual rows to
                continue with them. Unchanged same-name rules need no import.
              </Notice>
            )}
            <p className="text-xs text-fg-faint">
              Overlap checks compare incoming traffic with this policy, its
              parents and earlier selected CSV rows. They do not prove shadowing
              or determine the winning rule. DNS, service tags, URL paths and
              DNAT translations can require further review; Azure processing
              order still applies.
            </p>
            {!!plan.rows.length && (
              <div className="overflow-x-auto border border-line">
                <table className="w-full table-fixed text-left text-sm">
                  <thead className="bg-ink-900 text-xs text-fg-muted">
                    <tr>
                      <th className="w-14 px-3 py-2">Line</th>
                      <th className="w-56 px-3 py-2">Rule / target</th>
                      <th className="px-3 py-2">Review</th>
                      <th className="w-48 px-3 py-2">Import action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {plan.rows
                      .slice(shownPage * PAGE_SIZE, (shownPage + 1) * PAGE_SIZE)
                      .map((row) => (
                        <tr
                          key={row.line}
                          className="border-t border-line align-top"
                        >
                          <td className="px-3 py-2 tabular-nums">{row.line}</td>
                          <td className="px-3 py-2">
                            <p className="break-words font-medium">
                              {row.rule.name}
                            </p>
                            <p className="break-words text-xs text-fg-muted">
                              {row.group} / {row.collection}
                            </p>
                            <p className="text-xs text-fg-faint">
                              {row.kind} · {row.action}
                            </p>
                            <p className="mt-1 break-words font-mono text-[11px] text-fg-muted">
                              {summarizeRule(row.rule)}
                            </p>
                          </td>
                          <td className="px-3 py-2 text-xs">
                            {row.unchanged && (
                              <p className="text-fg-muted">
                                This rule already exists unchanged. No update is
                                needed.
                              </p>
                            )}
                            {row.conflicts.slice(0, 10).map((c, i) => (
                              <p
                                key={i}
                                className="mb-1 break-words text-fg-muted"
                              >
                                <span className="font-semibold">
                                  {c.kind === 'same-name'
                                    ? 'Existing name'
                                    : c.kind === 'duplicate'
                                      ? 'Identical contents'
                                      : c.kind === 'overlap'
                                        ? 'Traffic overlap'
                                        : 'Potential overlap'}
                                  :
                                </span>{' '}
                                {c.target} ({c.action}
                                {c.inherited ? ', inherited' : ''})
                                <span className="block break-words font-mono text-fg-faint">
                                  {c.summary}
                                </span>
                              </p>
                            ))}
                            {row.conflicts.length > 10 && (
                              <details>
                                <summary className="cursor-pointer text-azure">
                                  Show {row.conflicts.length - 10} more matching
                                  rules
                                </summary>
                                {row.conflicts.slice(10).map((c, i) => (
                                  <p
                                    key={i}
                                    className="mb-1 break-words text-fg-muted"
                                  >
                                    {c.kind}: {c.target} ({c.action}
                                    {c.inherited ? ', inherited' : ''})
                                    <span className="block break-words font-mono text-fg-faint">
                                      {c.summary}
                                    </span>
                                  </p>
                                ))}
                              </details>
                            )}
                            {row.warnings.map((w) => (
                              <p key={w} className="mb-1 text-fg-muted">
                                {w}
                              </p>
                            ))}
                            {!row.conflicts.length && !row.warnings.length && (
                              <span className="text-fg-faint">
                                Ready to import
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-2">
                            <SelectMenu
                              label={`Action for CSV line ${row.line}`}
                              widthClass="w-full"
                              value={row.choice}
                              disabled={busy || row.unchanged}
                              onChange={(action) =>
                                setChoices((old) => ({
                                  ...old,
                                  [String(row.line)]: {
                                    action,
                                    token: row.token,
                                  },
                                }))
                              }
                              options={[
                                { value: 'skip', label: 'Skip' },
                                ...(!row.unchanged
                                  ? [
                                      {
                                        value: row.sameName
                                          ? ('replace' as const)
                                          : ('import' as const),
                                        label: row.sameName
                                          ? 'Replace existing rule'
                                          : row.conflicts.length
                                            ? 'Import anyway'
                                            : 'Import',
                                      },
                                    ]
                                  : []),
                              ]}
                            />
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
                {pages > 1 && (
                  <div className="flex items-center justify-end gap-3 border-t border-line px-3 py-2 text-sm">
                    <span>
                      Page {shownPage + 1} of {pages}
                    </span>
                    <button
                      className="btn-ghost"
                      disabled={busy || shownPage === 0}
                      onClick={() => setPage(shownPage - 1)}
                    >
                      Previous
                    </button>
                    <button
                      className="btn-ghost"
                      disabled={busy || shownPage === pages - 1}
                      onClick={() => setPage(shownPage + 1)}
                    >
                      Next
                    </button>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}
