import { useMemo, useState, type ReactNode } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import { ConfirmModal, Modal, useGuardedClose } from '../components/Modal';
import { CollectionForm } from './CollectionForm';
import { useRuleLookups } from '../lookups';
import {
  PRIORITY_MAX,
  PRIORITY_MIN,
  newGroupErrors,
  stableStringify,
} from '../../shared/rules';
import {
  collectionFromDraft,
  draftFromCollection,
  duplicateRow,
  emptyCollection,
  emptyRow,
  isBlankRow,
  validateDraft,
  type CollectionDraft,
} from '../../shared/ruleDraft';
import type { RuleCollection } from '../../shared/types';

const snapshot = (d: CollectionDraft) =>
  stableStringify(collectionFromDraft(d));

function ErrorSummary({ count }: { count: number }) {
  if (!count) return null;
  return (
    <span className="mr-auto text-xs text-deny" role="alert">
      {count} {count === 1 ? 'problem' : 'problems'} to fix; see the highlighted
      rows.
    </span>
  );
}

/**
 * Creates or edits one rule collection: its settings plus all of its rules in one place.
 * `focusRule` opens with that rule highlighted; `addRule` opens with a fresh row ready;
 * `duplicateRule` inserts a copy of that rule.
 */
export function CollectionEditor({
  collection,
  groupName,
  others,
  suggestedPriority,
  focusRule,
  addRule,
  duplicateRule,
  onSave,
  onClose,
}: {
  collection?: RuleCollection;
  groupName: string;
  /** The other collections in the group (for name and priority clashes). */
  others: { name: string; priority: number }[];
  suggestedPriority: number;
  focusRule?: string;
  addRule?: boolean;
  duplicateRule?: string;
  onSave: (c: RuleCollection) => Promise<boolean>;
  onClose: () => void;
}) {
  const [{ initial, focusKey }] = useState(() => {
    const d = collection
      ? draftFromCollection(collection)
      : emptyCollection(suggestedPriority);
    let focus: string | undefined;
    if (collection) {
      if (duplicateRule) {
        const i = d.rows.findIndex((r) => r.name === duplicateRule);
        if (i >= 0) {
          const copy = duplicateRow(
            d.rows[i],
            d.rows.map((r) => r.name),
          );
          d.rows.splice(i + 1, 0, copy);
          focus = copy.key;
        }
      }
      // A trailing empty row is always ready for the next rule.
      const blank = emptyRow(d.kind);
      d.rows.push(blank);
      focus ??= focusRule
        ? d.rows.find((r) => r.name === focusRule)?.key
        : addRule
          ? blank.key
          : undefined;
    }
    return { initial: d, focusKey: focus };
  });
  const [draft, setDraft] = useState(initial);
  const [showErrors, setShowErrors] = useState(false);
  const [saving, setSaving] = useState(false);
  const [confirmFlip, setConfirmFlip] = useState(false);
  const { known } = useRuleLookups();
  const errors = useMemo(
    () => validateDraft(draft, others, known),
    [draft, others, known],
  );
  // Compare against the collection as it was opened (a duplicated rule counts as a change).
  const baseline = useMemo(
    () => (collection ? stableStringify(collection) : snapshot(initial)),
    [collection, initial],
  );
  const dirty = snapshot(draft) !== baseline;
  const guard = useGuardedClose(dirty, onClose);

  const ruleCount = draft.rows.filter((r) => !isBlankRow(r)).length;
  // Flipping Allow ↔ Deny on a populated collection changes what all of its rules do.
  const flips =
    !!collection &&
    collection.action.type !== 'DNAT' &&
    draft.kind !== 'DNAT' &&
    collection.action.type !== draft.action &&
    ruleCount > 0;

  const save = async (confirmed = false) => {
    setShowErrors(true);
    if (errors.count || saving) return;
    if (flips && !confirmed) {
      setConfirmFlip(true);
      return;
    }
    setConfirmFlip(false);
    setSaving(true);
    const ok = await onSave(collectionFromDraft(draft));
    if (!ok) setSaving(false);
  };

  return (
    <>
      <Modal
        title={collection ? `Edit ${collection.name}` : 'New rule collection'}
        subtitle={`In ${groupName}. ${ruleCount} ${ruleCount === 1 ? 'rule' : 'rules'}. Changes go to your draft; Azure changes only when you commit.`}
        onClose={guard.request}
        widthClass="max-w-6xl"
        footer={
          <>
            {showErrors && <ErrorSummary count={errors.count} />}
            <button className="btn-ghost" onClick={guard.request}>
              Cancel
            </button>
            <button
              className="btn-primary"
              disabled={saving || (!dirty && !!collection)}
              onClick={() => save()}
            >
              {collection ? 'Save to draft' : 'Add collection'}
            </button>
          </>
        }
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            save();
          }}
        >
          <CollectionForm
            value={draft}
            onChange={setDraft}
            errors={showErrors ? errors : undefined}
            warnings={errors.warnings}
            focusRowKey={focusKey}
            autoFocusName={!collection}
          />
          <button type="submit" hidden />
        </form>
      </Modal>
      {confirmFlip && collection && (
        <ConfirmModal
          title={`Change ${collection.name} to ${draft.action}?`}
          message={`All ${ruleCount} ${ruleCount === 1 ? 'rule' : 'rules'} in this collection will ${draft.action === 'Deny' ? 'block' : 'allow'} the traffic they match instead of ${draft.action === 'Deny' ? 'allowing' : 'blocking'} it. This goes to your draft and is flagged again at commit.`}
          confirmLabel={`Change to ${draft.action}`}
          onCancel={() => setConfirmFlip(false)}
          onConfirm={() => save(true)}
        />
      )}
      {guard.dialog}
    </>
  );
}

export function GroupPriorityEditor({
  name,
  priority,
  onSave,
  onClose,
}: {
  name: string;
  priority: number;
  onSave: (p: number) => void;
  onClose: () => void;
}) {
  const [value, setValue] = useState(String(priority));
  const n = Number(value);
  const valid = Number.isInteger(n) && n >= PRIORITY_MIN && n <= PRIORITY_MAX;
  return (
    <Modal
      title={`Change priority of ${name}`}
      onClose={onClose}
      widthClass="max-w-sm"
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={!valid}
            onClick={() => onSave(n)}
          >
            Update
          </button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) onSave(n);
        }}
      >
        <label className="label" htmlFor="grp-priority">
          Priority
        </label>
        <input
          id="grp-priority"
          className="input"
          type="number"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          autoFocus
        />
        {!valid && (
          <p className="mt-1 text-xs text-deny">
            Priority must be {PRIORITY_MIN}–{PRIORITY_MAX}.
          </p>
        )}
      </form>
    </Modal>
  );
}

/** An untouched collection card (no name, no rules) is skipped rather than flagged. */
const isUntouched = (d: CollectionDraft) =>
  !d.name.trim() && d.rows.every(isBlankRow);

function Card({
  title,
  onRemove,
  children,
}: {
  title: string;
  onRemove: () => void;
  children: ReactNode;
}) {
  return (
    <section className="border border-line">
      <header className="flex items-center justify-between border-b border-line bg-ink-900 px-3 py-1.5">
        <h3 className="text-sm font-semibold text-fg">{title}</h3>
        <button
          type="button"
          className="btn-ghost h-7 px-2 text-xs hover:text-deny"
          onClick={onRemove}
        >
          <Trash2 size={13} /> Remove
        </button>
      </header>
      <div className="p-3">{children}</div>
    </section>
  );
}

/**
 * Drafts a new rule collection group, optionally with its rule collections and rules, in one go.
 * Everything is created in Azure on commit.
 */
export function NewGroupEditor({
  policyName,
  existing,
  suggestedPriority,
  onSave,
  onClose,
}: {
  policyName: string;
  existing: { name: string; priority: number }[];
  suggestedPriority: number;
  onSave: (
    name: string,
    priority: number,
    collections: RuleCollection[],
  ) => Promise<boolean>;
  onClose: () => void;
}) {
  const [name, setName] = useState('');
  const [priority, setPriority] = useState(String(suggestedPriority));
  const [collections, setCollections] = useState<CollectionDraft[]>(() => [
    emptyCollection(100),
  ]);
  const [showErrors, setShowErrors] = useState(false);
  const [saving, setSaving] = useState(false);

  const trimmed = name.trim();
  const groupProblems = newGroupErrors(trimmed, Number(priority), existing);
  const nameProblem =
    trimmed || name || showErrors ? groupProblems.name : undefined;
  const used = collections.filter((d) => !isUntouched(d));
  const { known } = useRuleLookups();
  const collectionErrors = new Map(
    used.map((d) => [
      d.key,
      validateDraft(
        d,
        used
          .filter((o) => o !== d)
          .map((o) => ({ name: o.name.trim(), priority: o.priority })),
        known,
      ),
    ]),
  );
  const problemCount =
    (groupProblems.name ? 1 : 0) +
    (groupProblems.priority ? 1 : 0) +
    [...collectionErrors.values()].reduce((n, e) => n + e.count, 0);
  const dirty =
    !!trimmed || used.length > 0 || priority !== String(suggestedPriority);
  const guard = useGuardedClose(dirty, onClose);

  const update = (d: CollectionDraft) =>
    setCollections((all) => all.map((x) => (x.key === d.key ? d : x)));

  const addCollection = () =>
    setCollections((all) => [
      ...all,
      emptyCollection(
        Math.min(
          PRIORITY_MAX,
          Math.max(0, ...all.map((d) => Number(d.priority) || 0)) + 100,
        ),
      ),
    ]);

  const save = async () => {
    setShowErrors(true);
    if (problemCount || saving) return;
    setSaving(true);
    const ok = await onSave(
      trimmed,
      Number(priority),
      used.map(collectionFromDraft),
    );
    if (!ok) setSaving(false);
  };

  return (
    <>
      <Modal
        title="New rule collection group"
        subtitle={`In ${policyName}. Everything here is created in Azure when you commit.`}
        onClose={guard.request}
        widthClass="max-w-6xl"
        footer={
          <>
            {showErrors && <ErrorSummary count={problemCount} />}
            <button className="btn-ghost" onClick={guard.request}>
              Cancel
            </button>
            <button className="btn-primary" disabled={saving} onClick={save}>
              Create group
            </button>
          </>
        }
      >
        <form
          className="space-y-5"
          onSubmit={(e) => {
            e.preventDefault();
            save();
          }}
        >
          <div className="grid grid-cols-[minmax(0,1fr)_10rem] gap-4">
            <div>
              <label className="label" htmlFor="grp-name">
                Group name
              </label>
              <input
                id="grp-name"
                className="input"
                value={name}
                placeholder="rcg-app-contoso"
                onChange={(e) => setName(e.target.value)}
                aria-invalid={!!nameProblem}
                autoFocus
              />
              {nameProblem ? (
                <p className="mt-1 text-xs text-deny" role="alert">
                  {nameProblem}
                </p>
              ) : (
                <p className="mt-1 text-xs text-fg-faint">
                  1-80 characters: letters, digits, _ . - (no spaces). Can't be
                  renamed later.
                </p>
              )}
            </div>
            <div>
              <label className="label" htmlFor="new-grp-priority">
                Group priority
              </label>
              <input
                id="new-grp-priority"
                className="input"
                type="number"
                min={PRIORITY_MIN}
                max={PRIORITY_MAX}
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                aria-invalid={!!groupProblems.priority}
              />
              {groupProblems.priority ? (
                <p className="mt-1 text-xs text-deny" role="alert">
                  {groupProblems.priority}
                </p>
              ) : (
                <p className="mt-1 text-xs text-fg-faint">
                  Lower numbers are processed first.
                </p>
              )}
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-baseline justify-between">
              <h3 className="text-sm font-semibold text-fg">
                Rule collections
              </h3>
              <span className="text-xs text-fg-faint">
                Optional. Leave a collection blank or remove it to create an
                empty group.
              </span>
            </div>
            {collections.map((d, i) => (
              <Card
                key={d.key}
                title={d.name.trim() || `Collection ${i + 1}`}
                onRemove={() =>
                  setCollections((all) => all.filter((x) => x.key !== d.key))
                }
              >
                <CollectionForm
                  value={d}
                  onChange={update}
                  errors={showErrors ? collectionErrors.get(d.key) : undefined}
                  warnings={collectionErrors.get(d.key)?.warnings}
                />
              </Card>
            ))}
            <button
              type="button"
              className="btn-outline"
              onClick={addCollection}
            >
              <Plus size={15} />{' '}
              {collections.length
                ? 'Add another collection'
                : 'Add a collection'}
            </button>
          </div>
          <button type="submit" hidden />
        </form>
      </Modal>
      {guard.dialog}
    </>
  );
}
