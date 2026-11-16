import { useMemo, useState } from 'react';
import { Modal } from '../components/Modal';
import { Notice } from '../components/ui';
import { SelectMenu } from '../components/Dropdown';
import type { PolicyLayer } from '../../shared/flow';
import { ruleEffect, type RuleSuggestion } from '../../shared/logRuleSuggest';
import { collectionKindOf } from '../../shared/ruleDraft';
import { nextGroupPriority } from '../../shared/rules';
import type { PolicyView } from '../../shared/types';

const NEW = '__new__';

/** The firewall's chain as the flow evaluation wants it: parents first, then its own policy. */
const layersOf = (view: PolicyView, parents: PolicyView[]): PolicyLayer[] => [
  ...[...parents].reverse().map((p) => ({
    policyId: p.policy.id,
    policyName: p.policy.name,
    inherited: true,
    groups: p.groups.map((g) => g.group),
  })),
  {
    policyId: view.policy.id,
    policyName: view.policy.name,
    inherited: false,
    groups: view.groups.map((g) => g.group),
  },
];

/**
 * Where a rule suggested from a denied flow goes: one of the policy's own rule collection groups,
 * then an existing Allow collection of the right kind, or a new one. Nothing is added to the draft
 * here; the collection editor opens next with the rule filled in, and the normal draft, review and
 * commit steps apply.
 */
export function LogRuleDialog({
  suggestion,
  view,
  parents,
  onChoose,
  onClose,
}: {
  suggestion: RuleSuggestion;
  view: PolicyView;
  parents: PolicyView[];
  onChoose: (target: { groupId: string; collection?: string }) => void;
  onClose: () => void;
}) {
  const groups = view.groups;
  const [groupId, setGroupId] = useState(groups[0]?.group.id ?? '');
  const group = groups.find((g) => g.group.id === groupId)?.group;
  const allowCollections = useMemo(
    () =>
      (group?.ruleCollections ?? []).filter(
        (c) =>
          c.action.type === 'Allow' &&
          collectionKindOf(c) === suggestion.kind &&
          c.rules.length > 0,
      ),
    [group, suggestion.kind],
  );
  const [picked, setPicked] = useState<string>();
  // Default to the first existing Allow collection; fall back to a new one.
  const collection =
    picked &&
    (picked === NEW || allowCollections.some((c) => c.name === picked))
      ? picked
      : (allowCollections[0]?.name ?? NEW);

  const effect = useMemo(
    () =>
      group
        ? ruleEffect(suggestion, layersOf(view, parents), view.policy.id, {
            groupId: group.id,
            collection: collection === NEW ? undefined : collection,
            newPriority: nextGroupPriority(group.ruleCollections),
          })
        : undefined,
    [suggestion, view, parents, group, collection],
  );

  const kindLabel = suggestion.kind === 'Network' ? 'network' : 'application';
  const denied = suggestion.deniedBy;

  return (
    <Modal
      title="Add an Allow rule for this flow?"
      subtitle={<span className="netval">{suggestion.summary}</span>}
      onClose={onClose}
      widthClass="max-w-xl"
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={!group}
            onClick={() =>
              onChoose({
                groupId,
                collection: collection === NEW ? undefined : collection,
              })
            }
          >
            Continue to the rule editor
          </button>
        </>
      }
    >
      <div className="space-y-4 text-sm text-fg-muted">
        <p>
          This opens the rule editor with the narrowest {kindLabel} rule the log
          allows: this exact source, destination and port. Nothing reaches Azure
          until you review and commit the draft.
        </p>
        {denied && (
          <Notice tone="error" title="An explicit rule denied this flow">
            {`Rule "${denied.rule}" in "${denied.collection}" (${denied.group}${denied.policy ? `, policy ${denied.policy}` : ''}) denied it. A new Allow rule only wins if it is processed before that rule.`}
          </Notice>
        )}
        {groups.length === 0 ? (
          <p className="text-fg">
            This policy has no rule collection groups of its own. Create one
            first (Rules, then New group), then try again.
          </p>
        ) : (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">Rule collection group</label>
              <SelectMenu
                value={groupId}
                widthClass="w-full"
                options={groups.map((g) => ({
                  value: g.group.id,
                  label: g.group.name,
                  hint: `priority ${g.group.priority}`,
                }))}
                onChange={(id) => {
                  setGroupId(id);
                  setPicked(undefined);
                }}
              />
            </div>
            <div>
              <label className="label">Rule collection (Allow)</label>
              <SelectMenu
                value={collection}
                widthClass="w-full"
                options={[
                  ...allowCollections.map((c) => ({
                    value: c.name,
                    label: c.name,
                    hint: `priority ${c.priority}`,
                  })),
                  { value: NEW, label: 'Create a new Allow collection' },
                ]}
                onChange={setPicked}
              />
            </div>
          </div>
        )}
        {effect && (
          <Notice
            tone={effect.allowed ? 'info' : 'error'}
            title={
              effect.allowed
                ? 'Would allow this flow'
                : 'This rule would not allow the flow'
            }
          >
            {effect.message}
          </Notice>
        )}
      </div>
    </Modal>
  );
}
