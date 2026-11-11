import { createContext, useContext, useMemo } from 'react';
import { knownValuesFromLookups, type KnownValues } from '../shared/ruleDraft';
import type { IpGroupMembers } from '../shared/flow';
import type { IpGroupInfo, RuleLookups } from '../shared/types';

export interface LookupsState {
  lookups?: RuleLookups;
  loading: boolean;
}

export const RuleLookupsContext = createContext<LookupsState>({
  loading: false,
});

export interface Lookups extends LookupsState {
  /** Sets for validating picked values; a set is omitted when that list couldn't be loaded. */
  known: KnownValues;
  ipGroupById: Map<string, IpGroupInfo>;
  ipGroupMembers: IpGroupMembers;
}

export function useRuleLookups(): Lookups {
  const state = useContext(RuleLookupsContext);
  return useMemo(() => {
    const l = state.lookups;
    const ipGroupById = new Map(
      (l?.ipGroups ?? []).map((g) => [g.id.toLowerCase(), g]),
    );
    // Only check against a list that actually loaded (an empty list may just mean no access).
    const known = knownValuesFromLookups(l);
    return {
      ...state,
      known,
      ipGroupById,
      ipGroupMembers: new Map(
        [...ipGroupById].map(([id, g]) => [id, g.addresses]),
      ),
    };
  }, [state]);
}
