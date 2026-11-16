// Which firewall (and policy) a log row came from, among the firewalls this app manages.
//
// A row only carries the firewall's resource ID, which Azure writes in upper case, and the NAME of
// the policy that holds the matched rule (which can be a parent of the firewall's own policy). The
// links from a row to the rules, the Flow tester and a new rule all start from this lookup.
import type { FirewallLogRow } from './fwLogs';
import type { FirewallSummary } from './types';
import { resourceName, sameResourceId } from './resourceId';

export type OwnerFirewall = Pick<FirewallSummary, 'id' | 'name' | 'policyId'>;

export interface RowOwner {
  /** The managed firewall that wrote the row; absent when it is not one of the managed ones. */
  firewall?: OwnerFirewall;
  /** The firewall's own policy, when it has one. */
  policyId?: string;
  policyName?: string;
}

export function resolveRowOwner(
  row: Pick<FirewallLogRow, 'resourceId'>,
  managed: readonly OwnerFirewall[],
): RowOwner {
  const firewall = managed.find((f) => sameResourceId(f.id, row.resourceId));
  if (!firewall) return {};
  return {
    firewall,
    policyId: firewall.policyId,
    policyName: firewall.policyId ? resourceName(firewall.policyId) : undefined,
  };
}
