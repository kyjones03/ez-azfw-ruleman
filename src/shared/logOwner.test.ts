import { describe, expect, it } from 'vitest';
import { resolveRowOwner, type OwnerFirewall } from './logOwner';

const FW =
  '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw-hub-eus2';
const POLICY =
  '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/fp-hub';
const firewalls: OwnerFirewall[] = [
  { id: FW, name: 'fw-hub-eus2', policyId: POLICY },
  { id: FW.replace('eus2', 'cus'), name: 'fw-hub-cus' },
];

describe('resolveRowOwner', () => {
  it('finds the managed firewall and its policy, whatever the case of the resource ID', () => {
    const owner = resolveRowOwner({ resourceId: FW.toUpperCase() }, firewalls);
    expect(owner.firewall?.name).toBe('fw-hub-eus2');
    expect(owner.policyId).toBe(POLICY);
    expect(owner.policyName).toBe('fp-hub');
  });

  it('finds a firewall that has no policy', () => {
    const owner = resolveRowOwner(
      { resourceId: FW.replace('eus2', 'cus') },
      firewalls,
    );
    expect(owner.firewall?.name).toBe('fw-hub-cus');
    expect(owner.policyId).toBeUndefined();
    expect(owner.policyName).toBeUndefined();
  });

  it('returns nothing for a firewall that is not managed here', () => {
    expect(
      resolveRowOwner({ resourceId: FW.replace('eus2', 'other') }, firewalls),
    ).toEqual({});
  });

  it('returns nothing for an empty resource ID or no managed firewalls', () => {
    expect(resolveRowOwner({ resourceId: '' }, firewalls)).toEqual({});
    expect(resolveRowOwner({ resourceId: FW }, [])).toEqual({});
  });
});
