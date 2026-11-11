import { describe, expect, it } from 'vitest';
import {
  ipGroupAddressesError,
  ipGroupErrors,
  type CreateIpGroupRequest,
} from './ipGroups';
import { parseList } from './rules';

const request: CreateIpGroupRequest = {
  subscriptionId: '00000000-1111-2222-3333-444444444444',
  resourceGroup: 'rg-network',
  name: 'ipg-office_01',
  location: 'eastus',
  addresses: ['10.0.0.1', '10.1.0.0/24', '10.2.0.1-10.2.0.20'],
};

describe('IP group validation', () => {
  it('accepts the same IPv4 addresses, CIDRs and ranges as firewall rules', () => {
    expect(ipGroupErrors(request)).toEqual({});
    expect(
      ipGroupAddressesError(['0.0.0.0/0', '255.255.255.255/32']),
    ).toBeUndefined();
  });

  it.each([
    ['10.256.0.1', 'above 255'],
    ['010.0.0.1', 'leading zeros'],
    ['10.0.0.5/24', 'host bits'],
    ['10.0.0.0/33', 'prefix length'],
    ['10.0.0.20-10.0.0.1', 'backwards'],
    ['2001:db8::1', "isn't an IPv4 address"],
    ['example.com', "isn't an IPv4 address"],
    ['*', 'Wildcards'],
    ['', "isn't an IPv4 address"],
  ])(
    'rejects invalid entry %s with its position and reason',
    (value, reason) => {
      expect(ipGroupAddressesError(['10.0.0.1', value])).toContain(
        'Address 2:',
      );
      expect(ipGroupAddressesError([value])).toContain(reason);
    },
  );

  it('requires addresses and enforces the 5000 entry limit', () => {
    expect(ipGroupAddressesError([])).toContain('at least one');
    expect(
      ipGroupAddressesError(Array.from({ length: 5000 }, () => '10.0.0.1')),
    ).toBeUndefined();
    expect(
      ipGroupAddressesError(Array.from({ length: 5001 }, () => '10.0.0.1')),
    ).toContain('at most 5000');
  });

  it('uses the existing list parsing for mixed separators and duplicates', () => {
    const addresses = parseList(
      '10.0.0.1,10.1.0.0/24;\n10.2.0.1-10.2.0.20 10.0.0.1',
    );
    expect(addresses).toEqual(request.addresses);
    expect(ipGroupAddressesError(addresses)).toBeUndefined();
  });

  it('applies the shared Azure naming rules to IP groups and resource groups', () => {
    for (const name of [
      '',
      'office networks',
      '-office',
      'office.',
      'a'.repeat(81),
    ]) {
      expect(ipGroupErrors({ ...request, name }).name).toBeTruthy();
    }
    expect(ipGroupErrors({ ...request, name: 'a'.repeat(80) })).toEqual({});
    expect(
      ipGroupErrors({ ...request, resourceGroup: 'rg.' }).resourceGroup,
    ).toContain("can't end with a period");
  });

  it('requires a valid subscription and location', () => {
    const errors = ipGroupErrors({
      ...request,
      subscriptionId: 'bad',
      location: '../eastus',
    });
    expect(errors.subscriptionId).toBeTruthy();
    expect(errors.location).toBeTruthy();
  });
});
