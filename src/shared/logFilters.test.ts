import { describe, expect, it } from 'vitest';
import { parseRecord, type FirewallLogRow } from './fwLogs';
import {
  categoryMatches,
  DEFAULT_FILTERS,
  differsFromDefault,
  filterRows,
  NO_FILTERS,
  rowMatches,
  type LogFilters,
} from './logFilters';

const FW =
  '/SUBSCRIPTIONS/0/RESOURCEGROUPS/rg/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/FW';
const mk = (
  category: string,
  props: Record<string, unknown>,
): FirewallLogRow => {
  const r = parseRecord({
    resourceId: FW,
    category,
    time: '2026-01-01T00:00:00Z',
    properties: props,
  });
  if (r.kind !== 'row') throw new Error('skip');
  return r.row;
};
const f = (over: Partial<LogFilters>): LogFilters => ({
  ...NO_FILTERS,
  ...over,
});

const allow = mk('AZFWNetworkRule', {
  Protocol: 'TCP',
  SourceIp: '10.3.1.5',
  DestinationIp: '8.8.8.8',
  DestinationPort: 443,
  Action: 'Allow',
});
const deny = mk('AZFWNetworkRule', {
  Protocol: 'UDP',
  SourceIp: '[fd10:0002:0000:0000:0000:0000:0000:0010]',
  DestinationIp: '1.1.1.1',
  DestinationPort: 53,
  Action: 'Deny',
});
const app = mk('AZFWApplicationRule', {
  Protocol: 'HTTPS',
  SourceIp: '10.3.1.5',
  Fqdn: 'www.Contoso.com',
  DestinationPort: 443,
  Action: 'Allow',
});
const dns = mk('AZFWDnsQuery', {
  SourceIp: '10.3.1.5',
  QueryType: 'A',
  QueryName: 'contoso.com.',
  ResponseCode: 'NOERROR',
});
const dnsFail = mk('AZFWFqdnResolveFailure', { Fqdn: 'nope.invalid' });
const flow = mk('AZFWFlowTrace', {
  Flag: 'RST',
  SourceIp: '10.0.0.1',
  DestinationIp: '10.0.0.2',
  SourcePort: 5,
  DestinationPort: 6,
});
const rows = [allow, deny, app, dns, dnsFail, flow];
const ids = (rs: FirewallLogRow[]) => rs.map((r) => rows.indexOf(r));

describe('logFilters', () => {
  it('no filters keeps everything (as a copy)', () => {
    const out = filterRows(rows, NO_FILTERS);
    expect(out).toEqual(rows);
    expect(out).not.toBe(rows);
  });
  it('source and destination accept CIDR, IPv6 any spelling, substring, FQDN', () => {
    expect(ids(filterRows(rows, f({ source: '10.3.0.0/16' })))).toEqual([
      0, 2, 3,
    ]);
    expect(ids(filterRows(rows, f({ source: 'fd10:2::/32' })))).toEqual([1]);
    expect(ids(filterRows(rows, f({ source: 'FD10:2::10' })))).toEqual([1]);
    expect(ids(filterRows(rows, f({ source: '::10' })))).toEqual([1]);
    expect(ids(filterRows(rows, f({ destination: 'contoso' })))).toEqual([
      2, 3,
    ]);
    expect(ids(filterRows(rows, f({ destination: '8.8.8.0/24' })))).toEqual([
      0,
    ]);
  });
  it('action, protocol and port are case-insensitive substrings', () => {
    expect(ids(filterRows(rows, f({ action: 'ALLOW' })))).toEqual([0, 2]);
    expect(ids(filterRows(rows, f({ action: 'rst' })))).toEqual([5]);
    expect(ids(filterRows(rows, f({ protocol: 'https' })))).toEqual([2]);
    expect(ids(filterRows(rows, f({ port: '443' })))).toEqual([0, 2]);
    expect(ids(filterRows(rows, f({ action: 'allow', port: '53' })))).toEqual(
      [],
    );
  });
  it('category presets and single categories', () => {
    expect(ids(filterRows(rows, f({ category: 'group:decisions' })))).toEqual([
      0, 1, 2,
    ]);
    expect(ids(filterRows(rows, f({ category: 'group:traffic' })))).toEqual([
      5,
    ]);
    expect(ids(filterRows(rows, f({ category: 'group:dns' })))).toEqual([3, 4]);
    expect(ids(filterRows(rows, f({ category: 'DnsFailure' })))).toEqual([4]);
    expect(ids(filterRows(rows, f({ category: 'dns' })))).toEqual([3, 4]); // plain values are substrings
    expect(categoryMatches('group:nope', 'NetworkRule')).toBe(false);
    expect(categoryMatches('', 'anything')).toBe(true);
  });
  it('hide DNS drops DnsQuery but keeps DnsFailure', () => {
    expect(ids(filterRows(rows, f({ hideDns: true })))).toEqual([
      0, 1, 2, 4, 5,
    ]);
    expect(rowMatches(dnsFail, f({ hideDns: true }))).toBe(true);
  });
  it('DNS queries start hidden, and "clear filters" returns to that', () => {
    expect(DEFAULT_FILTERS.hideDns).toBe(true);
    expect(ids(filterRows(rows, DEFAULT_FILTERS))).toEqual([0, 1, 2, 4, 5]);
    expect(differsFromDefault(DEFAULT_FILTERS)).toBe(false);
    // Showing DNS again is a change from the default, so the clear link appears.
    expect(differsFromDefault(f({ hideDns: false }))).toBe(true);
    expect(differsFromDefault({ ...DEFAULT_FILTERS, port: '53' })).toBe(true);
  });
  it('whitespace-only filters do not hide rows', () => {
    expect(filterRows(rows, f({ action: '  ', port: ' ' })).length).toBe(
      rows.length,
    );
  });
});
