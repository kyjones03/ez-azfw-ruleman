import { describe, expect, it } from 'vitest';
import { logsCsvFileName, logsToCsv } from './logCsv';
import type { FirewallLogRow } from './fwLogs';

const row = (patch: Partial<FirewallLogRow> = {}): FirewallLogRow => ({
  id: '1',
  time: '2026-11-16T17:30:00Z',
  category: 'NetworkRule',
  protocol: 'TCP',
  sourceIp: '10.50.1.4',
  sourcePort: '40000',
  targetIp: '1.1.1.1',
  targetPort: '443',
  action: 'Deny',
  policy: 'Default deny',
  moreInfo: '',
  resourceId:
    '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw',
  fwPolicy: '',
  ruleCollectionGroup: '',
  ruleCollection: '',
  ruleName: '',
  natDstIp: '',
  natDstPort: '',
  explicitProxy: '',
  tlsInspected: '',
  ...patch,
});

const lines = (csv: string) =>
  csv.replace('\uFEFF', '').trimEnd().split('\r\n');

describe('logsToCsv', () => {
  it('writes a header and one line per row, in the order given', () => {
    const out = lines(
      logsToCsv([row({ targetIp: 'first' }), row({ targetIp: 'second' })]),
    );
    expect(out).toHaveLength(3);
    expect(out[0].startsWith('Time,Category,Action')).toBe(true);
    expect(out[1]).toContain('first');
    expect(out[2]).toContain('second');
  });

  it('starts with a byte-order mark and writes only a header for no rows', () => {
    const csv = logsToCsv([]);
    expect(csv.startsWith('\uFEFF')).toBe(true);
    expect(lines(csv)).toHaveLength(1);
  });

  it('defuses formulas in untrusted fields', () => {
    const out = logsToCsv([
      row({
        targetIp: '=HYPERLINK("http://evil","x")',
        ruleName: '+cmd|calc',
        moreInfo: '@SUM(1)',
      }),
    ]);
    expect(out).toContain(`"'=HYPERLINK(""http://evil"",""x"")"`);
    expect(out).toContain(`'+cmd|calc`);
    expect(out).toContain(`'@SUM(1)`);
  });

  it('quotes commas and line breaks so a field cannot add a column or a row', () => {
    const out = logsToCsv([row({ moreInfo: 'a,b\r\nc' })]);
    expect(out).toContain('"a,b\r\nc"');
    expect(out.match(/\r\n/g)).toHaveLength(3);
  });
});

describe('logsCsvFileName', () => {
  it('is a safe file name with the date', () => {
    expect(logsCsvFileName()).toMatch(/^firewall-logs_\d{4}-\d{2}-\d{2}\.csv$/);
  });
});
