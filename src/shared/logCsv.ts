// CSV export of the rows shown in the Firewall logs view. Log text comes from the network (a
// hostname or a rule name can be chosen by whoever sent the traffic), so every cell goes through
// `csvCell`, which defuses values a spreadsheet would run as a formula.
import { csvCell, csvFileName } from './csv';
import type { FirewallLogRow } from './fwLogs';

const COLUMNS: { header: string; value: (r: FirewallLogRow) => string }[] = [
  { header: 'Time', value: (r) => r.time },
  { header: 'Category', value: (r) => r.category },
  { header: 'Action', value: (r) => r.action },
  { header: 'Protocol', value: (r) => r.protocol },
  { header: 'Source', value: (r) => r.sourceIp },
  { header: 'Source port', value: (r) => r.sourcePort },
  { header: 'Destination', value: (r) => r.targetIp },
  { header: 'Destination port', value: (r) => r.targetPort },
  { header: 'NAT destination', value: (r) => r.natDstIp },
  { header: 'NAT destination port', value: (r) => r.natDstPort },
  { header: 'Policy', value: (r) => r.fwPolicy },
  { header: 'Rule collection group', value: (r) => r.ruleCollectionGroup },
  { header: 'Rule collection', value: (r) => r.ruleCollection },
  { header: 'Rule', value: (r) => r.ruleName },
  { header: 'Reason', value: (r) => r.policy },
  { header: 'More info', value: (r) => r.moreInfo },
  { header: 'Firewall resource', value: (r) => r.resourceId },
];

/** The rows as CSV, in the order given (the view shows newest first). */
export function logsToCsv(rows: readonly FirewallLogRow[]): string {
  // A byte-order mark makes Excel read the file as UTF-8.
  return (
    '\uFEFF' +
    [
      COLUMNS.map((c) => c.header),
      ...rows.map((r) => COLUMNS.map((c) => c.value(r))),
    ]
      .map((cells) => cells.map(csvCell).join(','))
      .join('\r\n') +
    '\r\n'
  );
}

/** e.g. "firewall-logs_2026-11-16.csv". */
export const logsCsvFileName = () => csvFileName('firewall-logs');
