// Filters for the Logs view. Pure, so the renderer can derive the visible rows from the buffer
// on every keystroke. Semantics follow az-firewall-watch: case-insensitive substrings, with the
// address filters also understanding CIDR prefixes and IPv6 in any spelling.
import { addressMatches } from './ipAddress';
import type { FirewallLogRow, LogCategory } from './fwLogs';

export type CategoryGroup = 'decisions' | 'traffic' | 'dns';

/** One pick hides whole classes of rows: FlowTrace and DNS can flood the table. */
export const CATEGORY_GROUPS: Record<CategoryGroup, readonly LogCategory[]> = {
  decisions: ['NetworkRule', 'AppRule', 'NATRule', 'ThreatIntel', 'IDPS'],
  traffic: ['FlowTrace', 'FatFlow'],
  dns: ['DnsQuery', 'DnsFailure'],
};

/** Category dropdown: presets first, then single categories. Value "" means all. */
export const CATEGORY_OPTIONS: readonly { label: string; value: string }[] = [
  { label: 'Decisions', value: 'group:decisions' },
  { label: 'Traffic', value: 'group:traffic' },
  { label: 'DNS', value: 'group:dns' },
  { label: 'NetworkRule', value: 'NetworkRule' },
  { label: 'AppRule', value: 'AppRule' },
  { label: 'NATRule', value: 'NATRule' },
  { label: 'DnsQuery', value: 'DnsQuery' },
  { label: 'DnsFailure', value: 'DnsFailure' },
  { label: 'IDPS', value: 'IDPS' },
  { label: 'ThreatIntel', value: 'ThreatIntel' },
  { label: 'FlowTrace', value: 'FlowTrace' },
  { label: 'FatFlow', value: 'FatFlow' },
];

export interface LogFilters {
  /** Address, CIDR or substring. */
  source: string;
  /** Address, CIDR, FQDN or substring. */
  destination: string;
  action: string;
  /** "" (all), "group:<name>" or a single category name. */
  category: string;
  protocol: string;
  /** Destination port, substring. */
  port: string;
  /** Hides DnsQuery rows (DnsFailure stays: it is a firewall problem, not client noise). */
  hideDns: boolean;
}

export const NO_FILTERS: LogFilters = {
  source: '',
  destination: '',
  action: '',
  category: '',
  protocol: '',
  port: '',
  hideDns: false,
};

/**
 * What the view starts with, and what "Clear filters" returns to. DNS queries are most of the
 * volume on a busy firewall and rarely what you came for, so they start hidden; the switch is
 * one click away.
 */
export const DEFAULT_FILTERS: LogFilters = { ...NO_FILTERS, hideDns: true };

/** True when anything differs from the defaults, i.e. when "Clear filters" would change something. */
export function differsFromDefault(f: LogFilters): boolean {
  return (Object.keys(DEFAULT_FILTERS) as (keyof LogFilters)[]).some(
    (key) => f[key] !== DEFAULT_FILTERS[key],
  );
}

export function isFiltering(f: LogFilters): boolean {
  return (
    f.hideDns ||
    Boolean(
      f.source ||
      f.destination ||
      f.action ||
      f.category ||
      f.protocol ||
      f.port,
    )
  );
}

export function categoryMatches(selected: string, category: string): boolean {
  const sel = selected.trim().toLowerCase();
  if (!sel) return true;
  const cat = category.toLowerCase();
  if (sel.startsWith('group:')) {
    const group = CATEGORY_GROUPS[sel.slice(6) as CategoryGroup] as
      | readonly string[]
      | undefined;
    return !!group && group.some((c) => c.toLowerCase() === cat);
  }
  return cat.includes(sel);
}

const has = (needle: string, value: string) =>
  !needle.trim() || value.toLowerCase().includes(needle.trim().toLowerCase());

export function rowMatches(row: FirewallLogRow, f: LogFilters): boolean {
  if (f.hideDns && row.category === 'DnsQuery') return false;
  return (
    addressMatches(f.source, row.sourceIp) &&
    addressMatches(f.destination, row.targetIp) &&
    has(f.action, row.action) &&
    categoryMatches(f.category, row.category) &&
    has(f.protocol, row.protocol) &&
    has(f.port, row.targetPort)
  );
}

export const filterRows = (
  rows: readonly FirewallLogRow[],
  f: LogFilters,
): FirewallLogRow[] =>
  isFiltering(f) ? rows.filter((r) => rowMatches(r, f)) : rows.slice();
