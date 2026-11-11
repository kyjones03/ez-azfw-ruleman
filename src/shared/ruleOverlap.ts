import { fqdnMatches, type IpGroupMembers } from './flow';
import { addressContains } from './search';
import { isAddress, portCovers, stableStringify } from './rules';
import type { ApplicationRule, FirewallRule } from './types';

export type RuleOverlap = 'overlap' | 'potential' | 'none';
type Match = 'yes' | 'maybe' | 'no';

const any = (values: Match[]): Match =>
  values.includes('yes') ? 'yes' : values.includes('maybe') ? 'maybe' : 'no';
const all = (...values: Match[]): Match =>
  values.includes('no') ? 'no' : values.includes('maybe') ? 'maybe' : 'yes';

const firstAddress = (entry: string) =>
  entry === '*' ? '0.0.0.0' : entry.split(/[/-]/)[0];

function addresses(a: string, b: string): Match {
  if (!isAddress(a) || !isAddress(b))
    return a.toLowerCase() === b.toLowerCase() ? 'yes' : 'maybe';
  return addressContains(a, firstAddress(b)) ||
    addressContains(b, firstAddress(a))
    ? 'yes'
    : 'no';
}

function addressSets(a: string[] | undefined, b: string[] | undefined): Match {
  return any((a ?? []).flatMap((x) => (b ?? []).map((y) => addresses(x, y))));
}

function expand(
  entries: string[] | undefined,
  ids: string[] | undefined,
  groups: IpGroupMembers | undefined,
): { entries: string[]; unknown: boolean } {
  const out = [...(entries ?? [])];
  let unknown = false;
  for (const id of ids ?? []) {
    const members = groups?.get(id.toLowerCase());
    if (members) out.push(...members);
    else unknown = true;
  }
  return { entries: out, unknown };
}

function sources(
  a: FirewallRule,
  b: FirewallRule,
  groups?: IpGroupMembers,
): Match {
  const x = expand(a.sourceAddresses, a.sourceIpGroups, groups);
  const y = expand(b.sourceAddresses, b.sourceIpGroups, groups);
  const result = addressSets(x.entries, y.entries);
  return result === 'yes' ? 'yes' : x.unknown || y.unknown ? 'maybe' : result;
}

function ports(a: string[], b: string[]): boolean {
  return a.some((x) =>
    b.some(
      (y) =>
        x === '*' ||
        y === '*' ||
        portCovers(x, Number(y.split('-')[0])) ||
        portCovers(y, Number(x.split('-')[0])),
    ),
  );
}

function services(a: FirewallRule, b: FirewallRule): Match {
  const protocols = (r: FirewallRule) =>
    r.ruleType === 'ApplicationRule' ? ['TCP'] : (r.ipProtocols ?? []);
  const common = ['TCP', 'UDP', 'ICMP'].filter((p) =>
    [a, b].every((r) => protocols(r).some((v) => v === 'Any' || v === p)),
  );
  if (!common.length) return 'no';
  if (common.includes('ICMP')) return 'yes';
  const portList = (r: FirewallRule) =>
    r.ruleType === 'ApplicationRule'
      ? (r.protocols ?? []).map((p) => String(p.port))
      : (r.destinationPorts ?? []);
  if (a.ruleType === 'ApplicationRule' && b.ruleType === 'ApplicationRule')
    return (a.protocols ?? []).some((x) =>
      (b.protocols ?? []).some(
        (y) => x.protocolType === y.protocolType && x.port === y.port,
      ),
    )
      ? 'yes'
      : 'no';
  return ports(portList(a), portList(b)) ? 'yes' : 'no';
}

function hosts(a: string, b: string): boolean {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  if (x.startsWith('*') && y.startsWith('*'))
    return x.slice(1).endsWith(y.slice(1)) || y.slice(1).endsWith(x.slice(1));
  return x.startsWith('*') ? fqdnMatches(x, y) : fqdnMatches(y, x);
}

function applicationTargets(a: ApplicationRule, b: ApplicationRule): Match {
  if (
    (a.targetFqdns ?? []).some((x) =>
      (b.targetFqdns ?? []).some((y) => hosts(x, y)),
    )
  )
    return 'yes';
  const symbolic = (r: ApplicationRule) =>
    !!(r.fqdnTags?.length || r.webCategories?.length || r.targetUrls?.length);
  if (symbolic(a) || symbolic(b)) return 'maybe';
  const ips = addressSets(a.destinationAddresses, b.destinationAddresses);
  if (ips === 'yes') return 'yes';
  if (
    (a.targetFqdns?.length && b.destinationAddresses?.length) ||
    (b.targetFqdns?.length && a.destinationAddresses?.length)
  )
    return 'maybe';
  return ips;
}

function destinations(
  a: FirewallRule,
  b: FirewallRule,
  groups?: IpGroupMembers,
): Match {
  if (a.ruleType === 'ApplicationRule' && b.ruleType === 'ApplicationRule')
    return applicationTargets(a, b);
  const entries = (r: FirewallRule) =>
    expand(
      r.destinationAddresses,
      r.ruleType === 'NetworkRule' ? r.destinationIpGroups : undefined,
      groups,
    );
  const x = entries(a);
  const y = entries(b);
  const result = addressSets(x.entries, y.entries);
  const fqdn = (r: FirewallRule) =>
    r.ruleType === 'NetworkRule'
      ? (r.destinationFqdns ?? [])
      : r.ruleType === 'ApplicationRule'
        ? (r.targetFqdns ?? [])
        : [];
  if (result === 'yes') return 'yes';
  const namesA = fqdn(a);
  const namesB = fqdn(b);
  if (namesA.some((f) => namesB.some((g) => hosts(f, g)))) return 'yes';
  if (
    x.unknown ||
    y.unknown ||
    (namesA.length &&
      namesB.length &&
      (a.ruleType === 'NetworkRule' || b.ruleType === 'NetworkRule')) ||
    (namesA.length && y.entries.length) ||
    (namesB.length && x.entries.length) ||
    (a.ruleType === 'ApplicationRule' &&
      (a.fqdnTags?.length ||
        a.webCategories?.length ||
        a.targetUrls?.length)) ||
    (b.ruleType === 'ApplicationRule' &&
      (b.fqdnTags?.length || b.webCategories?.length || b.targetUrls?.length))
  )
    return 'maybe';
  return result;
}

/** Intersection of incoming traffic matches, not a shadowing or effective-policy verdict. */
export function ruleOverlap(
  a: FirewallRule,
  b: FirewallRule,
  groups?: IpGroupMembers,
): RuleOverlap {
  const result = all(
    services(a, b),
    sources(a, b, groups),
    destinations(a, b, groups),
  );
  // Cross-pass FQDN/IP matching depends on DNS and processing order.
  return result === 'no'
    ? 'none'
    : result === 'maybe' || a.ruleType !== b.ruleType
      ? 'potential'
      : 'overlap';
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value))
    return value
      .map(canonical)
      .sort((a, b) => stableStringify(a).localeCompare(stableStringify(b)));
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        k,
        k === 'targetUrls' && Array.isArray(v) ? [...v].sort() : canonical(v),
      ]),
    );
  return typeof value === 'string' ? value.toLowerCase() : value;
}

/** Names and descriptions don't change traffic behavior; list ordering is immaterial. */
export function ruleContents(
  rule: FirewallRule,
  includeDescription = false,
): string {
  const {
    name: _name,
    description,
    terminateTLS: _tls,
    ...rest
  } = {
    ...rule,
    terminateTLS:
      rule.ruleType === 'ApplicationRule' ? rule.terminateTLS : undefined,
  };
  return (
    stableStringify(
      canonical({
        ...rest,
        ...(rule.ruleType === 'ApplicationRule' && rule.terminateTLS
          ? { terminateTLS: true }
          : {}),
      }),
    ) + (includeDescription ? `\n${description ?? ''}` : '')
  );
}
