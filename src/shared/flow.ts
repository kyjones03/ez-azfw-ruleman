// "Would this flow match?" — evaluates a flow the way Azure Firewall does:
// DNAT rules first, then network rules, then application rules; within each pass, inherited
// (parent) policy groups before the policy's own, groups and collections by priority; the first
// matching rule wins. DNAT rules aren't inherited, so only the policy's own DNAT rules apply.
// Things the app can't resolve locally (IP Group members, service-tag ranges, FQDN resolution,
// web categories, FQDN tags) make a rule a "maybe" instead of a guess.
import { addressContains } from './search';
import { collectionKindOf, type CollectionKind } from './ruleDraft';
import { portCovers } from './rules';
import type {
  ApplicationRule,
  FirewallRule,
  NatRule,
  NetworkRule,
  RuleCollection,
  RuleCollectionGroup,
} from './types';

export type FlowProtocol = 'TCP' | 'UDP' | 'ICMP';

export interface Flow {
  source: string;
  /** IPv4 address or FQDN. */
  destination: string;
  protocol: FlowProtocol;
  port?: number;
}

export interface PolicyLayer {
  policyId: string;
  policyName: string;
  /** True for a parent (base) policy; its groups are processed before the child's. */
  inherited: boolean;
  groups: RuleCollectionGroup[];
}

type Tri = 'match' | 'maybe' | 'no';

export interface FlowHit {
  pass: CollectionKind;
  policyId: string;
  policyName: string;
  inherited: boolean;
  groupId: string;
  groupName: string;
  collection: string;
  action: RuleCollection['action']['type'];
  rule: string;
  result: 'match' | 'maybe';
  /** Why a "maybe" couldn't be decided. */
  unknowns: string[];
  translatedTo?: string;
}

export interface FlowResult {
  verdict: 'Allow' | 'Deny' | 'DNAT' | 'default-deny';
  winner?: FlowHit;
  /** Rules evaluated before the winner that might match first, in processing order. */
  maybes: FlowHit[];
  rulesChecked: number;
  notes: string[];
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
export const isIpv4 = (v: string) =>
  IPV4.test(v) && v.split('.').every((o) => Number(o) <= 255);

/** RFC 1918, CGNAT, loopback and link-local ranges. */
const NON_PUBLIC = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
];
const isPrivateIp = (ip: string) =>
  NON_PUBLIC.some((range) => addressContains(range, ip));

const combine = (...parts: Tri[]): Tri =>
  parts.includes('no') ? 'no' : parts.includes('maybe') ? 'maybe' : 'match';

/** Best result over a list of entries: any definite match wins, else any unknown, else no. */
const anyOf = (results: Tri[]): Tri =>
  results.includes('match')
    ? 'match'
    : results.includes('maybe')
      ? 'maybe'
      : 'no';

/**
 * Matches an FQDN pattern against a host. A leading "*." matches subdomains only; a bare leading
 * "*" matches anything ending with the rest ("*contoso.com" matches contoso.com and
 * mycontoso.com), as Azure Firewall does.
 */
export function fqdnMatches(pattern: string, host: string): boolean {
  const p = pattern.trim().toLowerCase().replace(/\.$/, '');
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  if (p === '*') return true;
  if (p.startsWith('*')) return h.endsWith(p.slice(1));
  return p === h;
}

class Unknowns {
  list: string[] = [];
  add(reason: string): Tri {
    if (!this.list.includes(reason)) this.list.push(reason);
    return 'maybe';
  }
}

/** IP Group resource ID (lowercase) → member addresses, when they've been loaded. */
export type IpGroupMembers = Map<string, string[]>;

/** Matches an IP against IP Groups, using their members when known. */
function matchIpGroups(
  ids: string[] | undefined,
  ip: string | undefined,
  groups: IpGroupMembers | undefined,
  side: string,
  u: Unknowns,
): Tri[] {
  return (ids ?? []).map((id): Tri => {
    const members = groups?.get(id.toLowerCase());
    if (!members)
      return u.add(`the ${side} IP Group’s members couldn’t be loaded`);
    if (!ip) return 'no';
    return members.some((m) => addressContains(m, ip)) ? 'match' : 'no';
  });
}

function matchSource(
  r: FirewallRule,
  ip: string,
  u: Unknowns,
  groups?: IpGroupMembers,
): Tri {
  return anyOf([
    ...(r.sourceAddresses ?? []).map(
      (a): Tri => (addressContains(a, ip) ? 'match' : 'no'),
    ),
    ...matchIpGroups(r.sourceIpGroups, ip, groups, 'source', u),
  ]);
}

function matchProtocolPort(
  protocols: string[] | undefined,
  ports: string[] | undefined,
  flow: Flow,
): Tri {
  const protoOk = (protocols ?? []).some(
    (p) => p === 'Any' || p === flow.protocol,
  );
  if (!protoOk) return 'no';
  // ICMP has no ports.
  if (flow.protocol === 'ICMP' || flow.port === undefined) return 'match';
  return (ports ?? []).some((p) => portCovers(p, flow.port!)) ? 'match' : 'no';
}

function matchNetwork(
  r: NetworkRule,
  flow: Flow,
  u: Unknowns,
  groups?: IpGroupMembers,
): Tri {
  const destIsIp = isIpv4(flow.destination);
  const dest = anyOf([
    ...(r.destinationAddresses ?? []).map((a): Tri => {
      if (a.trim() === '*') return 'match';
      // "Internet" is all public address space (including Azure's public IPs), so it's decidable.
      if (a.trim().toLowerCase() === 'internet')
        return destIsIp
          ? isPrivateIp(flow.destination)
            ? 'no'
            : 'match'
          : 'no';
      if (/[a-z]/i.test(a) && !a.includes('/'))
        return u.add(
          `it depends on whether the address is in the ${a} service tag, whose ranges aren’t checked here`,
        );
      return destIsIp
        ? addressContains(a, flow.destination)
          ? 'match'
          : 'no'
        : 'no';
    }),
    ...(r.destinationFqdns ?? []).map(
      (f): Tri =>
        destIsIp
          ? u.add(
              `it depends on what ${f} resolves to, which only the firewall’s DNS knows`,
            )
          : fqdnMatches(f, flow.destination)
            ? 'match'
            : 'no',
    ),
    ...matchIpGroups(
      r.destinationIpGroups,
      destIsIp ? flow.destination : undefined,
      groups,
      'destination',
      u,
    ),
  ]);
  return combine(
    matchProtocolPort(r.ipProtocols, r.destinationPorts, flow),
    matchSource(r, flow.source, u, groups),
    dest,
  );
}

function matchApplication(
  r: ApplicationRule,
  flow: Flow,
  u: Unknowns,
  groups?: IpGroupMembers,
): Tri {
  // Application rules see HTTP(S)/MSSQL over TCP, matched on the requested host name.
  if (flow.protocol !== 'TCP' || flow.port === undefined) return 'no';
  const portOk = (r.protocols ?? []).some((p) => p.port === flow.port);
  if (!portOk) return 'no';
  const destIsIp = isIpv4(flow.destination);
  const dest = anyOf([
    ...(r.targetFqdns ?? []).map(
      (f): Tri =>
        f.trim() === '*'
          ? 'match'
          : destIsIp
            ? 'no'
            : fqdnMatches(f, flow.destination)
              ? 'match'
              : 'no',
    ),
    ...(r.targetUrls ?? []).map(
      (url): Tri =>
        !destIsIp && fqdnMatches(url.split('/')[0], flow.destination)
          ? u.add('it depends on the URL path, which this test doesn’t include')
          : 'no',
    ),
    // Tags and categories describe internet services and sites, never private addresses.
    ...(r.fqdnTags ?? []).map(
      (t): Tri =>
        destIsIp && isPrivateIp(flow.destination)
          ? 'no'
          : u.add(
              `it depends on whether the destination is part of the ${t} FQDN tag, which only Azure knows`,
            ),
    ),
    ...(r.webCategories ?? []).map(
      (c): Tri =>
        destIsIp && isPrivateIp(flow.destination)
          ? 'no'
          : u.add(
              `it depends on whether the site is in the ${c} web category, which only Azure can look up`,
            ),
    ),
    ...(r.destinationAddresses ?? []).map(
      (a): Tri =>
        destIsIp && addressContains(a, flow.destination) ? 'match' : 'no',
    ),
  ]);
  return combine(matchSource(r, flow.source, u, groups), dest);
}

function matchNat(
  r: NatRule,
  flow: Flow,
  u: Unknowns,
  groups?: IpGroupMembers,
): Tri {
  if (!isIpv4(flow.destination)) return 'no';
  const dest = (r.destinationAddresses ?? []).some((a) =>
    addressContains(a, flow.destination),
  )
    ? 'match'
    : 'no';
  return combine(
    matchProtocolPort(r.ipProtocols, r.destinationPorts, flow),
    matchSource(r, flow.source, u, groups),
    dest,
  );
}

const PASSES: CollectionKind[] = ['DNAT', 'Network', 'Application'];

export function evaluateFlow(
  flow: Flow,
  layers: PolicyLayer[],
  ipGroups?: IpGroupMembers,
): FlowResult {
  const ordered = [
    ...layers.filter((l) => l.inherited),
    ...layers.filter((l) => !l.inherited),
  ];
  const maybes: FlowHit[] = [];
  let rulesChecked = 0;
  const notes: string[] = [];
  if (!isIpv4(flow.destination))
    notes.push(
      'The destination is a host name, so DNAT and IP-based network rules can’t match it; application rules and network-rule FQDNs can.',
    );

  // Only uncertain rules that would change the outcome are worth showing: a possible Deny ahead of
  // a Deny result (or Allow ahead of Allow) makes no difference.
  const finish = (
    verdict: FlowResult['verdict'],
    winner?: FlowHit,
  ): FlowResult => {
    const allows = (a: string) => a === 'Allow' || a === 'DNAT';
    const relevant = maybes.filter((m) => allows(m.action) !== allows(verdict));
    return { verdict, winner, maybes: relevant, rulesChecked, notes };
  };

  for (const pass of PASSES) {
    for (const layer of ordered) {
      if (pass === 'DNAT' && layer.inherited) continue;
      const groups = [...layer.groups].sort((a, b) => a.priority - b.priority);
      for (const g of groups) {
        const collections = g.ruleCollections
          .filter((c) => collectionKindOf(c) === pass)
          .sort((a, b) => a.priority - b.priority);
        for (const c of collections) {
          for (const r of c.rules as FirewallRule[]) {
            rulesChecked++;
            const u = new Unknowns();
            const result =
              r.ruleType === 'NatRule'
                ? matchNat(r, flow, u, ipGroups)
                : r.ruleType === 'NetworkRule'
                  ? matchNetwork(r, flow, u, ipGroups)
                  : matchApplication(r, flow, u, ipGroups);
            if (result === 'no') continue;
            const hit: FlowHit = {
              pass,
              policyId: layer.policyId,
              policyName: layer.policyName,
              inherited: layer.inherited,
              groupId: g.id,
              groupName: g.name,
              collection: c.name,
              action: c.action.type,
              rule: r.name,
              result,
              unknowns: u.list,
              translatedTo:
                r.ruleType === 'NatRule'
                  ? `${r.translatedAddress ?? r.translatedFqdn ?? '?'}:${r.translatedPort ?? '?'}`
                  : undefined,
            };
            if (result === 'maybe') {
              maybes.push(hit);
              continue;
            }
            return finish(c.action.type, hit);
          }
        }
      }
    }
  }
  return finish('default-deny', undefined);
}
