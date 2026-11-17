// Azure Firewall diagnostic-log parser: turns one record from an Event Hub message into a flat,
// display-safe row. Handles the structured (AZFW*) and legacy (properties.msg) formats.
//
// Ported from az-firewall-watch (https://github.com/cloudchristoph/az-firewall-watch, MIT,
// Copyright (c) 2026 CloudChristoph), which in turn builds on azure-firewall-mon by Nicola
// Delfino. See NOTICE in the repository root.
import { normaliseAddress, splitEndpoint } from './ipAddress';

/** Display categories, as shown in the Logs view. Legacy DNS proxy rows map to DnsQuery. */
export const LOG_CATEGORIES = [
  'NetworkRule',
  'AppRule',
  'NATRule',
  'DnsQuery',
  'DnsFailure',
  'IDPS',
  'ThreatIntel',
  'FlowTrace',
  'FatFlow',
] as const;
export type LogCategory = (typeof LOG_CATEGORIES)[number];

export interface FirewallLogRow {
  /** Unique within this process; assigned by the parser. */
  id: string;
  /** Event timestamp as sent (ISO 8601). */
  time: string;
  category: LogCategory;
  protocol: string;
  sourceIp: string;
  sourcePort: string;
  /** Destination address or FQDN (the translated target for NATRule). */
  targetIp: string;
  targetPort: string;
  action: string;
  /** Policy » group » collection » rule path, or the firewall's own reason. */
  policy: string;
  moreInfo: string;
  resourceId: string;
  fwPolicy: string;
  ruleCollectionGroup: string;
  ruleCollection: string;
  ruleName: string;
  /** NATRule only: the public destination the client actually hit. */
  natDstIp: string;
  natDstPort: string;
  /** AppRule only: tri-state "yes" | "no" | "" (unknown; legacy rows never carry these). */
  explicitProxy: string;
  tlsInspected: string;
}

export type ParsedRecord =
  | { kind: 'row'; row: FirewallLogRow }
  | { kind: 'skip'; reason: string };

let counter = 0;
const nextId = () => String(++counter);

// ── display safety ───────────────────────────────────────────────────────────
// Records are untrusted input. Control characters and bidi overrides could spoof or reorder what
// the user reads (and would reach a CSV export), so they become a visible U+FFFD; a tab is a space.
/* oxlint-disable no-control-regex */
const UNSAFE =
  /[\u0000-\u0008\u000A-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;
/* oxlint-enable no-control-regex */

export function displaySafe(value: string): string {
  if (!value) return value;
  return value.replace(/\t/g, ' ').replace(UNSAFE, '\uFFFD');
}

// ── small helpers ────────────────────────────────────────────────────────────
type Props = Record<string, unknown>;

const s = (props: Props, key: string): string => {
  const v = props[key];
  return v === undefined || v === null ? '' : String(v);
};
const port = (props: Props, key: string): string => s(props, key) || '-';
const ip = (props: Props, key: string): string =>
  normaliseAddress(s(props, key));
const rstripDots = (v: string): string => v.replace(/\.+$/, '');
const capitalise = (v: string): string =>
  v.charAt(0).toUpperCase() + v.slice(1);
const joinPath = (...parts: string[]): string =>
  parts.filter(Boolean).join('»');

/** Tri-state boolean column: "yes" / "no" / "" when absent or unreadable. Never guessed. */
function flag(props: Props, key: string): string {
  const v = props[key];
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (typeof v === 'string') {
    const low = v.trim().toLowerCase();
    if (low === 'true') return 'yes';
    if (low === 'false') return 'no';
  }
  return '';
}

function formatMbps(rate: string): string {
  if (!rate) return '-';
  const value = rate.trim() === '' ? NaN : Number(rate);
  if (Number.isNaN(value)) return `${rate} Mbps`;
  return value >= 1 ? `${value.toFixed(1)} Mbps` : `${value.toFixed(3)} Mbps`;
}

/**
 * Which way a FlowTrace packet went. SYN and SYN-ACK are unambiguous; otherwise the side with the
 * ephemeral (higher) port is the client. Equal or non-numeric ports give "".
 */
export function tcpDirection(
  flagText: string,
  sport: string,
  dport: string,
): string {
  const f = (flagText || '').toUpperCase();
  if (f === 'SYN') return 'client → server';
  if (f === 'SYN-ACK') return 'server → client';
  const a = parseInt(sport, 10);
  const b = parseInt(dport, 10);
  if (Number.isNaN(a) || Number.isNaN(b) || a === b) return '';
  return a > b ? 'client → server' : 'server → client';
}

const FLOWTRACE_BOILERPLATE = 'Log Additional TCP Log';

function blank(
  category: LogCategory,
  time: string,
  resourceId: string,
): FirewallLogRow {
  return {
    id: nextId(),
    time,
    category,
    protocol: '-',
    sourceIp: '-',
    sourcePort: '-',
    targetIp: '-',
    targetPort: '-',
    action: '-',
    policy: '',
    moreInfo: '',
    resourceId,
    fwPolicy: '',
    ruleCollectionGroup: '',
    ruleCollection: '',
    ruleName: '',
    natDstIp: '',
    natDstPort: '',
    explicitProxy: '',
    tlsInspected: '',
  };
}

const STRUCTURED = new Set([
  'AZFWNetworkRule',
  'AZFWApplicationRule',
  'AZFWNatRule',
  'AZFWDnsQuery',
  'AZFWIdpsSignature',
  'AZFWThreatIntel',
  'AZFWFqdnResolveFailure',
  // The Log Analytics table name for the same data; accepted in case it shows up.
  'AZFWInternalFqdnResolutionFailure',
  'AZFWFlowTrace',
  'AZFWFatFlow',
]);

const LEGACY = new Set([
  'AzureFirewallNetworkRule',
  'AzureFirewallApplicationRule',
  'AzureFirewallNatRule',
  'AzureFirewallDnsProxy',
]);

const FIREWALL_RESOURCE = '/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/';

/**
 * Parses one diagnostic record. Never throws: anything that isn't a displayable firewall row
 * comes back as a skip with a reason, so callers can count it. Every string field leaves
 * display-safe.
 */
export function parseRecord(record: unknown): ParsedRecord {
  if (!record || typeof record !== 'object' || Array.isArray(record))
    return { kind: 'skip', reason: 'NotAnObject' };
  let result: ParsedRecord;
  try {
    result = parseInner(record as Props);
  } catch {
    return { kind: 'skip', reason: 'ParseErr' };
  }
  if (result.kind === 'row') {
    const row = result.row as unknown as Record<string, unknown>;
    for (const key of Object.keys(row))
      if (typeof row[key] === 'string') row[key] = displaySafe(row[key]);
  } else {
    result = { kind: 'skip', reason: displaySafe(result.reason) };
  }
  return result;
}

function parseInner(record: Props): ParsedRecord {
  const resourceId =
    typeof record.resourceId === 'string' ? record.resourceId : '';
  const category = typeof record.category === 'string' ? record.category : '';
  const opName =
    typeof record.operationName === 'string' ? record.operationName : '';
  const time =
    record.time === undefined || record.time === null
      ? ''
      : String(record.time);

  if (!resourceId.toUpperCase().includes(FIREWALL_RESOURCE))
    return { kind: 'skip', reason: 'ResourceType' };

  const raw = record.properties;
  const props: Props =
    raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Props) : {};

  if (STRUCTURED.has(category))
    return parseStructured(props, category, time, resourceId);
  if (LEGACY.has(category)) return parseLegacy(props, opName, time, resourceId);
  return { kind: 'skip', reason: `Category:${category}` };
}

// ── structured format ────────────────────────────────────────────────────────

function parseStructured(
  props: Props,
  category: string,
  time: string,
  resourceId: string,
): ParsedRecord {
  const rulePath = () => ({
    fwPolicy: s(props, 'Policy'),
    ruleCollectionGroup: s(props, 'RuleCollectionGroup'),
    ruleCollection: s(props, 'RuleCollection'),
    ruleName: s(props, 'Rule'),
  });
  const row = (
    cat: LogCategory,
    fields: Partial<FirewallLogRow>,
  ): ParsedRecord => ({
    kind: 'row',
    row: { ...blank(cat, time, resourceId), ...fields },
  });

  switch (category) {
    case 'AZFWDnsQuery':
      return row('DnsQuery', {
        protocol: s(props, 'QueryType'), // A / AAAA / MX … in the Proto column
        sourceIp: ip(props, 'SourceIp'),
        sourcePort: port(props, 'SourcePort'),
        targetIp: rstripDots(s(props, 'QueryName')),
        targetPort: '53',
        action: s(props, 'ResponseCode') || 'Request',
        moreInfo: s(props, 'ErrorMessage'),
      });

    case 'AZFWApplicationRule': {
      const p = rulePath();
      // A partial rule path is still more than the reason; without any, the firewall's reason,
      // and failing that the policy name rather than nothing.
      const policy =
        p.ruleCollectionGroup || p.ruleCollection || p.ruleName
          ? joinPath(
              p.fwPolicy,
              p.ruleCollectionGroup,
              p.ruleCollection,
              p.ruleName,
            )
          : s(props, 'ActionReason') || p.fwPolicy;
      return row('AppRule', {
        protocol: s(props, 'Protocol'),
        sourceIp: ip(props, 'SourceIp'),
        sourcePort: port(props, 'SourcePort'),
        targetIp: s(props, 'Fqdn'),
        targetPort: port(props, 'DestinationPort'),
        action: s(props, 'Action'),
        policy,
        moreInfo: s(props, 'TargetUrl'),
        ...p,
        explicitProxy: flag(props, 'IsExplicitProxyRequest'),
        tlsInspected: flag(props, 'IsTlsInspected'),
      });
    }

    case 'AZFWNetworkRule': {
      const p = rulePath();
      return row('NetworkRule', {
        protocol: s(props, 'Protocol'),
        sourceIp: ip(props, 'SourceIp'),
        sourcePort: port(props, 'SourcePort'),
        targetIp: ip(props, 'DestinationIp'),
        targetPort: port(props, 'DestinationPort'),
        action: s(props, 'Action'),
        policy: p.ruleCollectionGroup
          ? joinPath(
              p.fwPolicy,
              p.ruleCollectionGroup,
              p.ruleCollection,
              p.ruleName,
            )
          : s(props, 'ActionReason'),
        ...p,
      });
    }

    case 'AZFWNatRule': {
      const p = rulePath();
      return row('NATRule', {
        protocol: s(props, 'Protocol'),
        sourceIp: ip(props, 'SourceIp'),
        sourcePort: port(props, 'SourcePort'),
        // The log carries the translated target; the rule matched the public destination.
        targetIp: ip(props, 'TranslatedIp'),
        targetPort: port(props, 'TranslatedPort'),
        action: 'DNAT',
        policy: p.ruleCollectionGroup
          ? joinPath(
              p.fwPolicy,
              p.ruleCollectionGroup,
              p.ruleCollection,
              p.ruleName,
            )
          : s(props, 'ActionReason'),
        ...p,
        natDstIp: ip(props, 'DestinationIp'),
        natDstPort: port(props, 'DestinationPort'),
      });
    }

    case 'AZFWIdpsSignature': {
      const sev = s(props, 'Severity');
      return row('IDPS', {
        protocol: s(props, 'Protocol'),
        sourceIp: ip(props, 'SourceIp'),
        sourcePort: port(props, 'SourcePort'),
        targetIp: ip(props, 'DestinationIp'),
        targetPort: port(props, 'DestinationPort'),
        action: capitalise(s(props, 'Action')), // the firewall sends "alert" / "deny"
        moreInfo: [
          sev ? `SEV:${sev}` : '',
          s(props, 'SignatureId'),
          s(props, 'Category'),
          s(props, 'Description'),
        ]
          .filter(Boolean)
          .join(' · '),
      });
    }

    case 'AZFWThreatIntel':
      // HTTP/HTTPS hits carry the FQDN (DestinationIp is then empty); IP indicators keep the address.
      return row('ThreatIntel', {
        protocol: s(props, 'Protocol'),
        sourceIp: ip(props, 'SourceIp'),
        sourcePort: port(props, 'SourcePort'),
        targetIp: s(props, 'Fqdn') || ip(props, 'DestinationIp'),
        targetPort: port(props, 'DestinationPort'),
        action: capitalise(s(props, 'Action')),
        moreInfo: s(props, 'ThreatDescription'),
      });

    case 'AZFWFqdnResolveFailure':
    case 'AZFWInternalFqdnResolutionFailure': {
      // The firewall's own resolution of an FQDN used in a network/DNAT rule failed.
      const p = rulePath();
      return row('DnsFailure', {
        targetIp: s(props, 'Fqdn'),
        action: 'ResolveFail',
        policy: joinPath(
          p.fwPolicy,
          p.ruleCollectionGroup,
          p.ruleCollection,
          p.ruleName,
        ),
        moreInfo: s(props, 'Error'),
        ...p,
      });
    }

    case 'AZFWFlowTrace': {
      // Source/destination are the packet's own, so a SYN-ACK lists the server as source.
      const flagText = s(props, 'Flag') || '-';
      const sport = port(props, 'SourcePort');
      const dport = port(props, 'DestinationPort');
      const reason = [s(props, 'Action'), s(props, 'ActionReason')]
        .filter(Boolean)
        .join(' ');
      let info = tcpDirection(flagText, sport, dport);
      if (reason && reason !== FLOWTRACE_BOILERPLATE)
        info = info ? `${info} · ${reason}` : reason;
      return row('FlowTrace', {
        protocol: s(props, 'Protocol'),
        sourceIp: ip(props, 'SourceIp'),
        sourcePort: sport,
        targetIp: ip(props, 'DestinationIp'),
        targetPort: dport,
        action: flagText,
        moreInfo: info,
      });
    }

    case 'AZFWFatFlow': {
      const sport = port(props, 'SourcePort');
      const dport = port(props, 'DestinationPort');
      return row('FatFlow', {
        protocol: s(props, 'Protocol'),
        sourceIp: ip(props, 'SourceIp'),
        sourcePort: sport,
        targetIp: ip(props, 'DestinationIp'),
        targetPort: dport,
        action: formatMbps(s(props, 'FlowRate')),
        moreInfo: tcpDirection('', sport, dport),
      });
    }
  }
  return { kind: 'skip', reason: category };
}

// ── legacy format (properties.msg) ───────────────────────────────────────────

/** Splits once on a separator that must be present (else the message isn't what we expect). */
function splitOnce(text: string, sep: string): [string, string] {
  const i = text.indexOf(sep);
  if (i < 0) throw new Error(`missing "${sep}"`);
  return [text.slice(0, i), text.slice(i + sep.length)];
}

interface Sentences {
  action: string;
  policy: string;
  group: string;
  collection: string;
  rule: string;
  url: string;
  noRuleMatched: boolean;
}

/** Reads the ". "-separated "Key: value" sentences after the first one. */
function readSentences(msg: string): Sentences {
  const out: Sentences = {
    action: '',
    policy: '',
    group: '',
    collection: '',
    rule: '',
    url: '',
    noRuleMatched: false,
  };
  for (const sentence of msg.split('. ')) {
    const i = sentence.indexOf(': ');
    if (i < 0) {
      if (sentence.includes('No rule matched')) out.noRuleMatched = true;
      continue;
    }
    const key = sentence.slice(0, i).trim();
    const val = rstripDots(sentence.slice(i + 2));
    if (key === 'Action') out.action = val;
    else if (key === 'Policy') out.policy = val;
    else if (key === 'Rule Collection Group') out.group = val;
    else if (key === 'Rule Collection') out.collection = val;
    else if (key === 'Rule') out.rule = val;
    else if (key === 'Url' || key === 'URL') out.url = val;
  }
  return out;
}

function parseLegacy(
  props: Props,
  opName: string,
  time: string,
  resourceId: string,
): ParsedRecord {
  const msg = typeof props.msg === 'string' ? props.msg : '';
  const row = (
    cat: LogCategory,
    fields: Partial<FirewallLogRow>,
  ): ParsedRecord => ({
    kind: 'row',
    row: { ...blank(cat, time, resourceId), ...fields },
  });
  const failed: ParsedRecord = { kind: 'skip', reason: `ParseErr:${opName}` };

  try {
    if (opName === 'AzureFirewallNetworkRuleLog') {
      // "TCP request from 10.1.1.1:1234 to 10.2.2.2:80. Action: Allow. [Rule Collection Group: X. …]"
      const [proto, rest] = splitOnce(msg, ' request from ');
      const first = rest.split('. ')[0];
      const [srcStr, dstStr] = splitOnce(first, ' to ');
      const [srcIp, srcPort] = splitEndpoint(srcStr);
      const [dstIp, dstPort] = splitEndpoint(dstStr);
      const q = readSentences(msg);
      let policy = joinPath(q.policy, q.group, q.collection, q.rule);
      // A deny with no rule named is the firewall's default action; the structured format says so
      // in ActionReason. Any other rule-less row is left unexplained rather than guessed at.
      if (!policy && q.action === 'Deny') policy = 'Default Action';
      return row('NetworkRule', {
        protocol: proto,
        sourceIp: normaliseAddress(srcIp),
        sourcePort: srcPort,
        targetIp: normaliseAddress(dstIp),
        targetPort: rstripDots(dstPort),
        action: q.action || '-',
        policy,
        fwPolicy: q.policy,
        ruleCollectionGroup: q.group,
        ruleCollection: q.collection,
        ruleName: q.rule,
      });
    }

    if (opName === 'AzureFirewallNatRuleLog') {
      // "TCP request from 1.2.3.4:1234 to 5.6.7.8:3389 was DNAT'ed to 10.1.1.1:3389"
      const words = msg.split(' ');
      if (words.length < 10) return failed;
      const [srcIp, srcPort] = splitEndpoint(words[3]);
      const [dstIp, dstPort] = splitEndpoint(words[9]);
      const [natIp, natPort] = splitEndpoint(words[5]);
      return row('NATRule', {
        protocol: words[0],
        sourceIp: normaliseAddress(srcIp),
        sourcePort: srcPort,
        targetIp: normaliseAddress(dstIp),
        targetPort: rstripDots(dstPort),
        action: 'DNAT',
        natDstIp: normaliseAddress(natIp),
        natDstPort: rstripDots(natPort),
      });
    }

    if (opName === 'AzureFirewallApplicationRuleLog') {
      // "HTTPS request from 10.1.1.1:55583 to example.com:443. Action: Allow. Policy: P. …"
      const proto = msg.split(' ')[0];
      const [, rest] = splitOnce(msg, ' request from ');
      const first = rest.split('. ')[0];
      const [srcStr, dstStr] = splitOnce(first, ' to ');
      const [srcIp, srcPort] = splitEndpoint(srcStr);
      const colon = dstStr.lastIndexOf(':'); // last colon, so FQDNs keep their dots
      const q = readSentences(msg);
      const fwPolicy = q.noRuleMatched && !q.policy ? 'N/A' : q.policy;
      return row('AppRule', {
        protocol: proto,
        sourceIp: normaliseAddress(srcIp),
        sourcePort: srcPort,
        targetIp: colon < 0 ? dstStr : dstStr.slice(0, colon),
        targetPort: colon < 0 ? '-' : dstStr.slice(colon + 1),
        action: q.action || '-',
        policy: joinPath(fwPolicy, q.group, q.collection, q.rule),
        moreInfo: q.url,
        fwPolicy,
        ruleCollectionGroup: q.group,
        ruleCollection: q.collection,
        ruleName: q.rule,
      });
    }

    if (opName === 'AzureFirewallDNSResolutionFailureLog') {
      // "Failed to resolve FQDN example.com. Error lookup …. Rule Collection: policy:rcg:rc. Rule: r"
      const marker = ' Rule Collection: ';
      const at = msg.indexOf(marker);
      const head = at < 0 ? msg : msg.slice(0, at);
      const tail = at < 0 ? '' : msg.slice(at + marker.length);
      const m =
        /^Failed to resolve FQDN (\S+?)\.?(?:\s+Error\s+([\s\S]*))?$/.exec(
          head,
        );
      const fqdn = m ? m[1] : '-';
      const error = rstripDots(m ? (m[2] ?? '') : head);
      const ruleAt = tail.indexOf('. Rule: ');
      const rcPath = ruleAt < 0 ? tail : tail.slice(0, ruleAt);
      const ruleName = rstripDots(
        ruleAt < 0 ? '' : tail.slice(ruleAt + '. Rule: '.length),
      );
      const seg = rcPath.split(':'); // policy:rcg:rc; older firewalls may omit parts
      const [fwPolicy, group, collection] =
        seg.length >= 3 ? seg : ['', '', rcPath];
      return row('DnsFailure', {
        targetIp: fqdn,
        action: 'ResolveFail',
        policy: joinPath(fwPolicy, group, collection, ruleName),
        moreInfo: error,
        fwPolicy,
        ruleCollectionGroup: group,
        ruleCollection: collection,
        ruleName,
      });
    }

    if (
      opName === 'AzureFirewallDnsProxyLog' ||
      opName === 'AzureFirewallDnsProxy'
    ) {
      // "DNS Request: 10.2.0.6:5350 - 10407 A IN ifconfig.me. udp 40 false 1232 NOERROR qr,aa,rd,ra 56 0.000324423s"
      // words[2] source endpoint, [5] query type, [7] query name, [12] response code
      const words = msg.split(' ');
      const [srcIp, srcPort] =
        words.length > 2 ? splitEndpoint(words[2]) : ['-', '-'];
      return row('DnsQuery', {
        protocol: words.length > 5 ? words[5] : '-',
        sourceIp: normaliseAddress(srcIp),
        sourcePort: srcPort,
        targetIp: words.length > 7 ? rstripDots(words[7]) : '-',
        targetPort: '53',
        action: words.length > 12 ? words[12] : '-',
      });
    }
  } catch {
    return failed;
  }
  return failed;
}
