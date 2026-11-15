// Dual-stack (IPv4 + IPv6) address helpers for firewall log rows. Pure: no Node imports, so the
// renderer can use them. The existing cidr.ts / search.ts helpers are IPv4-only by design (they
// validate Azure subnets and rules); log rows can carry IPv6 from dual-stack firewalls.

export interface ParsedAddress {
  version: 4 | 6;
  value: bigint;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/i;

function parseV4(text: string): bigint | undefined {
  const m = IPV4.exec(text);
  if (!m) return undefined;
  let n = 0n;
  for (const part of m.slice(1, 5)) {
    // Leading zeros are ambiguous (octal in some parsers); refuse them like Python's ipaddress.
    if (part.length > 1 && part.startsWith('0')) return undefined;
    const o = Number(part);
    if (o > 255) return undefined;
    n = n * 256n + BigInt(o);
  }
  return n;
}

function parseV6(text: string): bigint | undefined {
  if (!text.includes(':') || text.includes(':::')) return undefined;
  let head = text;
  // An IPv4 tail ("::ffff:1.2.3.4") stands for the last two groups.
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseV4(tail);
    if (v4 === undefined) return undefined;
    const hi = (v4 >> 16n).toString(16);
    const lo = (v4 & 0xffffn).toString(16);
    head = `${text.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const halves = head.split('::');
  if (halves.length > 2) return undefined;
  const groups = (s: string) => (s === '' ? [] : s.split(':'));
  const left = groups(halves[0]);
  const right = halves.length === 2 ? groups(halves[1]) : [];
  const all = [...left, ...right];
  if (!all.every((g) => HEX_GROUP.test(g))) return undefined;
  if (halves.length === 1 ? left.length !== 8 : all.length > 7)
    return undefined;
  const fill = halves.length === 2 ? 8 - all.length : 0;
  const full = [...left, ...Array<string>(fill).fill('0'), ...right];
  return full.reduce((n, g) => (n << 16n) | BigInt(`0x${g}`), 0n);
}

/** An address as a number; undefined for FQDNs, "-", empty text and anything malformed. */
export function parseAddress(value: string): ParsedAddress | undefined {
  const text = (value ?? '').trim();
  if (!text || text === '-') return undefined;
  const v4 = parseV4(text);
  if (v4 !== undefined) return { version: 4, value: v4 };
  const v6 = parseV6(text);
  return v6 === undefined ? undefined : { version: 6, value: v6 };
}

/** RFC 5952 text: lower-case, no leading zeros, longest zero run (>= 2 groups) as "::". */
export function formatAddress(a: ParsedAddress): string {
  if (a.version === 4) {
    return [24n, 16n, 8n, 0n]
      .map((s) => ((a.value >> s) & 0xffn).toString())
      .join('.');
  }
  const groups = Array.from({ length: 8 }, (_, i) =>
    Number((a.value >> BigInt((7 - i) * 16)) & 0xffffn),
  );
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = (gs: number[]) => gs.map((g) => g.toString(16)).join(':');
  if (bestLen < 2) return hex(groups);
  return `${hex(groups.slice(0, bestStart))}::${hex(groups.slice(bestStart + bestLen))}`;
}

/**
 * One spelling per address: brackets off, IPv6 compressed. A dual-stack firewall writes the same
 * address bracketed+expanded in one category and compressed in another. FQDNs, "-" and anything
 * that isn't an address come back unchanged.
 */
export function normaliseAddress(value: string): string {
  let text = (value ?? '').trim();
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  const a = parseAddress(text);
  return a ? formatAddress(a) : value;
}

/**
 * Splits a legacy log's "address:port" token. Tries the LAST colon first and accepts it when the
 * part before is an address, because "fd00::1:1234" is itself a valid IPv6 address. A missing
 * port is "-".
 */
export function splitEndpoint(text: string): [address: string, port: string] {
  if (!text) return [text, '-'];
  if (text.startsWith('[') && text.includes(']')) {
    const end = text.indexOf(']');
    const rest = text.slice(end + 1);
    return [
      text.slice(1, end),
      (rest.startsWith(':') ? rest.slice(1) : '') || '-',
    ];
  }
  if (!text.includes(':')) return [text, '-'];
  const i = text.lastIndexOf(':');
  const address = text.slice(0, i);
  const port = text.slice(i + 1) || '-';
  if (parseAddress(address)) return [address, port];
  if (parseAddress(text)) return [text, '-'];
  return [address, port]; // FQDN:port, or malformed: pass through
}

export interface ParsedNetwork {
  version: 4 | 6;
  /** Inclusive bounds. */
  first: bigint;
  last: bigint;
}

/** "10.0.0.0/8" or "fd10:2::/32"; host bits are tolerated (what people type into a filter). */
export function parseNetwork(value: string): ParsedNetwork | undefined {
  const [base, bitsText, ...extra] = (value ?? '').trim().split('/');
  if (extra.length || bitsText === undefined || !/^\d{1,3}$/.test(bitsText))
    return undefined;
  const a = parseAddress(base);
  if (!a) return undefined;
  const total = a.version === 4 ? 32 : 128;
  const bits = Number(bitsText);
  if (bits > total) return undefined;
  const hostMask = (1n << BigInt(total - bits)) - 1n;
  return {
    version: a.version,
    first: a.value & ~hostMask,
    last: a.value | hostMask,
  };
}

export function networkContains(net: ParsedNetwork, a: ParsedAddress): boolean {
  return (
    a.version === net.version && a.value >= net.first && a.value <= net.last
  );
}

/**
 * Filter semantics for the Source and Destination inputs (`needle` as typed):
 * - a CIDR matches every address inside it, never an FQDN or the other family;
 * - a full address matches the same address in any spelling;
 * - anything else is a case-insensitive substring of the value as logged or, for IPv6, of its
 *   compressed form ("::10" finds "fd10:0:0:2:0:0:0:10").
 */
export function addressMatches(needle: string, value: string): boolean {
  const n = (needle ?? '').trim().toLowerCase();
  if (!n) return true;
  const haystack = (value ?? '').toLowerCase();
  if (n.includes('/')) {
    const net = parseNetwork(n);
    if (!net) return haystack.includes(n); // not a CIDR after all: plain text
    const a = parseAddress(haystack);
    return !!a && networkContains(net, a);
  }
  if (haystack.includes(n)) return true;
  const a = parseAddress(haystack);
  if (!a) return false;
  const typed = parseAddress(n);
  return (
    (typed !== undefined &&
      typed.version === a.version &&
      typed.value === a.value) ||
    formatAddress(a).includes(n)
  );
}
