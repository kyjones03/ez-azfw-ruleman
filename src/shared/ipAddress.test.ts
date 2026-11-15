import { describe, expect, it } from 'vitest';
import {
  addressMatches,
  formatAddress,
  normaliseAddress,
  parseAddress,
  parseNetwork,
  splitEndpoint,
} from './ipAddress';

describe('parseAddress / normaliseAddress', () => {
  it('compresses the bracketed, expanded form the structured network log uses', () => {
    expect(normaliseAddress('[fd10:0003:0005:0001:0000:0000:0000:0004]')).toBe(
      'fd10:3:5:1::4',
    );
  });
  it('leaves the compressed form, IPv4, FQDNs and placeholders alone', () => {
    expect(normaliseAddress('fd10:3:5:1::4')).toBe('fd10:3:5:1::4');
    expect(normaliseAddress('10.0.1.4')).toBe('10.0.1.4');
    expect(normaliseAddress('example.com')).toBe('example.com');
    expect(normaliseAddress('-')).toBe('-');
    expect(normaliseAddress('')).toBe('');
  });
  it('follows RFC 5952 for zero runs', () => {
    expect(formatAddress(parseAddress('0:0:0:0:0:0:0:0')!)).toBe('::');
    expect(formatAddress(parseAddress('0:0:0:0:0:0:0:1')!)).toBe('::1');
    expect(formatAddress(parseAddress('1:0:0:2:0:0:0:3')!)).toBe('1:0:0:2::3');
    expect(formatAddress(parseAddress('1:0:2:3:4:5:6:7')!)).toBe(
      '1:0:2:3:4:5:6:7',
    );
    expect(formatAddress(parseAddress('2600:1901:0:b2bd::')!)).toBe(
      '2600:1901:0:b2bd::',
    );
  });
  it('reads an embedded IPv4 tail', () => {
    expect(parseAddress('::ffff:1.2.3.4')?.value).toBe(0xffff01020304n);
  });
  it('rejects malformed input', () => {
    for (const bad of [
      '1.2.3',
      '256.1.1.1',
      '01.2.3.4',
      ':::',
      '1::2::3',
      'g::1',
      '1:2:3:4:5:6:7',
      '1:2:3:4:5:6:7:8:9',
      'host',
    ]) {
      expect(parseAddress(bad)).toBeUndefined();
    }
  });
});

describe('splitEndpoint', () => {
  it('splits IPv4, bracketed and bare IPv6, FQDN and missing port', () => {
    expect(splitEndpoint('10.0.0.1:443')).toEqual(['10.0.0.1', '443']);
    expect(splitEndpoint('[fd00::1]:1234')).toEqual(['fd00::1', '1234']);
    expect(splitEndpoint('fd00::1:1234')).toEqual(['fd00::1', '1234']);
    expect(splitEndpoint('fd00::1')).toEqual(['fd00::1', '-']);
    expect(splitEndpoint('example.com:80')).toEqual(['example.com', '80']);
    expect(splitEndpoint('10.0.0.1')).toEqual(['10.0.0.1', '-']);
    expect(splitEndpoint('10.0.0.1:')).toEqual(['10.0.0.1', '-']);
  });
});

describe('parseNetwork', () => {
  it('tolerates host bits and rejects bad prefixes', () => {
    expect(parseNetwork('10.0.0.7/8')).toBeDefined();
    expect(parseNetwork('10.0.0.0/33')).toBeUndefined();
    expect(parseNetwork('fd10:2::/129')).toBeUndefined();
    expect(parseNetwork('10.0.0.0')).toBeUndefined();
  });
});

describe('addressMatches', () => {
  it('matches CIDRs per family only', () => {
    expect(addressMatches('10.3.0.0/16', '10.3.9.9')).toBe(true);
    expect(addressMatches('10.3.0.0/16', '10.4.0.1')).toBe(false);
    expect(addressMatches('10.3.0.0/16', 'example.com')).toBe(false);
    expect(addressMatches('fd10:2::/32', 'fd10:2:0:0:0:0:0:9')).toBe(true);
    expect(addressMatches('fd10:2::/32', '10.3.9.9')).toBe(false);
    expect(addressMatches('::/0', '10.3.9.9')).toBe(false);
  });
  it('matches a full IPv6 address in any spelling', () => {
    expect(addressMatches('fd10::10', 'fd10:0:0:0:0:0:0:10')).toBe(true);
    expect(addressMatches('FD10:0:0:0:0:0:0:10', 'fd10::10')).toBe(true);
  });
  it('falls back to substrings, including the compressed form', () => {
    expect(addressMatches('10.0.1.4', '10.0.1.44')).toBe(true);
    expect(addressMatches('::10', 'fd10:0:0:2:0:0:0:10')).toBe(true);
    expect(addressMatches('contoso', 'www.Contoso.com')).toBe(true);
    expect(addressMatches('', 'anything')).toBe(true);
    expect(addressMatches('nope', '10.0.0.1')).toBe(false);
  });
  it('treats an invalid CIDR as plain text', () => {
    expect(addressMatches('a/b', 'x a/b y')).toBe(true);
  });
});
