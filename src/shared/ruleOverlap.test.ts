import { describe, expect, it } from 'vitest';
import { ruleContents, ruleOverlap } from './ruleOverlap';
import type { ApplicationRule, NetworkRule } from './types';

const net: NetworkRule = {
  ruleType: 'NetworkRule',
  name: 'a',
  sourceAddresses: ['10.0.0.1-10.0.0.20'],
  destinationAddresses: ['10.20.0.0/24'],
  destinationPorts: ['8000-8090'],
  ipProtocols: ['TCP'],
};
const app: ApplicationRule = {
  ruleType: 'ApplicationRule',
  name: 'web',
  sourceAddresses: ['10.0.0.0/24'],
  protocols: [{ protocolType: 'Https', port: 443 }],
  targetFqdns: ['*.contoso.com'],
};

describe('import overlap warnings', () => {
  it('detects partial address and port intersections, not just containment', () => {
    expect(
      ruleOverlap(net, {
        ...net,
        sourceAddresses: ['10.0.0.15-10.0.0.30'],
        destinationPorts: ['8080-9000'],
      }),
    ).toBe('overlap');
    expect(ruleOverlap(net, { ...net, sourceAddresses: ['10.0.1.0/24'] })).toBe(
      'none',
    );
    expect(ruleOverlap(net, { ...net, destinationPorts: ['443'] })).toBe(
      'none',
    );
    expect(ruleOverlap(net, { ...net, ipProtocols: ['UDP'] })).toBe('none');
  });

  it('resolves known IP Groups and marks missing members as potential, not certain', () => {
    const grouped = {
      ...net,
      sourceAddresses: [],
      sourceIpGroups: ['group-id'],
    };
    expect(ruleOverlap(net, grouped)).toBe('potential');
    expect(
      ruleOverlap(net, grouped, new Map([['group-id', ['192.168.0.0/24']]])),
    ).toBe('none');
    expect(
      ruleOverlap(net, grouped, new Map([['group-id', ['10.0.0.5']]])),
    ).toBe('overlap');
  });

  it('handles FQDN wildcards and application protocol/port combinations', () => {
    expect(
      ruleOverlap(app, { ...app, targetFqdns: ['login.contoso.com'] }),
    ).toBe('overlap');
    expect(ruleOverlap(app, { ...app, targetFqdns: ['www.example.com'] })).toBe(
      'none',
    );
    expect(
      ruleOverlap(app, {
        ...app,
        protocols: [{ protocolType: 'Http', port: 443 }],
      }),
    ).toBe('none');
    expect(
      ruleOverlap(app, {
        ...app,
        targetFqdns: [],
        targetUrls: ['login.contoso.com/path'],
      }),
    ).toBe('potential');
  });

  it('does not guess DNS or service-tag membership and distinguishes cross-type matches', () => {
    expect(ruleOverlap({ ...net, destinationPorts: ['443'] }, app)).toBe(
      'potential',
    );
    expect(
      ruleOverlap(net, { ...net, destinationAddresses: ['AzureCloud'] }),
    ).toBe('potential');
  });

  it('ignores names, descriptions and list ordering when identifying equivalent traffic', () => {
    const a = { ...net, ipProtocols: ['TCP', 'UDP'] as const };
    const b = {
      ...net,
      name: 'renamed',
      description: 'Different note',
      ipProtocols: ['UDP', 'TCP'] as const,
    };
    expect(ruleContents({ ...a, ipProtocols: [...a.ipProtocols] })).toBe(
      ruleContents({ ...b, ipProtocols: [...b.ipProtocols] }),
    );
    expect(ruleContents({ ...net, description: 'Case' }, true)).not.toBe(
      ruleContents({ ...net, description: 'case' }, true),
    );
  });
});
