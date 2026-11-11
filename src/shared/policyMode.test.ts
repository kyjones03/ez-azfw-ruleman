import { describe, expect, it } from 'vitest';
import {
  isThreatIntelMode,
  policyModeError,
  policyModeWarnings,
} from './policyMode';

describe('policy threat-intelligence settings', () => {
  it('accepts only supported modes and enforces Basic-tier limitations', () => {
    expect(isThreatIntelMode('Deny')).toBe(true);
    expect(isThreatIntelMode('Allow')).toBe(false);
    expect(isThreatIntelMode(undefined)).toBe(false);
    expect(policyModeError('Deny', 'Basic')).toContain('not Deny');
    expect(policyModeError('Alert', 'Basic')).toBeUndefined();
  });

  it('never allows a child to weaken inherited threat intelligence', () => {
    expect(policyModeError('Off', 'Standard', 'Alert')).toContain(
      'less strict',
    );
    expect(policyModeError('Alert', 'Premium', 'Deny')).toContain(
      'less strict',
    );
    expect(policyModeError('Deny', 'Standard', 'Alert')).toBeUndefined();
    expect(policyModeError('Off', 'Standard', 'Off')).toBeUndefined();
  });

  it('warns about blocking, weakening protection and scope of impact', () => {
    expect(policyModeWarnings('Alert', 'Deny').join(' ')).toContain(
      'may interrupt traffic',
    );
    expect(policyModeWarnings('Deny', 'Alert').join(' ')).toContain(
      'Stops blocking',
    );
    expect(policyModeWarnings('Alert', 'Off').join(' ')).toContain('Disables');
    expect(policyModeWarnings('Off', 'Alert').join(' ')).toContain(
      'child policies',
    );
  });
});
