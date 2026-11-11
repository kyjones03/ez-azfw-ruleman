import type { ThreatIntelMode } from './deploy';
import type { ChangeItem } from './types';
import {
  POLICY_SETTING_KEYS,
  settingsChanges,
  type PolicyAdvancedSettings,
} from './resourceSettings';

export const THREAT_INTEL_MODES: readonly ThreatIntelMode[] = [
  'Off',
  'Alert',
  'Deny',
];

export function isThreatIntelMode(value: unknown): value is ThreatIntelMode {
  return value === 'Off' || value === 'Alert' || value === 'Deny';
}

export interface PolicyModeConfig {
  name: string;
  threatIntelMode: ThreatIntelMode;
  settings?: PolicyAdvancedSettings;
}

export function policyConfigurationChanges(
  before: PolicyModeConfig,
  after: PolicyModeConfig,
): ChangeItem[] {
  return [
    ...(before.threatIntelMode !== after.threatIntelMode
      ? policyModeChanges(before.threatIntelMode, after.threatIntelMode)
      : []),
    ...(after.settings
      ? settingsChanges(
          before.settings ?? after.settings,
          after.settings,
          POLICY_SETTING_KEYS,
          'policy',
        )
      : []),
  ];
}

export function policyConfigurationWarnings(
  before: PolicyModeConfig,
  after: PolicyModeConfig,
): string[] {
  const warnings =
    before.threatIntelMode !== after.threatIntelMode
      ? policyModeWarnings(before.threatIntelMode, after.threatIntelMode)
      : [];
  if (
    after.settings &&
    policyConfigurationChanges(before, after).some((c) =>
      c.detail?.startsWith('DNS'),
    )
  )
    warnings.push(
      'DNS changes can interrupt name resolution. Client virtual networks must use the firewall address when DNS proxy is enabled.',
    );
  if (
    after.settings &&
    policyConfigurationChanges(before, after).some((c) =>
      c.detail?.startsWith('Threat-intelligence allowlist'),
    )
  )
    warnings.push(
      'Allowlisted IPs and FQDNs bypass threat-intelligence filtering, including on inheriting child policies.',
    );
  if (
    after.settings &&
    policyConfigurationChanges(before, after).some((c) =>
      c.detail?.startsWith('TLS'),
    )
  )
    warnings.push(
      'TLS configuration affects decrypted traffic and replaces the selected policy managed-identity association. The CA must be trusted by clients and the identity must already have Key Vault secret access. Per-rule TLS inspection remains separately configured.',
    );
  if (
    after.settings &&
    policyConfigurationChanges(before, after).some((c) =>
      c.detail?.startsWith('SNAT'),
    )
  )
    warnings.push(
      'SNAT changes affect address translation and return routing on every firewall using this policy.',
    );
  return warnings;
}
export function policyModeError(
  mode: ThreatIntelMode,
  tier?: string,
  parentMode?: ThreatIntelMode,
): string | undefined {
  if (tier === 'Basic' && mode === 'Deny')
    return 'Basic policies support threat-intelligence alerts, not Deny mode.';
  if (
    parentMode &&
    THREAT_INTEL_MODES.indexOf(mode) < THREAT_INTEL_MODES.indexOf(parentMode)
  )
    return `Threat intelligence cannot be less strict than the parent policy (${parentMode}).`;
  return undefined;
}

export function policyModeChanges(
  before: ThreatIntelMode,
  after: ThreatIntelMode,
): ChangeItem[] {
  return [
    {
      target: 'policy',
      kind: 'modified',
      detail: `Threat intelligence: ${before} -> ${after}`,
    },
  ];
}

export function policyModeWarnings(
  before: ThreatIntelMode,
  after: ThreatIntelMode,
): string[] {
  const warning =
    after === 'Off'
      ? 'Disables threat-intelligence alerts and blocking.'
      : after === 'Deny'
        ? 'Blocks traffic to known malicious IP addresses and domains; this may interrupt traffic.'
        : before === 'Deny'
          ? 'Stops blocking threat-intelligence matches; traffic will only generate alerts.'
          : 'Enables threat-intelligence alerts without blocking matches.';
  return [
    warning,
    'This policy setting affects all associated firewalls and inheriting child policies.',
  ];
}
