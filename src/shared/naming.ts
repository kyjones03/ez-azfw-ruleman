// Azure naming rules for the resources the deploy wizard creates. Source:
// https://learn.microsoft.com/azure/azure-resource-manager/management/resource-name-rules

export type NameKind =
  | 'firewall'
  | 'policy'
  | 'vnet'
  | 'publicIp'
  | 'ipGroup'
  | 'ruleCollectionGroup'
  | 'ruleCollection'
  | 'rule'
  | 'resourceGroup';

interface NameRule {
  label: string;
  min: number;
  max: number;
  /** Characters allowed anywhere in the name. */
  allowed: RegExp;
  allowedText: string;
  start: RegExp;
  startText: string;
  end: RegExp;
  endText: string;
}

// Network resources: alphanumerics, underscores, periods and hyphens; start alphanumeric; end
// alphanumeric or underscore.
const network = (label: string, min: number, max: number): NameRule => ({
  label,
  min,
  max,
  allowed: /[A-Za-z0-9_.-]/,
  allowedText: 'letters, digits, underscores (_), periods (.) and hyphens (-)',
  start: /^[A-Za-z0-9]/,
  startText: 'must start with a letter or digit',
  end: /[A-Za-z0-9_]$/,
  endText: 'must end with a letter, digit or underscore',
});

export const NAME_RULES: Record<NameKind, NameRule> = {
  firewall: network('Firewall name', 1, 80),
  policy: network('Policy name', 1, 80),
  vnet: network('VNet name', 2, 64),
  publicIp: network('Public IP name', 1, 80),
  ipGroup: network('IP group name', 1, 80),
  ruleCollectionGroup: network('Rule collection group name', 1, 80),
  ruleCollection: network('Collection name', 1, 80),
  rule: network('Rule name', 1, 80),
  // Resource groups also allow parentheses and Unicode letters/digits, but can't end with a period.
  resourceGroup: {
    label: 'Resource group name',
    min: 1,
    max: 90,
    allowed: /[\p{L}\p{Nd}_.()-]/u,
    allowedText:
      'letters, digits, underscores (_), periods (.), hyphens (-) and parentheses',
    start: /^./u,
    startText: '',
    end: /[^.]$/u,
    endText: "can't end with a period",
  },
};

const describe = (c: string) =>
  c === ' ' ? 'spaces' : /\s/.test(c) ? 'whitespace' : `"${c}"`;

/**
 * Returns a specific, readable problem with `value` as an Azure name, or undefined when valid.
 * `label` overrides the rule's label (e.g. "Policy resource group").
 */
export function nameError(
  kind: NameKind,
  value: string | undefined,
  label?: string,
): string | undefined {
  const rule = NAME_RULES[kind];
  const what = label ?? rule.label;
  const v = value ?? '';
  if (!v) return `${what} is required.`;
  const chars = [...v];
  const bad = [...new Set(chars.filter((c) => !rule.allowed.test(c)))];
  if (bad.length) {
    return `${what} can't contain ${bad.map(describe).join(', ')}. Use ${rule.allowedText}.`;
  }
  if (chars.length < rule.min || chars.length > rule.max) {
    return `${what} must be ${rule.min}-${rule.max} characters (it's ${chars.length}).`;
  }
  if (!rule.start.test(v)) return `${what} ${rule.startText}.`;
  if (!rule.end.test(v)) return `${what} ${rule.endText}.`;
  return undefined;
}

export const TAG_NAME_MAX = 512;
export const TAG_VALUE_MAX = 256;
export const MAX_TAGS = 50;
const TAG_NAME_FORBIDDEN = /[<>%&\\?/]/g;

/** Azure tag rules: names up to 512 characters without < > % & \ ? /, values up to 256. */
export function tagError(name: string, value: string): string | undefined {
  if (!name) return 'Tag name is required.';
  const bad = [...new Set(name.match(TAG_NAME_FORBIDDEN) ?? [])];
  if (bad.length)
    return `Tag "${name}" can't contain ${bad.map((c) => `"${c}"`).join(', ')}.`;
  if (name.length > TAG_NAME_MAX)
    return `Tag name "${name.slice(0, 20)}…" is longer than ${TAG_NAME_MAX} characters.`;
  if (value.length > TAG_VALUE_MAX)
    return `Tag "${name}" value is longer than ${TAG_VALUE_MAX} characters.`;
  return undefined;
}
