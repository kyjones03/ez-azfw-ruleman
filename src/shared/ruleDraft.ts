// Editable "draft" model behind the collection editor's rules grid. Pure functions only, so the
// grid logic is unit-tested without React.
import {
  FQDN,
  IP_GROUP_ID,
  SERVICE_TAG,
  isValidPort,
  parseList,
  stableStringify,
  validateCollection,
  validateRule,
} from './rules';
import { addressEntryError } from './cidr';
import { nameError } from './naming';
import { ruleWarnings } from './risk';
import type {
  ApplicationProtocolType,
  ApplicationRule,
  FirewallRule,
  NatRule,
  NetworkProtocol,
  NetworkRule,
  RuleCollection,
  RuleLookups,
} from './types';

/** Azure collections are typed: every rule in a collection has the collection's type. */
export type CollectionKind = 'Network' | 'Application' | 'DNAT';
export type FilterAction = 'Allow' | 'Deny';

const RULE_TYPE: Record<CollectionKind, FirewallRule['ruleType']> = {
  Network: 'NetworkRule',
  Application: 'ApplicationRule',
  DNAT: 'NatRule',
};

/** Rule fields that hold lists, edited as comma/newline-separated text. */
export type ListField =
  | 'sourceAddresses'
  | 'sourceIpGroups'
  | 'destinationAddresses'
  /** Editor-only: service tags, stored in Azure's destinationAddresses alongside IPs. */
  | 'destinationServiceTags'
  | 'destinationFqdns'
  | 'destinationIpGroups'
  | 'destinationPorts'
  | 'targetFqdns'
  | 'fqdnTags'
  | 'targetUrls'
  | 'webCategories';

const LIST_FIELDS: ListField[] = [
  'sourceAddresses',
  'sourceIpGroups',
  'destinationAddresses',
  'destinationServiceTags',
  'destinationFqdns',
  'destinationIpGroups',
  'destinationPorts',
  'targetFqdns',
  'fqdnTags',
  'targetUrls',
  'webCategories',
];

/** Fields whose values are picked from lists loaded from Azure. */
export type PickerKind = 'ipGroup' | 'serviceTag' | 'fqdnTag' | 'webCategory';
export const PICKER: Partial<Record<ListField, PickerKind>> = {
  sourceIpGroups: 'ipGroup',
  destinationIpGroups: 'ipGroup',
  destinationServiceTags: 'serviceTag',
  fqdnTags: 'fqdnTag',
  webCategories: 'webCategory',
};

/** Source "type" choices, as in the Azure portal's rule grid. */
export const SOURCE_TYPES: { field: ListField; label: string }[] = [
  { field: 'sourceAddresses', label: 'IP/CIDR' },
  { field: 'sourceIpGroups', label: 'IP Group' },
];

/** Destination "type" choices per collection kind. */
export const DEST_TYPES: Record<
  CollectionKind,
  { field: ListField; label: string; placeholder: string }[]
> = {
  Network: [
    {
      field: 'destinationAddresses',
      label: 'IP/CIDR',
      placeholder: '10.1.0.0/16, 10.0.0.1-10.0.0.9, *',
    },
    {
      field: 'destinationServiceTags',
      label: 'Service tag',
      placeholder: 'Search service tags…',
    },
    { field: 'destinationFqdns', label: 'FQDN', placeholder: 'db.contoso.com' },
    {
      field: 'destinationIpGroups',
      label: 'IP Group',
      placeholder: 'Search IP Groups…',
    },
  ],
  Application: [
    {
      field: 'targetFqdns',
      label: 'FQDN',
      placeholder: '*.contoso.com, www.example.com',
    },
    {
      field: 'fqdnTags',
      label: 'FQDN tag',
      placeholder: 'WindowsUpdate, AzureKubernetesService',
    },
    {
      field: 'targetUrls',
      label: 'URL (Premium)',
      placeholder: 'www.contoso.com/path',
    },
    {
      field: 'webCategories',
      label: 'Web category',
      placeholder: 'Gambling, SocialNetworking',
    },
    {
      field: 'destinationAddresses',
      label: 'IP/CIDR',
      placeholder: '10.1.0.0/16, 52.10.0.0/24',
    },
  ],
  DNAT: [
    {
      field: 'destinationAddresses',
      label: 'Firewall IP',
      placeholder: '20.62.18.40',
    },
  ],
};

export const NET_PROTOCOLS: NetworkProtocol[] = ['TCP', 'UDP', 'ICMP', 'Any'];
export const NAT_PROTOCOLS: NetworkProtocol[] = ['TCP', 'UDP'];

export interface RuleRow {
  /** Stable identity for React and error mapping. */
  key: string;
  /** The rule this row was loaded from; fields the grid doesn't show are preserved from it. */
  base?: FirewallRule;
  name: string;
  description: string;
  lists: Record<ListField, string>;
  /** Which list the grid's Source / Destination cells edit. */
  sourceField: ListField;
  destField: ListField;
  protocols: NetworkProtocol[];
  /** Application protocols as text, e.g. "Https:443, Http:80". */
  appProtocols: string;
  translatedAddress: string;
  translatedFqdn: string;
  translatedPort: string;
  terminateTLS: boolean;
}

export interface CollectionDraft {
  key: string;
  /** The collection this was loaded from (undefined for a new one). */
  base?: RuleCollection;
  name: string;
  priority: string;
  kind: CollectionKind;
  action: FilterAction;
  rows: RuleRow[];
}

let seq = 0;
const nextKey = (prefix: string) => `${prefix}${++seq}`;

const join = (v?: string[]) => (v ?? []).join(', ');

/** A destination entry that's a service tag (letters, optionally ".Region"), not an IP or "*". */
const isServiceTag = (v: string) => SERVICE_TAG.test(v.trim());

/** IPs then tags, but in the original rule's order when the entries are unchanged. */
function mergeDestinations(
  addresses: string[],
  tags: string[],
  original: string[] | undefined,
): string[] {
  const merged = [...addresses, ...tags];
  const sorted = (l: string[]) => [...l].sort().join('\n');
  return original && sorted(original) === sorted(merged) ? original : merged;
}

/** The kind of an existing collection (filter collections take the type of their rules). */
export function collectionKindOf(c: RuleCollection): CollectionKind {
  if (c.ruleCollectionType === 'FirewallPolicyNatRuleCollection') return 'DNAT';
  return c.rules[0]?.ruleType === 'ApplicationRule' ? 'Application' : 'Network';
}

const firstFilled = (
  lists: Record<ListField, string>,
  options: { field: ListField }[],
) => options.find((o) => lists[o.field].trim())?.field ?? options[0].field;

export function emptyRow(kind: CollectionKind): RuleRow {
  const lists = Object.fromEntries(LIST_FIELDS.map((f) => [f, ''])) as Record<
    ListField,
    string
  >;
  return {
    key: nextKey('r'),
    name: '',
    description: '',
    lists,
    sourceField: 'sourceAddresses',
    destField: DEST_TYPES[kind][0].field,
    protocols: ['TCP'],
    appProtocols: 'Https:443',
    translatedAddress: '',
    translatedFqdn: '',
    translatedPort: '',
    terminateTLS: false,
  };
}

export function rowFromRule(rule: FirewallRule, kind: CollectionKind): RuleRow {
  const row = emptyRow(kind);
  const r = rule as Partial<NetworkRule & ApplicationRule & NatRule> as Record<
    string,
    unknown
  >;
  for (const f of LIST_FIELDS)
    row.lists[f] = join(r[f] as string[] | undefined);
  // Azure keeps service tags and IPs in one list; the editor shows them as separate types.
  const destinations = (r.destinationAddresses as string[] | undefined) ?? [];
  row.lists.destinationAddresses = join(
    destinations.filter((v) => !isServiceTag(v)),
  );
  row.lists.destinationServiceTags = join(destinations.filter(isServiceTag));
  row.base = rule;
  row.name = rule.name;
  row.description = rule.description ?? '';
  row.sourceField = firstFilled(row.lists, SOURCE_TYPES);
  row.destField = firstFilled(row.lists, DEST_TYPES[kind]);
  if (rule.ruleType !== 'ApplicationRule')
    row.protocols = rule.ipProtocols ?? ['TCP'];
  if (rule.ruleType === 'ApplicationRule') {
    row.appProtocols = (rule.protocols ?? [])
      .map((p) => `${p.protocolType}:${p.port}`)
      .join(', ');
    row.terminateTLS = !!rule.terminateTLS;
  }
  if (rule.ruleType === 'NatRule') {
    row.translatedAddress = rule.translatedAddress ?? '';
    row.translatedFqdn = rule.translatedFqdn ?? '';
    row.translatedPort = rule.translatedPort ?? '';
  }
  return row;
}

/** A copy of a row for "Duplicate": new identity, name suffixed, nothing preserved as original. */
export function duplicateRow(row: RuleRow, existingNames: string[]): RuleRow {
  const taken = new Set(existingNames.map((n) => n.toLowerCase()));
  let name = `${row.name}-copy`;
  for (let i = 2; taken.has(name.toLowerCase()); i++)
    name = `${row.name}-copy${i}`;
  return {
    ...structuredClone({ ...row, base: undefined }),
    key: nextKey('r'),
    name,
    base: row.base ? { ...row.base, name } : undefined,
  };
}

/**
 * Switches which list a Source/Destination cell edits. Text typed under the old type moves to
 * the new one when the new one is empty, so changing the type doesn't lose what was typed.
 */
export function switchField(
  row: RuleRow,
  side: 'source' | 'dest',
  to: ListField,
): RuleRow {
  const from = side === 'source' ? row.sourceField : row.destField;
  if (from === to) return row;
  const lists = { ...row.lists };
  // Typed text moves between free-text types (e.g. IP → FQDN); picked values (IP Groups, tags)
  // are a different kind of thing, so they stay where they are.
  if (!lists[to].trim() && !PICKER[from] && !PICKER[to]) {
    lists[to] = lists[from];
    lists[from] = '';
  }
  return side === 'source'
    ? { ...row, lists, sourceField: to }
    : { ...row, lists, destField: to };
}

/** True when the user hasn't typed anything (defaults don't count); blank rows are ignored on save. */
export function isBlankRow(row: RuleRow): boolean {
  return (
    !row.base &&
    !row.name.trim() &&
    !row.description.trim() &&
    LIST_FIELDS.every((f) => !row.lists[f].trim()) &&
    !row.translatedAddress.trim() &&
    !row.translatedFqdn.trim() &&
    !row.translatedPort.trim()
  );
}

function parseAppProtocols(input: string): ApplicationRule['protocols'] {
  return parseList(input).map((token) => {
    const [type, port] = token.split(':');
    const protocolType = (
      ['Http', 'Https', 'Mssql'] as ApplicationProtocolType[]
    ).find((t) => t.toLowerCase() === type.toLowerCase());
    const defaultPort =
      protocolType === 'Https' ? 443 : protocolType === 'Http' ? 80 : undefined;
    return {
      protocolType,
      port: port ? Number(port) : defaultPort,
    };
  });
}

export function ruleFromRow(row: RuleRow, kind: CollectionKind): FirewallRule {
  const ruleType = RULE_TYPE[kind];
  const list = (f: ListField) => parseList(row.lists[f]);
  // Keep fields the grid doesn't expose, but only from a rule of the same type.
  const original = row.base?.ruleType === ruleType ? row.base : {};
  const destinations = mergeDestinations(
    list('destinationAddresses'),
    list('destinationServiceTags'),
    (row.base as { destinationAddresses?: string[] } | undefined)
      ?.destinationAddresses,
  );
  const common = {
    name: row.name.trim(),
    description: row.description.trim() || undefined,
    sourceAddresses: list('sourceAddresses'),
    sourceIpGroups: list('sourceIpGroups'),
  };
  if (kind === 'Network') {
    return {
      ...original,
      ...common,
      ruleType: 'NetworkRule',
      ipProtocols: row.protocols,
      destinationAddresses: destinations,
      destinationFqdns: list('destinationFqdns'),
      destinationIpGroups: list('destinationIpGroups'),
      destinationPorts: list('destinationPorts'),
    } as NetworkRule;
  }
  if (kind === 'Application') {
    return {
      ...original,
      ...common,
      ruleType: 'ApplicationRule',
      protocols: parseAppProtocols(row.appProtocols),
      targetFqdns: list('targetFqdns'),
      fqdnTags: list('fqdnTags'),
      targetUrls: list('targetUrls'),
      webCategories: list('webCategories'),
      destinationAddresses: destinations,
      terminateTLS: row.terminateTLS || undefined,
    } as ApplicationRule;
  }
  return {
    ...original,
    ...common,
    ruleType: 'NatRule',
    ipProtocols: row.protocols,
    destinationAddresses: destinations,
    destinationPorts: list('destinationPorts'),
    translatedAddress: row.translatedAddress.trim() || undefined,
    translatedFqdn: row.translatedFqdn.trim() || undefined,
    translatedPort: row.translatedPort.trim() || undefined,
  } as NatRule;
}

export function draftFromCollection(c: RuleCollection): CollectionDraft {
  const kind = collectionKindOf(c);
  return {
    key: nextKey('c'),
    base: c,
    name: c.name,
    priority: String(c.priority),
    kind,
    action: c.action.type === 'Deny' ? 'Deny' : 'Allow',
    rows: (c.rules as FirewallRule[]).map((r) => rowFromRule(r, kind)),
  };
}

export function emptyCollection(
  priority: number,
  kind: CollectionKind = 'Network',
): CollectionDraft {
  return {
    key: nextKey('c'),
    name: '',
    priority: String(priority),
    kind,
    action: 'Allow',
    rows: [emptyRow(kind)],
  };
}

/**
 * Changes a collection's kind. Only allowed while it has no real rules, because rule types
 * differ; blank rows are reset to the new kind's defaults.
 */
export function setCollectionKind(
  d: CollectionDraft,
  kind: CollectionKind,
): CollectionDraft {
  if (d.kind === kind || d.rows.some((r) => !isBlankRow(r))) return d;
  return { ...d, kind, rows: d.rows.length ? [emptyRow(kind)] : [] };
}

export function collectionFromDraft(d: CollectionDraft): RuleCollection {
  const rules = d.rows
    .filter((r) => !isBlankRow(r))
    .map((r) => ruleFromRow(r, d.kind));
  const base = { name: d.name.trim(), priority: Number(d.priority) };
  return d.kind === 'DNAT'
    ? {
        ...base,
        ruleCollectionType: 'FirewallPolicyNatRuleCollection',
        action: { type: 'DNAT' },
        rules: rules as NatRule[],
      }
    : {
        ...base,
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
        action: { type: d.action },
        rules: rules as (NetworkRule | ApplicationRule)[],
      };
}

/** Grid cells that can show their own error. */
export type CellKey =
  | 'name'
  | ListField
  | 'appProtocols'
  | 'translatedAddress'
  | 'translatedFqdn'
  | 'translatedPort';

/** Values loaded from Azure; when present, picked entries are checked against them. */
export interface KnownValues {
  ipGroups?: Set<string>;
  serviceTags?: Set<string>;
  fqdnTags?: Set<string>;
  webCategories?: Set<string>;
}

export function knownValuesFromLookups(
  lookups: RuleLookups | undefined,
): KnownValues {
  if (!lookups) return {};
  const known = (label: string, values: string[]) =>
    !lookups.errors.some((e) => e.toLowerCase().includes(label)) &&
    values.length
      ? new Set(values.map((v) => v.toLowerCase()))
      : undefined;
  return {
    ipGroups: known(
      'ip groups',
      lookups.ipGroups.map((g) => g.id),
    ),
    serviceTags: known(
      'service tags',
      lookups.serviceTags.map((t) => t.name),
    ),
    fqdnTags: known('fqdn tags', lookups.fqdnTags),
    webCategories: known(
      'web categories',
      lookups.webCategories.map((c) => c.name),
    ),
  };
}

const lower = (v: string) => v.trim().toLowerCase();

/** "first problem (and N more)". */
function summarize(problems: string[]): string | undefined {
  if (!problems.length) return undefined;
  const end = (s: string) => (/[.?!]$/.test(s) ? s : `${s}.`);
  return problems.length > 1
    ? `${problems[0].replace(/[.]$/, '')} (and ${problems.length - 1} more).`
    : end(problems[0]);
}

function fqdnProblem(v: string, wildcard: boolean): string | undefined {
  if (wildcard && v === '*') return undefined;
  if (/^[a-z]+:\/\//i.test(v) || v.includes('/'))
    return `"${v}": enter just the host name, without https:// or a path`;
  if (/\s/.test(v)) return `"${v}" can't contain spaces`;
  if (!wildcard && v.startsWith('*'))
    return `"${v}": wildcards aren't supported here`;
  return FQDN.test(v) ? undefined : `"${v}" isn't a valid host name`;
}

/**
 * Live check of one grid cell, with the same rules and wording as the deploy wizard's fields.
 * Returns undefined when the cell is fine (empty cells are judged by the row check on save).
 */
export function cellError(
  cell: CellKey,
  row: RuleRow,
  kind: CollectionKind,
  known: KnownValues = {},
): string | undefined {
  const items = (f: ListField) => parseList(row.lists[f]);
  switch (cell) {
    case 'name': {
      // Existing names were accepted by Azure; only judge new or renamed rules.
      if (row.base && row.name.trim() === row.base.name) return undefined;
      return row.name.trim() ? nameError('rule', row.name.trim()) : undefined;
    }
    case 'sourceAddresses':
    case 'destinationAddresses':
      return summarize(
        items(cell)
          .map((v) =>
            kind === 'DNAT' && cell === 'destinationAddresses' && v === '*'
              ? '"*" isn\'t allowed: use the firewall\'s public IP'
              : addressEntryError(v),
          )
          .filter((e): e is string => !!e),
      );
    case 'destinationServiceTags':
      return summarize(
        items(cell).flatMap((v) =>
          !SERVICE_TAG.test(v)
            ? [`"${v}" isn't a service tag name`]
            : known.serviceTags && !known.serviceTags.has(lower(v))
              ? [`"${v}" isn't a service tag in this region`]
              : [],
        ),
      );
    case 'sourceIpGroups':
    case 'destinationIpGroups':
      return summarize(
        items(cell).flatMap((v) =>
          !IP_GROUP_ID.test(v)
            ? [
                `"${v}" isn't an IP Group resource ID; pick the group from the list`,
              ]
            : known.ipGroups && !known.ipGroups.has(lower(v))
              ? [`IP Group "${v.split('/').pop()}" wasn't found`]
              : [],
        ),
      );
    case 'destinationFqdns':
      return summarize(
        items(cell)
          .map((v) => fqdnProblem(v, false))
          .filter((e): e is string => !!e),
      );
    case 'targetFqdns':
      return summarize(
        items(cell)
          .map((v) => fqdnProblem(v, true))
          .filter((e): e is string => !!e),
      );
    case 'targetUrls':
      return summarize(
        items(cell).flatMap((v) =>
          /^[a-z]+:\/\//i.test(v)
            ? [`"${v}": leave out http:// or https://`]
            : /^[^\s/]+\.[^\s/]+(\/\S*)?$/.test(v)
              ? []
              : [`"${v}" isn't a valid URL (e.g. www.contoso.com/path)`],
        ),
      );
    case 'fqdnTags':
      return summarize(
        items(cell).flatMap((v) =>
          known.fqdnTags && !known.fqdnTags.has(lower(v))
            ? [`"${v}" isn't a known FQDN tag`]
            : [],
        ),
      );
    case 'webCategories':
      return summarize(
        items(cell).flatMap((v) =>
          known.webCategories && !known.webCategories.has(lower(v))
            ? [`"${v}" isn't a known web category`]
            : [],
        ),
      );
    case 'destinationPorts': {
      const ports = items(cell);
      const bad = ports
        .filter((p) => !isValidPort(p))
        .map((p) => `"${p}" isn't a valid port. Use 443, 8000-8080 or *`);
      if (bad.length) return summarize(bad);
      if (kind === 'DNAT' && ports.length > 1)
        return 'DNAT rules take exactly one destination port.';
      if (kind === 'DNAT' && ports[0] === '*')
        return 'DNAT rules need a specific port, not *.';
      return undefined;
    }
    case 'appProtocols':
      return summarize(
        parseList(row.appProtocols).flatMap((token) => {
          const [type, port] = token.split(':');
          if (!/^(https?|mssql)$/i.test(type))
            return [`"${token}": protocol must be Http, Https or Mssql`];
          if (/^mssql$/i.test(type) && !port)
            return [`"${token}": Mssql needs a port, e.g. Mssql:1433`];
          if (port && !(Number(port) >= 1 && Number(port) <= 64000))
            return [`"${token}": port must be 1-64000`];
          return [];
        }),
      );
    case 'translatedAddress':
      return row.translatedAddress.trim()
        ? row.translatedAddress.includes('/') ||
          row.translatedAddress.includes('-')
          ? 'Enter a single IP address, not a CIDR or range.'
          : summarize(
              [addressEntryError(row.translatedAddress)].filter(
                (e): e is string => !!e,
              ),
            )
        : undefined;
    case 'translatedFqdn':
      return row.translatedFqdn.trim()
        ? summarize(
            [fqdnProblem(row.translatedFqdn.trim(), false)].filter(
              (e): e is string => !!e,
            ),
          )
        : undefined;
    case 'translatedPort': {
      const p = row.translatedPort.trim();
      return p && (!isValidPort(p) || p === '*' || p.includes('-'))
        ? 'Enter a single port number (1-65535).'
        : undefined;
    }
  }
}

const CELLS: Record<CollectionKind, CellKey[]> = {
  Network: [
    'name',
    'sourceAddresses',
    'sourceIpGroups',
    'destinationAddresses',
    'destinationServiceTags',
    'destinationFqdns',
    'destinationIpGroups',
    'destinationPorts',
  ],
  Application: [
    'name',
    'sourceAddresses',
    'sourceIpGroups',
    'appProtocols',
    'targetFqdns',
    'fqdnTags',
    'targetUrls',
    'webCategories',
    'destinationAddresses',
  ],
  DNAT: [
    'name',
    'sourceAddresses',
    'sourceIpGroups',
    'destinationAddresses',
    'destinationPorts',
    'translatedAddress',
    'translatedFqdn',
    'translatedPort',
  ],
};

/** All cell problems in a row, for rows that are new or edited. */
export function rowCellErrors(
  row: RuleRow,
  kind: CollectionKind,
  known: KnownValues = {},
): Partial<Record<CellKey, string>> {
  const out: Partial<Record<CellKey, string>> = {};
  for (const cell of CELLS[kind]) {
    const e = cellError(cell, row, kind, known);
    if (e) out[cell] = e;
  }
  return out;
}

/** Whether a row differs from the rule it was loaded from (new rows count as changed). */
export function rowChanged(row: RuleRow, kind: CollectionKind): boolean {
  if (!row.base) return true;
  return stableStringify(ruleFromRow(row, kind)) !== stableStringify(row.base);
}

// Format problems are reported per cell, so the row summary keeps only "missing" problems.
const FORMAT_ERROR =
  /isn't valid|aren't valid|^Invalid port|^Rule name "|^Translated (address|FQDN):|^Firewall IP:/;

export interface DraftErrors {
  /** Collection-level problems (name, priority, duplicates). */
  collection: string[];
  /** Per-row problems that aren't tied to one cell (e.g. a missing destination). */
  rows: Record<string, string[]>;
  /** Per-cell problems, shown live under the cell. */
  cells: Record<string, Partial<Record<CellKey, string>>>;
  /** Per-row risk warnings (valid but broad); they don't block saving. */
  warnings: Record<string, string[]>;
  count: number;
}

/** Validates a collection draft against the other collections in the same group. */
export function validateDraft(
  d: CollectionDraft,
  others: { name: string; priority: number | string }[],
  known: KnownValues = {},
): DraftErrors {
  const built = collectionFromDraft(d);
  const collection: string[] = [];
  const nameChanged = !d.base || d.base.name !== built.name;
  const collectionNameError = !built.name
    ? 'Collection name is required.'
    : nameChanged
      ? nameError('ruleCollection', built.name)
      : undefined;
  if (collectionNameError) collection.push(collectionNameError);
  collection.push(
    ...validateCollection({ ...built, rules: [] }).filter(
      (e) => !e.startsWith('Collection name'),
    ),
  );
  if (
    built.name &&
    others.some((o) => o.name.toLowerCase() === built.name.toLowerCase())
  ) {
    collection.unshift(
      `A collection named "${built.name}" already exists in this group.`,
    );
  }
  const clash = others.find((o) => Number(o.priority) === built.priority);
  if (clash && Number.isInteger(built.priority)) {
    collection.push(
      `Priority ${built.priority} is already used by "${clash.name}" in this group. Give each collection its own priority so the processing order is unambiguous.`,
    );
  }
  const rows: Record<string, string[]> = {};
  const cells: DraftErrors['cells'] = {};
  const warnings: Record<string, string[]> = {};
  const seen = new Set<string>();
  let count = collection.length;
  for (const row of d.rows) {
    if (isBlankRow(row)) continue;
    const rule = ruleFromRow(row, d.kind);
    const changed = rowChanged(row, d.kind);
    let errs = validateRule(rule);
    if (changed) {
      const cellProblems = rowCellErrors(row, d.kind, known);
      if (Object.keys(cellProblems).length) {
        cells[row.key] = cellProblems;
        count += Object.keys(cellProblems).length;
      }
      errs = errs.filter((e) => !FORMAT_ERROR.test(e));
    }
    const nameKey = row.name.trim().toLowerCase();
    if (nameKey && seen.has(nameKey))
      errs.unshift(
        `Another rule in this collection is named "${row.name.trim()}".`,
      );
    seen.add(nameKey);
    if (errs.length) {
      rows[row.key] = errs;
      count += errs.length;
    }
    const risky = ruleWarnings(rule, d.kind === 'DNAT' ? 'DNAT' : d.action);
    if (risky.length) warnings[row.key] = risky;
  }
  return { collection, rows, cells, warnings, count };
}
