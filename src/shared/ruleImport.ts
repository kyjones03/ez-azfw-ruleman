import { csvCell } from './csv';
import {
  collectionFromDraft,
  collectionKindOf,
  emptyCollection,
  NET_PROTOCOLS,
  NAT_PROTOCOLS,
  validateDraft,
  type CollectionKind,
  type KnownValues,
} from './ruleDraft';
import {
  newGroupErrors,
  parseList,
  SERVICE_TAG,
  stableStringify,
  summarizeRule,
  validateGroup,
} from './rules';
import { ruleContents, ruleOverlap } from './ruleOverlap';
import type { IpGroupMembers } from './flow';
import type {
  CandidateStatus,
  FirewallRule,
  RuleCollectionGroup,
} from './types';

export const MAX_RULE_IMPORT_BYTES = 5 * 1024 * 1024;
export const RULE_IMPORT_COLUMNS = [
  'Rule collection group',
  'Group priority',
  'Rule collection',
  'Collection priority',
  'Collection type',
  'Action',
  'Rule name',
  'Description',
  'Source addresses',
  'Source IP Groups',
  'Protocols',
  'Destination ports',
  'Destination addresses',
  'Destination IP Groups',
  'Destination FQDNs',
  'Target FQDNs',
  'Target URLs',
  'FQDN tags',
  'Web categories',
  'TLS inspection',
  'Translated address',
  'Translated FQDN',
  'Translated port',
] as const;
type Column = (typeof RULE_IMPORT_COLUMNS)[number];
const REQUIRED: Column[] = [
  'Rule collection group',
  'Group priority',
  'Rule collection',
  'Collection priority',
  'Collection type',
  'Action',
  'Rule name',
  'Protocols',
];

export interface RuleImportChoice {
  action: 'import' | 'replace' | 'skip';
  /** Exact conflicts that were displayed when the user made this choice. */
  token?: string;
}
export type RuleImportChoices = Record<string, RuleImportChoice>;
export interface RuleImportIssue {
  line: number;
  message: string;
}
export interface RuleImportConflict {
  kind: 'same-name' | 'duplicate' | 'overlap' | 'potential-overlap';
  target: string;
  action: string;
  inherited: boolean;
  summary: string;
}
export interface RuleImportRow {
  line: number;
  group: string;
  collection: string;
  kind: CollectionKind;
  action: string;
  rule: FirewallRule;
  conflicts: RuleImportConflict[];
  token: string;
  sameName: boolean;
  unchanged: boolean;
  choice: RuleImportChoice['action'];
  warnings: string[];
}
export interface RuleImportPlan {
  groups: RuleCollectionGroup[];
  rows: RuleImportRow[];
  errors: RuleImportIssue[];
  ruleCount: number;
  newGroupCount: number;
  newCollectionCount: number;
  skippedCount: number;
}
export interface RuleImportResult {
  status: CandidateStatus;
  ruleCount: number;
  groupIds: string[];
  skippedCount: number;
}
export interface RuleImportContext {
  policyId: string;
  groups: RuleCollectionGroup[];
  inheritedGroups?: RuleCollectionGroup[];
  known?: KnownValues;
  ipGroups?: IpGroupMembers;
}

interface CsvRecord {
  line: number;
  cells: string[];
}

class CsvParseError extends Error {
  constructor(
    readonly line: number,
    message: string,
  ) {
    super(message);
  }
}

/** RFC-style quoted cells, escaped quotes, BOMs, CRLF/LF and multiline descriptions. */
function csvRecords(input: string): CsvRecord[] {
  const text = input.replace(/^\uFEFF/, '');
  const rows: CsvRecord[] = [];
  let cells: string[] = [];
  let field = '';
  let quoted = false;
  let closed = false;
  let line = 1;
  let startLine = 1;
  const finish = () => {
    cells.push(field);
    if (cells.some((v) => v.trim())) rows.push({ line: startLine, cells });
    cells = [];
    field = '';
    closed = false;
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      if (quoted && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (quoted) {
        quoted = false;
        closed = true;
      } else if (!field && !closed) quoted = true;
      else
        throw new CsvParseError(
          line,
          'Unexpected quote. Quote the entire cell and double any quotes inside it.',
        );
    } else if (c === '\r' || c === '\n') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      if (quoted) field += '\n';
      else finish();
      line++;
      if (!quoted) startLine = line;
    } else if (c === ',' && !quoted) {
      cells.push(field);
      field = '';
      closed = false;
    } else if (closed) {
      if (c !== ' ' && c !== '\t')
        throw new CsvParseError(line, 'Unexpected text after a closing quote.');
    } else field += c;
  }
  if (quoted)
    throw new CsvParseError(
      startLine,
      'A quoted cell is missing its closing quote.',
    );
  finish();
  return rows;
}

interface Reference {
  rule: FirewallRule;
  action: string;
  group: string;
  collection: string;
  inherited: boolean;
}

function references(context: RuleImportContext): Reference[] {
  return [
    ...context.groups.map((group) => ({ group, inherited: false })),
    ...(context.inheritedGroups ?? []).map((group) => ({
      group,
      inherited: true,
    })),
  ].flatMap(({ group, inherited }) =>
    group.ruleCollections.flatMap((c) =>
      (c.rules as FirewallRule[])
        .filter((r) => !inherited || r.ruleType !== 'NatRule')
        .map((rule) => ({
          rule,
          action: c.action.type,
          group: group.name,
          collection: c.name,
          inherited,
        })),
    ),
  );
}

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

export function planRuleImport(
  csv: string,
  context: RuleImportContext,
  choices: RuleImportChoices = {},
): RuleImportPlan {
  const plan: RuleImportPlan = {
    groups: [],
    rows: [],
    errors: [],
    ruleCount: 0,
    newGroupCount: 0,
    newCollectionCount: 0,
    skippedCount: 0,
  };
  const error = (line: number, message: string) => {
    plan.errors.push({ line, message });
  };
  if (new TextEncoder().encode(csv).length > MAX_RULE_IMPORT_BYTES) {
    error(1, 'The CSV file exceeds the 5 MB limit.');
    return plan;
  }
  let records: CsvRecord[];
  try {
    records = csvRecords(csv);
  } catch (err) {
    if (!(err instanceof CsvParseError)) throw err;
    error(err.line, err.message);
    return plan;
  }
  const header = records.shift();
  if (!header) {
    error(
      1,
      'The CSV file is empty. Download the import template to get started.',
    );
    return plan;
  }
  const columns = new Map<string, number>();
  const supported = new Set(RULE_IMPORT_COLUMNS.map((c) => c.toLowerCase()));
  for (const [i, value] of header.cells.entries()) {
    const key = value.trim().toLowerCase();
    if (!supported.has(key))
      error(
        header.line,
        `Unknown column "${value}". Use the import template, not the review/export CSV.`,
      );
    if (columns.has(key)) error(header.line, `Duplicate column "${value}".`);
    columns.set(key, i);
  }
  for (const column of REQUIRED)
    if (!columns.has(column.toLowerCase()))
      error(header.line, `Missing column "${column}".`);
  if (plan.errors.length) return plan;
  if (!records.length) error(header.line, 'The file has no rule rows.');

  const working = structuredClone(context.groups);
  const changed = new Set<string>();
  const seen = new Set<string>();
  const refs = references(context);
  const firstLines = new Map<string, number>();
  for (const record of records) {
    const { line } = record;
    const initialErrors = plan.errors.length;
    if (record.cells.length !== header.cells.length) {
      error(
        line,
        `Expected ${header.cells.length} columns, found ${record.cells.length}. Quote cells containing commas.`,
      );
      continue;
    }
    const get = (column: Column) =>
      record.cells[columns.get(column.toLowerCase()) ?? -1]?.trim() ?? '';
    const groupName = get('Rule collection group');
    const collectionName = get('Rule collection');
    const name = get('Rule name');
    const kind = (['Network', 'Application', 'DNAT'] as const).find((v) =>
      same(v, get('Collection type')),
    );
    if (!kind) {
      error(line, 'Collection type must be Network, Application or DNAT.');
      continue;
    }
    const action = (['Allow', 'Deny', 'DNAT'] as const).find((v) =>
      same(v, get('Action')),
    );
    if (!action || (kind === 'DNAT' ? action !== 'DNAT' : action === 'DNAT')) {
      error(
        line,
        `${kind} collections require ${kind === 'DNAT' ? 'DNAT' : 'Allow or Deny'} as their action.`,
      );
      continue;
    }
    const groupPriority = /^\d+$/.test(get('Group priority'))
      ? Number(get('Group priority'))
      : NaN;
    const priority = /^\d+$/.test(get('Collection priority'))
      ? Number(get('Collection priority'))
      : NaN;
    let group = working.find((g) => same(g.name, groupName));
    if (group) {
      if (group.priority !== groupPriority)
        error(
          line,
          `Group "${groupName}" has priority ${group.priority}; importing cannot change it.`,
        );
    } else {
      const problems = newGroupErrors(groupName, groupPriority, working);
      for (const message of Object.values(problems))
        if (message) error(line, message);
    }
    const collection = group?.ruleCollections.find((c) =>
      same(c.name, collectionName),
    );
    if (
      collection &&
      (collection.priority !== priority ||
        collection.action.type !== action ||
        (collection.rules.length && collectionKindOf(collection) !== kind) ||
        (collection.ruleCollectionType ===
          'FirewallPolicyNatRuleCollection') !==
          (kind === 'DNAT'))
    )
      error(
        line,
        `Collection "${collectionName}" has different settings. Match its priority, type and action, or use a new collection name.`,
      );

    const draft = emptyCollection(priority, kind);
    draft.name = collectionName;
    draft.action = action === 'Deny' ? 'Deny' : 'Allow';
    const row = draft.rows[0];
    row.name = name;
    row.description = get('Description');
    row.lists.sourceAddresses = get('Source addresses');
    row.lists.sourceIpGroups = get('Source IP Groups');
    row.lists.destinationAddresses = get('Destination addresses');
    row.lists.destinationIpGroups = get('Destination IP Groups');
    row.lists.destinationFqdns = get('Destination FQDNs');
    row.lists.destinationPorts = get('Destination ports');
    row.lists.targetFqdns = get('Target FQDNs');
    row.lists.targetUrls = get('Target URLs');
    row.lists.fqdnTags = get('FQDN tags');
    row.lists.webCategories = get('Web categories');
    row.translatedAddress = get('Translated address');
    row.translatedFqdn = get('Translated FQDN');
    row.translatedPort = get('Translated port');
    const tls = get('TLS inspection');
    if (tls && !/^(yes|no|true|false)$/i.test(tls))
      error(line, 'TLS inspection must be Yes, No, True, False or blank.');
    row.terminateTLS = /^(yes|true)$/i.test(tls);
    const unused: Column[] =
      kind === 'Network'
        ? [
            'Target FQDNs',
            'Target URLs',
            'FQDN tags',
            'Web categories',
            'TLS inspection',
            'Translated address',
            'Translated FQDN',
            'Translated port',
          ]
        : kind === 'Application'
          ? [
              'Destination IP Groups',
              'Destination FQDNs',
              'Destination ports',
              'Translated address',
              'Translated FQDN',
              'Translated port',
            ]
          : [
              'Destination IP Groups',
              'Destination FQDNs',
              'Target FQDNs',
              'Target URLs',
              'FQDN tags',
              'Web categories',
              'TLS inspection',
            ];
    for (const column of unused)
      if (get(column))
        error(line, `"${column}" is not supported for ${kind} rules.`);
    if (kind === 'Network') {
      const destinations = parseList(row.lists.destinationAddresses);
      row.lists.destinationServiceTags = destinations
        .filter((v) => SERVICE_TAG.test(v))
        .join(';');
      row.lists.destinationAddresses = destinations
        .filter((v) => !SERVICE_TAG.test(v))
        .join(';');
    }
    if (kind === 'Application') {
      row.appProtocols = get('Protocols');
      if (
        parseList(row.appProtocols).some(
          (v) => !/^(https?|mssql)(?::\d+)?$/i.test(v),
        )
      )
        error(line, 'Protocols: use Http:80, Https:443 or Mssql:1433.');
    } else {
      row.protocols = [];
      const allowed = kind === 'DNAT' ? NAT_PROTOCOLS : NET_PROTOCOLS;
      for (const token of parseList(get('Protocols'))) {
        const protocol = allowed.find((p) => same(p, token));
        if (protocol && !row.protocols.includes(protocol))
          row.protocols.push(protocol);
        else if (protocol) continue;
        else
          error(line, `Protocol "${token}" is not allowed for ${kind} rules.`);
      }
      if (row.protocols.includes('Any') && row.protocols.length > 1)
        error(line, 'Any protocol cannot be combined with specific protocols.');
    }
    const validation = validateDraft(
      draft,
      (group?.ruleCollections ?? []).filter(
        (c) => !same(c.name, collectionName),
      ),
      context.known,
    );
    for (const message of [
      ...validation.collection,
      ...(validation.rows[row.key] ?? []),
      ...Object.values(validation.cells[row.key] ?? {}),
    ])
      if (message) error(line, message);
    // A completely blank grid row is ignored by the editor; a CSV row must always be a rule.
    if (!name) error(line, 'Rule name is required.');
    const rowKey = `${groupName.toLowerCase()}/${collectionName.toLowerCase()}/${name.toLowerCase()}`;
    if (seen.has(rowKey))
      error(
        line,
        `The CSV already contains "${name}" in this collection. Keep only one row for each rule name.`,
      );
    seen.add(rowKey);
    if (plan.errors.length !== initialErrors) continue;

    const rule = collectionFromDraft(draft).rules[0];
    if (!rule) {
      error(line, 'This row does not contain a rule.');
      continue;
    }
    const conflicts: RuleImportConflict[] = [];
    const signatures: unknown[] = [];
    let sameName = false;
    let unchanged = false;
    for (const ref of refs) {
      const collision =
        !ref.inherited &&
        same(ref.group, groupName) &&
        same(ref.collection, collectionName) &&
        same(ref.rule.name, name);
      let conflict: RuleImportConflict['kind'] | undefined;
      if (collision) {
        sameName = true;
        unchanged = ruleContents(ref.rule, true) === ruleContents(rule, true);
        conflict = 'same-name';
      } else if (
        ref.action === action &&
        ruleContents(ref.rule) === ruleContents(rule)
      )
        conflict = 'duplicate';
      else {
        const overlap = ruleOverlap(rule, ref.rule, context.ipGroups);
        if (overlap !== 'none')
          conflict = overlap === 'overlap' ? 'overlap' : 'potential-overlap';
      }
      if (conflict) {
        conflicts.push({
          kind: conflict,
          target: `${ref.group} / ${ref.collection} / ${ref.rule.name}`,
          action: ref.action,
          inherited: ref.inherited,
          summary: summarizeRule(ref.rule),
        });
        signatures.push({ conflict, ...ref });
      }
    }
    const token = stableStringify(
      signatures.sort((a, b) =>
        stableStringify(a).localeCompare(stableStringify(b)),
      ),
    );
    const choice = choices[String(line)] ?? {
      action: conflicts.length ? 'skip' : 'import',
    };
    if (choice.action !== 'skip') {
      if (unchanged)
        error(line, 'This rule already exists unchanged; leave it skipped.');
      else if (sameName && choice.action !== 'replace')
        error(
          line,
          'Choose Replace or Skip for the existing rule with this name.',
        );
      else if (!sameName && choice.action === 'replace')
        error(
          line,
          'There is no same-name rule to replace. Review the file again.',
        );
      if (conflicts.length && choice.token !== token)
        error(
          line,
          'The conflicts changed since they were reviewed. Choose an action for this row again.',
        );
    }
    plan.rows.push({
      line,
      group: groupName,
      collection: collectionName,
      kind,
      action,
      rule,
      conflicts,
      token,
      sameName,
      unchanged,
      choice: choice.action,
      warnings: validation.warnings[row.key] ?? [],
    });
    if (choice.action === 'skip') {
      plan.skippedCount++;
      continue;
    }
    if (!group) {
      group = {
        id: `${context.policyId}/ruleCollectionGroups/${groupName}`,
        name: groupName,
        priority: groupPriority,
        ruleCollections: [],
      };
      working.push(group);
    }
    let target = group.ruleCollections.find((c) =>
      same(c.name, collectionName),
    );
    if (!target) {
      target = collectionFromDraft(draft);
      group.ruleCollections.push(target);
    } else {
      const rules = target.rules as FirewallRule[];
      const index = rules.findIndex((r) => same(r.name, name));
      if (index >= 0 && choice.action === 'replace') rules[index] = rule;
      else rules.push(rule);
    }
    changed.add(group.id.toLowerCase());
    firstLines.set(
      group.id.toLowerCase(),
      firstLines.get(group.id.toLowerCase()) ?? line,
    );
    plan.ruleCount++;
    if (choice.action === 'replace') {
      for (let i = refs.length - 1; i >= 0; i--)
        if (
          !refs[i].inherited &&
          same(refs[i].group, group.name) &&
          same(refs[i].collection, target.name) &&
          same(refs[i].rule.name, rule.name)
        )
          refs.splice(i, 1);
    }
    refs.push({
      rule,
      action,
      group: group.name,
      collection: target.name,
      inherited: false,
    });
  }
  plan.groups = working.filter((g) => changed.has(g.id.toLowerCase()));
  for (const group of plan.groups) {
    for (const message of validateGroup(group))
      error(
        firstLines.get(group.id.toLowerCase()) ?? 1,
        `${group.name}: ${message}`,
      );
    const old = context.groups.find((g) => same(g.name, group.name));
    if (!old) plan.newGroupCount++;
    plan.newCollectionCount += group.ruleCollections.filter(
      (c) => !old?.ruleCollections.some((o) => same(o.name, c.name)),
    ).length;
  }
  return plan;
}

/** Bundled example rows cover all supported rule types; customers replace/remove them. */
export function ruleImportTemplate(
  groupName = 'rcg-csv-import',
  priority = 1000,
): string {
  const base = {
    'Rule collection group': groupName,
    'Group priority': String(priority),
  };
  const examples: Partial<Record<Column, string>>[] = [
    {
      ...base,
      'Rule collection': 'net-allow',
      'Collection priority': '100',
      'Collection type': 'Network',
      Action: 'Allow',
      'Rule name': 'example-internal-https',
      Description: 'Replace or remove this example',
      'Source addresses': '10.0.0.0/8',
      Protocols: 'TCP',
      'Destination ports': '443',
      'Destination addresses': '10.20.0.0/16',
    },
    {
      ...base,
      'Rule collection': 'app-allow',
      'Collection priority': '200',
      'Collection type': 'Application',
      Action: 'Allow',
      'Rule name': 'example-web',
      Description: 'Replace or remove this example',
      'Source addresses': '10.0.0.0/8',
      Protocols: 'Https:443',
      'Target FQDNs': 'www.contoso.com',
    },
    {
      ...base,
      'Rule collection': 'dnat-web',
      'Collection priority': '300',
      'Collection type': 'DNAT',
      Action: 'DNAT',
      'Rule name': 'example-publish-https',
      Description: 'Replace or remove this example',
      'Source addresses': '192.0.2.0/24',
      Protocols: 'TCP',
      'Destination ports': '443',
      'Destination addresses': '203.0.113.10',
      'Translated address': '10.20.0.4',
      'Translated port': '443',
    },
    {
      ...base,
      'Rule collection': 'net-allow',
      'Collection priority': '100',
      'Collection type': 'Network',
      Action: 'Allow',
      'Rule name': 'example-ip-groups-https',
      Description:
        'Replace both placeholders with the full Azure resource IDs of your IP Groups, not their names. Remove this example if unused.',
      'Source IP Groups':
        '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example/providers/Microsoft.Network/ipGroups/ipg-sources',
      Protocols: 'TCP',
      'Destination ports': '443',
      'Destination IP Groups':
        '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example/providers/Microsoft.Network/ipGroups/ipg-destinations',
    },
  ];
  return (
    '\uFEFF' +
    [
      RULE_IMPORT_COLUMNS.map(csvCell).join(','),
      ...examples.map((row) =>
        RULE_IMPORT_COLUMNS.map((column) => csvCell(row[column])).join(','),
      ),
    ].join('\r\n') +
    '\r\n'
  );
}
