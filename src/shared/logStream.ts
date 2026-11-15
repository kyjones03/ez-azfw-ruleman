// Types and validation for the live firewall-log stream (Azure Event Hubs, Entra ID only).
import type { FirewallLogRow } from './fwLogs';

export const LOG_RECEIVER_ROLE = 'Azure Event Hubs Data Receiver';
export const DEFAULT_CONSUMER_GROUP = '$Default';
const NAMESPACE_SUFFIX = '.servicebus.windows.net';

/** `latest`: only new events. `earliest`: replay what the hub still retains (1 day by default). */
export type StartPosition = 'latest' | 'earliest';

export interface LogStreamConfig {
  /** Fully qualified, e.g. contoso-fw.servicebus.windows.net. */
  namespace: string;
  eventHub: string;
  consumerGroup: string;
  startPosition: StartPosition;
}

export type LogStreamState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'retrying'
  | 'reconnecting'
  | 'failed'
  | 'stopped';

export type LogErrorKind = 'permission' | 'notFound' | 'signedOut' | 'network';

export interface LogStreamStatus {
  state: LogStreamState;
  /** Short progress text, e.g. "attempt 2/3 in 5s". */
  detail: string;
  /** Last error, display-safe. Empty when there is none. */
  error: string;
  /** What to do about a configuration error (missing role, wrong name…). */
  hint: string;
  /** What kind of problem the error is, so the UI can offer the matching fix. */
  errorKind?: LogErrorKind;
  config?: LogStreamConfig;
}

export const IDLE_STATUS: LogStreamStatus = {
  state: 'idle',
  detail: '',
  error: '',
  hint: '',
};

/** One flush of the main-process queue (about once a second). */
export interface LogBatch {
  rows: FirewallLogRow[];
  /** Records received but not displayable (other resources, aggregation categories, junk). */
  skipped: number;
}

const HUB_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/;
const CONSUMER_GROUP = /^[A-Za-z0-9$][A-Za-z0-9$._-]{0,49}$/;
const NAMESPACE_LABEL = /^[a-z0-9][a-z0-9-]{4,48}[a-z0-9]$/;

/**
 * Accepts "contoso-fw" or "contoso-fw.servicebus.windows.net" (any case, optional https:// and
 * trailing slash) and returns the fully qualified lower-case name, or undefined.
 * Only the public cloud: the sign-in token is issued for that cloud's Event Hubs audience.
 */
export function normaliseNamespace(input: string): string | undefined {
  let v = input.trim().toLowerCase();
  v = v.replace(/^https?:\/\//, '').replace(/\/+$/, '');
  if (!v) return undefined;
  const label = v.endsWith(NAMESPACE_SUFFIX)
    ? v.slice(0, -NAMESPACE_SUFFIX.length)
    : v;
  return NAMESPACE_LABEL.test(label)
    ? `${label}${NAMESPACE_SUFFIX}`
    : undefined;
}

/** Throws a readable error for anything that isn't a valid config; returns the cleaned config. */
export function validateLogStreamConfig(raw: unknown): LogStreamConfig {
  if (!raw || typeof raw !== 'object')
    throw new Error('Invalid Event Hub settings.');
  const r = raw as Record<string, unknown>;
  const namespace =
    typeof r.namespace === 'string'
      ? normaliseNamespace(r.namespace)
      : undefined;
  if (!namespace)
    throw new Error(
      'Enter the Event Hubs namespace, e.g. contoso-fw or contoso-fw.servicebus.windows.net.',
    );
  const eventHub = typeof r.eventHub === 'string' ? r.eventHub.trim() : '';
  if (!HUB_NAME.test(eventHub))
    throw new Error('Enter a valid event hub name.');
  const group =
    typeof r.consumerGroup === 'string' && r.consumerGroup.trim()
      ? r.consumerGroup.trim()
      : DEFAULT_CONSUMER_GROUP;
  if (!CONSUMER_GROUP.test(group))
    throw new Error('Enter a valid consumer group name.');
  if (r.startPosition !== 'latest' && r.startPosition !== 'earliest')
    throw new Error('Start position must be "latest" or "earliest".');
  return {
    namespace,
    eventHub,
    consumerGroup: group,
    startPosition: r.startPosition,
  };
}
