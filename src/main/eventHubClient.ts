// The real HubClient: @azure/event-hubs with the signed-in user's Entra token. Entra only; there
// is deliberately no connection-string or SAS path.
import {
  EventHubConsumerClient,
  earliestEventPosition,
  latestEventPosition,
  type EventPosition,
} from '@azure/event-hubs';
import type { TokenCredential } from '@azure/identity';
import type { LogStreamConfig } from '../shared/logStream';
import type { HubClient, PartitionStart } from './eventHub';

const toPosition = (start: PartitionStart): EventPosition =>
  start === 'latest'
    ? latestEventPosition
    : start === 'earliest'
      ? earliestEventPosition
      : { sequenceNumber: start.afterSequenceNumber, isInclusive: false };

export function createHubClient(
  config: LogStreamConfig,
  credential: TokenCredential,
): HubClient {
  // No checkpoint store: nothing is persisted, and several viewers can share a consumer group.
  const client = new EventHubConsumerClient(
    config.consumerGroup,
    config.namespace,
    config.eventHub,
    credential,
    // Failures are handled by the session's own reconnect policy, not by SDK retries.
    { retryOptions: { maxRetries: 0 } },
  );
  return {
    getPartitionIds: (signal) =>
      client.getPartitionIds({ abortSignal: signal }),
    subscribe(handlers, start) {
      const startPosition: Record<string, EventPosition> = {};
      for (const [id, s] of Object.entries(start))
        startPosition[id] = toPosition(s);
      const sub = client.subscribe(
        {
          processEvents: async (events, context) => {
            if (events.length === 0) return;
            handlers.onEvents(
              context.partitionId,
              events.map((e) => ({
                body: e.body,
                sequenceNumber: e.sequenceNumber,
              })),
            );
          },
          processError: async (err) => handlers.onError(err),
        },
        {
          startPosition,
          maxBatchSize: 500,
          // Small, so events reach the 1 s flush quickly even on a quiet hub.
          maxWaitTimeInSeconds: 1,
          // We decode and size-check the bytes ourselves.
          skipParsingBodyAsJson: true,
        },
      );
      return { close: () => sub.close() };
    },
    close: () => client.close(),
  };
}
