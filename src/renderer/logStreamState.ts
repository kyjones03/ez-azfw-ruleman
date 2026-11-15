// Row state for the Logs view: the capped buffer plus the pause flag, as a pure reducer so the
// pause/resume rules are tested without React.
import {
  clear,
  EMPTY_BUFFER,
  ingest,
  release,
  type LogBuffer,
} from '../shared/logBuffer';
import type { LogBatch } from '../shared/logStream';

export interface LogViewState {
  buffer: LogBuffer;
  paused: boolean;
}

export type LogViewAction =
  | { type: 'batch'; batch: LogBatch }
  | { type: 'pause' }
  | { type: 'resume' }
  | { type: 'clear' };

export const INITIAL_LOG_STATE: LogViewState = {
  buffer: EMPTY_BUFFER,
  paused: false,
};

export function logViewReducer(
  state: LogViewState,
  action: LogViewAction,
): LogViewState {
  switch (action.type) {
    case 'batch':
      return {
        ...state,
        buffer: ingest(
          state.buffer,
          action.batch.rows,
          action.batch.skipped,
          state.paused,
        ),
      };
    case 'pause':
      return state.paused ? state : { ...state, paused: true };
    case 'resume':
      return { paused: false, buffer: release(state.buffer) };
    case 'clear':
      // The stream keeps running; clearing while paused also empties the hold list.
      return { ...state, buffer: clear() };
  }
}
