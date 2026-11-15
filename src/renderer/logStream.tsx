import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import {
  IDLE_STATUS,
  type LogStreamConfig,
  type LogStreamStatus,
} from '../shared/logStream';
import { INITIAL_LOG_STATE, logViewReducer } from './logStreamState';
import type { LogBuffer } from '../shared/logBuffer';

export interface LogStreamApi {
  status: LogStreamStatus;
  /** The saved (or last used) hub settings; null until the user enters some. */
  config: LogStreamConfig | null;
  buffer: LogBuffer;
  paused: boolean;
  connect(config: LogStreamConfig): Promise<void>;
  disconnect(): Promise<void>;
  pause(): void;
  resume(): void;
  clear(): void;
  /** True once the saved settings have been read, so the view doesn't flash an empty form. */
  ready: boolean;
}

const Ctx = createContext<LogStreamApi | null>(null);

export const useLogStream = (): LogStreamApi => {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useLogStream needs a LogStreamProvider.');
  return ctx;
};

const sameConfig = (a?: LogStreamConfig | null, b?: LogStreamConfig | null) =>
  !!a &&
  !!b &&
  a.namespace === b.namespace &&
  a.eventHub === b.eventHub &&
  a.consumerGroup === b.consumerGroup;

/**
 * Owns the log stream for the signed-in session, so it keeps running (and keeps its rows) while
 * the user looks at other tabs. Mount it with a key that changes with the directory: the main
 * process stops the stream on sign-out and directory switches, and a fresh mount starts clean.
 */
export function LogStreamProvider({ children }: { children: ReactNode }) {
  const [view, dispatch] = useReducer(logViewReducer, INITIAL_LOG_STATE);
  const [status, setStatus] = useState<LogStreamStatus>(IDLE_STATUS);
  const [config, setConfig] = useState<LogStreamConfig | null>(null);
  const [ready, setReady] = useState(false);
  const statusRef = useRef(status);
  statusRef.current = status;

  useEffect(() => {
    const offBatch = window.api.onLogBatch((batch) =>
      dispatch({ type: 'batch', batch }),
    );
    const offStatus = window.api.onLogStreamStatus(setStatus);
    let cancelled = false;
    Promise.all([
      window.api.getLogStreamStatus(),
      window.api.getLogStreamConfig(),
    ])
      .then(([s, c]) => {
        if (cancelled) return;
        // A stream can already be running (e.g. after a window reload in development).
        setStatus((cur) => (cur === IDLE_STATUS ? s : cur));
        setConfig(s.config ?? c);
      })
      .catch(() => undefined)
      .finally(() => !cancelled && setReady(true));
    return () => {
      cancelled = true;
      offBatch();
      offStatus();
    };
  }, []);

  const connect = useCallback(async (next: LogStreamConfig) => {
    // Rows from another hub would be misleading next to the new ones.
    if (!sameConfig(statusRef.current.config ?? null, next))
      dispatch({ type: 'clear' });
    const started = await window.api.startLogStream(next);
    setConfig(started.config ?? next);
    setStatus(started);
  }, []);

  const disconnect = useCallback(() => window.api.stopLogStream(), []);
  const pause = useCallback(() => dispatch({ type: 'pause' }), []);
  const resume = useCallback(() => dispatch({ type: 'resume' }), []);
  const clear = useCallback(() => dispatch({ type: 'clear' }), []);

  const value = useMemo<LogStreamApi>(
    () => ({
      status,
      config,
      buffer: view.buffer,
      paused: view.paused,
      connect,
      disconnect,
      pause,
      resume,
      clear,
      ready,
    }),
    [status, config, view, connect, disconnect, pause, resume, clear, ready],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
