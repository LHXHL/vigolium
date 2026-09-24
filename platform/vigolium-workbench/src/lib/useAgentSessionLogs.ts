'use client';

import { useEffect, useRef, useState } from 'react';
import { buildApiUrl, buildAuthHeaders } from '@/api/client';
import { isTerminalAgentStatus } from '@/api/types';

export interface AgentSessionLogsState {
  logs: string;
  isStreaming: boolean;
  error: string | null;
}

// Cap the in-memory log buffer so a long-running session can't blow up
// React state / the rendered <pre>. The slice keeps the most recent
// MAX_LOG_BYTES of output, which is what users want when tailing.
const MAX_LOG_BYTES = 512 * 1024;

// Batching window for streamed chunks: each flush copies the (up to 512 KB)
// buffer and re-renders the log, so 4 Hz, not per chunk or 10 Hz.
const FLUSH_INTERVAL_MS = 250;
const RECONNECT_DELAY_MS = 2000;
const MAX_RECONNECTS = 50;
const MAX_NOT_FOUND_RETRIES = 6;

function capTail(text: string): string {
  return text.length > MAX_LOG_BYTES ? text.slice(-MAX_LOG_BYTES) : text;
}

export function useAgentSessionLogs(uuid: string | null, status?: string): AgentSessionLogsState {
  const [logs, setLogs] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const lastUuidRef = useRef<string | null>(null);

  // Boolean dep avoids reconnecting the SSE stream on every poll-induced
  // identity change of `status` (the parent useAgentSessionDetail polls
  // every 5s while running, replacing the response object each tick).
  const terminal = isTerminalAgentStatus(status);

  useEffect(() => {
    abortRef.current?.abort();
    abortRef.current = null;

    if (!uuid) {
      setLogs('');
      setIsStreaming(false);
      setError(null);
      lastUuidRef.current = null;
      return;
    }

    // Only blank the panel when switching to a different session. A
    // running→terminal transition reuses the same uuid, so keep what we
    // already have rendered until the terminal fetch fills it back in.
    if (uuid !== lastUuidRef.current) {
      setLogs('');
      lastUuidRef.current = uuid;
    }
    setError(null);

    const abort = new AbortController();
    abortRef.current = abort;
    const url = buildApiUrl(`/api/agent/sessions/${uuid}/logs?strip=1`);

    if (terminal) {
      setIsStreaming(false);
      (async () => {
        try {
          const res = await fetch(`${url}&max_bytes=${MAX_LOG_BYTES}`, { headers: buildAuthHeaders(), signal: abort.signal });
          if (abort.signal.aborted) return;
          if (!res.ok) {
            let msg = res.statusText;
            try { const j = await res.json(); msg = j.error || msg; } catch { /* ignore */ }
            setError(`${res.status}: ${msg}`);
            return;
          }
          const text = await res.text();
          if (abort.signal.aborted) return;
          setLogs(capTail(text));
        } catch (err) {
          if ((err as Error).name !== 'AbortError') setError((err as Error).message);
        }
      })();
      return () => { abort.abort(); };
    }

    setIsStreaming(true);

    // Chunks are batched: one state update per chunk copied the whole
    // (up to 512 KB) buffer and re-rendered the page for every 4 KB of log.
    let pending = '';
    // Every (re)connect replays the server's last 512 KB, so the first flush
    // of a connection replaces the buffer instead of appending a duplicate.
    let fresh = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const flush = () => {
      timer = null;
      if (!pending) return;
      const text = pending;
      const replace = fresh;
      pending = '';
      fresh = false;
      setLogs((prev) => capTail((replace ? '' : prev) + text));
    };
    const push = (text: string) => {
      pending += text;
      if (!timer) timer = setTimeout(flush, FLUSH_INTERVAL_MS);
    };
    const sleep = (ms: number) => new Promise<void>((resolve) => {
      const t = setTimeout(resolve, ms);
      abort.signal.addEventListener('abort', () => { clearTimeout(t); resolve(); }, { once: true });
    });

    (async () => {
      let reconnects = 0;
      let notFound = 0;
      try {
        while (!abort.signal.aborted) {
          const res = await fetch(url, { headers: buildAuthHeaders({ sse: true }), signal: abort.signal });
          if (!res.ok) {
            // A run's session dir and runtime.log are created by its goroutine
            // after the 202, so the first connect can race them. Retry while
            // the run is live instead of showing a permanent 404.
            if (res.status === 404 && notFound < MAX_NOT_FOUND_RETRIES) {
              notFound++;
              await sleep(Math.min(500 * 2 ** notFound, 8000));
              continue;
            }
            let msg = res.statusText;
            try { const j = await res.json(); msg = j.error || msg; } catch { /* ignore */ }
            setError(`${res.status}: ${msg}`);
            break;
          }
          notFound = 0;
          const reader = res.body?.getReader();
          if (!reader) {
            setError('No response body');
            break;
          }
          fresh = true;
          let sawDone = false;
          const decoder = new TextDecoder();
          let buffer = '';
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';
            for (const line of lines) {
              if (!line.startsWith('data: ')) continue;
              const payload = line.slice(6).trim();
              if (!payload) continue;
              try {
                const parsed = JSON.parse(payload);
                if (parsed.type === 'chunk' && typeof parsed.text === 'string') {
                  push(parsed.text);
                } else if (parsed.type === 'error' && typeof parsed.error === 'string') {
                  setError(parsed.error);
                } else if (parsed.type === 'done') {
                  sawDone = true;
                }
              } catch {
                push(payload);
              }
            }
          }
          flush();
          // No "done" means the follower hit its safety cap ("reconnect") or
          // the connection dropped while the run is still going. Reconnect;
          // the status poll flips `terminal` and aborts this loop once the
          // run really ends.
          if (sawDone || abort.signal.aborted || ++reconnects > MAX_RECONNECTS) break;
          await sleep(RECONNECT_DELAY_MS);
        }
      } catch (err) {
        if ((err as Error).name !== 'AbortError') setError((err as Error).message);
      } finally {
        if (!abort.signal.aborted) {
          flush();
          setIsStreaming(false);
        }
      }
    })();

    return () => {
      abort.abort();
      if (timer) clearTimeout(timer);
    };
  }, [uuid, terminal]);

  return { logs, isStreaming, error };
}
