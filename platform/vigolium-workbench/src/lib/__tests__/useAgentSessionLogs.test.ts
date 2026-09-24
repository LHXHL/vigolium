import { describe, it, expect, vi, afterEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { useAgentSessionLogs } from '../useAgentSessionLogs';

function sse(...events: object[]): Response {
  const body = events.map((e) => `data: ${JSON.stringify(e)}\n\n`).join('');
  return new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('useAgentSessionLogs (live run)', () => {
  it('reconnects after a "reconnect" event and replaces, not duplicates, the replayed backlog', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'line 1\n' }, { type: 'reconnect' }))
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'line 1\nline 2\n' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);

    const { result } = renderHook(() => useAgentSessionLogs('run-1', 'running'));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2), { timeout: 5000 });
    await waitFor(() => expect(result.current.isStreaming).toBe(false), { timeout: 5000 });
    // The second connection replays the backlog; it must replace the buffer.
    expect(result.current.logs).toBe('line 1\nline 2\n');
  });

  it('retries a 404 while the run is live (session dir not created yet)', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('{"error":"session directory not found"}', { status: 404 }))
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'started\n' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);

    const { result } = renderHook(() => useAgentSessionLogs('run-2', 'running'));

    await waitFor(() => expect(result.current.logs).toBe('started\n'), { timeout: 5000 });
    expect(result.current.error).toBeNull();
  });

  it('does not reconnect after "done"', async () => {
    const fetchMock = vi.fn().mockResolvedValue(sse({ type: 'chunk', text: 'x\n' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);

    const { result } = renderHook(() => useAgentSessionLogs('run-3', 'running'));

    await waitFor(() => expect(result.current.isStreaming).toBe(false), { timeout: 5000 });
    await new Promise((r) => setTimeout(r, 2500));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('useAgentSessionLogs (finished run)', () => {
  it('treats completed_with_warnings as terminal and caps the fetched tail', async () => {
    const big = 'a'.repeat(600 * 1024);
    const fetchMock = vi.fn().mockResolvedValue(new Response(big, { status: 200, headers: { 'Content-Type': 'text/plain' } }));
    vi.stubGlobal('fetch', fetchMock);

    const { result } = renderHook(() => useAgentSessionLogs('run-4', 'completed_with_warnings'));

    await waitFor(() => expect(result.current.logs.length).toBe(512 * 1024));
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain('max_bytes=');
    // A terminal status must not open the SSE follower.
    expect(fetchMock.mock.calls[0][1]?.headers?.Accept).toBeUndefined();
  });
});
