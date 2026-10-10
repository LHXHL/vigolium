import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

async function loadClient() {
  vi.resetModules();
  return import('../client');
}

afterEach(() => {
  localStorage.clear();
  delete process.env.NEXT_PUBLIC_API_BASE_URL;
});

describe('getBaseUrl', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: new URL('http://localhost:3002/'),
    });
  });

  it('uses NEXT_PUBLIC_API_BASE_URL when set', async () => {
    process.env.NEXT_PUBLIC_API_BASE_URL = 'http://localhost:9002';
    const { getBaseUrl } = await loadClient();
    expect(getBaseUrl()).toBe('http://localhost:9002');
  });

  it('falls back to window.location.origin when env is unset and no localStorage override', async () => {
    delete process.env.NEXT_PUBLIC_API_BASE_URL;
    const { getBaseUrl } = await loadClient();
    expect(getBaseUrl()).toBe('http://localhost:3002');
  });

  it('localStorage override wins over env', async () => {
    process.env.NEXT_PUBLIC_API_BASE_URL = 'http://localhost:9002';
    localStorage.setItem('vigolium_api_url', 'http://override:1234');
    const { getBaseUrl } = await loadClient();
    expect(getBaseUrl()).toBe('http://override:1234');
  });
});

describe('project UUID localStorage', () => {
  it('round-trips through getProjectUUID/setProjectUUID', async () => {
    const { getProjectUUID, setProjectUUID } = await loadClient();
    setProjectUUID('11111111-2222-3333-4444-555555555555');
    expect(getProjectUUID()).toBe('11111111-2222-3333-4444-555555555555');
  });

  it('clears UUID when set to null', async () => {
    const { getProjectUUID, setProjectUUID } = await loadClient();
    setProjectUUID('abc');
    setProjectUUID(null);
    expect(getProjectUUID()).toBe(null);
  });
});

describe('apiGet — X-Project-UUID header injection', () => {
  // Project bootstrap and public-utility paths must not carry the header.
  // Otherwise a stale localStorage UUID makes /api/projects un-recoverable.
  const exemptPaths = [
    '/server-info',
    '/health',
    '/metrics',
    '/swagger/index.html',
    '/api/projects',
    '/api/projects/stats',
  ];
  const projectScopedPaths = [
    '/api/findings',
    '/api/scan/list',
    '/api/http-records',
  ];

  beforeEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: new URL('http://localhost:3002/'),
    });
  });

  async function setupClient() {
    const client = await loadClient();
    client.setProjectUUID('proj-uuid-xyz');
    return client;
  }

  it.each(exemptPaths)('does NOT send X-Project-UUID for exempt path %s', async (path) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200 }),
    );
    const { apiGet } = await setupClient();
    await apiGet(path);
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined;
    const headers = init?.headers as Record<string, string> | undefined;
    expect(headers?.['X-Project-UUID']).toBeUndefined();
  });

  it.each(projectScopedPaths)('SENDS X-Project-UUID for scoped path %s', async (path) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200 }),
    );
    const { apiGet } = await setupClient();
    await apiGet(path);
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined;
    const headers = init?.headers as Record<string, string> | undefined;
    expect(headers?.['X-Project-UUID']).toBe('proj-uuid-xyz');
  });

  it('does not send the header when no project is selected', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200 }),
    );
    const { apiGet, setProjectUUID } = await loadClient();
    setProjectUUID(null);
    await apiGet('/api/findings');
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined;
    const headers = init?.headers as Record<string, string> | undefined;
    expect(headers?.['X-Project-UUID']).toBeUndefined();
  });
});

describe('ApiError', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: new URL('http://localhost:3002/'),
    });
  });

  it('reads a v1 error body: status from the response, code from error_code', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(JSON.stringify({ error: 'forbidden', code: 403, error_code: 'forbidden', details: 'no access' }), {
        status: 403,
      }),
    );
    const { apiGet, ApiError } = await loadClient();
    expect.assertions(5);
    try {
      await apiGet('/api/findings');
    } catch (e) {
      const err = e as InstanceType<typeof ApiError>;
      expect(err).toBeInstanceOf(ApiError);
      expect(err.status).toBe(403);
      expect(err.code).toBe('forbidden');
      expect(err.message).toBe('forbidden');
      expect(err.details).toBe('no access');
    }
  });

  it('reads a v2 error body (error object)', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(JSON.stringify({
        schema_version: 2, ok: false,
        error: { code: 'scan_not_found', message: 'scan not found', status: 404, details: 'gone' },
      }), { status: 404 }),
    );
    const { apiGet, ApiError } = await loadClient();
    expect.assertions(5);
    try {
      await apiGet('/api/scans/x');
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      const err = e as InstanceType<typeof ApiError>;
      expect(err.status).toBe(404);
      expect(err.code).toBe('scan_not_found');
      expect(err.message).toBe('scan not found');
      expect(err.details).toBe('gone');
    }
  });

  it('falls back to the status text when the body is not JSON', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response('boom', { status: 502, statusText: 'Bad Gateway' }),
    );
    const { apiGet, ApiError } = await loadClient();
    expect.assertions(4);
    try {
      await apiGet('/api/findings');
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      const err = e as InstanceType<typeof ApiError>;
      expect(err.status).toBe(502);
      expect(err.code).toBe('');
      expect(err.message).toBe('Bad Gateway');
    }
  });
});

describe('project_not_found recovery', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: new URL('http://localhost:3002/'),
    });
  });

  it('clears the stale UUID, notifies listeners, and retries once without the header', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: 'project not found', code: 404, error_code: 'project_not_found',
      }), { status: 404 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: [1], total: 1 }), { status: 200 }));
    const client = await loadClient();
    client.setProjectUUID('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    const seen: Array<string | null> = [];
    client.onProjectNotFound((stale) => seen.push(stale));

    const out = await client.apiGet<{ data: number[] }>('/api/findings');

    expect(out.data).toEqual([1]);
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    const first = fetchSpy.mock.calls[0]?.[1]?.headers as Record<string, string>;
    const second = fetchSpy.mock.calls[1]?.[1]?.headers as Record<string, string>;
    expect(first['X-Project-UUID']).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    expect(second['X-Project-UUID']).toBeUndefined();
    expect(client.getProjectUUID()).toBe(null);
    expect(seen).toEqual(['aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee']);
  });

  it('does not retry other 404s', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'scan not found', code: 404, error_code: 'scan_not_found' }), { status: 404 }),
    );
    const client = await loadClient();
    client.setProjectUUID('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    await expect(client.apiGet('/api/scans/x')).rejects.toMatchObject({ status: 404, code: 'scan_not_found' });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(client.getProjectUUID()).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
  });
});

describe('list unwrapping', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: new URL('http://localhost:3002/'),
    });
  });

  it('aliases v2 items as data', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ schema_version: 2, ok: true, items: [{ id: 1 }], total: 1 }), { status: 200 }),
    );
    const { apiGet } = await loadClient();
    const out = await apiGet<{ data: Array<{ id: number }>; total: number }>('/api/findings');
    expect(out.data).toEqual([{ id: 1 }]);
    expect(out.total).toBe(1);
  });

  it('leaves v1 data and bare arrays alone', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: [2], total: 1 }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([{ uuid: 'p' }]), { status: 200 }));
    const { apiGet } = await loadClient();
    expect(await apiGet('/api/findings')).toEqual({ data: [2], total: 1 });
    expect(await apiGet('/api/projects')).toEqual([{ uuid: 'p' }]);
  });
});

describe('apiGetJSONOrText', () => {
  it('returns a text/plain body as a string (scan runtime.log tail)', async () => {
    const { apiGetJSONOrText } = await loadClient();
    vi.stubGlobal('fetch', vi.fn(async () => new Response('line one\nline two\n', {
      status: 200,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })));
    await expect(apiGetJSONOrText('/api/scans/abc/logs')).resolves.toBe('line one\nline two\n');
  });

  it('still parses JSON bodies', async () => {
    const { apiGetJSONOrText } = await loadClient();
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"logs":[],"total":0}', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })));
    await expect(apiGetJSONOrText('/api/scans/abc/logs')).resolves.toEqual({ logs: [], total: 0 });
  });

  it('leaves plain apiGet JSON-only', async () => {
    const { apiGet } = await loadClient();
    vi.stubGlobal('fetch', vi.fn(async () => new Response('not json', {
      status: 200,
      headers: { 'Content-Type': 'text/plain' },
    })));
    await expect(apiGet('/api/x')).rejects.toThrow();
  });
});
