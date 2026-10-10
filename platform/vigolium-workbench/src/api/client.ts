import type { ErrorResponse } from './types';
import { isStaticBuild } from '@/lib/buildMode';

const TOKEN_KEY = 'vigolium_api_token';
const URL_KEY = 'vigolium_api_url';
const PROJECT_KEY = 'vigolium_project_uuid';
const USER_KEY = 'vigolium_user_info';

// ── Project UUID (shared) ──────────────────────────────────────────

export function getProjectUUID(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(PROJECT_KEY);
}

export function setProjectUUID(uuid: string | null) {
  if (uuid) {
    localStorage.setItem(PROJECT_KEY, uuid);
  } else {
    localStorage.removeItem(PROJECT_KEY);
  }
}

// ── Error ──────────────────────────────────────────────────────────

/**
 * A failed API call. `status` is the HTTP status; `code` is the server's
 * stable string error code (`project_not_found`, `scan_not_found`, …) — the
 * value to branch on. Never branch on `message`.
 */
export class ApiError extends Error {
  status: number;
  code: string;
  details?: string;

  constructor(error: string, status: number, code?: string, details?: string) {
    super(error);
    this.name = 'ApiError';
    this.status = status;
    this.code = code ?? '';
    this.details = details;
  }
}

/**
 * Builds an ApiError from a non-2xx response body. Reads both server shapes:
 * v1 `{error: "msg", code: 404, error_code: "…", details}` and
 * v2 `{ok: false, error: {code: "…", message, status, details}}`.
 */
export function apiErrorFromBody(body: unknown, status: number, fallback: string): ApiError {
  const b = (body && typeof body === 'object' ? body : {}) as ErrorResponse;
  const err = b.error;
  if (err && typeof err === 'object') {
    return new ApiError(err.message || fallback, status, err.code, err.details);
  }
  return new ApiError(err || fallback, status, b.error_code, b.details);
}

/** The human message of an error body in either server shape. */
export function errorMessageFromBody(body: unknown, fallback: string): string {
  return apiErrorFromBody(body, 0, fallback).message;
}

async function apiErrorFromResponse(res: Response, fallback: string = res.statusText): Promise<ApiError> {
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    // ignore parse error
  }
  return apiErrorFromBody(body, res.status, fallback);
}

/** The server's code for a request naming a project it does not have. */
export const PROJECT_NOT_FOUND = 'project_not_found';

type ProjectNotFoundListener = (staleUUID: string | null) => void;
const projectNotFoundListeners: ProjectNotFoundListener[] = [];

/**
 * Subscribe to "the stored project UUID no longer exists on the server".
 * By the time listeners run the stale UUID is already cleared from
 * localStorage; ProjectContext uses this to refetch the project list.
 */
export function onProjectNotFound(listener: ProjectNotFoundListener) {
  projectNotFoundListeners.push(listener);
  return () => {
    const idx = projectNotFoundListeners.indexOf(listener);
    if (idx >= 0) projectNotFoundListeners.splice(idx, 1);
  };
}

function emitProjectNotFound(staleUUID: string | null) {
  projectNotFoundListeners.forEach((fn) => fn(staleUUID));
}

/**
 * v2 list bodies carry rows under `items`; v1 under `data`. Callers read
 * `data`, so alias it once here.
 */
function unwrapListBody<T>(body: T): T {
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    const b = body as Record<string, unknown>;
    if (Array.isArray(b.items) && b.data === undefined) {
      return { ...b, data: b.items } as T;
    }
  }
  return body;
}

// ── Auth (static/workbench mode only) ──────────────────────────────

type AuthListener = () => void;
const authListeners: AuthListener[] = [];

export function onAuthRequired(listener: AuthListener) {
  authListeners.push(listener);
  return () => {
    const idx = authListeners.indexOf(listener);
    if (idx >= 0) authListeners.splice(idx, 1);
  };
}

function emitAuthRequired() {
  authListeners.forEach((fn) => fn());
}

// ── Demo mode (cloud only) ─────────────────────────────────────────

let demoMode = false;

export function setDemoMode(active: boolean) {
  demoMode = active;
}

export function isDemoMode(): boolean {
  return demoMode;
}

type DemoBlockedListener = (method: string, path: string) => void;
const demoBlockedListeners: DemoBlockedListener[] = [];

export function onDemoBlocked(listener: DemoBlockedListener) {
  demoBlockedListeners.push(listener);
  return () => {
    const idx = demoBlockedListeners.indexOf(listener);
    if (idx >= 0) demoBlockedListeners.splice(idx, 1);
  };
}

function emitDemoBlocked(method: string, path: string) {
  demoBlockedListeners.forEach((fn) => fn(method, path));
}

export class DemoReadOnlyError extends ApiError {
  constructor() {
    super('This action is disabled in demo mode', 403, 'forbidden');
    this.name = 'DemoReadOnlyError';
  }
}

function guardDemoMutation(method: string, path: string) {
  if (demoMode && method !== 'GET' && method !== 'HEAD') {
    emitDemoBlocked(method, path);
    throw new DemoReadOnlyError();
  }
}

/** Throw + toast if the current session is demo mode. Use this for raw fetch() mutations. */
export function assertNotDemo(path: string = '') {
  guardDemoMutation('POST', path);
}

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export interface UserInfo {
  uuid: string;
  name: string;
  email: string;
  role: string;
}

export function getUserInfo(): UserInfo | null {
  if (typeof window === 'undefined') return null;
  const stored = localStorage.getItem(USER_KEY);
  if (!stored) return null;
  try { return JSON.parse(stored); } catch { return null; }
}

export function setUserInfo(user: UserInfo) {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export async function fetchUserInfo(): Promise<UserInfo | null> {
  try {
    const base = getBaseUrl();
    const token = getToken();
    const headers: Record<string, string> = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const res = await fetch(new URL('/api/user/info', base).toString(), {
      headers,
    });
    if (!res.ok) return null;
    const user: UserInfo = await res.json();
    setUserInfo(user);
    return user;
  } catch {
    return null;
  }
}

// ── Base URL ───────────────────────────────────────────────────────

export function getBaseUrl(): string {
  if (isStaticBuild) {
    // Static/workbench mode: talk directly to Go backend
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem(URL_KEY);
      if (stored) return stored;
      return process.env.NEXT_PUBLIC_API_BASE_URL || window.location.origin;
    }
    return process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:9002';
  }

  // Cloud/console mode: route through server-side proxy
  if (typeof window !== 'undefined') {
    return `${window.location.origin}/api/proxy`;
  }
  return process.env.VIGOLIUM_SCAN_SERVER || 'http://localhost:9002';
}

export function setBaseUrl(url: string) {
  localStorage.setItem(URL_KEY, url);
}

// ── Shared header/URL builders ─────────────────────────────────────
// Used by `request()` below, `apiUpload`, `fetchSSE`, and any hook that
// needs to talk to the scan server outside the JSON helpers (e.g.
// streaming text/SSE endpoints). Keeps the static-vs-cloud branching,
// bearer token, project header, and demo_key rules in one place.

export function buildApiUrl(path: string): string {
  const base = getBaseUrl();
  const url = isStaticBuild ? new URL(path, base).toString() : base + path;
  return isStaticBuild ? url : withDemoKey(url);
}

export interface AuthHeaderOptions {
  json?: boolean;
  sse?: boolean;
  /** Path being requested — used to skip X-Project-UUID for non-scoped paths. */
  path?: string;
}

// Project bootstrap (list/create/manage) and public utility endpoints aren't
// project-scoped; sending X-Project-UUID for them locks users out of recovery
// when localStorage holds a stale UUID.
function isProjectScopeExempt(path: string): boolean {
  return (
    path === '/server-info' ||
    path === '/health' ||
    path === '/metrics' ||
    path.startsWith('/swagger') ||
    path === '/api/projects' ||
    path.startsWith('/api/projects/')
  );
}

export function buildAuthHeaders(opts: AuthHeaderOptions = {}): Record<string, string> {
  const headers: Record<string, string> = {};
  if (opts.json) headers['Content-Type'] = 'application/json';
  if (opts.sse) headers['Accept'] = 'text/event-stream';
  if (isStaticBuild) {
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
  }
  const projectUUID = getProjectUUID();
  const skipProjectHeader = opts.path ? isProjectScopeExempt(opts.path) : false;
  if (projectUUID && !skipProjectHeader) headers['X-Project-UUID'] = projectUUID;
  return headers;
}

// ── Demo key (cloud only, URL-sourced) ─────────────────────────────

/** Read demo_key from the current browser URL. Returns null on server or when absent. */
export function getDemoKeyFromUrl(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return new URLSearchParams(window.location.search).get('demo_key');
  } catch {
    return null;
  }
}

/** Append demo_key to a URL string if it's not already there and demo mode is active. */
export function withDemoKey(urlOrPath: string): string {
  const key = getDemoKeyFromUrl();
  if (!key) return urlOrPath;
  const [pathAndQuery, fragment] = urlOrPath.split('#');
  const [path, query = ''] = pathAndQuery.split('?');
  const params = new URLSearchParams(query);
  if (!params.has('demo_key')) {
    params.set('demo_key', key);
  }
  const qs = params.toString();
  const rebuilt = qs ? `${path}?${qs}` : path;
  return fragment ? `${rebuilt}#${fragment}` : rebuilt;
}

// ── HTTP helpers ───────────────────────────────────────────────────

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  opts: { allowText?: boolean; retried?: boolean } = {},
): Promise<T> {
  guardDemoMutation(method, path);

  const url = buildApiUrl(path);
  const headers = buildAuthHeaders({ json: true, path });

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (isStaticBuild && res.status === 401) {
    emitAuthRequired();
    throw new ApiError('Unauthorized', 401, 'unauthorized');
  }

  if (!res.ok) {
    const err = await apiErrorFromResponse(res);
    // The stored project is gone (DB reset, deleted elsewhere): forget it,
    // let ProjectContext refetch the list, and retry once without it.
    if (err.code === PROJECT_NOT_FOUND && headers['X-Project-UUID'] && !opts.retried) {
      const stale = getProjectUUID();
      setProjectUUID(null);
      emitProjectNotFound(stale);
      return request<T>(method, path, body, { ...opts, retried: true });
    }
    throw err;
  }

  if (opts.allowText && (res.headers.get('Content-Type') || '').startsWith('text/plain')) {
    return (await res.text()) as T;
  }
  return unwrapListBody(await res.json()) as T;
}

function withQuery(path: string, params?: Record<string, string | number | undefined>): string {
  if (!params) return path;
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') sp.set(k, String(v));
  }
  const qs = sp.toString();
  return qs ? `${path}?${qs}` : path;
}

export function apiGet<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  return request<T>('GET', withQuery(path, params));
}

/** GET an endpoint that answers either JSON or a plain-text body - a scan's
 *  logs are its runtime.log tail as text/plain when the file exists, and
 *  structured JSON rows otherwise. */
export function apiGetJSONOrText<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T | string> {
  return request<T | string>('GET', withQuery(path, params), undefined, { allowText: true });
}

export function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return request<T>('POST', path, body);
}

export function apiPut<T>(path: string, body?: unknown): Promise<T> {
  return request<T>('PUT', path, body);
}

export function apiPatch<T>(path: string, body?: unknown): Promise<T> {
  return request<T>('PATCH', path, body);
}

export function apiDelete<T>(path: string, body?: unknown): Promise<T> {
  return request<T>('DELETE', path, body);
}

export async function apiUpload<T>(path: string, file: File): Promise<T> {
  guardDemoMutation('POST', path);

  const url = buildApiUrl(path);
  // No `json: true` — fetch sets the multipart boundary itself when the body
  // is a FormData. Setting Content-Type manually breaks the upload.
  const headers = buildAuthHeaders({ path });

  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: formData,
  });

  if (isStaticBuild && res.status === 401) {
    emitAuthRequired();
    throw new ApiError('Unauthorized', 401, 'unauthorized');
  }

  if (!res.ok) {
    throw await apiErrorFromResponse(res);
  }

  return res.json();
}

// ── Login (static/workbench mode only) ─────────────────────────────

export async function login(username: string, accessCode: string): Promise<{ token: string; user: { uuid: string; name: string; email: string; role: string } }> {
  const base = getBaseUrl();
  const res = await fetch(new URL('/api/auth/login', base).toString(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, access_code: accessCode }),
  });

  if (!res.ok) {
    throw await apiErrorFromResponse(res, 'login failed');
  }

  return res.json();
}

export async function checkServerInfo(): Promise<{ ok: boolean; noAuth: boolean }> {
  try {
    const base = getBaseUrl();
    const res = await fetch(new URL('/server-info', base).toString());
    return { ok: res.ok, noAuth: res.ok };
  } catch {
    return { ok: false, noAuth: false };
  }
}
