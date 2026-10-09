import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import { traverse, type NodePath } from '../ast-utils/babel';
import type { AnalysisContext } from '../context';
import type { AuthContext } from '../protocol';

/**
 * Credential-source recovery for extracted requests.
 *
 * Header templates already say *that* a request is authenticated
 * (`Authorization: Bearer ${localStorage.getItem()}`) but the value resolver
 * drops call arguments, so *where the token lives* is lost. An agent replaying
 * the request needs exactly that: "read `jwt` from localStorage". This pass
 * walks back from each request's call node to the expression feeding its
 * credential header and names the storage slot. It never records a value; a
 * hard-coded credential is reported as `literal` and left to secret scanning.
 */

type SourceKind = AuthContext['sourceKind'];

interface Source {
  kind: SourceKind;
  key?: string;
}

const AUTH_HEADER = /^(authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|x-session-token|x-token|x-(?:xsrf|csrf)-token)$/i;
const API_KEY_HEADER = /^(x-api-key|api-key|apikey)$/i;
const API_KEY_QUERY = /^(api_?key|apikey|access_token|auth_token|token)$/i;
const SCHEME = /^([A-Za-z][\w-]*)\s+\S/;
const MAX_DEPTH = 5;

function headerParts(header: string): { name: string; value: string } {
  const separator = header.indexOf(':');
  return separator === -1
    ? { name: header.trim(), value: '' }
    : { name: header.slice(0, separator).trim(), value: header.slice(separator + 1).trim() };
}

function keyName(node: t.Node): string | undefined {
  if (t.isIdentifier(node)) return node.name;
  if (t.isStringLiteral(node)) return node.value;
  return undefined;
}

function memberChain(node: t.Node | null | undefined): string[] {
  const parts: string[] = [];
  let current = node;
  while (current && (t.isMemberExpression(current) || t.isOptionalMemberExpression(current))) {
    const name = t.isIdentifier(current.property) && !current.computed
      ? current.property.name
      : t.isStringLiteral(current.property) ? current.property.value : '*';
    parts.unshift(name);
    current = current.object as t.Node;
  }
  if (t.isIdentifier(current)) parts.unshift(current.name);
  else if (t.isThisExpression(current)) parts.unshift('this');
  else if (t.isCallExpression(current)) parts.unshift(`${memberChain(current.callee).join('.')}()`);
  return parts;
}

function firstStringArg(node: t.CallExpression | t.OptionalCallExpression): string | undefined {
  const arg = node.arguments[0];
  if (t.isStringLiteral(arg)) return arg.value;
  if (t.isTemplateLiteral(arg) && arg.expressions.length === 0) return arg.quasis[0].value.cooked ?? undefined;
  return undefined;
}

/** Cookie name read by a regex/split over document.cookie, when it is literal. */
function cookieNameFrom(node: t.Node): string | undefined {
  let found: string | undefined;
  const visit = (current: t.Node | null | undefined) => {
    if (!current || found) return;
    if (t.isRegExpLiteral(current)) {
      found = current.pattern.match(/([A-Za-z0-9_.-]+)=/)?.[1];
      return;
    }
    if (t.isStringLiteral(current)) {
      found = current.value.match(/^\s*;?\s*([A-Za-z0-9_.-]+)=?$/)?.[1];
      return;
    }
    for (const key of t.VISITOR_KEYS[current.type] ?? []) {
      const child = (current as unknown as Record<string, unknown>)[key];
      if (Array.isArray(child)) child.forEach((item) => t.isNode(item) && visit(item));
      else if (t.isNode(child)) visit(child);
    }
  };
  visit(node);
  return found;
}

function mentionsDocumentCookie(node: t.Node): boolean {
  if ((t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) && memberChain(node).join('.').endsWith('document.cookie')) {
    return true;
  }
  for (const key of t.VISITOR_KEYS[node.type] ?? []) {
    const child = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(child) ? child.some((item) => t.isNode(item) && mentionsDocumentCookie(item)) : t.isNode(child) && mentionsDocumentCookie(child)) {
      return true;
    }
  }
  return false;
}

/**
 * Name the storage slot feeding `node`. Follows constant bindings and a
 * single-return helper function a few levels; anything else is `unknown`.
 */
function traceSource(node: t.Node | null | undefined, path: NodePath, depth = 0): Source | undefined {
  if (!node || depth > MAX_DEPTH) return undefined;

  if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
    const callee = memberChain(node.callee).join('.');
    const key = firstStringArg(node);
    if (/(^|\.)localStorage\.getItem$/.test(callee)) return { kind: 'localStorage', key };
    if (/(^|\.)sessionStorage\.getItem$/.test(callee)) return { kind: 'sessionStorage', key };
    if (/(^|\.)(Cookies?|cookies|cookie|jsCookie|cookieService)\.get$/i.test(callee) ||
      /^(\$|jQuery)\.cookie$/.test(callee) || /^(get|read)Cookie$/i.test(callee)) {
      return { kind: 'cookie', key };
    }
    if (mentionsDocumentCookie(node)) return { kind: 'cookie', key: cookieNameFrom(node) };
    // A local helper such as getToken(): follow its single return value.
    if (t.isIdentifier(node.callee)) {
      const binding = path.scope.getBinding(node.callee.name);
      const fn = binding?.path.isFunctionDeclaration()
        ? binding.path
        : binding?.path.isVariableDeclarator() ? binding.path.get('init') : undefined;
      if (fn && !Array.isArray(fn) && (fn.isFunction())) {
        const body = (fn.node as t.Function).body;
        if (t.isExpression(body)) return traceSource(body, fn as NodePath, depth + 1);
        const returned = t.isBlockStatement(body)
          ? body.body.find((statement): statement is t.ReturnStatement => t.isReturnStatement(statement))
          : undefined;
        if (returned?.argument) return traceSource(returned.argument, fn as NodePath, depth + 1);
      }
    }
    for (const arg of node.arguments) {
      const source = t.isNode(arg) ? traceSource(arg, path, depth + 1) : undefined;
      if (source) return source;
    }
    if (t.isMemberExpression(node.callee)) return traceSource(node.callee.object, path, depth + 1);
    return undefined;
  }

  if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
    const chain = memberChain(node);
    const state = chain.findIndex((part) => part.endsWith('getState()'));
    if (state !== -1 && state < chain.length - 1) return { kind: 'state', key: chain.slice(state + 1).join('.') };
    if (chain.join('.').endsWith('document.cookie')) return { kind: 'cookie' };
    // match[1] over a document.cookie match bound to `match`.
    return traceSource(node.object as t.Node, path, depth + 1);
  }

  if (t.isIdentifier(node)) {
    const binding = path.scope.getBinding(node.name);
    if (!binding || !binding.constant || !binding.path.isVariableDeclarator()) return undefined;
    const init = binding.path.node.init;
    return init ? traceSource(init, binding.path, depth + 1) : undefined;
  }

  if (t.isTemplateLiteral(node)) {
    for (const expression of node.expressions) {
      const source = traceSource(expression, path, depth + 1);
      if (source) return source;
    }
    return node.expressions.length === 0 ? { kind: 'literal' } : undefined;
  }

  if (t.isBinaryExpression(node) && node.operator === '+') {
    const left = t.isNode(node.left) ? traceSource(node.left, path, depth + 1) : undefined;
    const right = traceSource(node.right, path, depth + 1);
    if (left && left.kind !== 'literal') return left;
    if (right && right.kind !== 'literal') return right;
    return left && right ? { kind: 'literal' } : undefined;
  }

  if (t.isLogicalExpression(node) || t.isConditionalExpression(node)) {
    const parts = t.isLogicalExpression(node) ? [node.left, node.right] : [node.consequent, node.alternate];
    for (const part of parts) {
      const source = traceSource(part, path, depth + 1);
      if (source && source.kind !== 'literal') return source;
    }
    return undefined;
  }

  if (t.isStringLiteral(node)) return { kind: 'literal' };
  return undefined;
}

function authFor(header: string, value: string, source: Source | undefined): AuthContext {
  const scheme = value.match(SCHEME)?.[1];
  let kind: AuthContext['kind'] = 'custom';
  if (/^(proxy-)?authorization$/i.test(header)) {
    if (scheme?.toLowerCase() === 'bearer') kind = 'bearer';
    else if (scheme?.toLowerCase() === 'basic') kind = 'basic';
  } else if (API_KEY_HEADER.test(header)) {
    kind = 'apikey-header';
  }
  // The header template is the fallback: a value with no variables is a
  // hard-coded credential even when the expression could not be walked.
  const sourceKind: SourceKind = source?.kind ?? (/\$\{/.test(value) ? 'unknown' : 'literal');
  const key = sourceKind === 'literal' || sourceKind === 'unknown' ? undefined : source?.key;
  return {
    kind,
    header,
    ...(scheme && /^(proxy-)?authorization$/i.test(header) ? { scheme } : {}),
    source: key ? `${sourceKind}:${key}` : sourceKind,
    sourceKind,
  };
}

/** Find the expression assigned to `header` inside a request call's arguments. */
function headerValuePath(call: NodePath, header: string): NodePath | undefined {
  const wanted = header.toLowerCase();
  let found: NodePath | undefined;
  const search = (root: NodePath) => {
    root.traverse({
      ObjectProperty(property) {
        if (found) return property.stop();
        const name = keyName(property.node.key);
        if (name?.toLowerCase() === wanted) {
          found = property.get('value') as NodePath;
          property.stop();
        }
      },
    });
  };
  search(call);
  if (found) return found;
  // fetch(url, options) / axios(url, config) with the config bound elsewhere.
  const args = call.get('arguments');
  for (const arg of Array.isArray(args) ? args : []) {
    if (!arg.isIdentifier()) continue;
    const binding = arg.scope.getBinding(arg.node.name);
    if (binding?.path.isVariableDeclarator()) {
      const init = binding.path.get('init');
      if (!Array.isArray(init) && init.isObjectExpression()) search(init);
      if (found) return found;
    }
  }
  return undefined;
}

interface GlobalAuth {
  header: string;
  value: NodePath;
}

/** `axios.defaults.headers.common.Authorization = ...` and interceptor assignments. */
function globalAxiosAuth(path: NodePath<t.AssignmentExpression>): GlobalAuth | undefined {
  const chain = memberChain(path.node.left);
  const header = chain[chain.length - 1];
  if (!header || !AUTH_HEADER.test(header) || !chain.includes('headers')) return undefined;
  const inDefaults = chain.includes('defaults');
  const inInterceptor = Boolean(path.findParent((parent) =>
    parent.isCallExpression() && memberChain(parent.node.callee).join('.').endsWith('interceptors.request.use')));
  return inDefaults || inInterceptor ? { header, value: path.get('right') as NodePath } : undefined;
}

/**
 * Attach `auth` to every request origin whose credential header (or API-key
 * query parameter) can be traced. Runs after request extraction.
 */
export function attachAuthSources(ast: ParseResult<t.File> | null, context: AnalysisContext): void {
  if (!ast || context.requests.length === 0) return;

  const pending = new Map<object, number[]>();
  for (let index = 0; index < context.requests.length; index++) {
    const request = context.requests[index];
    const origin = context.requestOrigins[index];
    if (!origin) continue;
    const header = request.headers.map(headerParts).find((part) => AUTH_HEADER.test(part.name));
    if (header && origin.node) {
      const list = pending.get(origin.node) ?? [];
      list.push(index);
      pending.set(origin.node, list);
    } else if (header) {
      origin.auth = authFor(header.name, header.value, undefined);
    } else {
      const query = request.params.split('&').map((part) => part.split('=')[0]).find((name) => API_KEY_QUERY.test(name));
      if (query) origin.auth = { kind: 'apikey-query', query, source: 'unknown', sourceKind: 'unknown' };
    }
  }

  const globals: GlobalAuth[] = [];
  const hasAxios = context.requestOrigins.some((origin) => origin?.client === 'axios');
  const wantsGlobals = hasAxios && /interceptors|defaults\.headers/.test(context.source);
  if (pending.size === 0 && !wantsGlobals) return;

  traverse(ast, {
    'CallExpression|NewExpression'(path: NodePath) {
      const indexes = pending.get(path.node);
      if (!indexes) return;
      for (const index of indexes) {
        const header = context.requests[index].headers.map(headerParts).find((part) => AUTH_HEADER.test(part.name))!;
        const valuePath = headerValuePath(path, header.name);
        const source = valuePath ? traceSource(valuePath.node, valuePath) : undefined;
        context.requestOrigins[index].auth = authFor(header.name, header.value, source);
      }
      pending.delete(path.node);
    },
    AssignmentExpression(path) {
      if (!wantsGlobals) return;
      const global = globalAxiosAuth(path);
      if (global) globals.push(global);
    },
  });

  // Nodes the traversal never reached (synthesized or replaced) still get the
  // header-only classification.
  for (const indexes of pending.values()) {
    for (const index of indexes) {
      const header = context.requests[index].headers.map(headerParts).find((part) => AUTH_HEADER.test(part.name))!;
      context.requestOrigins[index].auth = authFor(header.name, header.value, undefined);
    }
  }

  // An interceptor or defaults header authenticates every axios request that
  // does not carry its own credential.
  const global = globals[0];
  if (!global) return;
  const rendered = global.value.isStringLiteral() ? global.value.node.value : '${token}';
  const prefix = t.isBinaryExpression(global.value.node) && t.isStringLiteral(global.value.node.left)
    ? global.value.node.left.value
    : t.isTemplateLiteral(global.value.node) ? global.value.node.quasis[0].value.cooked ?? '' : '';
  const auth = authFor(global.header, prefix ? `${prefix}\${token}` : rendered, traceSource(global.value.node, global.value));
  for (const origin of context.requestOrigins) {
    if (origin && origin.client === 'axios' && !origin.auth) origin.auth = auth;
  }
}
