import * as t from '@babel/types';
import type { NodePath } from '../ast-utils/babel';
import { getEngineState } from '../context/engine-state';
import type { StructuralIndex } from '../structure';
import { createResolutionContext, resolveValueSingle, type ResolutionContext } from './extractRequest';
import type { TrackedVariableMap } from './types';

/**
 * Static model of `new URL(...)` and `new URLSearchParams(...)` bindings.
 *
 * `const u = new URL("/api/search", location.origin); u.searchParams.set("q", q);
 * fetch(u)` issues `GET /api/search?q=${q}`, but nothing in the generic value
 * resolver knows that the later `.set` calls mutate `u`. This pass folds every
 * mutation of a bound URL/URLSearchParams object into one rendered string and
 * publishes it where the request extractors already look:
 *
 * - a scope-qualified tracked variable (`scope:<uid>:<name>`), so an identifier
 *   reference such as `fetch(u)` or `body: params` resolves to it;
 * - `urlModels`, keyed by the constructor node, so code that first resolves an
 *   identifier to its initializer (axios `params`, request bodies) gets it too;
 * - `urlModelRefs`, so `isValidUrlNode` accepts a short binding name like `u`.
 *
 * Mutations are folded in source order with no control-flow analysis: a
 * parameter set on one branch is still a parameter the endpoint accepts.
 */

type Pair = [name: string, value: string];

interface UrlModel {
  kind: 'url' | 'params';
  /** URL without its query: absolute, origin-relative or relative. */
  path: string;
  query: Pair[];
}

const LOCATION_BASES = new Set([
  'location', 'location.origin', 'location.href',
  'window.location', 'window.location.origin', 'window.location.href',
  'self.location', 'self.location.origin', 'self.location.href',
  'globalThis.location', 'globalThis.location.origin', 'globalThis.location.href',
  'document.location', 'document.location.origin', 'document.location.href',
  'document.baseURI', 'document.URL',
]);

function memberPath(node: t.Node | null | undefined): string {
  if (!node) return '';
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node) && !node.computed && t.isIdentifier(node.property)) {
    const object = memberPath(node.object);
    return object ? `${object}.${node.property.name}` : '';
  }
  return '';
}

function propertyName(node: t.MemberExpression): string | undefined {
  if (t.isIdentifier(node.property) && !node.computed) return node.property.name;
  if (t.isStringLiteral(node.property)) return node.property.value;
  return undefined;
}

/** Constructor callee name when `node` builds a URL or URLSearchParams. */
export function urlConstructorKind(node: t.Node | null | undefined): UrlModel['kind'] | undefined {
  if (!t.isNewExpression(node)) return undefined;
  const callee = memberPath(node.callee);
  if (callee === 'URL' || callee === 'window.URL' || callee === 'globalThis.URL') return 'url';
  if (callee === 'URLSearchParams' || callee === 'window.URLSearchParams') return 'params';
  return undefined;
}

function decode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

/** Split a rendered query string; template placeholders survive intact. */
function parseQuery(raw: string): Pair[] {
  const query = raw.replace(/^\?/, '');
  if (!query) return [];
  return query.split('&').filter(Boolean).map((part) => {
    const separator = part.indexOf('=');
    return separator === -1
      ? [decode(part), '']
      : [decode(part.slice(0, separator)), decode(part.slice(separator + 1))];
  });
}

function splitQuery(rendered: string): { path: string; query: Pair[] } {
  const index = rendered.indexOf('?');
  if (index === -1) return { path: rendered, query: [] };
  return { path: rendered.slice(0, index), query: parseQuery(rendered.slice(index + 1)) };
}

const ABSOLUTE_URL = /^[a-z][a-z\d+.-]*:\/\//i;

function joinBase(path: string, baseNode: t.Node | undefined, trackedVars: TrackedVariableMap, context?: ResolutionContext): string {
  if (!baseNode || ABSOLUTE_URL.test(path) || path.startsWith('//')) return path;
  if (LOCATION_BASES.has(memberPath(baseNode))) {
    // Same-origin: the request goes to the page's own host.
    return path.startsWith('/') || path.startsWith('${') ? path : `/${path.replace(/^\.\//, '')}`;
  }
  const base = resolveValueSingle(baseNode, trackedVars, context);
  if (ABSOLUTE_URL.test(base) && !base.includes('${')) {
    const origin = base.match(/^[a-z][a-z\d+.-]*:\/\/[^/?#]+/i)?.[0] ?? base;
    if (path.startsWith('/')) return `${origin}${path}`;
    const directory = base.replace(/[?#].*$/, '').replace(/\/[^/]*$/, '');
    return `${directory || origin}/${path.replace(/^\.\//, '')}`;
  }
  // Unknown base. An absolute path keeps only the unknown origin, so render it
  // origin-relative; a relative one depends on the base's path, so keep it.
  if (path.startsWith('/')) return path;
  return base ? `${base.replace(/\/+$/, '')}/${path}` : path;
}

function constructorModel(
  node: t.NewExpression,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): UrlModel | undefined {
  const kind = urlConstructorKind(node);
  if (!kind) return undefined;
  const [first, second] = node.arguments as Array<t.Node | undefined>;
  if (kind === 'url') {
    if (!first || t.isSpreadElement(first)) return undefined;
    const rendered = joinBase(resolveValueSingle(first, trackedVars, context), second, trackedVars, context);
    if (!rendered) return undefined;
    return { kind, ...splitQuery(rendered) };
  }
  const model: UrlModel = { kind, path: '', query: [] };
  if (!first) return model;
  if (t.isObjectExpression(first)) {
    for (const property of first.properties) {
      if (!t.isObjectProperty(property)) continue;
      const name = t.isIdentifier(property.key) && !property.computed
        ? property.key.name
        : t.isStringLiteral(property.key) ? property.key.value : undefined;
      if (!name) continue;
      model.query.push([name, resolveValueSingle(property.value, trackedVars, context)]);
    }
  } else if (t.isArrayExpression(first)) {
    for (const element of first.elements) {
      if (!t.isArrayExpression(element) || element.elements.length < 2) continue;
      const [name, value] = element.elements;
      if (!name || !value || t.isSpreadElement(name) || t.isSpreadElement(value)) continue;
      model.query.push([resolveValueSingle(name, trackedVars, context), resolveValueSingle(value, trackedVars, context)]);
    }
  } else if (t.isStringLiteral(first) || t.isTemplateLiteral(first)) {
    model.query.push(...parseQuery(resolveValueSingle(first, trackedVars, context)));
  }
  return model;
}

function render(model: UrlModel): string {
  const query = model.query.map(([name, value]) => `${name}=${value}`).join('&');
  if (model.kind === 'params') return query;
  return query ? `${model.path}?${query}` : model.path;
}

function applyParamsCall(
  model: UrlModel,
  call: NodePath | null,
  method: string | undefined,
  trackedVars: TrackedVariableMap,
): void {
  if (!call?.isCallExpression() || !method) return;
  const args = call.node.arguments;
  if (!args[0] || t.isSpreadElement(args[0])) return;
  const context = createResolutionContext(undefined, { callSiteIndex: 0 }, call);
  const name = resolveValueSingle(args[0], trackedVars, context);
  if (!name) return;
  switch (method) {
    case 'set': {
      const value = args[1] && !t.isSpreadElement(args[1]) ? resolveValueSingle(args[1], trackedVars, context) : '';
      // set() replaces the first entry in place and drops the rest.
      const at = model.query.findIndex(([existing]) => existing === name);
      if (at === -1) {
        model.query.push([name, value]);
        break;
      }
      model.query = model.query.filter(([existing], index) => existing !== name || index === at);
      model.query[at] = [name, value];
      break;
    }
    case 'append': {
      const value = args[1] && !t.isSpreadElement(args[1]) ? resolveValueSingle(args[1], trackedVars, context) : '';
      model.query.push([name, value]);
      break;
    }
    case 'delete':
      model.query = model.query.filter(([existing]) => existing !== name);
      break;
    default:
  }
}

/** Fold one reference to a modelled binding into its model. */
function applyReference(model: UrlModel, ref: NodePath, trackedVars: TrackedVariableMap): void {
  const parent = ref.parentPath;
  if (!parent?.isMemberExpression() || parent.node.object !== ref.node) return;
  const property = propertyName(parent.node);
  if (model.kind === 'params') {
    applyParamsCall(model, parent.parentPath, property, trackedVars);
    return;
  }
  if (property === 'searchParams') {
    const method = parent.parentPath;
    if (method?.isMemberExpression() && method.node.object === parent.node) {
      applyParamsCall(model, method.parentPath, propertyName(method.node), trackedVars);
    }
    return;
  }
  const assignment = parent.parentPath;
  if (!assignment?.isAssignmentExpression() || assignment.node.left !== parent.node || assignment.node.operator !== '=') return;
  const context = createResolutionContext(undefined, { callSiteIndex: 0 }, assignment);
  const value = resolveValueSingle(assignment.node.right, trackedVars, context);
  if (property === 'pathname') {
    const origin = model.path.match(/^[a-z][a-z\d+.-]*:\/\/[^/?#]+/i)?.[0] ?? '';
    model.path = `${origin}${value.startsWith('/') ? value : `/${value}`}`;
  } else if (property === 'search') {
    model.query = parseQuery(value);
  } else if (property === 'href') {
    Object.assign(model, splitQuery(value));
  }
}

/**
 * Model every `const x = new URL(...)` / `new URLSearchParams(...)` binding in
 * the structural index. Runs after value tracking, before request extraction.
 */
export function collectUrlModels(index: StructuralIndex, trackedVars: TrackedVariableMap): void {
  const state = getEngineState();
  for (const path of index.variableDeclarators) {
    const { id, init } = path.node;
    if (!t.isIdentifier(id) || !t.isNewExpression(init) || !urlConstructorKind(init)) continue;
    const binding = path.scope.getBinding(id.name);
    if (!binding) continue;
    const model = constructorModel(init, trackedVars, createResolutionContext(undefined, { callSiteIndex: 0 }, path));
    if (!model) continue;
    const refs = [...binding.referencePaths].sort((a, b) => (a.node.start ?? 0) - (b.node.start ?? 0));
    for (const ref of refs) {
      state.urlModelRefs.add(ref.node);
      applyReference(model, ref, trackedVars);
    }
    const rendered = render(model);
    if (!rendered) continue;
    state.urlModels.set(init, [rendered]);
    const key = `scope:${binding.scope.uid}:${id.name}`;
    state.trackedVariables.set(key, new Set([rendered]));
    if (model.kind === 'url') state.trackedVariables.set(`${key}.href`, new Set([rendered]));
  }
}

/**
 * Resolve a URL/URLSearchParams constructor: the folded binding model when the
 * pre-pass saw one, else a constructor-only model for an inline `new URL(...)`.
 */
export function resolveUrlConstructor(
  node: t.NewExpression,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string[] | undefined {
  const modelled = getEngineState().urlModels.get(node);
  if (modelled) return modelled;
  const model = constructorModel(node, trackedVars, context);
  if (!model) return undefined;
  const rendered = render(model);
  return rendered ? [rendered] : undefined;
}

/** True for an identifier that refers to a modelled URL/URLSearchParams binding. */
export function isUrlModelReference(node: t.Node | null | undefined): boolean {
  return Boolean(node) && getEngineState().urlModelRefs.has(node as object);
}
