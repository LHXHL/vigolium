import * as t from '@babel/types';
import type { ParseResult } from '@babel/parser';
import { traverse, type NodePath } from '../ast-utils/babel';
import type { AnalysisContext } from '../context';
import type { AssetLoader, AssetReferenceFact, AssetType, Confidence, TemplateVariable } from '../protocol';
import { memberPath, provenance, stableId } from './common';
import {
  evaluateFunctionBody,
  evaluateSymbolic,
  propertyKey,
  type Evaluated,
  type SymbolicValue,
} from './symbolic';

/**
 * Runtime-loaded chunks: files a bundle loads by a name it computes at runtime,
 * so they never appear as a literal URL.
 *
 * - webpack 5: `__webpack_require__.u = id => <expr>` (minified `n.u=`, `r.u=`)
 *   and `.miniCssF` render a chunk filename from an id; `.p` is the publicPath;
 *   `.e(id)` call sites name the ids a bundle loads.
 * - webpack 4: the `jsonpScriptSrc(id)` function returns `R.p + <expr>`.
 * - Vite: `__vitePreload(() => import("./x.js"), ["assets/x.css", ...])`, under
 *   any (minified) callee name, including Vite 5 `__vite__mapDeps([i, ...])`.
 * - Rollup/Vite: `import(\`./x-${MAP[k]}.js\`)` over a literal map.
 *
 * The filename functions are evaluated symbolically (see symbolic.ts) for each
 * id in the chunk-id set; nothing is executed.
 */

const JS_CHUNK = /\.m?js(?:[?#]|$)/i;
const CSS_CHUNK = /\.css(?:[?#]|$)/i;
const ABSOLUTE_OR_RELATIVE = /^(?:[a-z][a-z0-9+.-]*:|\/\/|\/|\.\.?\/)/i;

type ChunkId = string | number;
type FunctionNode = t.FunctionDeclaration | t.FunctionExpression | t.ArrowFunctionExpression;

/** Ordered, de-duplicated chunk ids. Canonical numeric strings become numbers, as webpack ids are. */
class ChunkIdSet {
  private readonly ids = new Map<string, ChunkId>();

  add(value: SymbolicValue): void {
    if (typeof value === 'number' && Number.isFinite(value)) this.put(value);
    else if (typeof value === 'string' && value.length > 0 && value.length <= 256) {
      this.put(/^(?:0|[1-9]\d{0,14})$/.test(value) ? Number(value) : value);
    }
  }

  addAll(other: Iterable<ChunkId>): void {
    for (const id of other) this.add(id);
  }

  private put(id: ChunkId): void {
    const key = String(id);
    if (!this.ids.has(key)) this.ids.set(key, id);
  }

  values(): ChunkId[] {
    return [...this.ids.values()];
  }
}

type PublicPath = { kind: 'static' | 'relative'; value: string } | { kind: 'unknown' };

interface ChunkFunction {
  runtime: string;
  fn: FunctionNode;
  param: string;
  loader: Extract<AssetLoader, 'webpack-chunk' | 'webpack-css-chunk'>;
  extractor: string;
  path: NodePath;
  /** webpack 4 reads `R.p` inside the function; webpack 5 prefixes it at the call. */
  publicPathInline: boolean;
}

interface ChunkCall {
  object: string;
  id: SymbolicValue;
  webpackShaped: boolean;
}

interface PreloadCall {
  path: NodePath<t.CallExpression>;
  deps: t.Node;
}

function singleParam(fn: t.Function): string | undefined {
  return fn.params.length === 1 && t.isIdentifier(fn.params[0]) ? fn.params[0].name : undefined;
}

/** The expression a function returns when it is a single expression or `return`. */
function returnedExpression(fn: t.Function): t.Node | undefined {
  if (!t.isBlockStatement(fn.body)) return fn.body;
  const body = fn.body.body.filter((statement) => !t.isEmptyStatement(statement));
  return body.length === 1 && t.isReturnStatement(body[0]) ? body[0].argument ?? undefined : undefined;
}

function leftmostConcatOperand(node: t.Node): t.Node {
  let current = node;
  while (t.isBinaryExpression(current, { operator: '+' })) current = current.left;
  return current;
}

function publicPathMember(node: t.Node): string | undefined {
  return t.isMemberExpression(node) && !node.computed && t.isIdentifier(node.property, { name: 'p' }) &&
    t.isIdentifier(node.object) ? node.object.name : undefined;
}

function looksLikeIdLookup(node: t.Node, param: string): boolean {
  let found = false;
  t.traverseFast(node, (child) => {
    if (!found && t.isMemberExpression(child) && child.computed && t.isObjectExpression(child.object) &&
        t.isIdentifier(child.property, { name: param })) {
      found = true;
    }
  });
  return found;
}

/** Ids a chunk-filename function itself names: hash/name map keys and `id === <literal>` guards. */
function idsInFunction(fn: FunctionNode, param: string, ids: ChunkIdSet): void {
  t.traverseFast(fn.body, (node) => {
    if (t.isObjectExpression(node)) {
      for (const property of node.properties) {
        if (t.isObjectProperty(property)) {
          const key = propertyKey(property);
          if (key !== undefined) ids.add(key);
        }
      }
    } else if (t.isBinaryExpression(node) && ['===', '==', '!==', '!='].includes(node.operator)) {
      const [ident, other] = t.isIdentifier(node.left, { name: param }) ? [node.left, node.right]
        : t.isIdentifier(node.right, { name: param }) ? [node.right, node.left] : [undefined, undefined];
      if (ident && (t.isNumericLiteral(other) || t.isStringLiteral(other))) ids.add(other.value);
    }
  });
}

function objectKeys(node: t.Node, ids: ChunkIdSet): void {
  t.traverseFast(node, (child) => {
    if (!t.isObjectExpression(child)) return;
    for (const property of child.properties) {
      if (t.isObjectProperty(property)) {
        const key = propertyKey(property);
        if (key !== undefined) ids.add(key);
      }
    }
  });
}

function classifyPublicPath(rhs: t.Node): PublicPath {
  if (t.isStringLiteral(rhs)) return { kind: 'static', value: rhs.value };
  if (t.isTemplateLiteral(rhs) && rhs.expressions.length === 0) {
    return { kind: 'static', value: rhs.quasis.map((quasi) => quasi.value.cooked ?? '').join('') };
  }
  // webpack 5 `publicPath: "auto"`: `R.p = scriptDir` or `R.p = scriptDir + "../../"`,
  // so the chunk path is relative to the bundle's own URL.
  if (t.isIdentifier(rhs)) return { kind: 'relative', value: '' };
  if (t.isBinaryExpression(rhs, { operator: '+' }) && t.isIdentifier(rhs.left) && t.isStringLiteral(rhs.right) &&
      /^(?:\.\.?\/)*$/.test(rhs.right.value)) {
    return { kind: 'relative', value: rhs.right.value };
  }
  return { kind: 'unknown' };
}

function mergePublicPaths(paths: PublicPath[] | undefined): PublicPath {
  if (!paths?.length) return { kind: 'unknown' };
  const first = paths[0];
  const same = paths.every((path) => path.kind === first.kind &&
    (path.kind === 'unknown' || (first.kind !== 'unknown' && path.value === first.value)));
  return same ? first : { kind: 'unknown' };
}

function publicPathValue(path: PublicPath): string {
  return path.kind === 'unknown' ? '' : path.value;
}

/** `X.e(<literal>)` inside `.then(X.bind(...))` or `Promise.all([...])`: a webpack chunk load. */
function isWebpackChunkCall(path: NodePath<t.CallExpression>): boolean {
  const parent = path.parentPath;
  if (!parent) return false;
  if (parent.isMemberExpression() && !parent.node.computed &&
      t.isIdentifier(parent.node.property, { name: 'then' }) && parent.parentPath?.isCallExpression()) {
    const first = (parent.parentPath.node as t.CallExpression).arguments[0];
    return !!first && t.isCallExpression(first) && t.isMemberExpression(first.callee) &&
      t.isIdentifier(first.callee.property, { name: 'bind' });
  }
  if (parent.isArrayExpression() && parent.parentPath?.isCallExpression()) {
    return memberPath((parent.parentPath.node as t.CallExpression).callee) === 'Promise.all';
  }
  return false;
}

/** `() => import("./x.js")`: the thunk Vite passes to its preload helper. */
function importThunk(node: t.Node | undefined): boolean {
  if (!node || !(t.isArrowFunctionExpression(node) || t.isFunctionExpression(node)) || node.params.length) return false;
  const expression = returnedExpression(node);
  return !!expression && t.isImportExpression(expression);
}

function staticTruthiness(node: t.Node): boolean | undefined {
  if (t.isBooleanLiteral(node)) return node.value;
  if (t.isUnaryExpression(node, { operator: '!' }) && t.isNumericLiteral(node.argument)) return node.argument.value === 0;
  return undefined;
}

function stringArray(node: t.Node | null | undefined): string[] | undefined {
  if (!node || !t.isArrayExpression(node) || !node.elements.length) return undefined;
  const values: string[] = [];
  for (const element of node.elements) {
    if (!t.isStringLiteral(element)) return undefined;
    values.push(element.value);
  }
  return values;
}

function chunkFact(
  context: AnalysisContext,
  path: NodePath,
  rendered: string,
  assetType: AssetType,
  loader: AssetLoader,
  extractor: string,
  confidence: Confidence,
): AssetReferenceFact {
  const parent = context.sourceUrl ?? '';
  return {
    kind: 'assetReference', id: stableId(assetType, rendered, parent), assetType,
    url: { rendered, static: true, variables: [] },
    ...(parent ? { parentSourceUrl: parent } : {}),
    eager: false, loader,
    provenance: provenance(path, extractor, confidence, context.source),
  };
}

/**
 * Emit up to maxChunksPerRuntime facts for one runtime and count the rest in
 * `truncated.assetReference`.
 */
function emitBounded(context: AnalysisContext, facts: AssetReferenceFact[], runtime: string): void {
  const limit = context.limits.maxChunksPerRuntime;
  let emitted = 0;
  let dropped = 0;
  for (const fact of facts) {
    if (emitted >= limit) {
      dropped++;
      continue;
    }
    if (context.addChunkReference(fact)) emitted++;
  }
  if (dropped > 0) {
    context.noteTruncated('assetReference', 'assetDiscovery', 'chunk_limit_reached',
      `Chunks rendered from ${runtime} were limited to ${limit}`, dropped);
  }
}

function renderWebpackChunks(
  context: AnalysisContext,
  chunk: ChunkFunction,
  ids: ChunkId[],
  publicPath: PublicPath,
): void {
  const pattern = chunk.loader === 'webpack-css-chunk' ? CSS_CHUNK : JS_CHUNK;
  const prefix = chunk.publicPathInline ? '' : publicPathValue(publicPath);
  const resolveMember = (node: t.MemberExpression): Evaluated | undefined =>
    chunk.publicPathInline && publicPathMember(node) === chunk.runtime ? publicPathValue(publicPath) : undefined;
  const seen = new Set<string>();
  const facts: AssetReferenceFact[] = [];
  for (let i = 0; i < ids.length; i++) {
    if (i % 512 === 511 && !context.checkBudget('assetDiscovery')) break;
    const value = evaluateFunctionBody(chunk.fn, { bindings: new Map([[chunk.param, ids[i]]]), resolveMember });
    if (typeof value !== 'string' || !pattern.test(value) || /\s/.test(value)) continue;
    const rendered = prefix + value;
    if (seen.has(rendered)) continue;
    seen.add(rendered);
    facts.push(chunkFact(context, chunk.path, rendered, 'chunk', chunk.loader, chunk.extractor, 'high'));
  }
  emitBounded(context, facts, `${chunk.runtime}.${chunk.loader === 'webpack-css-chunk' ? 'miniCssF' : 'u'}`);
}

function viteDepURL(dep: string, base: string): string {
  return ABSOLUTE_OR_RELATIVE.test(dep) ? dep : base + dep;
}

/** Webpack runtimes and Vite preload calls in one pass over the transformed AST. */
export function extractRuntimeChunks(ast: ParseResult<t.File>, context: AnalysisContext): void {
  const chunkFunctions: ChunkFunction[] = [];
  const publicPaths = new Map<string, PublicPath[]>();
  const cssIdMaps = new Map<string, ChunkIdSet>();
  const chunkCalls: ChunkCall[] = [];
  const preloads: PreloadCall[] = [];
  const mapDeps = new Map<string, string[]>();
  const viteBases = new Set<string>();
  const runtimeFunctions = new WeakSet<t.Node>();
  const preloadHelper = context.source.includes('modulepreload');

  const visitFunction = (path: NodePath<FunctionNode>) => {
    const fn = path.node;
    const param = singleParam(fn);
    if (!param || runtimeFunctions.has(fn)) return;
    const expression = returnedExpression(fn);
    if (!expression || !t.isBinaryExpression(expression, { operator: '+' })) return;
    // Vite's assetsURL helper: `function(dep) { return "/" + dep }`.
    if (preloadHelper && t.isStringLiteral(expression.left) && t.isIdentifier(expression.right, { name: param })) {
      viteBases.add(expression.left.value);
      return;
    }
    // webpack 4 jsonpScriptSrc: `return R.p + "js/" + ({}[id]||id) + "." + {id:"hash"}[id] + ".js"`.
    const runtime = publicPathMember(leftmostConcatOperand(expression));
    if (runtime && looksLikeIdLookup(expression, param)) {
      chunkFunctions.push({
        runtime, fn, param, loader: 'webpack-chunk', extractor: 'webpack4-jsonp-script-src', path,
        publicPathInline: true,
      });
    }
  };

  traverse(ast, {
    AssignmentExpression(path) {
      const { left, right } = path.node;
      if (!t.isMemberExpression(left) || left.computed || !t.isIdentifier(left.property)) return;
      const property = left.property.name;
      if (t.isIdentifier(left.object)) {
        const runtime = left.object.name;
        if (property === 'p') {
          const list = publicPaths.get(runtime) ?? [];
          list.push(classifyPublicPath(right));
          publicPaths.set(runtime, list);
          return;
        }
        if ((property === 'u' || property === 'miniCssF') &&
            (t.isArrowFunctionExpression(right) || t.isFunctionExpression(right))) {
          const param = singleParam(right);
          if (!param) return;
          runtimeFunctions.add(right);
          const css = property === 'miniCssF';
          chunkFunctions.push({
            runtime, fn: right, param, loader: css ? 'webpack-css-chunk' : 'webpack-chunk',
            extractor: css ? 'webpack-css-chunk-runtime' : 'webpack-chunk-runtime', path, publicPathInline: false,
          });
        }
        return;
      }
      // `R.f.miniCss = (id, promises) => { ... {42:1}[id] && ... }`: the ids with CSS.
      if (property === 'miniCss' && t.isMemberExpression(left.object) && !left.object.computed &&
          t.isIdentifier(left.object.property, { name: 'f' }) && t.isIdentifier(left.object.object)) {
        const ids = cssIdMaps.get(left.object.object.name) ?? new ChunkIdSet();
        objectKeys(right, ids);
        cssIdMaps.set(left.object.object.name, ids);
      }
    },
    FunctionDeclaration: visitFunction,
    FunctionExpression: visitFunction,
    ArrowFunctionExpression: visitFunction,
    VariableDeclarator(path) {
      // Vite 5: const __vite__mapDeps = (i, m = __vite__mapDeps, d = (m.f || (m.f = [...]))) => i.map(i => d[i])
      if (!t.isIdentifier(path.node.id) || !/mapDeps/.test(path.node.id.name) || !path.node.init) return;
      let table: string[] | undefined;
      t.traverseFast(path.node.init, (node) => {
        if (!table) table = stringArray(node as t.Node);
      });
      if (table) mapDeps.set(path.node.id.name, table);
    },
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      if (t.isMemberExpression(callee) && !callee.computed && t.isIdentifier(callee.property, { name: 'e' }) &&
          t.isIdentifier(callee.object) && args.length === 1 &&
          (t.isNumericLiteral(args[0]) || t.isStringLiteral(args[0]))) {
        chunkCalls.push({ object: callee.object.name, id: args[0].value, webpackShaped: isWebpackChunkCall(path) });
        return;
      }
      if (args.length >= 2 && importThunk(args[0] as t.Node)) {
        let deps = args[1] as t.Node;
        if (t.isConditionalExpression(deps)) {
          const truth = staticTruthiness(deps.test);
          if (truth === undefined) return;
          deps = truth ? deps.consequent : deps.alternate;
        }
        preloads.push({ path, deps });
      }
    },
  });

  if (chunkFunctions.length) {
    const runtimes = new Set(chunkFunctions.map((chunk) => chunk.runtime));
    const calledIds = new ChunkIdSet();
    for (const call of chunkCalls) {
      if (call.webpackShaped || runtimes.has(call.object)) calledIds.add(call.id);
    }
    for (const chunk of chunkFunctions) {
      const ids = new ChunkIdSet();
      idsInFunction(chunk.fn, chunk.param, ids);
      if (chunk.loader === 'webpack-css-chunk') {
        // CSS exists only for the chunks the miniCss loader lists; every other
        // `.e()` id has no stylesheet.
        const cssIds = cssIdMaps.get(chunk.runtime);
        if (cssIds) ids.addAll(cssIds.values());
      } else {
        ids.addAll(calledIds.values());
      }
      renderWebpackChunks(context, chunk, ids.values(), mergePublicPaths(publicPaths.get(chunk.runtime)));
    }
  }

  if (preloads.length) {
    const base = viteBases.size === 1 ? [...viteBases][0] : '/';
    const facts: AssetReferenceFact[] = [];
    for (const preload of preloads) {
      let deps = stringArray(preload.deps);
      if (!deps && t.isCallExpression(preload.deps) && t.isIdentifier(preload.deps.callee)) {
        const table = mapDeps.get(preload.deps.callee.name);
        const indices = preload.deps.arguments[0];
        if (table && t.isArrayExpression(indices)) {
          deps = indices.elements
            .map((element) => (t.isNumericLiteral(element) ? table[element.value] : undefined))
            .filter((dep): dep is string => typeof dep === 'string');
        }
      }
      for (const dep of deps ?? []) {
        if (!dep || /\s/.test(dep)) continue;
        facts.push(chunkFact(context, preload.path, viteDepURL(dep, base), 'chunk', 'vite-preload', 'vite-preload', 'high'));
      }
    }
    emitBounded(context, facts, 'the Vite preload helper');
  }
}

function constantInit(path: NodePath, name: string): t.Node | undefined {
  const binding = path.scope.getBinding(name);
  if (!binding || !binding.constant || !binding.path.isVariableDeclarator()) return undefined;
  return (binding.path.node as t.VariableDeclarator).init ?? undefined;
}

function renderTemplateSource(node: t.Node): string {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node)) {
    const object = renderTemplateSource(node.object);
    if (!node.computed && t.isIdentifier(node.property)) return `${object}.${node.property.name}`;
    return `${object}[${renderTemplateSource(node.property)}]`;
  }
  if (t.isStringLiteral(node)) return JSON.stringify(node.value);
  if (t.isNumericLiteral(node)) return String(node.value);
  return 'expr';
}

/**
 * `import(\`./locale-${HASHES[lang]}.js\`)` where HASHES is a constant object
 * literal: enumerate one URL per key. The fact keeps the template as `rendered`
 * and lists the concrete URLs as alternatives; anything less certain (a free
 * variable with no literal map) returns false and stays a plain template hint.
 */
export function enumerateTemplateImport(
  context: AnalysisContext,
  path: NodePath,
  template: t.TemplateLiteral,
): boolean {
  if (!template.expressions.length) return false;
  let driver: string | undefined;
  let keys: ChunkIdSet | undefined;
  let ambiguous = false;
  for (const expression of template.expressions) {
    t.traverseFast(expression, (node) => {
      if (!t.isMemberExpression(node) || !node.computed || !t.isIdentifier(node.property)) return;
      const map = t.isObjectExpression(node.object) ? node.object
        : t.isIdentifier(node.object) ? constantInit(path, node.object.name) : undefined;
      if (!map || !t.isObjectExpression(map)) return;
      if (driver && driver !== node.property.name) {
        ambiguous = true;
        return;
      }
      driver = node.property.name;
      keys ??= new ChunkIdSet();
      for (const property of map.properties) {
        if (!t.isObjectProperty(property)) continue;
        const key = propertyKey(property);
        // Map keys stay strings here: `lang` is compared and concatenated as text.
        if (key !== undefined) keys.add(key);
      }
    });
  }
  if (ambiguous || !driver || !keys) return false;

  const values = new Set<string>();
  for (const key of keys.values()) {
    const value = evaluateSymbolic(template, {
      bindings: new Map([[driver, String(key)]]),
      resolveIdentifier: (name) => constantInit(path, name),
    });
    if (typeof value === 'string' && value && !/\s/.test(value)) values.add(value);
  }
  if (!values.size) return false;

  let rendered = '';
  const variables: TemplateVariable[] = [];
  template.quasis.forEach((quasi, index) => {
    rendered += quasi.value.cooked ?? quasi.value.raw;
    const expression = template.expressions[index];
    if (!expression) return;
    const name = renderTemplateSource(expression);
    const placeholder = `\${${name}}`;
    rendered += placeholder;
    if (!variables.some((variable) => variable.name === name)) variables.push({ name, placeholder });
  });

  const limit = context.limits.maxChunksPerRuntime;
  const alternatives = [...values];
  if (alternatives.length > limit) {
    context.noteTruncated('assetReference', 'assetDiscovery', 'chunk_limit_reached',
      `Template import alternatives were limited to ${limit}`, alternatives.length - limit);
    alternatives.length = limit;
  }
  const parent = context.sourceUrl ?? '';
  context.addChunkReference({
    kind: 'assetReference', id: stableId('dynamic-import', rendered, parent), assetType: 'dynamic-import',
    url: { rendered, static: false, variables, alternatives },
    ...(parent ? { parentSourceUrl: parent } : {}),
    eager: false, loader: 'template-import',
    provenance: provenance(path, 'template-import', 'medium', context.source),
  });
  return true;
}
