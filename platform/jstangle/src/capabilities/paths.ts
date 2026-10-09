import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import { traverse, type NodePath } from '../ast-utils/babel';
import type { AnalysisContext } from '../context';
import { sha256, valueTemplate, type PathLiteralFact, type PathLiteralReason } from '../protocol';

/**
 * Path-shaped string literals that never reach a request call:
 * `{profile: "/api/v2/profile"}`, `const EXPORT = "/api/v2/export"`, route
 * tables, default parameters. The Go linkfinder sees these in the scan path;
 * emitting them as typed, low-confidence facts makes every entry point agree
 * and keeps the binding name (`profile`, `admin`) that tells an agent or the
 * param miner what the path is for. Never a replay template.
 */

const PATH_SHAPE = /^\/[A-Za-z0-9_\-./~%{}$:]+$/;
const DATE_FORMAT = /^\/?(?:(?:y{2,4}|Y{2,4}|m{1,2}|M{1,2}|d{1,2}|D{1,2}|h{1,2}|H{1,2}|s{1,2})[/\-.:]?)+$/;
const PLACEHOLDER = /\$\{[^}]*\}/g;
const MIN_LENGTH = 2;
const MAX_LENGTH = 256;
const MAX_DOTS = 3;
const MAX_EVIDENCE = 200;

/** Shape filter shared with tests: true for a plausible URL path literal. */
export function isPathLiteral(value: string): boolean {
  if (value.length < MIN_LENGTH || value.length > MAX_LENGTH) return false;
  if (!PATH_SHAPE.test(value)) return false;
  if (value.startsWith('//')) return false;
  const literal = value.replace(PLACEHOLDER, '');
  // A `$` or brace left after removing placeholders is a regex anchor or junk.
  if (/[${}]/.test(literal)) return false;
  if (!/[A-Za-z]/.test(literal) || /^\/+$/.test(literal)) return false;
  if ((literal.match(/\./g) ?? []).length > MAX_DOTS) return false;
  if (/\/\.{1,2}(\/|$)/.test(literal)) return false;
  if (DATE_FORMAT.test(literal)) return false;
  return true;
}

function keyName(node: t.Node | null | undefined): string | undefined {
  if (!node) return undefined;
  if (t.isIdentifier(node)) return node.name;
  if (t.isStringLiteral(node)) return node.value;
  if (t.isMemberExpression(node) && !node.computed && t.isIdentifier(node.property)) return node.property.name;
  return undefined;
}

function expressionName(node: t.Node): string {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node) && !node.computed && t.isIdentifier(node.property)) {
    const object = expressionName(node.object);
    return object === 'X' ? node.property.name : `${object}.${node.property.name}`;
  }
  return 'X';
}

function render(node: t.StringLiteral | t.TemplateLiteral): string | undefined {
  if (t.isStringLiteral(node)) return node.value;
  let rendered = '';
  for (let index = 0; index < node.quasis.length; index++) {
    const cooked = node.quasis[index].value.cooked;
    if (cooked === null || cooked === undefined) return undefined;
    rendered += cooked;
    const expression = node.expressions[index];
    if (expression) rendered += `\${${expressionName(expression)}}`;
  }
  return rendered;
}

/** How the literal is bound, or undefined for positions this kind ignores. */
function classify(path: NodePath): { reason: PathLiteralReason; key?: string } | undefined {
  const parent = path.parentPath;
  if (!parent) return undefined;
  const node = parent.node;
  if (t.isObjectProperty(node) && node.value === path.node) {
    return { reason: 'object-value', key: keyName(node.key) };
  }
  if (t.isArrayExpression(node)) {
    const holder = parent.parentPath?.node;
    const key = t.isObjectProperty(holder) ? keyName(holder.key)
      : t.isVariableDeclarator(holder) ? keyName(holder.id) : undefined;
    return { reason: 'array-element', ...(key ? { key } : {}) };
  }
  if (t.isVariableDeclarator(node) && node.init === path.node) {
    return { reason: 'const-init', key: keyName(node.id) };
  }
  if (t.isAssignmentPattern(node) && node.right === path.node) {
    return { reason: 'default-param', key: keyName(node.left) };
  }
  if (t.isReturnStatement(node) || (t.isArrowFunctionExpression(node) && node.body === path.node)) {
    return { reason: 'return' };
  }
  if (t.isAssignmentExpression(node) && node.right === path.node) {
    return { reason: 'assignment', key: keyName(node.left) };
  }
  return undefined;
}

function stripQuery(url: string): string {
  const index = url.indexOf('?');
  return index === -1 ? url : url.slice(0, index);
}

export function extractPathLiterals(ast: ParseResult<t.File>, context: AnalysisContext): void {
  // A literal inside a retained request call, or equal to a request URL or a
  // route path, is already reported by a stronger fact.
  const consumed = new Set<string>();
  const spans: Array<[number, number]> = [];
  context.requests.forEach((request, index) => {
    consumed.add(stripQuery(request.url));
    const node = context.requestOrigins[index]?.node as t.Node | undefined;
    if (node && typeof node.start === 'number' && typeof node.end === 'number') spans.push([node.start, node.end]);
  });
  for (const route of context.clientRoutes) {
    consumed.add(route.path.rendered);
    if (route.fullPath) consumed.add(route.fullPath.rendered);
  }
  const insideConsumedSpan = (node: t.Node) =>
    typeof node.start === 'number' && spans.some(([start, end]) => node.start! >= start && node.end! <= end);

  const visit = (path: NodePath<t.StringLiteral | t.TemplateLiteral>) => {
    const value = render(path.node);
    if (!value || !isPathLiteral(value) || consumed.has(value)) return;
    const binding = classify(path);
    if (!binding || insideConsumedSpan(path.node)) return;
    const { node } = path;
    const evidence = typeof node.start === 'number' && typeof node.end === 'number'
      ? context.source.slice(node.start, Math.min(node.end, node.start + MAX_EVIDENCE))
      : undefined;
    const fact: PathLiteralFact = {
      kind: 'pathLiteral',
      // One fact per distinct value: a path repeated across a bundle is one hint.
      id: `path-${sha256(value).slice(0, 20)}`,
      value: valueTemplate(value),
      reason: binding.reason,
      ...(binding.key ? { key: binding.key } : {}),
      provenance: {
        extractor: 'path-literal',
        confidence: 'low',
        ...(node.loc?.start ? {
          start: { line: node.loc.start.line, column: node.loc.start.column, ...(typeof node.start === 'number' ? { offset: node.start } : {}) },
        } : {}),
        ...(node.loc?.end ? {
          end: { line: node.loc.end.line, column: node.loc.end.column, ...(typeof node.end === 'number' ? { offset: node.end } : {}) },
        } : {}),
        ...(evidence ? { evidence } : {}),
      },
    };
    context.addPathLiteral(fact);
  };

  traverse(ast, {
    noScope: true,
    StringLiteral: visit,
    TemplateLiteral: visit,
  });
}
