import * as t from '@babel/types';

/**
 * A tiny, pure symbolic evaluator for chunk-filename functions.
 *
 * It folds only string concatenation, template literals, object/array lookups,
 * logical operators, equality tests and ternaries over literals and a fixed set
 * of parameter bindings. Any call, assignment, unknown identifier or unsupported
 * operator yields UNKNOWN, so the caller drops that input. Target code is never
 * executed and nothing here can observe or cause side effects.
 */

export const UNKNOWN: unique symbol = Symbol('unknown');

export type SymbolicValue = string | number | boolean | null | undefined;
export type Evaluated = SymbolicValue | typeof UNKNOWN;

export interface SymbolicEnv {
  /** Parameter bindings for this evaluation, e.g. the chunk id. */
  bindings: ReadonlyMap<string, SymbolicValue>;
  /** Constant initializer of a free identifier (an object map, a literal). */
  resolveIdentifier?: (name: string) => t.Node | undefined;
  /** Runtime members such as `__webpack_require__.p`; return undefined when not handled. */
  resolveMember?: (node: t.MemberExpression) => Evaluated | undefined;
  maxSteps?: number;
  maxDepth?: number;
}

const DEFAULT_MAX_STEPS = 2_000;
const DEFAULT_MAX_DEPTH = 8;
const MAX_STRING = 2_048;

interface State {
  env: SymbolicEnv;
  steps: number;
  maxSteps: number;
  maxDepth: number;
  resolving: Set<string>;
}

function newState(env: SymbolicEnv): State {
  return {
    env, steps: 0, resolving: new Set(),
    maxSteps: env.maxSteps ?? DEFAULT_MAX_STEPS,
    maxDepth: env.maxDepth ?? DEFAULT_MAX_DEPTH,
  };
}

/** Evaluate an expression; UNKNOWN when any part is not statically knowable. */
export function evaluateSymbolic(node: t.Node | null | undefined, env: SymbolicEnv): Evaluated {
  return evaluate(node, newState(env), 0);
}

/**
 * Evaluate a function's result: an expression-bodied arrow, or a block made of
 * `if (test) return x;` guards and a final `return`. Any other statement bails.
 */
export function evaluateFunctionBody(fn: t.Function, env: SymbolicEnv): Evaluated {
  const state = newState(env);
  if (!t.isBlockStatement(fn.body)) return evaluate(fn.body, state, 0);
  return evaluateStatements(fn.body.body, state);
}

function evaluateStatements(statements: t.Statement[], state: State): Evaluated {
  for (const statement of statements) {
    if (t.isEmptyStatement(statement)) continue;
    if (t.isReturnStatement(statement)) return statement.argument ? evaluate(statement.argument, state, 0) : undefined;
    if (t.isIfStatement(statement)) {
      const test = evaluate(statement.test, state, 0);
      if (test === UNKNOWN) return UNKNOWN;
      const branch = test ? statement.consequent : statement.alternate;
      if (!branch) continue;
      const body = t.isBlockStatement(branch) ? branch.body : [branch];
      const last = body[body.length - 1];
      // A branch must end in a return; otherwise control falls through to code
      // this evaluator does not model.
      if (!last || !t.isReturnStatement(last)) return UNKNOWN;
      return evaluateStatements(body, state);
    }
    return UNKNOWN;
  }
  return undefined;
}

/** JS-style property key of an object-literal key node, or undefined when computed. */
export function propertyKey(property: t.ObjectProperty | t.ObjectMethod): string | undefined {
  const key = property.key;
  if (!property.computed && t.isIdentifier(key)) return key.name;
  if (t.isStringLiteral(key)) return key.value;
  if (t.isNumericLiteral(key)) return String(key.value);
  return undefined;
}

function truthy(value: SymbolicValue): boolean {
  return Boolean(value);
}

function looseEquals(a: SymbolicValue, b: SymbolicValue): boolean {
  if (typeof a === typeof b) return a === b;
  if (a == null || b == null) return a == null && b == null;
  const toNumber = (value: string | number | boolean): number => (typeof value === 'number' ? value : Number(value));
  return toNumber(a) === toNumber(b);
}

function concat(left: SymbolicValue, right: SymbolicValue): Evaluated {
  // "undefined"/"null" inside a URL is never a real chunk name: an id missing
  // from a hash map must drop out, not render as `123.undefined.js`.
  if (left == null || right == null) return UNKNOWN;
  if (typeof left === 'number' && typeof right === 'number') return left + right;
  const joined = String(left) + String(right);
  return joined.length > MAX_STRING ? UNKNOWN : joined;
}

function resolveObject(node: t.Node, state: State, depth: number): t.ObjectExpression | t.ArrayExpression | undefined {
  if (t.isObjectExpression(node) || t.isArrayExpression(node)) return node;
  if (t.isIdentifier(node) && !state.env.bindings.has(node.name)) {
    const target = resolveIdentifierNode(node.name, state, depth);
    if (target && (t.isObjectExpression(target) || t.isArrayExpression(target))) return target;
  }
  return undefined;
}

function resolveIdentifierNode(name: string, state: State, depth: number): t.Node | undefined {
  if (depth >= state.maxDepth || state.resolving.has(name)) return undefined;
  return state.env.resolveIdentifier?.(name);
}

function lookup(container: t.ObjectExpression | t.ArrayExpression, key: SymbolicValue, state: State, depth: number): Evaluated {
  if (t.isArrayExpression(container)) {
    if (typeof key !== 'number' || !Number.isInteger(key) || key < 0) return UNKNOWN;
    const element = container.elements[key];
    if (key >= container.elements.length) return undefined;
    if (!element || t.isSpreadElement(element)) return UNKNOWN;
    return evaluate(element, state, depth + 1);
  }
  const wanted = String(key);
  let opaque = false;
  // Later keys win in JS object literals, so scan from the end.
  for (let i = container.properties.length - 1; i >= 0; i--) {
    const property = container.properties[i];
    if (t.isSpreadElement(property) || t.isObjectMethod(property)) {
      opaque = true;
      continue;
    }
    const name = propertyKey(property);
    if (name === undefined) {
      opaque = true;
      continue;
    }
    if (name === wanted) return evaluate(property.value, state, depth + 1);
  }
  return opaque ? UNKNOWN : undefined;
}

function evaluate(node: t.Node | null | undefined, state: State, depth: number): Evaluated {
  if (!node || depth > state.maxDepth * 8) return UNKNOWN;
  if (++state.steps > state.maxSteps) return UNKNOWN;

  if (t.isStringLiteral(node)) return node.value;
  if (t.isNumericLiteral(node)) return node.value;
  if (t.isBooleanLiteral(node)) return node.value;
  if (t.isNullLiteral(node)) return null;
  if (t.isParenthesizedExpression(node)) return evaluate(node.expression, state, depth + 1);

  if (t.isIdentifier(node)) {
    if (state.env.bindings.has(node.name)) return state.env.bindings.get(node.name);
    if (node.name === 'undefined') return undefined;
    const target = resolveIdentifierNode(node.name, state, depth);
    if (!target || t.isObjectExpression(target) || t.isArrayExpression(target)) return UNKNOWN;
    state.resolving.add(node.name);
    try {
      return evaluate(target, state, depth + 1);
    } finally {
      state.resolving.delete(node.name);
    }
  }

  if (t.isTemplateLiteral(node)) {
    let out = '';
    for (let i = 0; i < node.quasis.length; i++) {
      const cooked = node.quasis[i].value.cooked;
      if (cooked == null) return UNKNOWN;
      out += cooked;
      if (i < node.expressions.length) {
        const value = evaluate(node.expressions[i], state, depth + 1);
        if (value === UNKNOWN || value == null) return UNKNOWN;
        out += String(value);
      }
    }
    return out.length > MAX_STRING ? UNKNOWN : out;
  }

  if (t.isUnaryExpression(node)) {
    if (node.operator === 'void') return undefined;
    const value = evaluate(node.argument, state, depth + 1);
    if (value === UNKNOWN) return UNKNOWN;
    if (node.operator === '!') return !truthy(value);
    if (node.operator === '-' && typeof value === 'number') return -value;
    if (node.operator === '+' && typeof value === 'number') return value;
    return UNKNOWN;
  }

  if (t.isBinaryExpression(node)) {
    if (t.isPrivateName(node.left)) return UNKNOWN;
    const left = evaluate(node.left, state, depth + 1);
    if (left === UNKNOWN) return UNKNOWN;
    const right = evaluate(node.right, state, depth + 1);
    if (right === UNKNOWN) return UNKNOWN;
    switch (node.operator) {
      case '+': return concat(left, right);
      case '===': return left === right;
      case '!==': return left !== right;
      case '==': return looseEquals(left, right);
      case '!=': return !looseEquals(left, right);
      default: return UNKNOWN;
    }
  }

  if (t.isLogicalExpression(node)) {
    const left = evaluate(node.left, state, depth + 1);
    if (left === UNKNOWN) return UNKNOWN;
    switch (node.operator) {
      case '||': return truthy(left) ? left : evaluate(node.right, state, depth + 1);
      case '&&': return truthy(left) ? evaluate(node.right, state, depth + 1) : left;
      case '??': return left != null ? left : evaluate(node.right, state, depth + 1);
      default: return UNKNOWN;
    }
  }

  if (t.isConditionalExpression(node)) {
    const test = evaluate(node.test, state, depth + 1);
    if (test === UNKNOWN) return UNKNOWN;
    return evaluate(truthy(test) ? node.consequent : node.alternate, state, depth + 1);
  }

  if (t.isSequenceExpression(node)) {
    // Only side-effect-free leading expressions are dropped.
    const last = node.expressions[node.expressions.length - 1];
    for (const expression of node.expressions.slice(0, -1)) {
      if (!t.isLiteral(expression) && !t.isIdentifier(expression)) return UNKNOWN;
    }
    return evaluate(last, state, depth + 1);
  }

  if (t.isMemberExpression(node)) {
    const hooked = state.env.resolveMember?.(node);
    if (hooked !== undefined) return hooked;
    const container = resolveObject(node.object, state, depth);
    if (!container) return UNKNOWN;
    let key: Evaluated;
    if (node.computed) key = evaluate(node.property, state, depth + 1);
    else if (t.isIdentifier(node.property)) key = node.property.name;
    else return UNKNOWN;
    if (key === UNKNOWN) return UNKNOWN;
    return lookup(container, key, state, depth);
  }

  // Calls, `new`, assignments, functions, and everything else: bail.
  return UNKNOWN;
}
