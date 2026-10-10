import { createHash } from 'node:crypto';
import * as t from '@babel/types';
import type { NodePath } from '../ast-utils/babel';
import type { AssetType, Confidence, Provenance } from '../protocol';
import { findContainingFunction } from '../requestpattern/extractRequest';

export function stableId(kind: AssetType, rendered: string, parent: string): string {
  return `asset-${createHash('sha256').update(`${kind}\0${rendered}\0${parent}`).digest('hex').slice(0, 20)}`;
}

/** Dotted name of a non-computed member chain (`navigator.serviceWorker.register`). */
export function memberPath(node: t.Node): string {
  const parts: string[] = [];
  let current: t.Node = node;
  while (t.isMemberExpression(current) || t.isOptionalMemberExpression(current)) {
    const property = current.property;
    if (t.isIdentifier(property)) parts.unshift(property.name);
    else if (t.isStringLiteral(property)) parts.unshift(property.value);
    else return '';
    current = current.object as t.Node;
  }
  if (t.isIdentifier(current)) parts.unshift(current.name);
  return parts.join('.');
}

export function provenance(path: NodePath, extractor: string, confidence: Confidence, source: string): Provenance {
  const node = path.node;
  const start = node.loc?.start;
  const end = node.loc?.end;
  const evidence = typeof node.start === 'number' && typeof node.end === 'number'
    ? source.slice(node.start, Math.min(node.end, node.start + 300))
    : undefined;
  const functionName = findContainingFunction(path);
  return {
    extractor, confidence,
    ...(functionName ? { functionName } : {}),
    ...(start ? { start: { line: start.line, column: start.column, offset: node.start ?? undefined } } : {}),
    ...(end ? { end: { line: end.line, column: end.column, offset: node.end ?? undefined } } : {}),
    ...(evidence ? { evidence } : {}),
  };
}
