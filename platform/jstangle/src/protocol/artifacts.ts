import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { basename, resolve, sep } from 'node:path';
import type { AnalysisResultV2, ArtifactDescriptor, Diagnostic, TruncationCounts } from './types';
import { sha256 } from './result';

export function safeArtifactName(filename: string, suffix: string): string {
  const safe = basename(filename).replace(/[^a-zA-Z0-9._-]/g, '_') || 'source.js';
  return `${safe}.${suffix}`;
}

export async function writeArtifact(
  rootDir: string,
  artifactType: ArtifactDescriptor['artifactType'],
  filename: string,
  content: string,
  maxBytes: number,
  format?: string,
  moduleCount?: number,
  modulePaths?: string[],
): Promise<ArtifactDescriptor> {
  const byteLength = Buffer.byteLength(content);
  if (byteLength > maxBytes) {
    throw new Error(`artifact ${artifactType} is ${byteLength} bytes; limit is ${maxBytes}`);
  }
  await mkdir(rootDir, { recursive: true, mode: 0o700 });
  const root = await realpath(rootDir);
  const target = resolve(root, filename);
  if (target !== root && !target.startsWith(`${root}${sep}`)) {
    throw new Error(`artifact path escapes allocated directory: ${target}`);
  }
  await writeFile(target, content, { encoding: 'utf8', mode: 0o600 });
  return {
    kind: 'artifact', artifactType, path: target, sha256: sha256(content), byteLength,
    mediaType: 'application/javascript', filename,
    ...(format ? { format } : {}),
    ...(typeof moduleCount === 'number' ? { moduleCount } : {}),
    ...(modulePaths?.length ? { modulePaths } : {}),
  };
}

export function fitEnvelope(envelope: AnalysisResultV2, maxBytes: number): { envelope: AnalysisResultV2; omitted: number } {
  const available = Math.max(1024, maxBytes - 4096);
  let omitted = 0;
  const size = () => Buffer.byteLength(`${JSON.stringify(envelope)}\n`);
  while (envelope.records.length > 0 && size() > available) {
    let index = -1;
    for (let i = envelope.records.length - 1; i >= 0; i--) {
      const record = envelope.records[i];
      const confidence = record.kind === 'domFlow' ? record.confidence : record.provenance.confidence;
      if (confidence === 'low') {
        index = i;
        break;
      }
    }
    if (index === -1) index = envelope.records.length - 1;
    const [removed] = envelope.records.splice(index, 1);
    envelope.stats.truncated ??= {};
    envelope.stats.truncated[removed.kind] = (envelope.stats.truncated[removed.kind] ?? 0) + 1;
    omitted++;
  }
  if (omitted > 0) {
    envelope.stats.status = envelope.stats.status === 'failed' ? 'failed' : 'partial';
    envelope.diagnostics.push({
      type: 'diagnostic', severity: 'warning', stage: 'transport', code: 'output_budget_exceeded',
      message: `${omitted} record(s) omitted to fit the ${maxBytes}-byte output budget`, recoverable: true,
    });
  }
  for (const diagnostic of envelope.diagnostics) {
    if (size() <= available) break;
    diagnostic.message = diagnostic.message.slice(0, 256);
  }
  if (size() > available) throw new Error(`analysis envelope metadata exceeds ${maxBytes}-byte output budget`);
  return { envelope, omitted };
}

export function artifactFailureDiagnostic(error: unknown): Diagnostic {
  return {
    type: 'diagnostic', severity: 'warning', stage: 'artifacts', code: 'artifact_write_failed',
    message: error instanceof Error ? error.message : String(error), recoverable: true,
  };
}

/**
 * Completion reason for a run that lost records to a per-kind cap:
 * `request_cap` when endpoint facts were dropped, else `fact_cap:<kind>`.
 * Undefined when nothing was truncated.
 */
export function truncationReason(truncated: TruncationCounts | undefined): string | undefined {
  if (!truncated) return undefined;
  if ((truncated.httpRequest ?? 0) > 0) return 'request_cap';
  const kind = Object.keys(truncated).sort().find((name) => truncated[name] > 0);
  return kind ? `fact_cap:${kind}` : undefined;
}
