import { createHash } from 'node:crypto';
import type { AnalysisContext, RequestOrigin } from '../context';
import type { JstangleResult } from '../index';
import type { ExtractedRequest } from '../requestpattern/types';
import { getCapabilities } from './capabilities';
import {
  RESULT_SCHEMA_VERSION,
  type AnalysisRecord,
  type AnalysisResultV2,
  type ArtifactDescriptor,
  type BodyTemplate,
  type DomFlowFact,
  type FieldTemplate,
  type HeaderTemplate,
  type HttpRequestFact,
  type SourceDescriptor,
  type SuppressedFact,
  type ValueTemplate,
} from './types';

const TEMPLATE_VARIABLE = /\$\{([^}]+)\}/g;

export function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

export function valueTemplate(rendered: string, alternatives?: string[]): ValueTemplate {
  const variables = [...rendered.matchAll(TEMPLATE_VARIABLE)].map((match) => ({
    name: match[1],
    placeholder: match[0],
  }));
  const uniqueVariables = [...new Map(variables.map((variable) => [variable.placeholder, variable])).values()];
  const uniqueAlternatives = alternatives
    ? [...new Set(alternatives)].filter((value) => value !== rendered)
    : [];
  return {
    rendered,
    static: uniqueVariables.length === 0,
    variables: uniqueVariables,
    ...(uniqueAlternatives.length ? { alternatives: uniqueAlternatives } : {}),
  };
}

function decodeComponent(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

function fields(value: string): FieldTemplate[] {
  if (!value) return [];
  return value.split('&').filter(Boolean).map((part) => {
    const separator = part.indexOf('=');
    const name = separator === -1 ? part : part.slice(0, separator);
    const fieldValue = separator === -1 ? '' : part.slice(separator + 1);
    return {
      name: valueTemplate(decodeComponent(name)),
      value: valueTemplate(decodeComponent(fieldValue)),
    };
  });
}

function headers(values: string[]): HeaderTemplate[] {
  return values.map((header) => {
    const separator = header.indexOf(':');
    const name = (separator === -1 ? header : header.slice(0, separator)).trim();
    const value = (separator === -1 ? '' : header.slice(separator + 1)).trim();
    return {
      name: valueTemplate(name),
      value: valueTemplate(value),
      ...( /^(authorization|proxy-authorization|x-api-key)$/i.test(name) ? { sensitive: true } : {}),
    };
  });
}

function bodyTemplate(body: string, headerValues: string[], alternatives?: string[]): BodyTemplate | undefined {
  if (!body) return undefined;
  const contentTypeHeader = headerValues.find((header) => /^content-type\s*:/i.test(header));
  const contentType = contentTypeHeader?.slice(contentTypeHeader.indexOf(':') + 1).trim();
  let kind: BodyTemplate['kind'] = 'text';
  if (contentType?.includes('json') || /^[\[{]/.test(body.trim())) kind = 'json';
  else if (contentType?.includes('x-www-form-urlencoded') || /^[^=&]+=[^&]*(?:&|$)/.test(body)) kind = 'form';
  else if (body.includes('${unknown}')) kind = 'unknown';
  return {
    kind,
    value: valueTemplate(body, alternatives),
    ...(contentType ? { contentType } : {}),
  };
}

/**
 * Split a query left in a rendered URL (`/x?q=${q}&page=1`) into fields, so
 * `query[]` is populated however the extractor assembled the URL. Only a tail
 * that parses as `k=v(&k=v)*` is split; template placeholders may stand in for
 * values or names, and a name is never invented. `?` inside a placeholder
 * does not count.
 */
const QUERY_TAIL = /^(?:[^=&?#]+=[^&#]*)(?:&[^=&?#]+=[^&#]*)*$/;

function splitRenderedQuery(url: string): { url: string; query: string } | undefined {
  let depth = 0;
  for (let index = 0; index < url.length; index++) {
    if (url.startsWith('${', index)) depth++;
    else if (url[index] === '}' && depth > 0) depth--;
    else if (url[index] === '?' && depth === 0) {
      const query = url.slice(index + 1);
      return QUERY_TAIL.test(query) ? { url: url.slice(0, index), query } : undefined;
    }
  }
  return undefined;
}

/** Internal: the call sites behind a fact, used by suppressNoise and dropped. */
type SitedFact = HttpRequestFact & { sites?: Set<string> };

function requestFact(request: ExtractedRequest, origin: RequestOrigin, sourceHash: string): SitedFact {
  const identity = [request.url, request.method.toUpperCase(), request.params, request.body, sourceHash].join('|');
  const split = splitRenderedQuery(request.url);
  const url = split
    ? valueTemplate(split.url, [request.url, ...origin.alternatives.url])
    : valueTemplate(request.url, origin.alternatives.url);
  const query = split ? [...fields(split.query), ...fields(request.params)] : fields(request.params);
  return {
    kind: 'httpRequest',
    id: `http-${sha256(identity).slice(0, 20)}`,
    url,
    method: valueTemplate(request.method.toUpperCase(), origin.alternatives.method),
    query,
    ...(origin.alternatives.params.length
      ? { queryAlternatives: origin.alternatives.params.map((value) => valueTemplate(value)) }
      : {}),
    headers: headers(request.headers),
    cookies: fields(request.cookies.join('&')),
    ...(bodyTemplate(request.body, request.headers, origin.alternatives.body)
      ? { body: bodyTemplate(request.body, request.headers, origin.alternatives.body) }
      : {}),
    client: origin.client,
    provenance: origin.provenance,
    ...(origin.extractors.length > 1 ? { alternateExtractors: origin.extractors.filter((name) => name !== origin.provenance.extractor) } : {}),
    ...(origin.auth ? { auth: origin.auth } : {}),
    ...(origin.callSite ? { callSite: origin.callSite } : {}),
    sites: origin.sites,
  };
}

const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 } as const;

function suppressionReason(noise: HttpRequestFact, survivor: HttpRequestFact): SuppressedFact['reason'] | undefined {
  const dropped = noise.url.rendered;
  const kept = survivor.url.rendered;
  if (!dropped || dropped === kept || kept.length <= dropped.length) return undefined;
  // A base URL (`/api/v3`) that the survivor extends by whole path segments.
  if (kept.startsWith(`${dropped.replace(/\/+$/, '')}/`)) return 'prefix';
  // The un-prefixed path (`/things`) of the same verb, missing only its base.
  const tail = dropped.startsWith('/') ? dropped : `/${dropped}`;
  if (kept.endsWith(tail) && noise.method.rendered === survivor.method.rendered) return 'suffix';
  return undefined;
}

/**
 * Fold base-URL and un-prefixed noise into the resolved fact it came from.
 *
 * One axios call `api.get("/things")` on an instance with `baseURL: "/api/v3"`
 * yields the resolved `/api/v3/things` plus lower-confidence `/api/v3` and
 * `/things` from the generic extractors. A fact is dropped only when a
 * strictly higher-confidence fact covers every call site the dropped fact was
 * seen at, so a base URL also used standalone survives. The survivor lists
 * what it absorbed in `suppressed`.
 */
function suppressNoise(facts: SitedFact[]): HttpRequestFact[] {
  // Candidates must share every site of the noise fact, so indexing by site
  // and probing only the first site keeps this linear-ish on large bundles.
  const bySite = new Map<string, SitedFact[]>();
  for (const fact of facts) {
    for (const site of fact.sites ?? []) {
      const list = bySite.get(site) ?? [];
      list.push(fact);
      bySite.set(site, list);
    }
  }
  const dropped = new Set<SitedFact>();
  for (const noise of facts) {
    if (!noise.sites?.size || noise.provenance.confidence === 'high') continue;
    let best: { survivor: SitedFact; reason: SuppressedFact['reason'] } | undefined;
    const [firstSite] = noise.sites;
    for (const survivor of bySite.get(firstSite) ?? []) {
      if (survivor === noise || dropped.has(survivor) || !survivor.sites) continue;
      if (CONFIDENCE_RANK[survivor.provenance.confidence] <= CONFIDENCE_RANK[noise.provenance.confidence]) continue;
      if (![...noise.sites].every((site) => survivor.sites!.has(site))) continue;
      const reason = suppressionReason(noise, survivor);
      if (reason && (!best || CONFIDENCE_RANK[survivor.provenance.confidence] > CONFIDENCE_RANK[best.survivor.provenance.confidence])) {
        best = { survivor, reason };
      }
    }
    if (!best) continue;
    dropped.add(noise);
    (best.survivor.suppressed ??= []).push({ id: noise.id, url: noise.url.rendered, reason: best.reason });
  }
  return facts.filter((fact) => !dropped.has(fact)).map(({ sites: _sites, ...fact }) => fact);
}

function domFact(flow: JstangleResult['domFlows'][number], sourceHash: string): DomFlowFact {
  const line = Math.max(0, flow.line || 0);
  return {
    kind: 'domFlow',
    id: `dom-${sha256([flow.source, flow.sink, line, sourceHash].join('|')).slice(0, 20)}`,
    source: flow.source,
    sink: flow.sink,
    snippet: flow.snippet,
    line,
    confidence: flow.confidence,
    provenance: {
      extractor: 'dom-taint-v2',
      confidence: flow.confidence,
      ...(line ? { start: { line } } : {}),
      evidence: flow.snippet,
    },
    path: flow.path,
    flowType: flow.flowType,
  };
}

export interface ResultEnvelopeOptions {
  sourceUrl?: string;
  filename?: string;
  mediaType?: string;
  artifacts?: ArtifactDescriptor[];
}

export function buildAnalysisResultV2(
  result: JstangleResult,
  context: AnalysisContext,
  options: ResultEnvelopeOptions = {},
): AnalysisResultV2 {
  const capabilities = getCapabilities();
  const contentSha256 = sha256(context.source);
  const source: SourceDescriptor = {
    contentSha256,
    byteLength: Buffer.byteLength(context.source),
    ...(options.sourceUrl ? { url: options.sourceUrl } : {}),
    ...(options.filename ? { filename: options.filename } : {}),
    ...(options.mediaType ? { mediaType: options.mediaType } : {}),
    ...(result.beautified?.format && result.beautified.format !== 'none'
      ? { bundleFormat: result.beautified.format }
      : {}),
  };
  const requests = suppressNoise(result.extractedRequests.map((request, index) =>
    requestFact(request, context.requestOrigins[index] ?? context.defaultOrigin(), contentSha256)));
  // Low-confidence path literals go last: the output budget trims from the end.
  const records: AnalysisRecord[] = [
    ...requests,
    ...result.domFlows.map((flow) => domFact(flow, contentSha256)),
    ...result.assetReferences,
    ...result.graphqlOperations,
    ...result.webSockets,
    ...result.eventSources,
    ...result.clientRoutes,
    ...result.browserSecurityFlows,
    ...result.pathLiterals,
  ];
  return {
    type: 'analysisResult',
    schemaVersion: RESULT_SCHEMA_VERSION,
    jobId: context.scanId,
    profile: context.profile,
    tool: {
      version: capabilities.toolVersion,
      sourceHash: capabilities.sourceHash,
    },
    source,
    stats: {
      status: result.status,
      inputBytes: source.byteLength,
      durationMs: performance.now() - context.startedAt,
      recordCounts: {
        httpRequest: requests.length,
        domFlow: result.domFlows.length,
        assetReference: result.assetReferences.length,
        graphqlOperation: result.graphqlOperations.length,
        websocket: result.webSockets.length,
        eventSource: result.eventSources.length,
        clientRoute: result.clientRoutes.length,
        browserSecurityFlow: result.browserSecurityFlows.length,
        pathLiteral: result.pathLiterals.length,
      },
      stageMetrics: result.stageMetrics,
      ...(Object.keys(result.truncated).length ? { truncated: { ...result.truncated } } : {}),
    },
    diagnostics: result.diagnostics,
    records,
    artifacts: options.artifacts ?? [],
  };
}
