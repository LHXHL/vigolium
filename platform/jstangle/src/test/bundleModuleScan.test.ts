import { describe, expect, test } from 'vitest';
import { jstangle } from '../index';

// Minified webpack-5 bundle (same shape as the beautify fixture): base URL lives
// in module 200, endpoints in modules 100 and 300.
const WEBPACK5 =
  '(()=>{"use strict";var e={100:(e,t,r)=>{const n=r(200);' +
  't.listUsers=function(){return fetch(n.base+"/users",{method:"GET"}).then(x=>x.json())};' +
  't.createUser=function(u){return fetch(n.base+"/users",{method:"POST",body:JSON.stringify(u)})};' +
  't.deleteUser=function(id){return fetch(n.base+"/users/"+id,{method:"DELETE"})}},' +
  '200:(e,t)=>{t.base="/api/v3";t.timeout=3e4;t.headers={"X-Api":"1"}},' +
  '300:(e,t,r)=>{const n=r(200);t.listPosts=function(p){return fetch(n.base+"/posts?page="+p)}}},t={};' +
  'function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};' +
  'return e[n](o,o.exports,r),o.exports}r.n=e=>e;var n=r(100),s=r(300);console.log(n,s)})();';

function urls(res: Awaited<ReturnType<typeof jstangle>>): string[] {
  return res.extractedRequests.map((r) => r.url);
}

describe('bundle module re-scan (unpackModules)', () => {
  test('extracts endpoints from unpacked modules', async () => {
    const res = await jstangle(WEBPACK5, { profile: 'endpoints', unpackModules: true });
    const found = urls(res);
    expect(found.some((u) => u.includes('/users'))).toBe(true);
    expect(found.some((u) => u.includes('/posts'))).toBe(true);
  });

  test('stamps module-path provenance on re-scanned endpoints', async () => {
    const res = await jstangle(WEBPACK5, { profile: 'endpoints', unpackModules: true });
    const origins = res.analysisContext.requestOrigins;
    // Provenance uses the stable `bundle-module` extractor plus a structured modulePath.
    expect(origins.some((o) => o.extractors.includes('bundle-module'))).toBe(true);
    expect(origins.some((o) => !!o.provenance.modulePath)).toBe(true);
  });

  test('does not run the module scan when the option is off', async () => {
    const res = await jstangle(WEBPACK5, { profile: 'endpoints' });
    const origins = res.analysisContext.requestOrigins;
    expect(origins.some((o) => o.extractors.includes('bundle-module'))).toBe(false);
    // Baseline extraction still works from the monolithic AST.
    expect(res.extractedRequests.length).toBeGreaterThan(0);
  });

  test('is a no-op for non-bundle scripts even when enabled', async () => {
    const res = await jstangle('fetch("/api/plain");', {
      profile: 'endpoints',
      unpackModules: true,
    });
    // No bundle → no module provenance, but the plain endpoint is still found.
    const origins = res.analysisContext.requestOrigins;
    expect(origins.some((o) => o.extractors.includes('bundle-module'))).toBe(false);
    expect(urls(res).some((u) => u.includes('/api/plain'))).toBe(true);
  });
});

// A tree too dense to traverse whole is the strongest available signal that the
// input is a bundle. Rejecting it outright returned nothing at all, even though
// webcrack - which needs no AST - could still split it into analyzable modules.
describe('AST budget recovery (astBudgetRejected)', () => {
  // Small enough that WEBPACK5's own tree blows it, so the parse stage rejects.
  const OVER_BUDGET = { maxAstNodes: 200 };

  function diagnosticCodes(res: Awaited<ReturnType<typeof jstangle>>): string[] {
    return res.diagnostics.map((d) => d.code);
  }

  test('rescues an over-budget bundle without the opt-in flag', async () => {
    const res = await jstangle(WEBPACK5, { profile: 'endpoints', limits: OVER_BUDGET });

    expect(res.status).toBe('partial');
    expect(diagnosticCodes(res)).toContain('ast_node_limit_reached');
    expect(diagnosticCodes(res)).toContain('ast_budget_recovered_by_module_scan');
    expect(res.extractedRequests.length).toBeGreaterThan(0);
    expect(urls(res).some((u) => u.includes('/users'))).toBe(true);
    expect(urls(res).some((u) => u.includes('/posts'))).toBe(true);
  });

  // The regression that distinguishes a real rescue from the Go regex fallback:
  // a string pass cannot resolve a verb, so it reports every endpoint as one.
  test('methods survive the rescue', async () => {
    const res = await jstangle(WEBPACK5, { profile: 'endpoints', limits: OVER_BUDGET });
    const methods = new Set(res.extractedRequests.map((r) => r.method).filter(Boolean));
    expect(methods.has('POST')).toBe(true);
    expect(methods.has('DELETE')).toBe(true);
    expect(methods.size).toBeGreaterThan(1);
  });

  test('rescued endpoints carry module-path provenance', async () => {
    const res = await jstangle(WEBPACK5, { profile: 'endpoints', limits: OVER_BUDGET });
    const origins = res.analysisContext.requestOrigins;
    // The whole-file pass never ran, so bundle-module is the only source here and
    // its provenance cannot be shadowed by an earlier extractor.
    expect(origins.every((o) => o.extractors.includes('bundle-module'))).toBe(true);
    expect(origins.every((o) => !!o.provenance.modulePath)).toBe(true);
  });

  // The rescue must not become a blanket way around the budget: a dense script
  // that is not a bundle has no module map to split and still fails.
  test('a non-bundle over budget still fails', async () => {
    const dense = `${'const x = [' + '1,'.repeat(400) + '];'}fetch("/api/dense");`;
    const res = await jstangle(dense, { profile: 'endpoints', limits: OVER_BUDGET });

    expect(res.status).toBe('failed');
    expect(diagnosticCodes(res)).not.toContain('ast_budget_recovered_by_module_scan');
    expect(res.extractedRequests).toHaveLength(0);
  });

  test('a syntactically broken input is not rescued', async () => {
    const res = await jstangle('function (((( {', { profile: 'endpoints' });
    expect(res.status).toBe('failed');
    expect(diagnosticCodes(res)).not.toContain('ast_budget_recovered_by_module_scan');
  });

  // Truncation should cost the vendor tail, not the application code. The app
  // module is emitted last here and would fall outside a source-ordered cap.
  test('orders endpoint-bearing modules ahead of the vendor tail', async () => {
    const vendorModules = Array.from({ length: 6 }, (_, i) =>
      `${100 + i}:(e,t)=>{t.pad${i}=function(){return ${i}}}`,
    ).join(',');
    const bundle =
      '(()=>{"use strict";var e={' + vendorModules + ',' +
      '900:(e,t)=>{t.late=function(){return fetch("/api/v9/late-module",{method:"PUT"})}}},t={};' +
      'function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};' +
      'return e[n](o,o.exports,r),o.exports}var n=r(900);console.log(n)})();';

    const res = await jstangle(bundle, {
      profile: 'endpoints',
      limits: { ...OVER_BUDGET, maxBundleModules: 2 },
    });

    expect(urls(res).some((u) => u.includes('/api/v9/late-module'))).toBe(true);
  });
});

describe('bundle module re-scan regressions', () => {
  test('is a no-op for non-bundle scripts even when enabled', async () => {
    const res = await jstangle('fetch("/api/plain");', {
      profile: 'endpoints',
      unpackModules: true,
    });
    // No bundle → no module provenance, but the plain endpoint is still found.
    const origins = res.analysisContext.requestOrigins;
    expect(origins.some((o) => o.extractors.includes('bundle-module'))).toBe(false);
    expect(urls(res).some((u) => u.includes('/api/plain'))).toBe(true);
  });
});
