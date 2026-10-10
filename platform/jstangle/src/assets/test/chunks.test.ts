import { describe, expect, test } from 'vitest';
import { parse } from '@babel/parser';
import * as t from '@babel/types';
import { jstangle } from '../../index';
import { buildAnalysisResultV2, getCapabilities, type AssetReferenceFact } from '../../protocol';
import { evaluateFunctionBody, evaluateSymbolic, UNKNOWN } from '../symbolic';

const sourceUrl = 'https://app.test/static/js/main.js';

async function assets(code: string): Promise<AssetReferenceFact[]> {
  const result = await jstangle(code, { profile: 'discovery', sourceUrl });
  return result.assetReferences;
}

function chunks(facts: AssetReferenceFact[], loader?: string): string[] {
  return facts
    .filter((fact) => (loader ? fact.loader === loader : fact.loader !== undefined))
    .map((fact) => fact.url.rendered)
    .sort();
}

function expression(code: string): t.Expression {
  const statement = parse(`(${code})`).program.body[0];
  if (!t.isExpressionStatement(statement)) throw new Error('not an expression');
  return statement.expression;
}

describe('symbolic evaluator', () => {
  const env = (id: string | number) => ({ bindings: new Map([['e', id]]) });

  test('folds concatenation, object lookups, logical operators and ternaries', () => {
    const fn = expression('e => "vendors" === e ? "vendors.js" : ({17:"about"}[e] || e) + "." + {17:"abc",42:"def"}[e] + ".js"');
    if (!t.isFunction(fn)) throw new Error('not a function');
    expect(evaluateFunctionBody(fn, env(17))).toBe('about.abc.js');
    expect(evaluateFunctionBody(fn, env(42))).toBe('42.def.js');
    expect(evaluateFunctionBody(fn, env('vendors'))).toBe('vendors.js');
  });

  test('drops ids missing from the hash map instead of rendering "undefined"', () => {
    expect(evaluateSymbolic(expression('"js/" + e + "." + {17:"abc"}[e] + ".js"'), env(99))).toBe(UNKNOWN);
  });

  test('evaluates if/return blocks and bails on calls', () => {
    const fn = expression('function (e) { if (e === 7) return "seven.js"; return "" + e + ".js"; }');
    if (!t.isFunction(fn)) throw new Error('not a function');
    expect(evaluateFunctionBody(fn, env(7))).toBe('seven.js');
    expect(evaluateFunctionBody(fn, env(8))).toBe('8.js');
    expect(evaluateSymbolic(expression('"js/" + hash(e) + ".js"'), env(1))).toBe(UNKNOWN);
    expect(evaluateSymbolic(expression('"js/" + (x = e) + ".js"'), env(1))).toBe(UNKNOWN);
    expect(evaluateSymbolic(expression('"js/" + free + ".js"'), env(1))).toBe(UNKNOWN);
  });
});

describe('webpack chunk runtime', () => {
  test('renders webpack 5 minified chunk and CSS maps with a static publicPath', async () => {
    const facts = await assets(
      '!function(){var a={};function i(e){return a[e]}' +
      'i.u=function(e){return"static/js/"+e+"."+{17:"5c2e4a1f",42:"0b9d7e3c"}[e]+".chunk.js"},' +
      'i.miniCssF=function(e){return"static/css/"+e+"."+{42:"9f8e7d6c"}[e]+".chunk.css"},i.p="/",' +
      'function(){var e={};i.f.miniCss=function(t,n){e[t]?n.push(e[t]):0!==e[t]&&{42:1}[t]&&n.push(e[t])}}();' +
      'Promise.all([i.e(17),i.e(900)]).then(i.bind(i,123))}();',
    );
    expect(chunks(facts, 'webpack-chunk')).toEqual([
      '/static/js/17.5c2e4a1f.chunk.js',
      '/static/js/42.0b9d7e3c.chunk.js',
    ]);
    expect(chunks(facts, 'webpack-css-chunk')).toEqual(['/static/css/42.9f8e7d6c.chunk.css']);
    const fact = facts.find((candidate) => candidate.loader === 'webpack-chunk')!;
    expect(fact.assetType).toBe('chunk');
    expect(fact.eager).toBe(false);
    expect(fact.url.static).toBe(true);
    expect(fact.parentSourceUrl).toBe(sourceUrl);
    expect(fact.provenance.extractor).toBe('webpack-chunk-runtime');
  });

  test('takes ids from .e() call sites when the filename function has no map', async () => {
    const facts = await assets(`
      var __webpack_require__ = {};
      __webpack_require__.u = (chunkId) => "" + chunkId + ".bundle.js";
      __webpack_require__.p = "/dist/";
      __webpack_require__.e(5).then(__webpack_require__.bind(__webpack_require__, 77));
    `);
    expect(chunks(facts, 'webpack-chunk')).toEqual(['/dist/5.bundle.js']);
  });

  test('keeps auto publicPath relative to the bundle and renders named chunks', async () => {
    const facts = await assets(
      '(()=>{var r={};r.u=e=>"vendors"===e?"vendors.js":(({17:"about"})[e]||e)+"."+{17:"abc123",99:"fff000"}[e]+".js";' +
      '(()=>{var e=document.currentScript.src;e=e.replace(/\\/[^\\/]+$/,"/"),r.p=e+"../"})();})();',
    );
    expect(chunks(facts, 'webpack-chunk')).toEqual(['../99.fff000.js', '../about.abc123.js', '../vendors.js']);
  });

  test('renders the webpack 4 jsonpScriptSrc function with its inline publicPath', async () => {
    const facts = await assets(
      '!function(e){function u(e){return a.p+"static/js/"+({3:"admin"}[e]||e)+"."+{3:"31d6cfe0",4:"77ab12cd"}[e]+".chunk.js"}' +
      'function a(t){return t}a.p="/app/"}([]);',
    );
    expect(chunks(facts, 'webpack-chunk')).toEqual([
      '/app/static/js/4.77ab12cd.chunk.js',
      '/app/static/js/admin.31d6cfe0.chunk.js',
    ]);
    expect(facts.find((fact) => fact.loader === 'webpack-chunk')?.provenance.extractor).toBe('webpack4-jsonp-script-src');
  });

  test('ignores look-alike assignments that do not render chunk files', async () => {
    const facts = await assets('var o={};o.u=e=>e+1;o.e(3);o.p="/";');
    expect(chunks(facts)).toEqual([]);
  });

  test('caps chunks per runtime and reports the rest as truncated', async () => {
    let map = '';
    for (let i = 0; i < 2_050; i++) map += `${i}:"h${i}",`;
    const code = `(()=>{var n={};n.u=e=>"c/"+e+"."+{${map}}[e]+".js";n.p="/";})();`;
    const result = await jstangle(code, { profile: 'discovery', sourceUrl });
    expect(chunks(result.assetReferences, 'webpack-chunk')).toHaveLength(2_000);
    const envelope = buildAnalysisResultV2(result, result.analysisContext);
    expect(envelope.stats.truncated?.assetReference).toBe(50);
    expect(envelope.stats.status).toBe('partial');
  });

  test('runtime chunks do not consume the general asset-reference cap', async () => {
    const code = `(()=>{var n={};n.u=e=>"c/"+e+"."+{1:"a",2:"b",3:"c"}[e]+".js";n.p="/";})(); import("./lazy.js");`;
    const result = await jstangle(code, { profile: 'discovery', sourceUrl, limits: { maxAssetReferences: 1 } });
    expect(chunks(result.assetReferences, 'webpack-chunk')).toHaveLength(3);
    expect(result.assetReferences.some((fact) => fact.url.rendered === './lazy.js')).toBe(true);
  });
});

describe('Vite and Rollup lazy chunks', () => {
  test('emits __vitePreload dependencies against the detected base', async () => {
    const facts = await assets(`
      const scriptRel = "modulepreload", assetsURL = function (dep) { return "/app/" + dep };
      const About = () => __vitePreload(() => import("./About-B1x.js"), ["assets/About-B1x.js", "assets/About-C2y.css"]);
    `);
    expect(chunks(facts, 'vite-preload')).toEqual(['/app/assets/About-B1x.js', '/app/assets/About-C2y.css']);
    expect(facts.some((fact) => fact.assetType === 'dynamic-import' && fact.url.rendered === './About-B1x.js')).toBe(true);
  });

  test('resolves Vite 5 __vite__mapDeps indices under a minified callee', async () => {
    const facts = await assets(
      'const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/a-1.js","assets/a-2.css","assets/b-3.js"])))=>i.map(i=>d[i]);' +
      'const p=function(t,s){return t()};p(()=>import("./a-1.js"),__vite__mapDeps([0,1]));',
    );
    expect(chunks(facts, 'vite-preload')).toEqual(['/assets/a-1.js', '/assets/a-2.css']);
  });

  test('keeps importer-relative deps relative', async () => {
    const facts = await assets('p(() => import("./x.js"), ["./x.js", "../shared.css"]);');
    expect(chunks(facts, 'vite-preload')).toEqual(['../shared.css', './x.js']);
  });

  test('enumerates a template import over a literal map', async () => {
    const facts = await assets(`
      const LOCALE_CHUNKS = { en: "a1b2", fr: "c3d4" };
      export function loadLocale(lang) { return import(\`./locales/\${lang}.\${LOCALE_CHUNKS[lang]}.js\`); }
    `);
    const fact = facts.find((candidate) => candidate.loader === 'template-import');
    expect(fact?.assetType).toBe('dynamic-import');
    expect(fact?.url.static).toBe(false);
    expect(fact?.url.rendered).toBe('./locales/${lang}.${LOCALE_CHUNKS[lang]}.js');
    expect(fact?.url.alternatives).toEqual(['./locales/en.a1b2.js', './locales/fr.c3d4.js']);
  });

  test('leaves a free-variable template import as a hint', async () => {
    const facts = await assets('function load(name) { return import(`./pages/${name}.js`); }');
    const fact = facts.find((candidate) => candidate.assetType === 'dynamic-import');
    expect(fact?.url.rendered).toBe('./pages/${name}.js');
    expect(fact?.loader).toBeUndefined();
  });
});

test('advertises the chunk loaders', () => {
  const caps = getCapabilities();
  expect(caps.capabilities).toContain('loader.webpack-chunk');
  expect(caps.capabilities).toContain('loader.vite-preload');
  expect(caps.schemaVersions.assetReference).toBe(3);
});
