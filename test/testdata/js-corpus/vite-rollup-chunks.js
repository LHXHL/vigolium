// Vite preload helper (readable and Vite 5 __vite__mapDeps forms) and Rollup
// template imports: one enumerable from a literal map, one free variable.
const __vite__mapDeps = (i, m = __vite__mapDeps, d = (m.f || (m.f = ["assets/Admin-5d6e.js", "assets/Admin-8f90.css", "assets/vendor-12bc.js"]))) => i.map((i) => d[i]);
const scriptRel = "modulepreload";
const assetsURL = function (dep) { return "/" + dep; };

const Settings = () =>
  __vitePreload(() => import("./chunk-settings-3f9a.js"), ["assets/settings-77aa.css", "assets/vendor-12bc.js"]);
const Admin = () => p(() => import("./Admin-5d6e.js"), __vite__mapDeps([0, 1, 2]));

const LOCALE_CHUNKS = { en: "a1b2", fr: "c3d4" };
export function loadMessages(lang) {
  return import(`./i18n/${lang}.${LOCALE_CHUNKS[lang]}.js`);
}

function loadLocale(locale) {
  return import(`./locales/chunk-${locale}.js`);
}
