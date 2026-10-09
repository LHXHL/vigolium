// Vite preload helper and a Rollup template import. Chunk evaluation is D8
// scope; this file pins what the helper emits today.
const Settings = () =>
  __vitePreload(() => import("./chunk-settings-3f9a.js"), ["assets/settings-77aa.css", "assets/vendor-12bc.js"]);

function loadLocale(locale) {
  return import(`./locales/chunk-${locale}.js`);
}
