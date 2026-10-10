// Webpack 5 runtime lazy-chunk resolver (readable build). The helper evaluates
// __webpack_require__.u / .miniCssF over the chunk-id set (hash-map keys and
// .e() call sites) and prefixes the static .p publicPath.
(() => {
  var __webpack_require__ = {};
  __webpack_require__.p = "/static/";
  __webpack_require__.u = (chunkId) => {
    // return url for filenames not based on template
    if (chunkId === "vendors") return "js/vendors.bundle.js";
    // return url for filenames based on template
    return "js/" + chunkId + "." + { 123: "a1b2c3d4", 456: "e5f6a7b8" }[chunkId] + ".chunk.js";
  };
  __webpack_require__.miniCssF = (chunkId) => "css/" + chunkId + "." + { 123: "11aa22bb" }[chunkId] + ".css";
  __webpack_require__.e(123).then(__webpack_require__.bind(__webpack_require__, 9001));
  Promise.all([__webpack_require__.e("vendors"), __webpack_require__.e(456)]).then(() => {});
})();
