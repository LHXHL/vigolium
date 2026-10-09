// Webpack 5 runtime lazy-chunk resolver. Chunk evaluation is D8 scope; this
// file pins what the helper emits today.
(() => {
  var __webpack_require__ = {};
  __webpack_require__.p = "/static/";
  __webpack_require__.u = (chunkId) =>
    "js/" + chunkId + "." + { 123: "a1b2c3d4", 456: "e5f6a7b8" }[chunkId] + ".chunk.js";
  __webpack_require__.miniCssF = (chunkId) => "css/" + chunkId + "." + { 123: "11aa22bb" }[chunkId] + ".css";
  __webpack_require__.e(123).then(__webpack_require__.bind(__webpack_require__, 9001));
  Promise.all([__webpack_require__.e(456)]).then(() => {});
})();
