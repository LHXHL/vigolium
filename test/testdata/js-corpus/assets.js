// Asset references: dynamic import, worker, service worker, source map.
import("./lazy-panel.js");
const worker = new Worker("/workers/compute.js");
navigator.serviceWorker.register("/sw.js");
//# sourceMappingURL=assets.js.map
