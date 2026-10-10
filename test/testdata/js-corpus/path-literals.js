// Path-shaped strings that never reach a request call directly. They are
// low-confidence wordlist hints, tagged with how they appeared.
const routes = {
  profile: "/api/v2/profile",
  admin: "/api/v2/admin/config",
  help: "/static/help/index.html",
};

const API_EXPORT_PATH = "/api/v2/export";

const sitemap = ["/account/settings", "/account/billing"];

function go(target = "/dashboard/home") {
  return target;
}

function legacyEndpoint() {
  return "/legacy/rpc/handler";
}

let fallback;
fallback = "/internal/fallback";

fetch("/api/v2/consumed");
