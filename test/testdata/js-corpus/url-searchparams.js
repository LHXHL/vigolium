// new URL + searchParams, URLSearchParams as a query string, as a body and as
// axios params.
function search(term, page) {
  const u = new URL("/api/v6/search", location.origin);
  u.searchParams.set("q", term);
  u.searchParams.append("page", String(page));
  return fetch(u);
}

function suggest(prefix) {
  const target = new URL("https://api.example.test/v1/suggest");
  target.searchParams.set("prefix", prefix);
  return fetch(target.toString());
}

function lookup(sku) {
  const endpoint = new URL("/api/v6/lookup", window.location.href);
  endpoint.searchParams.set("sku", sku);
  return fetch(`${endpoint}`);
}

function filterOrders(status, limit) {
  const params = new URLSearchParams({ status: status, limit: "25" });
  params.append("sort", "desc");
  return fetch("/api/v6/orders?" + params);
}

function login(user, pass) {
  const form = new URLSearchParams();
  form.append("username", user);
  form.append("password", pass);
  return fetch("/api/v6/login", { method: "POST", body: form });
}

function report(kind) {
  const qp = new URLSearchParams({ kind: kind });
  return axios.get("/api/v6/reports", { params: qp });
}
