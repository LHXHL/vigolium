// Where request credentials come from. The helper must report the storage key,
// never a token value.
function me() {
  return fetch("/api/v4/me", {
    headers: { Authorization: "Bearer " + localStorage.getItem("jwt") },
  });
}

function orders() {
  const token = sessionStorage.getItem("access_token");
  return fetch("/api/v4/orders", { headers: { Authorization: `Bearer ${token}` } });
}

function cart() {
  return fetch("/api/v4/cart", { headers: { "X-API-Key": Cookies.get("api_key") } });
}

function csrfFromCookie() {
  const match = document.cookie.match(/(?:^|; )XSRF-TOKEN=([^;]*)/);
  return fetch("/api/v4/csrf", { method: "POST", headers: { "X-XSRF-TOKEN": match[1] } });
}

function stateToken(store) {
  return fetch("/api/v4/state", {
    headers: { Authorization: "Bearer " + store.getState().auth.token },
  });
}

function hardcoded() {
  return fetch("/api/v4/legacy", { headers: { Authorization: "Basic dXNlcjpwYXNz" } });
}
