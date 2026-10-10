// Query strings built by concatenation and templates: the names are static,
// the values are not.
function find(q, page) {
  return fetch("/api/v2/find?q=" + encodeURIComponent(q) + "&page=" + page);
}

function items(category, offset) {
  return fetch(`/api/v2/items?category=${category}&offset=${offset}&format=json`);
}

function opaque(qs) {
  return fetch("/api/v2/opaque?" + qs);
}
