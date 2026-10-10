// Plain fetch calls: literals, template literals, concatenation, JSON bodies
// and header templates.
const API_ROOT = "/api/v1";

function loadUser(userId) {
  return fetch(`${API_ROOT}/users/${userId}`);
}

function saveComment(postId, text) {
  return fetch("/api/v1/posts/" + postId + "/comments", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
    body: JSON.stringify({ text: text, draft: false }),
  });
}

fetch("/api/v1/health");
fetch("https://api.example.test/v2/status", { method: "GET", credentials: "include" });
