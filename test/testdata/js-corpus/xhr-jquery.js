// XMLHttpRequest and jQuery request styles.
var xhr = new XMLHttpRequest();
xhr.open("PUT", "/api/v1/profile");
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send(JSON.stringify({ name: "n" }));

$.ajax({ url: "/api/v1/items", method: "DELETE" });
$.get("/api/v1/config");
$.post("/api/v1/submit", { data: "value" });
