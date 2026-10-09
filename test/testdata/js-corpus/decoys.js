// Strings that look path-like but are not routes. None of these should become
// a pathLiteral or an httpRequest.
const formats = { date: "/yyyy/mm/dd", short: "dd/mm/yyyy" };
const mime = { html: "text/html", json: "application/json" };
const pattern = new RegExp("^/[a-z]+/\\d+$");
const commentish = "// TODO: remove";
const i18n = { key: "common.buttons.ok.label" };
const dots = { file: "/a.b.c.d.e" };
const spaced = { label: "/not a path" };
const root = { home: "/" };
const relative = { dot: "/./x" };
