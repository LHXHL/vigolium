// Passive: flags a response whose <title> names an admin page.
module.exports = {
  id: "title-check",
  name: "Admin Title",
  type: "passive",
  severity: "low",
  confidence: "firm",
  scope: "response",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;
    if (ctx.response.headers.get("content-type").indexOf("html") === -1) return null;
    if (!/<title>[^<]*admin/i.test(ctx.response.body)) return null;
    return [{ name: "Admin page title", url: ctx.request.url, matched: "<title>" }];
  }
};
