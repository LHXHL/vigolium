module.exports = {
  id: "always",
  name: "Always",
  type: "passive",
  severity: "info",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) { return [{ name: "Always fires", url: ctx.request.url }]; }
};
