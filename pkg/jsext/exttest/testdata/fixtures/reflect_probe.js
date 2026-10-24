// Active: sends a probe through an insertion point and reports a reflection.
module.exports = {
  id: "reflect-probe",
  name: "Reflected Probe",
  type: "active",
  severity: "medium",
  scanTypes: ["per_insertion_point"],

  scanPerInsertionPoint: function(ctx, insertion) {
    var resp = vigolium.http.send(insertion.buildRequest("VIGOLIUMPROBE"));
    if (resp && resp.body.indexOf("VIGOLIUMPROBE") !== -1) {
      return [{ name: "Reflected probe in " + insertion.name, url: ctx.request.url, matched: "VIGOLIUMPROBE" }];
    }
    return null;
  }
};
