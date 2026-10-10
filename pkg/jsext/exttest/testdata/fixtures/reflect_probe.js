// Active: sends a probe through an insertion point and reports a reflection.
module.exports = {
  id: "reflect-probe",
  name: "Reflected Probe",
  type: "active",
  severity: "medium",
  scanTypes: ["per_insertion_point"],

  scanPerInsertionPoint: function(ctx, insertion) {
    var resp = vigolium.http.send(insertion.buildRequest("VGNMPROBE"));
    if (resp && resp.body.indexOf("VGNMPROBE") !== -1) {
      return [{ name: "Reflected probe in " + insertion.name, url: ctx.request.url, matched: "VGNMPROBE" }];
    }
    return null;
  }
};
