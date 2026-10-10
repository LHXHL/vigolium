package diagnostics

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/audit/bin"
)

// The vigolium-audit fix item exists for audit_external builds, whose helper
// is downloaded; an embedded build's failing helper is not fixable by
// re-running the extraction, so --fix must not claim it.
func TestAuditHelperFixableOnlyWhenExternal(t *testing.T) {
	r := &Report{EmbeddedBinaries: map[string]*CheckResult{
		"vigolium-audit": {Status: StatusWarning},
	}}
	var item *fixableItem
	for _, it := range fixRegistry() {
		if it.Key == "vigolium-audit" {
			it := it
			item = &it
		}
	}
	if item == nil {
		t.Fatal("no vigolium-audit fix item")
	}
	if got, want := item.IsFailing(r), bin.External(); got != want {
		t.Errorf("IsFailing = %v, want %v (External=%v)", got, want, bin.External())
	}
	r.EmbeddedBinaries["vigolium-audit"].Status = StatusOK
	if item.IsFailing(r) {
		t.Error("IsFailing true for a healthy helper")
	}
}

// checkAuditBinary never downloads: a plain doctor run on an audit_external
// build reports the helper state, and a default build reports its source.
func TestCheckAuditBinaryReportsSource(t *testing.T) {
	t.Setenv(bin.CacheDirEnv, t.TempDir())
	t.Setenv(bin.BaseURLEnv, "")
	c := checkAuditBinary()
	want := "source: " + bin.SourceEmbedded
	if bin.External() {
		want = "source: " + bin.SourceDownload
	}
	found := false
	for _, d := range c.Details {
		if d == want {
			found = true
		}
	}
	if !found {
		t.Errorf("details %v lack %q", c.Details, want)
	}
	if bin.External() && c.Status == StatusOK {
		t.Error("an audit_external build without a base URL reported the helper OK")
	}
}
