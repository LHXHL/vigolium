package oast

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestClassFromLegacyLabel pins the label → class rules for the callers that
// still mint through GenerateURL (JS payload(), olium oast_mint) and for
// contexts built without a class. Module call sites pass their class
// explicitly (see pkg/modules TestOASTCallSitesUseExplicitClass).
func TestClassFromLegacyLabel(t *testing.T) {
	tests := []struct {
		label string
		want  Class
	}{
		// Historical substring rules, on labels used in-tree.
		{"os-command-injection (parameter)", oastclass.CMDI},
		{"os-command-injection (header)", oastclass.CMDI},
		{"file-upload code execution (command)", oastclass.CMDI},
		{"ssi-injection command execution", oastclass.CMDI},
		{"server-side-javascript command execution", oastclass.CMDI},
		{"xxe (external entity)", oastclass.XXE},
		{"XXE (SAML external DTD)", oastclass.XXE},
		{"aem-packmgr-xxe", oastclass.XXE},
		{"sql-injection (out-of-band)", oastclass.SQLi},
		{"jwt-header-key-url-injection (header)", oastclass.JWTKeyURL},
		{"ssrf-smuggle:redis-slaveof", oastclass.SSRFSmuggle},
		// Exact class names (olium oast_mint kinds, JS labels) map to themselves.
		{"ssrf", oastclass.SSRF},
		{"SQLi", oastclass.SQLi},
		{" esi ", oastclass.ESI},
		{"text4shell", oastclass.Text4Shell},
		// Free-form labels with no rule stay generic.
		{"parameter", oastclass.Generic},
		{"extension", oastclass.Generic},
		{"olium-manual", oastclass.Generic},
		{"", oastclass.Generic},
	}
	for _, tt := range tests {
		if got := ClassFromLegacyLabel(tt.label); got != tt.want {
			t.Errorf("ClassFromLegacyLabel(%q) = %q, want %q", tt.label, got, tt.want)
		}
	}
}

func TestClassParseAndValid(t *testing.T) {
	for _, c := range oastclass.All() {
		if !c.Valid() {
			t.Errorf("%q not Valid", c)
		}
		if got, ok := oastclass.Parse(string(c)); !ok || got != c {
			t.Errorf("Parse(%q) = (%q, %v)", c, got, ok)
		}
	}
	if _, ok := oastclass.Parse("rce"); ok {
		t.Error(`Parse("rce") accepted an unknown class`)
	}
}

// TestGenerateURLForTracksClass checks the class is fixed at mint time: an
// explicit class wins over the label, and GenerateURL derives it once.
func TestGenerateURLForTracksClass(t *testing.T) {
	srv, _ := fakeInteractshServer(t)
	svc, err := New(&config.OASTConfig{Enabled: true, ServerURL: srv.URL}, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(svc.Close)
	if err := svc.WaitReady(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}

	tests := []struct {
		name  string
		mint  func() string
		want  Class
		label string
	}{
		{"explicit class beats label", func() string {
			return svc.GenerateURLFor(oastclass.ESI, "http://t", "q", "esi include (command)", "esi-injection", "")
		}, oastclass.ESI, "esi include (command)"},
		{"legacy label derived once", func() string {
			return svc.GenerateURL("http://t", "q", "os-command-injection (parameter)", "m", "")
		}, oastclass.CMDI, "os-command-injection (parameter)"},
		{"empty class falls back to label", func() string {
			return svc.GenerateURLFor("", "http://t", "q", "xxe (external entity)", "m", "")
		}, oastclass.XXE, "xxe (external entity)"},
	}
	for _, tt := range tests {
		u := tt.mint()
		if u == "" {
			t.Fatalf("%s: empty URL", tt.name)
		}
		pctx, ok := svc.trackerCache().Get(extractNonce(u))
		if !ok {
			t.Fatalf("%s: context not tracked", tt.name)
		}
		if pctx.Class != tt.want || pctx.InjectionType != tt.label {
			t.Errorf("%s: tracked (class %q, label %q), want (%q, %q)", tt.name, pctx.Class, pctx.InjectionType, tt.want, tt.label)
		}
	}
}

// TestClassifyInteractionByClass rates each class on the HTTP and DNS legs. The
// label is deliberately uninformative so only the class can drive the result.
func TestClassifyInteractionByClass(t *testing.T) {
	type want struct {
		sev  severity.Severity
		conf severity.Confidence
	}
	tests := []struct {
		cls       Class
		http, dns want
	}{
		{oastclass.CMDI, want{severity.Critical, severity.Certain}, want{severity.High, severity.Firm}},
		{oastclass.XXE, want{severity.High, severity.Certain}, want{severity.High, severity.Firm}},
		{oastclass.SQLi, want{severity.Critical, severity.Certain}, want{severity.High, severity.Firm}},
		{oastclass.Text4Shell, want{severity.Critical, severity.Certain}, want{severity.High, severity.Firm}},
		{oastclass.ESI, want{severity.High, severity.Certain}, want{severity.Info, severity.Tentative}},
		{oastclass.HostRouting, want{severity.Info, severity.Certain}, want{severity.Info, severity.Tentative}},
		{oastclass.SSRFSmuggle, want{severity.High, severity.Certain}, want{severity.Info, severity.Tentative}},
		{oastclass.SSRF, want{severity.High, severity.Certain}, want{severity.Info, severity.Tentative}},
		{oastclass.Generic, want{severity.High, severity.Certain}, want{severity.Info, severity.Tentative}},
	}
	for _, tt := range tests {
		pctx := PayloadContext{TargetURL: "http://t", ParameterName: "q", InjectionType: "probe", Class: tt.cls}
		if sev, conf, desc := classifyInteraction("http", pctx); sev != tt.http.sev || conf != tt.http.conf || desc == "" {
			t.Errorf("%s/http = %s/%s, want %s/%s", tt.cls, sev, conf, tt.http.sev, tt.http.conf)
		}
		if sev, conf, _ := classifyInteraction("dns", pctx); sev != tt.dns.sev || conf != tt.dns.conf {
			t.Errorf("%s/dns = %s/%s, want %s/%s", tt.cls, sev, conf, tt.dns.sev, tt.dns.conf)
		}
	}
	// JWT's DNS leg is rated by classifyJWT; just check it is not the generic Info lead.
	jwt := PayloadContext{InjectionType: "probe", Class: oastclass.JWTKeyURL}
	if sev, _, _ := classifyInteraction("dns", jwt); sev == severity.Info {
		t.Errorf("jwt-key-url/dns rated Info, want the JWT classifier")
	}
}

// TestRefineOASTCallbackText4ShellAndESI: Commons Text fetches with
// java.net.URL, so a browser callback is a harvest; an ESI processor forwards
// the client's headers, so a browser UA on its fetch is expected.
func TestRefineOASTCallbackText4ShellAndESI(t *testing.T) {
	browser := &server.Interaction{Protocol: "http", RawRequest: "GET / HTTP/1.1\r\nHost: n.oast\r\nUser-Agent: Mozilla/5.0 Chrome/149 Safari/537.36\r\n\r\n"}

	t4s := PayloadContext{TargetURL: "http://t", InjectionType: "text4shell interpolation", Class: oastclass.Text4Shell}
	if sev, conf, _ := refineOASTCallback(browser, t4s, severity.Critical, severity.Certain, "x"); sev != severity.Low || conf != severity.Tentative {
		t.Errorf("text4shell browser callback = %s/%s, want low/tentative", sev, conf)
	}
	esi := PayloadContext{TargetURL: "http://t", InjectionType: "esi include", Class: oastclass.ESI}
	if sev, conf, _ := refineOASTCallback(browser, esi, severity.High, severity.Certain, "x"); sev != severity.High || conf != severity.Certain {
		t.Errorf("esi browser callback = %s/%s, want high/certain (ESI forwards client headers)", sev, conf)
	}
}
