package oast

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
)

var xidRe = regexp.MustCompile(`^[0-9a-v]{20}$`)

func TestParseFixedTemplate(t *testing.T) {
	cases := []struct {
		raw, wantRender string
	}{
		{"https://{nonce}.cb.example.com", "N.cb.example.com"},
		{"http://cb.example.com/{nonce}", "cb.example.com/N"},
		{"vg-{nonce}.cb.example.com", "vg-N.cb.example.com"},
		{"https://cb.example.com/hook/{nonce}/x", "cb.example.com/hook/N/x"},
	}
	for _, c := range cases {
		tmpl := parseFixedTemplate(c.raw)
		if tmpl == nil {
			t.Fatalf("parseFixedTemplate(%q) = nil", c.raw)
		}
		if got := tmpl.render("N"); got != c.wantRender {
			t.Errorf("render(%q) = %q, want %q", c.raw, got, c.wantRender)
		}
		if got := tmpl.nonceOf(c.wantRender); got != "N" {
			t.Errorf("nonceOf(%q) = %q", c.wantRender, got)
		}
		if got := tmpl.nonceOf("http://" + c.wantRender); got != "N" {
			t.Errorf("nonceOf with scheme = %q", got)
		}
	}
	for _, raw := range []string{"https://cb.example.com", "https://{nonce}.{nonce}.example.com", ""} {
		if parseFixedTemplate(raw) != nil {
			t.Errorf("parseFixedTemplate(%q) != nil", raw)
		}
	}
}

func newFixedService(t *testing.T, repo *database.Repository, oastURL, project, scan string) *Service {
	t.Helper()
	svc, err := New(&config.OASTConfig{Enabled: true, OastURL: oastURL}, nil, repo, scan, project, nil)
	if err != nil || svc == nil {
		t.Fatalf("New: %v %v", svc, err)
	}
	return svc
}

func TestFixedTemplateMintsAndPersists(t *testing.T) {
	repo := newOASTTestRepo(t)
	svc := newFixedService(t, repo, "https://{nonce}.cb.example.com", "proj-1", "scan-1")
	if svc.Mode() != ModeFixedTemplate {
		t.Fatalf("Mode = %q", svc.Mode())
	}
	u1 := svc.GenerateURLFor(oastclass.SSRF, "https://t.example/fetch?url=x", "url", "parameter", "ssrf-blind", "req-hash-1")
	u2 := svc.GenerateURLFor(oastclass.SSRF, "https://t.example/fetch?url=x", "url", "parameter", "ssrf-blind", "req-hash-1")
	if u1 == u2 {
		t.Fatalf("two probes got the same callback %q", u1)
	}
	nonce, rest, _ := strings.Cut(u1, ".")
	if !xidRe.MatchString(nonce) || rest != "cb.example.com" {
		t.Fatalf("callback %q is not <xid>.cb.example.com", u1)
	}
	svc.RecordPayload(u1, "http://"+u1+"/")
	svc.Close()

	rows, err := repo.GetOASTPayloadsByNonce(context.Background(), "proj-1", []string{nonce})
	if err != nil {
		t.Fatal(err)
	}
	row := rows[nonce]
	if row == nil {
		t.Fatalf("nonce %s not persisted", nonce)
	}
	if row.ScanUUID != "scan-1" || row.ModuleID != "ssrf-blind" || row.Param != "url" || row.Class != "ssrf" ||
		row.RequestHash != "req-hash-1" || row.Payload != "http://"+u1+"/" {
		t.Errorf("persisted row = %+v", row)
	}
	// Another project's lookup does not see it.
	if other, _ := repo.GetOASTPayloadsByNonce(context.Background(), "proj-2", []string{nonce}); len(other) != 0 {
		t.Errorf("nonce visible from another project: %+v", other)
	}
}

func TestFixedURLWithoutNonceIsUncorrelated(t *testing.T) {
	repo := newOASTTestRepo(t)
	svc := newFixedService(t, repo, "https://cb.example.com/abc", "proj-1", "scan-1")
	if svc.Mode() != ModeFixedUncorrelated {
		t.Fatalf("Mode = %q", svc.Mode())
	}
	if got := svc.GenerateURL("https://t.example/", "url", "parameter", "ssrf-blind", "h"); got != "https://cb.example.com/abc" {
		t.Fatalf("GenerateURL = %q, want the fixed URL unchanged", got)
	}
	svc.Close()
	n, err := repo.DB().NewSelect().Model((*database.OASTPayload)(nil)).Count(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("payload rows = %d (%v), want 0", n, err)
	}
}

func interactshLine(t *testing.T, proto, fullID, rawReq, remote string) string {
	t.Helper()
	return fmt.Sprintf(`{"protocol":%q,"unique-id":%q,"full-id":%q,"raw-request":%q,"remote-address":%q,"timestamp":"2026-10-10T10:00:00Z"}`,
		proto, fullID, fullID, rawReq, remote)
}

// TestIngestKnownNonce is the fixed-URL correlation round trip: a scan plants
// through a {nonce} template, the endpoint logs the callback, and ingest
// produces a finding with the right module and parameter on the original scan.
func TestIngestKnownNonce(t *testing.T) {
	ctx := context.Background()
	repo := newOASTTestRepo(t)
	svc := newFixedService(t, repo, "https://{nonce}.cb.example.com", "proj-1", "scan-1")
	cb := svc.GenerateURLFor(oastclass.SSRF, "https://t.example/fetch?url=x", "url", "parameter", "ssrf-blind", "h1")
	svc.Close()
	nonce, _, _ := strings.Cut(cb, ".")

	// Resolvers randomise query-name case (0x20); the HTTP leg names the host.
	host := strings.ToUpper(nonce[:5]) + nonce[5:] + ".cb.example.com"
	raw := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Go-http-client/1.1\r\n\r\n"
	input := interactshLine(t, "http", "", raw, "203.0.113.7") + "\n" +
		interactshLine(t, "dns", "cv0000000000000000aa.cb.example.com", "", "8.8.8.8") + "\n" // unknown nonce

	callbacks, err := ParseCallbacks(strings.NewReader(input), FormatInteractshJSON, ParseOptions{})
	if err != nil || len(callbacks) != 2 {
		t.Fatalf("parse: %d callbacks, %v", len(callbacks), err)
	}
	res, err := Ingest(ctx, repo, "proj-1", callbacks)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || res.Unmatched != 1 || len(res.Findings) != 1 {
		t.Fatalf("result = %+v", res)
	}
	f := res.Findings[0]
	if f.Nonce != nonce || f.ModuleID != "ssrf-blind" || f.Param != "url" || f.ScanUUID != "scan-1" ||
		f.Severity != "high" || f.Protocol != "http" {
		t.Errorf("finding = %+v", f)
	}

	highs, err := repo.GetFindingsBySeverity(ctx, "proj-1", "high", 10)
	if err != nil || len(highs) != 1 {
		t.Fatalf("stored high findings = %d (%v)", len(highs), err)
	}
	if highs[0].ScanUUID != "scan-1" || highs[0].ModuleID != "ssrf-blind" {
		t.Errorf("stored finding scan=%q module=%q", highs[0].ScanUUID, highs[0].ModuleID)
	}

	// Ingesting the same log again adds nothing.
	again, err := Ingest(ctx, repo, "proj-1", callbacks)
	if err != nil {
		t.Fatal(err)
	}
	if again.Duplicates != 1 || len(again.Findings) != 0 {
		t.Errorf("re-ingest = %+v, want 1 duplicate and no findings", again)
	}
	// Another project cannot claim the nonce.
	other, err := Ingest(ctx, repo, "proj-2", callbacks)
	if err != nil || other.Matched != 0 || other.Unmatched != 2 {
		t.Errorf("other project = %+v (%v)", other, err)
	}
}

func TestIngestUnknownNonceIgnored(t *testing.T) {
	repo := newOASTTestRepo(t)
	callbacks, err := ParseCallbacks(strings.NewReader(
		`203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET /cv1abcdefghijklmnopq HTTP/1.1" 200 0`+"\n"),
		FormatRawLog, ParseOptions{})
	if err != nil || len(callbacks) != 1 {
		t.Fatalf("parse: %v %v", callbacks, err)
	}
	res, err := Ingest(context.Background(), repo, "proj-1", callbacks)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 0 || res.Unmatched != 1 || len(res.Findings) != 0 {
		t.Fatalf("result = %+v", res)
	}
	n, _ := repo.DB().NewSelect().Model((*database.OASTInteraction)(nil)).Count(context.Background())
	if n != 0 {
		t.Errorf("unmatched callback stored (%d rows)", n)
	}
}

// TestIngestPathTemplateRawLog: a path template matched in an access log line,
// planted by a header probe, upgrading DNS → HTTP across two ingests.
func TestIngestPathTemplateRawLog(t *testing.T) {
	ctx := context.Background()
	repo := newOASTTestRepo(t)
	svc := newFixedService(t, repo, "https://cb.example.com/{nonce}", "proj-1", "scan-9")
	cb := svc.GenerateURLFor(oastclass.CMDI, "https://t.example/run", "cmd", "os-command-injection", "command-injection-oast", "h9")
	svc.RecordPayload(cb, ";curl http://"+cb)
	svc.Close()
	if !strings.HasPrefix(cb, "cb.example.com/") {
		t.Fatalf("callback = %q", cb)
	}
	nonce := strings.TrimPrefix(cb, "cb.example.com/")

	dnsLine := "2026-10-10T10:00:00Z dns query " + nonce + ".cb.example.com IN A from 198.51.100.4"
	res, err := Ingest(ctx, repo, "proj-1", mustParse(t, dnsLine, FormatRawLog))
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Protocol != "dns" {
		t.Fatalf("dns ingest = %+v (%v)", res, err)
	}
	httpLine := `198.51.100.4 - - [10/Oct/2026:10:00:02 +0000] "GET /` + nonce + ` HTTP/1.1" 200 0 "-" "curl/8.4.0"`
	res, err = Ingest(ctx, repo, "proj-1", mustParse(t, httpLine, FormatRawLog))
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("http ingest = %+v (%v)", res, err)
	}
	f := res.Findings[0]
	if f.ModuleID != "command-injection-oast" || f.Param != "cmd" || f.Protocol != "http" || f.ScanUUID != "scan-9" {
		t.Errorf("finding = %+v", f)
	}
}

func mustParse(t *testing.T, input, format string) []Callback {
	t.Helper()
	cbs, err := ParseCallbacks(strings.NewReader(input), format, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return cbs
}

func TestParseInteractshJSON(t *testing.T) {
	ndjson := interactshLine(t, "DNS", "abc.oast.example", "", "1.2.3.4") + "\n\n" +
		interactshLine(t, "http", "def.oast.example", "GET /p/q HTTP/1.1\r\nHost: def.oast.example\r\n\r\n", "5.6.7.8") + "\n"
	cbs := mustParse(t, ndjson, FormatInteractshJSON)
	if len(cbs) != 2 {
		t.Fatalf("ndjson: %d callbacks", len(cbs))
	}
	if cbs[0].Interaction.Protocol != "dns" || cbs[0].Interaction.RemoteAddress != "1.2.3.4" ||
		!cbs[0].Interaction.Timestamp.Equal(time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("dns callback = %+v", cbs[0].Interaction)
	}
	if !containsStr(cbs[1].Where, "def.oast.example/p/q") {
		t.Errorf("http Where = %v, want host+path", cbs[1].Where)
	}

	arr := "[" + interactshLine(t, "dns", "a.x", "", "") + "," + interactshLine(t, "smtp", "b.x", "", "") + "]"
	if cbs := mustParse(t, arr, FormatInteractshJSON); len(cbs) != 2 || cbs[1].Interaction.Protocol != "smtp" {
		t.Errorf("array: %+v", cbs)
	}
	if _, err := ParseCallbacks(strings.NewReader("{not json"), FormatInteractshJSON, ParseOptions{}); err == nil {
		t.Error("malformed input accepted")
	}
}

func TestParseCollaboratorJSON(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	doc := `{"responses":[
	  {"protocol":"http","opCode":"1","interactionString":"abcd1234","clientIp":"203.0.113.5","time":"1791712800000",
	   "data":{"request":"` + b64("GET /hook/n1 HTTP/1.1\r\nHost: n0.abcd1234.oastify.com\r\n\r\n") + `","response":"` + b64("HTTP/1.1 200 OK\r\n\r\n") + `"}},
	  {"protocol":"dns","opCode":"0","interactionString":"abcd1234","clientIp":"8.8.4.4","time":"1791712800001",
	   "data":{"subDomain":"N0.abcd1234.oastify.com","type":28,"rawRequest":"` + b64("raw-dns") + `"}}
	]}`
	cbs := mustParse(t, doc, FormatCollaboratorJSON)
	if len(cbs) != 2 {
		t.Fatalf("%d callbacks", len(cbs))
	}
	h := cbs[0]
	if h.Interaction.Protocol != "http" || h.Interaction.RemoteAddress != "203.0.113.5" ||
		!strings.HasPrefix(h.Interaction.RawRequest, "GET /hook/n1") || h.Interaction.Timestamp.IsZero() {
		t.Errorf("http = %+v", h.Interaction)
	}
	if !containsStr(h.Where, "n0.abcd1234.oastify.com/hook/n1") {
		t.Errorf("http Where = %v", h.Where)
	}
	d := cbs[1]
	if d.Interaction.Protocol != "dns" || d.Interaction.QType != "AAAA" || d.Interaction.FullId != "N0.abcd1234.oastify.com" {
		t.Errorf("dns = %+v", d.Interaction)
	}

	// Montoya-style field names, one per line.
	montoya := `{"id":"zz","type":"DNS","clientIp":"1.1.1.1","timeStamp":"2026-10-10T10:00:00Z","dnsDetails":{"query":"q.zz.oastify.com","queryType":"A"}}`
	if cbs := mustParse(t, montoya, FormatCollaboratorJSON); len(cbs) != 1 || cbs[0].Interaction.QType != "A" ||
		!containsStr(cbs[0].Where, "q.zz.oastify.com") {
		t.Errorf("montoya = %+v", cbs)
	}
}

func TestParseRawLog(t *testing.T) {
	input := strings.Join([]string{
		`203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET /x HTTP/1.1" 200 0`,
		``,
		`2026-10-10T10:00:01Z query: abc.cb.example.com IN A client 198.51.100.1`,
		`MAIL FROM:<a@b> from 192.0.2.1`,
		`something mentioning abc`,
	}, "\n")
	cbs := mustParse(t, input, FormatRawLog)
	if len(cbs) != 4 {
		t.Fatalf("%d callbacks", len(cbs))
	}
	want := []string{"http", "dns", "smtp", "dns"}
	for i, cb := range cbs {
		if cb.Interaction.Protocol != want[i] {
			t.Errorf("line %d protocol = %q, want %q", i, cb.Interaction.Protocol, want[i])
		}
	}
	if cbs[0].Interaction.RemoteAddress != "203.0.113.9" || !cbs[0].Interaction.Timestamp.Equal(time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("access-log line = %+v", cbs[0].Interaction)
	}
	if cbs[1].Interaction.Timestamp.IsZero() {
		t.Error("RFC 3339 time not parsed")
	}
	forced, _ := ParseCallbacks(strings.NewReader(input), FormatRawLog, ParseOptions{Protocol: "HTTP"})
	for _, cb := range forced {
		if cb.Interaction.Protocol != "http" {
			t.Errorf("--protocol override ignored: %q", cb.Interaction.Protocol)
		}
	}
	if _, err := ParseCallbacks(strings.NewReader(""), "bogus", ParseOptions{}); err == nil {
		t.Error("unknown format accepted")
	}
}

func TestNonceCandidates(t *testing.T) {
	n := "cv1abcdefghijklmnopq"[:20]
	got := nonceCandidates("GET /vg-" + strings.ToUpper(n) + "/x HTTP/1.1")
	if !containsStr(got, n) {
		t.Errorf("candidates = %v, want %s", got, n)
	}
	// A nonce glued to a prefix from its own alphabet is still found.
	if got := nonceCandidates("a" + n + ".cb.example.com"); !containsStr(got, n) {
		t.Errorf("prefixed candidates = %v", got)
	}
	if got := nonceCandidates("short.example.com"); len(got) != 0 {
		t.Errorf("candidates in a short host = %v", got)
	}
}

// TestReportCorrelatedSetsOASTSignal: every OAST-derived finding says its
// proof is an out-of-band callback (F12 reads it).
func TestReportCorrelatedSetsOASTSignal(t *testing.T) {
	var got *output.ResultEvent
	svc := &Service{emitResult: func(r *output.ResultEvent) { got = r }}
	svc.trackerCache().Add("n1", PayloadContext{TargetURL: "https://t.example/", ParameterName: "url",
		InjectionType: "parameter", Class: oastclass.SSRF, ModuleID: "ssrf-blind", CallbackURL: "n1.oast.example"})
	svc.handleInteraction(&server.Interaction{Protocol: "http", UniqueID: "n1"})
	if got == nil || got.Signal() != output.SignalOAST {
		t.Fatalf("result signal = %v", got)
	}
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
