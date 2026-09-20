package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

func TestConfidenceRankFor(t *testing.T) {
	cases := []struct {
		in    string
		rank  int
		known bool
	}{
		{"low", 0, true},
		{"LOW", 0, true},
		{"medium", 1, true},
		{"med", 1, true},
		{" high ", 2, true},
		{"bogus", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		rank, known := confidenceRankFor(c.in)
		if rank != c.rank || known != c.known {
			t.Errorf("confidenceRankFor(%q) = (%d,%v), want (%d,%v)", c.in, rank, known, c.rank, c.known)
		}
	}
}

func TestRedactSecret(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"abcdef", "******"},   // <= 2*keep, fully masked
		{"abcdefg", "abc*efg"}, // 7 chars: keep 3 each end, 1 star between
		{"sk_live_0123456789", "sk_************789"},
	}
	for _, c := range cases {
		if got := redactSecret(c.in); got != c.want {
			t.Errorf("redactSecret(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// A redacted secret never reveals the full middle.
	if got := redactSecret("supersecretvalue"); strings.Contains(got, "secret") {
		t.Errorf("redactSecret leaked the middle: %q", got)
	}
}

func TestLineOfOffset(t *testing.T) {
	data := []byte("line1\nline2\nline3")
	cases := []struct {
		off, line int
	}{
		{0, 1},
		{5, 1},  // the newline itself is still on line 1
		{6, 2},  // first byte of line2
		{12, 3}, // first byte of line3
		{9999, 3},
		{-5, 1},
	}
	for _, c := range cases {
		if got := lineOfOffset(data, c.off); got != c.line {
			t.Errorf("lineOfOffset(off=%d) = %d, want %d", c.off, got, c.line)
		}
	}
}

func TestToSet(t *testing.T) {
	if toSet(nil) != nil {
		t.Error("toSet(nil) should be nil")
	}
	s := toSet([]string{"a", " b ", "", "a"})
	if len(s) != 2 || !s["a"] || !s["b"] {
		t.Errorf("toSet trimming/dedup wrong: %v", s)
	}
}

func TestKitNormalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"https://acme.test/path?x=1", "acme.test"},
		{"http://acme.test:8443/a", "acme.test"},
		{"acme.test:8443", "acme.test"},
		{"acme.test/robots.txt", "acme.test"},
		{"  spaced.test  ", "spaced.test"},
		{"# comment", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := kitNormalizeDomain(c.in); got != c.want {
			t.Errorf("kitNormalizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestKitCollectDomainsDedupAndNormalize(t *testing.T) {
	// Explicit args (no "-"), so stdin is never consulted.
	got, err := kitCollectDomains([]string{"https://a.test/x", "A.TEST", "b.test:80", "# c"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.test", "b.test"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadOASTSession(t *testing.T) {
	dir := t.TempDir()

	// Missing file yields a helpful, actionable error.
	if _, err := loadOASTSession(filepath.Join(dir, "nope.yaml")); err == nil {
		t.Error("expected error for missing session file")
	} else if !strings.Contains(err.Error(), "oast new") {
		t.Errorf("missing-file error should point at `oast new`, got: %v", err)
	}

	// A session missing the correlation id / private key is rejected.
	incomplete := filepath.Join(dir, "incomplete.yaml")
	if err := os.WriteFile(incomplete, []byte("server-url: https://oast.pro\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOASTSession(incomplete); err == nil {
		t.Error("expected error for a session missing correlation id / private key")
	}

	// A well-formed session round-trips.
	good := filepath.Join(dir, "good.yaml")
	content := "server-url: https://oast.pro\n" +
		"server-token: tok\n" +
		"private-key: PRIVKEYDATA\n" +
		"correlation-id: abcdef1234567890\n" +
		"secret-key: sek\n" +
		"public-key: PUBKEYDATA\n"
	if err := os.WriteFile(good, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	si, err := loadOASTSession(good)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if si.CorrelationID != "abcdef1234567890" || si.ServerURL != "https://oast.pro" || si.Token != "tok" {
		t.Errorf("session parsed wrong: %+v", si)
	}
}

func TestResolveWordlistName(t *testing.T) {
	available := []string{"dir-long.txt", "fuzz.txt", "jwt.secrets.list"}
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"fuzz.txt", "fuzz.txt", true},    // exact filename
		{"fuzz", "fuzz.txt", true},        // basename without extension
		{"FUZZ", "fuzz.txt", true},        // case-insensitive
		{"jwt", "jwt.secrets.list", true}, // friendly alias
		{"jwt.secrets", "jwt.secrets.list", true},
		{"dir-long", "dir-long.txt", true},
		{"nope", "", false},
	}
	for _, c := range cases {
		got, ok := resolveWordlistName(c.in, available)
		if ok != c.ok || got != c.want {
			t.Errorf("resolveWordlistName(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSplitWordlistEntries(t *testing.T) {
	data := []byte("a\n# comment\n\n  b  \nc\n")
	got := splitWordlistEntries(data)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestKitReadJWTStripsBearer(t *testing.T) {
	if got, _ := kitReadJWT("Bearer abc.def.ghi"); got != "abc.def.ghi" {
		t.Errorf("kitReadJWT did not strip Bearer: %q", got)
	}
	if got, _ := kitReadJWT("  abc.def.ghi  "); got != "abc.def.ghi" {
		t.Errorf("kitReadJWT did not trim: %q", got)
	}
}

// Endpoints must carry the provenance that says whether a method was resolved
// from the AST or guessed by a regex. ExtractedRequest alone cannot express it.
func TestKitBeautifyEndpointsCarryProvenance(t *testing.T) {
	res := &jstangle.ScanResult{
		RequestFacts: []jstangle.HTTPRequestFact{{
			Kind: "httpRequest",
			URL:  jstangle.ValueTemplate{Rendered: "/api/v3/devices"},
			// Empty method: unresolved, the fallback's honest output.
			Method:     jstangle.ValueTemplate{Rendered: ""},
			Provenance: jstangle.Provenance{Extractor: "large-input-string-fallback", Confidence: "low"},
		}, {
			Kind:       "httpRequest",
			URL:        jstangle.ValueTemplate{Rendered: "/api/v3/tenants"},
			Method:     jstangle.ValueTemplate{Rendered: "POST"},
			Provenance: jstangle.Provenance{Extractor: "bundle-module", Confidence: "medium", ModulePath: "./src/api.js"},
		}},
	}
	endpoints := kitBeautifyEndpoints(res)
	if len(endpoints) != 2 {
		t.Fatalf("expected two endpoints, got %d", len(endpoints))
	}
	if endpoints[0].Extractor != "large-input-string-fallback" || endpoints[0].Confidence != "low" {
		t.Errorf("guessed endpoint lost its provenance: %+v", endpoints[0])
	}
	if endpoints[0].Method != "" {
		t.Errorf("unresolved method should stay empty, got %q", endpoints[0].Method)
	}
	if endpoints[1].ModulePath != "./src/api.js" || endpoints[1].Method != "POST" {
		t.Errorf("resolved endpoint lost provenance or method: %+v", endpoints[1])
	}
}

// Three distinct outcomes used to collapse into "neither minified nor bundled".
func TestKitBeautifyUnchangedReasonDistinguishesOutcomes(t *testing.T) {
	notABundle := kitBeautifyUnchangedReason("a.js", &jstangle.ScanResult{
		Completion: &jstangle.ScanCompletion{Status: "complete"},
	})
	if !strings.Contains(notABundle, "neither minified nor bundled") {
		t.Errorf("a clean scan of a plain script should say so: %q", notABundle)
	}

	neverDispatched := kitBeautifyUnchangedReason("big.js", &jstangle.ScanResult{
		Diagnostics: []jstangle.Diagnostic{{Stage: "admission", Code: "ast_analysis_skipped_very_large"}},
	})
	if !strings.Contains(neverDispatched, "was not analyzed") ||
		!strings.Contains(neverDispatched, "ast_analysis_skipped_very_large") {
		t.Errorf("an input the service refused must not look like a plain script: %q", neverDispatched)
	}

	analysisFailed := kitBeautifyUnchangedReason("bundle.js", &jstangle.ScanResult{
		Completion: &jstangle.ScanCompletion{Status: "failed", ReasonCode: "ast_node_limit_reached"},
	})
	if !strings.Contains(analysisFailed, "did not complete") ||
		!strings.Contains(analysisFailed, "ast_node_limit_reached") {
		t.Errorf("a failed analysis must not look like a plain script: %q", analysisFailed)
	}
}

// Recovered module paths come from bundle metadata, so they are
// attacker-influenced and must never escape the target directory.
func TestKitSafeModulePathConfinesToRoot(t *testing.T) {
	root := "/tmp/out"
	escapes := []string{
		"../../../etc/passwd",
		"./../../etc/passwd",
		"/etc/passwd",
		`C:\Windows\system32\drivers\etc\hosts`,
		`\\server\share\evil.js`,
		"",
		// Both Join back to root itself; appending an extension would write
		// /tmp/out.js, a sibling of the output directory rather than a file in it.
		".",
		"a/..",
	}
	for _, modulePath := range escapes {
		if target, ok := kitSafeModulePath(root, modulePath); ok {
			t.Errorf("path %q escaped the target directory as %q", modulePath, target)
		}
	}

	safe := map[string]string{
		"./src/api.js":     "/tmp/out/src/api.js",
		"src/nested/a.js":  "/tmp/out/src/nested/a.js",
		"./100":            "/tmp/out/100.js", // extensionless modules get one
		"./pages/index.ts": "/tmp/out/pages/index.ts",
	}
	for modulePath, want := range safe {
		target, ok := kitSafeModulePath(root, modulePath)
		if !ok {
			t.Errorf("path %q was rejected but is safe", modulePath)
			continue
		}
		if target != want {
			t.Errorf("path %q resolved to %q, want %q", modulePath, target, want)
		}
	}
}

// The engine ships one assembled document rather than per-module content, so
// splitting it back apart is how --modules produces a directory.
func TestBeautifiedCodeModulesSplitsAssembledDocument(t *testing.T) {
	beautified := &jstangle.BeautifiedCode{
		Format:      "webpack",
		ModuleCount: 3,
		ModulePaths: []string{"./entry.js", "./src/api.js", "./src/util.js"},
		Changed:     true,
		Content: "// ===== ./entry.js (entry) =====\nconst a = 1;\n\n" +
			"// ===== ./src/api.js =====\nfetch(\"/api/v3\");\n\n" +
			"// ===== ./src/util.js =====\nexport const noop = () => {};",
	}
	modules := beautified.Modules()
	if len(modules) != 3 {
		t.Fatalf("expected 3 modules, got %d: %#v", len(modules), modules)
	}
	if modules[0].Path != "./entry.js" || modules[0].Content != "const a = 1;" {
		t.Errorf("entry module mis-split: %#v", modules[0])
	}
	if modules[1].Content != `fetch("/api/v3");` {
		t.Errorf("middle module mis-split: %q", modules[1].Content)
	}
	if modules[2].Content != "export const noop = () => {};" {
		t.Errorf("last module mis-split: %q", modules[2].Content)
	}
}

// A banner-shaped string inside a module's own source must not be mistaken for
// the next section: matching walks forward from the previous match, in path order.
func TestBeautifiedCodeModulesIgnoresBannerLookalikesInSource(t *testing.T) {
	beautified := &jstangle.BeautifiedCode{
		ModulePaths: []string{"./a.js", "./b.js"},
		Content: "// ===== ./a.js =====\nconst s = \"// ===== ./b.js =====\";\n\n" +
			"// ===== ./b.js =====\nconst real = 2;",
	}
	modules := beautified.Modules()
	if len(modules) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(modules))
	}
	if !strings.Contains(modules[0].Content, `const s =`) {
		t.Errorf("first module lost its body: %q", modules[0].Content)
	}
	if modules[1].Content != "const real = 2;" {
		t.Errorf("second module took the lookalike instead of the real banner: %q", modules[1].Content)
	}
}

func TestBeautifiedCodeModulesReturnsNilForNonBundle(t *testing.T) {
	if modules := (&jstangle.BeautifiedCode{Content: "const a = 1;"}).Modules(); modules != nil {
		t.Errorf("a non-bundle document should not split: %#v", modules)
	}
	var nilCode *jstangle.BeautifiedCode
	if modules := nilCode.Modules(); modules != nil {
		t.Errorf("nil BeautifiedCode should not split: %#v", modules)
	}
}

func TestKitResolveJSInputFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.js")
	if err := os.WriteFile(p, []byte("var x=1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, label, mt, err := kitResolveJSInput(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "var x=1;" || label != p || mt != "application/javascript" {
		t.Errorf("file input resolved wrong: data=%q label=%q mt=%q", data, label, mt)
	}
}
