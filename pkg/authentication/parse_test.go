package authentication

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const singleYAML = `name: admin
role: primary
login:
  url: https://example.com/login
  method: POST
  type: bearer
  token_path: .token
`

func TestParseSessionBytes_SingleSession(t *testing.T) {
	sessions, issues, err := ParseSessionBytes([]byte(singleYAML), "admin.yaml", ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("unexpected issues: %+v", issues)
	}
	if len(sessions) != 1 || sessions[0].Name != "admin" || sessions[0].Login == nil {
		t.Fatalf("sessions = %+v", sessions)
	}

	doc, err := ParseSessionDocument([]byte(singleYAML), "admin.yaml", ParseOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Form != FormSingle {
		t.Errorf("form = %q, want single", doc.Form)
	}
	if lint := doc.Lint(); len(lint) != 0 {
		t.Errorf("a valid single-session file should lint clean, got %+v", lint)
	}
}

const typoYAML = `sessions:
  - name: admin
    role: primary
    login:
      url: https://example.com/login
      method: POST
      extarct:
        - source: cookie
`

func TestParseSessionDocument_UnknownFieldStrict(t *testing.T) {
	doc, err := ParseSessionDocument([]byte(typoYAML), "s.yaml", ParseOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Issues) != 1 {
		t.Fatalf("issues = %+v, want one", doc.Issues)
	}
	is := doc.Issues[0]
	if is.Severity != "error" || is.Field != "sessions[0].login.extarct" || is.Line != 7 || is.Column != 7 {
		t.Errorf("issue = %+v, want error at sessions[0].login.extarct line 7 col 7", is)
	}
	if !strings.Contains(is.Message, `did you mean "extract"`) {
		t.Errorf("message should suggest the real field: %q", is.Message)
	}
	// The typo means no extract rules: lint says so too, positioned at login.
	var found bool
	for _, l := range doc.Lint() {
		if l.Field == "sessions[0].login.extract" && l.Severity == "error" {
			found = true
			if l.Line != 4 {
				t.Errorf("missing extract should point at login (line 4), got line %d", l.Line)
			}
		}
	}
	if !found {
		t.Errorf("lint did not report the missing extract: %+v", doc.Lint())
	}
}

func TestParseSessionBytes_UnknownFieldIsWarningForLoaders(t *testing.T) {
	sessions, issues, err := ParseSessionBytes([]byte(typoYAML), "s.yaml", ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d", len(sessions))
	}
	if len(issues) != 1 || issues[0].Severity != "warning" {
		t.Errorf("issues = %+v, want one warning", issues)
	}
}

func TestParseSessionDocument_JSONUnknownFieldWithLine(t *testing.T) {
	content := "{\n  \"sessions\": [\n    {\n      \"name\": \"a\",\n      \"headerz\": {\"X\": \"1\"}\n    }\n  ]\n}\n"
	doc, err := ParseSessionDocument([]byte(content), "s.json", ParseOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Issues) != 1 || doc.Issues[0].Field != "sessions[0].headerz" || doc.Issues[0].Line != 5 {
		t.Fatalf("issues = %+v, want headerz at line 5", doc.Issues)
	}
}

// JSON keys match case-insensitively, as encoding/json decodes them: not
// unknown.
func TestParseSessionDocument_JSONCaseInsensitive(t *testing.T) {
	doc, err := ParseSessionDocument([]byte(`{"Sessions":[{"Name":"a","Headers":{"X":"1"}}]}`), "s.json", ParseOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Issues) != 0 || len(doc.Sessions) != 1 || doc.Sessions[0].Name != "a" {
		t.Fatalf("doc = %+v", doc)
	}
}

// An agent session-config.json carries "200" for 200; the native decoder
// refuses it, the sniffed agent decoder accepts it.
func TestParseSessionDocument_SniffsAgentFormat(t *testing.T) {
	content := `{"sessions":[{"name":"a","role":"compare","login":{"url":"https://x/login","method":"POST","type":"cookie","expect":{"status":["200"]}}},{"name":"junk","role":"comparelocalhost:3000"}]}`
	doc, err := ParseSessionDocument([]byte(content), "session-config.json", ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Form != FormAgent {
		t.Errorf("form = %q, want agent", doc.Form)
	}
	if len(doc.Sessions) != 1 {
		t.Fatalf("garbled-role entry should be dropped: %+v", doc.Sessions)
	}
	s := doc.Sessions[0]
	if s.Role != RolePrimary {
		t.Errorf("sole agent session should be promoted to primary, got %q", s.Role)
	}
	if s.Login == nil || s.Login.Expect == nil || len(s.Login.Expect.Status) != 1 || s.Login.Expect.Status[0] != 200 {
		t.Errorf("lenient status not decoded: %+v", s.Login)
	}

	forced, err := ParseSessionDocument([]byte(`{"sessions":[{"name":"b","role":"primary","headers":{"X":"1"}}]}`), "x.json", ParseOptions{Agent: true})
	if err != nil || forced.Form != FormAgent || len(forced.Sessions) != 1 {
		t.Fatalf("forced agent: %+v %v", forced, err)
	}
}

func TestParseSessionDocument_Errors(t *testing.T) {
	for name, tc := range map[string]struct {
		content, file string
		line          int
	}{
		"empty":          {"  \n", "s.yaml", 0},
		"bad yaml":       {"name: a\nrole: x\nheaders: {X: 1\n", "s.yaml", -1},
		"type mismatch":  {"sessions:\n  - name: a\n    login:\n      expect:\n        status: abc\n", "s.yaml", 5},
		"no sessions":    {"foo: bar\n", "s.yaml", 0},
		"bad json":       {"{\"sessions\": [\n  {\"name\": }\n]}", "s.json", 2},
		"top-level list": {"- a\n- b\n", "s.yaml", 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSessionDocument([]byte(tc.content), tc.file, ParseOptions{Strict: true})
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("want *ParseError, got %v", err)
			}
			if tc.line < 0 && pe.Line > 0 {
				return // located; yaml.v3 decides which line
			}
			if pe.Line != tc.line {
				t.Errorf("line = %d, want %d (%v)", pe.Line, tc.line, err)
			}
		})
	}
}

func TestParseSessionBytes_EmptyBundleIsAnError(t *testing.T) {
	if _, _, err := ParseSessionBytes([]byte("sessions: []\n"), "s.yaml", ParseOptions{}); err == nil {
		t.Fatal("a bundle with no sessions should not load")
	}
	doc, err := ParseSessionDocument([]byte("sessions: []\n"), "s.yaml", ParseOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if lint := doc.Lint(); len(lint) == 0 || lint[0].Message != "no sessions defined" {
		t.Errorf("lint should report no sessions: %+v", lint)
	}
}

func TestParseSessionBytes_ExpandsEnv(t *testing.T) {
	t.Setenv("G2_TEST_TOKEN", "secret-tok")
	sessions, _, err := ParseSessionBytes([]byte("name: a\nheaders:\n  Authorization: Bearer ${G2_TEST_TOKEN}\n"), "a.yaml", ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sessions[0].Headers["Authorization"] != "Bearer secret-tok" {
		t.Errorf("headers = %v", sessions[0].Headers)
	}
}

// The scan loader reads the agent format and warns (does not fail) on an
// unknown field.
func TestLoadFromAuthFiles_AgentFormatAndUnknownField(t *testing.T) {
	dir := t.TempDir()
	agentFile := filepath.Join(dir, "session-config.json")
	if err := os.WriteFile(agentFile, []byte(`{"sessions":[{"name":"a","role":"primary","login":{"url":"https://x/login","method":"POST","type":"cookie","expect":{"status":"200"}}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	typo := filepath.Join(dir, "typo.yaml")
	if err := os.WriteFile(typo, []byte("name: b\nheaders:\n  X: y\ncolour: red\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessions, err := LoadFromAuthFiles([]string{agentFile, typo}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 || sessions[0].Name != "a" || sessions[1].Name != "b" {
		t.Fatalf("sessions = %+v", sessions)
	}
}
