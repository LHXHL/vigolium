package authentication

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/utils/yamlschema"
	"gopkg.in/yaml.v3"
)

// parse.go is the ONE reader of session files. `scan --auth-file`
// (LoadFromAuthFiles), `auth load` and `auth lint` all go through
// ParseSessionDocument, so a file one of them accepts the others accept too.
// They used to have three parsers that disagreed: lint read only the
// `sessions:` bundle, so a valid single-session file failed lint; load read the
// bundle or the agent format but not a single session; the scan loader read a
// bundle or a single session but not the agent format. None of the three
// noticed a misspelt key, so `extarct:` silently produced a session with no
// extract rules.

// SessionForm names which accepted document shape a session file used.
type SessionForm string

const (
	// FormBundle is `sessions: [...]`.
	FormBundle SessionForm = "bundle"
	// FormSingle is one session at the top level (name, role, login, ...).
	FormSingle SessionForm = "single"
	// FormAgent is the agent's session-config.json: a bundle written by a model,
	// decoded leniently (status as strings, group as a string).
	FormAgent SessionForm = "agent"
)

// ParseOptions tunes ParseSessionDocument.
type ParseOptions struct {
	// Strict reports unknown fields as errors (auth lint). Otherwise they are
	// warnings, so an existing file with an extra key keeps loading.
	Strict bool
	// Agent forces the lenient agent session-config.json decoder (auth load
	// --agent-format, or a path that names an agent session file).
	Agent bool
	// KeepEnvRefs leaves ${ENV} references unexpanded, for a caller that
	// writes the sessions back to a file another loader expands (expanding
	// twice would mangle a value containing '$').
	KeepEnvRefs bool
}

// SessionDocument is a parsed session file.
type SessionDocument struct {
	Form     SessionForm
	Sessions []*Session
	// Issues are what parsing itself found: unknown fields, with line/column.
	// Semantic problems come from Lint.
	Issues []LintIssue

	// positions maps a field path (sessions[0].login.url) to where its key sits
	// in the source, so a semantic lint issue can name a line too.
	positions map[string]filePos
}

type filePos struct{ line, column int }

// ParseError is a session file that could not be decoded at all. Line is 0
// when the decoder did not say where.
type ParseError struct {
	File   string
	Line   int
	Column int
	Err    error
}

func (e *ParseError) Error() string {
	where := e.File
	if where == "" {
		where = "session file"
	}
	if e.Line > 0 {
		where = fmt.Sprintf("%s:%d", where, e.Line)
		if e.Column > 0 {
			where = fmt.Sprintf("%s:%d", where, e.Column)
		}
	}
	return fmt.Sprintf("failed to parse %s: %v", where, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// ParseSessionBytes parses a session file in any accepted form and returns its
// sessions plus the parse-level issues (unknown fields). name is the file path
// or a label such as "<stdin>"; a .json suffix selects JSON, otherwise the
// content is sniffed. ${ENV} references are expanded first.
//
// A file that defines no session is an error here (a loader has nothing to
// load); ParseSessionDocument returns it as an empty document for lint.
func ParseSessionBytes(content []byte, name string, opt ParseOptions) ([]*Session, []LintIssue, error) {
	doc, err := ParseSessionDocument(content, name, opt)
	if err != nil {
		return nil, nil, err
	}
	if len(doc.Sessions) == 0 {
		return nil, doc.Issues, fmt.Errorf("%s: no sessions defined (expected a `sessions:` list or one session with a name at the top level)", labelOf(name))
	}
	return doc.Sessions, doc.Issues, nil
}

// ParseSessionDocument is ParseSessionBytes without the "at least one session"
// rule, and with the form and source positions kept for Lint.
func ParseSessionDocument(content []byte, name string, opt ParseOptions) (*SessionDocument, error) {
	text := string(content)
	if !opt.KeepEnvRefs {
		text = os.ExpandEnv(text)
	}
	if strings.TrimSpace(text) == "" {
		return nil, &ParseError{File: name, Err: errors.New("file is empty")}
	}
	asJSON := isJSON(name, text)

	if opt.Agent {
		sessions, err := decodeAgentSessions(text)
		if err != nil {
			return nil, &ParseError{File: name, Err: err}
		}
		return &SessionDocument{Form: FormAgent, Sessions: sessions}, nil
	}

	doc := &SessionDocument{positions: map[string]filePos{}}

	// The node tree gives every key its line and column, for YAML and for JSON
	// alike (JSON is YAML flow syntax). It is also what the unknown-field walk
	// runs over, which reports every unknown key rather than only the first.
	var root yaml.Node
	nodeErr := yaml.Unmarshal([]byte(text), &root)
	if nodeErr != nil && !asJSON {
		line := yamlErrorLine(nodeErr)
		return nil, &ParseError{File: name, Line: line, Err: nodeErr}
	}

	var top *yaml.Node
	if nodeErr == nil {
		top = documentRoot(&root)
		if top == nil {
			return nil, &ParseError{File: name, Err: errors.New("file has no content (only comments?)")}
		}
	}
	form, err := detectForm(top, text, asJSON)
	if err != nil {
		return nil, &ParseError{File: name, Err: err}
	}
	doc.Form = form

	var target any
	var bundle SessionConfig
	var single Session
	if form == FormBundle {
		target = &bundle
	} else {
		target = &single
	}

	severity := "warning"
	if opt.Strict {
		severity = "error"
	}
	if top != nil {
		walkOpts := yamlschema.Options{CaseFold: asJSON, MapKeys: true}
		yamlschema.Walk(top, reflect.TypeOf(target).Elem(), "", walkOpts, func(path string, key *yaml.Node, known []string) {
			doc.positions[path] = filePos{key.Line, key.Column}
			if known == nil {
				return
			}
			msg := fmt.Sprintf("unknown field %q", key.Value)
			if s := yamlschema.Closest(key.Value, known, 2); s != "" {
				msg += fmt.Sprintf(" (did you mean %q?)", s)
			}
			doc.Issues = append(doc.Issues, LintIssue{
				Field: path, Severity: severity, Message: msg,
				Line: key.Line, Column: key.Column,
			})
		})
	} else if asJSON {
		// The node parse failed on JSON yaml.v3 cannot read: fall back to the
		// JSON decoder's own strictness, which names the first unknown key only
		// and gives no position.
		dec := json.NewDecoder(strings.NewReader(text))
		dec.DisallowUnknownFields()
		if strictErr := dec.Decode(target); strictErr != nil {
			if field, ok := strings.CutPrefix(strictErr.Error(), "json: unknown field "); ok {
				doc.Issues = append(doc.Issues, LintIssue{
					Field: strings.Trim(field, `"`), Severity: severity,
					Message: "unknown field " + field,
				})
			}
		}
		// Reset: a failed strict decode may have filled target partially.
		bundle, single = SessionConfig{}, Session{}
	}

	var decodeErr error
	if asJSON {
		decodeErr = json.Unmarshal([]byte(text), target)
	} else {
		decodeErr = top.Decode(target)
	}
	if decodeErr != nil {
		// A bundle that the native types reject may be an agent-written
		// session-config.json, whose decoder accepts "200" for 200.
		if asJSON && form == FormBundle {
			if sessions, agentErr := decodeAgentSessions(text); agentErr == nil {
				doc.Form = FormAgent
				doc.Sessions = sessions
				return doc, nil
			}
		}
		line, col := decodeErrorPos(decodeErr, text)
		return nil, &ParseError{File: name, Line: line, Column: col, Err: decodeErr}
	}

	if form == FormBundle {
		doc.Sessions = make([]*Session, len(bundle.Sessions))
		for i := range bundle.Sessions {
			doc.Sessions[i] = &bundle.Sessions[i]
		}
	} else if !isZeroSession(&single) {
		doc.Sessions = []*Session{&single}
	}
	return doc, nil
}

// Lint runs the semantic checks over the document's sessions (field paths
// follow its form: sessions[0].login.url for a bundle, login.url for a single
// session) and attaches source positions where the field, or its nearest
// present parent, appears in the file. Parse-level Issues are not included.
func (d *SessionDocument) Lint() []LintIssue {
	var issues []LintIssue
	if d.Form == FormSingle {
		if len(d.Sessions) == 0 {
			issues = []LintIssue{{Severity: "error", Message: "no session defined"}}
		} else {
			issues = lintSession(d.Sessions[0], "")
		}
	} else {
		cfg := SessionConfig{Sessions: make([]Session, len(d.Sessions))}
		for i, s := range d.Sessions {
			cfg.Sessions[i] = *s
		}
		issues = LintSessionConfig(&cfg)
	}
	for i := range issues {
		if issues[i].Line == 0 {
			if p, ok := d.lookupPos(issues[i].Field); ok {
				issues[i].Line, issues[i].Column = p.line, p.column
			}
		}
	}
	return issues
}

// lookupPos finds the position of path, or of its nearest ancestor present in
// the file: a missing login.url points at login.
func (d *SessionDocument) lookupPos(path string) (filePos, bool) {
	for path != "" {
		if p, ok := d.positions[path]; ok {
			return p, true
		}
		cut := strings.LastIndexAny(path, ".[")
		if cut <= 0 {
			break
		}
		path = path[:cut]
	}
	return filePos{}, false
}

// detectForm decides bundle vs single from the top-level keys. A mapping with
// `sessions` is a bundle; one with any session key is a single session.
func detectForm(top *yaml.Node, text string, asJSON bool) (SessionForm, error) {
	var keys []string
	if top != nil {
		if top.Kind != yaml.MappingNode {
			return "", fmt.Errorf("expected a mapping at the top level (a `sessions:` list or one session), got %s", nodeKindName(top))
		}
		for i := 0; i+1 < len(top.Content); i += 2 {
			keys = append(keys, top.Content[i].Value)
		}
	} else {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			return "", err
		}
		for k := range m {
			keys = append(keys, k)
		}
	}
	match := func(want string) bool {
		for _, k := range keys {
			if k == want || (asJSON && strings.EqualFold(k, want)) {
				return true
			}
		}
		return false
	}
	if match("sessions") {
		return FormBundle, nil
	}
	for _, k := range []string{"name", "role", "headers", "login", "login_request", "check", "reauth"} {
		if match(k) {
			return FormSingle, nil
		}
	}
	return "", errors.New("no sessions defined (expected a `sessions:` list or one session with a name at the top level)")
}

// decodeAgentSessions reads an agent session-config.json. The agent types are
// lenient where a model's output is sloppy ("200" for 200), and their JSON
// shape is the native bundle's, so the decoded value is re-encoded and read as
// a native bundle rather than mapped field by field a second time (the agent
// package's own converter cannot be called from here: it imports this one).
func decodeAgentSessions(text string) ([]*Session, error) {
	var cfg agenttypes.AgentSessionConfig
	if err := json.Unmarshal([]byte(text), &cfg); err != nil {
		return nil, fmt.Errorf("agent session config: %w", err)
	}
	if len(cfg.Sessions) == 0 {
		return nil, errors.New("no sessions found in agent config")
	}
	// Same rule as agent/authsession.AgentSessionConfigToSessions: a garbled
	// role ("comparelocalhost:3000/...") is model noise, not a session.
	kept := cfg.Sessions[:0]
	for _, e := range cfg.Sessions {
		if e.Role == "" || e.Role == string(RolePrimary) || e.Role == string(RoleCompare) {
			kept = append(kept, e)
		}
	}
	cfg.Sessions = kept
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var native SessionConfig
	if err := json.Unmarshal(raw, &native); err != nil {
		return nil, fmt.Errorf("agent session config: %w", err)
	}
	if len(native.Sessions) == 0 {
		return nil, errors.New("no sessions with a valid role in agent config")
	}
	sessions := make([]*Session, len(native.Sessions))
	hasPrimary := false
	for i := range native.Sessions {
		sessions[i] = &native.Sessions[i]
		hasPrimary = hasPrimary || sessions[i].Role == RolePrimary
	}
	if !hasPrimary {
		sessions[0].Role = RolePrimary
	}
	return sessions, nil
}

func documentRoot(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		return n.Content[0]
	}
	if n.Kind == 0 {
		return nil
	}
	return n
}

func nodeKindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		return "a scalar"
	default:
		return "something else"
	}
}

func isZeroSession(s *Session) bool {
	return s.Name == "" && s.Role == "" && len(s.Headers) == 0 && s.Login == nil && s.LoginRequest == "" &&
		s.Check == nil && s.Reauth == nil
}

func labelOf(name string) string {
	if name == "" {
		return "session file"
	}
	return name
}

var yamlLineRe = regexp.MustCompile(`line (\d+)`)

// yamlErrorLine pulls the first "line N" out of a yaml.v3 error, which carries
// its position only in the message.
func yamlErrorLine(err error) int {
	if m := yamlLineRe.FindStringSubmatch(err.Error()); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// decodeErrorPos locates a decode error: the JSON decoder reports a byte
// offset, the YAML decoder a line in its message.
func decodeErrorPos(err error, text string) (line, col int) {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return offsetToLineCol(text, syn.Offset)
	case errors.As(err, &typ):
		return offsetToLineCol(text, typ.Offset)
	}
	return yamlErrorLine(err), 0
}

func offsetToLineCol(text string, off int64) (int, int) {
	if off < 0 || off > int64(len(text)) {
		return 0, 0
	}
	before := []byte(text[:off])
	line := bytes.Count(before, []byte("\n")) + 1
	col := int(off) - bytes.LastIndexByte(before, '\n')
	return line, col
}
