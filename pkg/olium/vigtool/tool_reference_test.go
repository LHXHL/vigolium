package vigtool

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// snakeCaseToken matches the shape of a tool name as it appears in prose:
// two or more lowercase/digit segments joined by underscores.
var snakeCaseToken = regexp.MustCompile(`\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b`)

// notToolNames are snake_case tokens that legitimately appear in tool prose
// without naming a tool — parameter names, enum values, wire fields, CLI
// flags. Anything not listed here has to resolve in the registry.
var notToolNames = map[string]bool{
	// Parameters and response fields.
	"record_uuid": true, "scan_uuid": true, "raw_request": true, "script_path": true,
	"script_source": true, "auth_session": true, "session_dir": true, "unique_id": true,
	"target_url": true, "parameter_name": true, "insertion_point": true, "content_type": true,
	"has_params": true, "only_phase": true, "skip_phases": true, "project_uuid": true,
	"module_tag": true, "base_value": true, "dedup_key": true, "source_file": true,
	"cwe_id": true, "false_positive": true, "accepted_risk": true, "save_as": true,
	"http_records": true, "http_record": true, "max_duration": true, "per_record": true,
	"replay_record_uuid": true,
	// Insertion-point types and payload classes.
	"url_param": true, "body_param": true, "json_param": true, "cmd_injection": true,
	"path_traversal": true, "open_redirect": true,
	// Env vars and external commands.
	"agent_browser": true, "session_name": true,
}

// A tool description that names a sibling tool is a promise the model will
// act on: it reads "call replay_request next" as an instruction. When a tool
// is renamed, nothing compiles those mentions, so they rot silently — that is
// exactly how every vigtool description came to advertise `run_scan` for
// months after the tool became `run_native_scan`. This test is the missing
// compiler.
func TestDescriptionsOnlyNameRealTools(t *testing.T) {
	scanCtx := &ScanContext{}
	sessCtx := &SessionsContext{}
	reg := tool.NewRegistry()
	tool.RegisterBuiltins(reg, nil)
	// Every vigtool an autopilot run registers (see autopilot.Run). A new
	// tool added there but not here still gets checked as a *referent*; it
	// just is not scanned itself, so keep this list in step.
	for _, tl := range []tool.Tool{
		NewRunScanTool(scanCtx),
		NewRunModuleTool(scanCtx),
		NewRunExtensionTool(scanCtx),
		NewSendRawHTTPTool(scanCtx),
		NewOASTMintTool(scanCtx),
		NewAttackKitTool(),
		NewListModulesTool(),
		NewListSessionsTool(sessCtx),
		NewGetSessionTool(sessCtx),
		NewListFindingsTool(sessCtx),
		NewUpdateFindingTool(sessCtx),
		NewListAuthSessionsTool(sessCtx),
		NewAuthSessionLookupTool(sessCtx),
		NewQueryRecordsTool(sessCtx),
		NewInspectRecordTool(sessCtx),
		NewSearchBurpItemsTool(sessCtx),
		NewInspectBurpItemTool(sessCtx),
		NewReplayRequestTool(sessCtx),
		NewOASTPollTool(sessCtx),
	} {
		reg.Register(tl)
	}
	// Registered by autopilot itself, not by this package, but referenced from
	// vigtool prose.
	known := map[string]bool{
		"report_finding":    true,
		"propose_candidate": true,
		"halt_scan":         true,
		"load_skill":        true,
		"update_plan":       true,
		"remember":          true,
		"browser_auth":      true,
	}

	for _, tl := range reg.List() {
		known[tl.Name()] = true
	}

	for _, tl := range reg.List() {
		schema, err := json.Marshal(tl.Schema())
		if err != nil {
			t.Fatalf("%s: marshal schema: %v", tl.Name(), err)
		}
		prose := tl.Description() + " " + string(schema)
		for _, token := range snakeCaseToken.FindAllString(prose, -1) {
			if known[token] || notToolNames[token] {
				continue
			}
			// Only flag tokens that look like a tool being recommended, i.e.
			// ones that were a registered tool name at some point. A bare
			// unknown token is far more likely a field name, so require the
			// verb-ish shape vigtool names use.
			if strings.HasPrefix(token, "run_") || strings.HasPrefix(token, "list_") ||
				strings.HasPrefix(token, "get_") || strings.HasPrefix(token, "inspect_") ||
				strings.HasPrefix(token, "query_") || strings.HasPrefix(token, "update_") ||
				strings.HasPrefix(token, "report_") || strings.HasPrefix(token, "search_") ||
				strings.HasPrefix(token, "replay_") || strings.HasPrefix(token, "send_") ||
				strings.HasPrefix(token, "oast_") || strings.HasPrefix(token, "attack_") ||
				strings.HasPrefix(token, "browser_") || strings.HasPrefix(token, "auth_") {
				t.Errorf("%s description/schema names %q, which is not a registered tool — rename it or add it to notToolNames", tl.Name(), token)
			}
		}
	}
}
