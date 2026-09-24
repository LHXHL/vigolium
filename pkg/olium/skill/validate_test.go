package skill

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

type fakeTool struct{ name string }

func (f fakeTool) Name() string           { return f.name }
func (f fakeTool) Label() string          { return f.name }
func (f fakeTool) Description() string    { return "" }
func (f fakeTool) Schema() map[string]any { return map[string]any{"type": "object"} }
func (f fakeTool) Category() string       { return tool.CategoryBuiltin }
func (f fakeTool) IsReadOnly() bool       { return true }
func (f fakeTool) Execute(_ context.Context, _ map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	return tool.Result{}, nil
}

func TestUnknownAllowedTools(t *testing.T) {
	reg := &Registry{
		skills: map[string]*Skill{
			"good":  {Name: "good", AllowedTools: []string{"read_file", "run_native_scan"}},
			"stale": {Name: "stale", AllowedTools: []string{"run_scan", "read_file"}},
		},
		order: []string{"good", "stale"},
	}
	tools := tool.NewRegistry()
	tools.Register(fakeTool{name: "read_file"})
	tools.Register(fakeTool{name: "run_native_scan"})

	got := UnknownAllowedTools(reg, tools)
	if len(got) != 1 {
		t.Fatalf("want 1 warning, got %d: %v", len(got), got)
	}
	if want := "skill: stale declares unknown allowed-tools: run_scan"; got[0] != want {
		t.Errorf("warning = %q, want %q", got[0], want)
	}

	// No registry means "tools unknown", not "every declaration is stale".
	if got := UnknownAllowedTools(reg, nil); got != nil {
		t.Errorf("want no warnings without a tool registry, got %v", got)
	}
}
