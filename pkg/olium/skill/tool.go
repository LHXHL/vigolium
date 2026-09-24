package skill

import (
	"context"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// NewLoadTool returns the load_skill tool, bound to reg. The tool serves
// skill bodies from the in-memory registry — which is necessary for
// embedded skills (whose "paths" point inside the binary's embed FS and
// aren't reachable via read_file) and desirable for disk-based skills
// (the registry already parsed them once at startup).
// tools, when non-nil, filters each skill's advisory allowed-tools line down
// to the tools this run actually exposes, so a stale frontmatter entry never
// points the model at something it cannot call.
func NewLoadTool(reg *Registry, tools *tool.Registry) tool.Tool {
	return &loadTool{reg: reg, tools: tools}
}

type loadTool struct {
	reg   *Registry
	tools *tool.Registry
}

// callableTools returns the subset of want that this run exposes, preserving
// the author's order. A nil registry means "tools unknown" — pass through
// rather than silently blanking the line.
func (t *loadTool) callableTools(want []string) []string {
	if t.tools == nil {
		return want
	}
	known := make(map[string]struct{})
	for _, reg := range t.tools.List() {
		known[reg.Name()] = struct{}{}
	}
	out := make([]string, 0, len(want))
	for _, name := range want {
		if _, ok := known[strings.TrimSpace(name)]; ok {
			out = append(out, name)
		}
	}
	return out
}

func (*loadTool) Name() string     { return "load_skill" }
func (*loadTool) Label() string    { return "Load skill" }
func (*loadTool) Category() string { return tool.CategoryBuiltin }
func (*loadTool) IsReadOnly() bool { return true }
func (*loadTool) Description() string {
	return "Fetch a skill's full body text by name. Use this for any skill listed in <available_skills>; prefer it over read_file, since embedded skills don't have filesystem paths and disk-based skills are already parsed into memory."
}

func (*loadTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "The skill name as listed in <available_skills> (e.g. 'audit-auth').",
			},
		},
		"required": []string{"name"},
	}
}

func (t *loadTool) Execute(_ context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	rawName, _ := args["name"].(string)
	name := strings.TrimSpace(rawName)
	if name == "" {
		return tool.Result{
			Content: "load_skill: name is required",
			IsError: true,
		}, nil
	}
	if t.reg == nil {
		return tool.Result{
			Content: fmt.Sprintf("load_skill: no skill registry available (requested %q)", name),
			IsError: true,
		}, nil
	}
	s := t.reg.Get(name)
	if s == nil {
		available := skillNames(t.reg)
		return tool.Result{
			Content: fmt.Sprintf("load_skill: unknown skill %q. Available: %s", name, strings.Join(available, ", ")),
			IsError: true,
		}, nil
	}
	// Frame the body so the model treats it as instructional input rather
	// than something to quote verbatim in its reply.
	var b strings.Builder
	fmt.Fprintf(&b, "<skill name=\"%s\" source=\"%s\">\n", s.Name, s.Source)
	b.WriteString(s.Body)
	if !strings.HasSuffix(s.Body, "\n") {
		b.WriteByte('\n')
	}
	// A skill's allowed-tools frontmatter used to be parsed and then dropped,
	// so an author's declaration reached nobody. Surfacing it with the body
	// makes it steer the tools the model reaches for while it follows the
	// skill; it is guidance, not a sandbox — the registry is not narrowed.
	expects := t.callableTools(s.AllowedTools)
	if len(expects) > 0 {
		fmt.Fprintf(&b, "\nTools this skill expects to use: %s. Anything outside that list is probably a sign you have left the skill's workflow.\n", strings.Join(expects, ", "))
	}
	b.WriteString("</skill>")
	details := map[string]any{
		"skill":  s.Name,
		"source": string(s.Source),
		"bytes":  len(s.Body),
	}
	if len(expects) > 0 {
		details["allowed_tools"] = expects
	}
	return tool.Result{Content: b.String(), Details: details}, nil
}

func skillNames(reg *Registry) []string {
	all := reg.List()
	names := make([]string, 0, len(all))
	for _, s := range all {
		names = append(names, s.Name)
	}
	return names
}
