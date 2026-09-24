package skill

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// UnknownAllowedTools reports skills whose allowed-tools frontmatter names a
// tool the run does not expose. The field is advisory guidance handed to the
// model with the skill body (see loadTool.Execute), so a stale name there is
// a silent lie rather than an error: it points the model at a tool that will
// never resolve.
//
// A nil tool registry means "tools unknown" and produces no warnings, so a
// tool-less engine never spams the log.
func UnknownAllowedTools(reg *Registry, tools *tool.Registry) []string {
	if reg == nil || tools == nil {
		return nil
	}
	known := make(map[string]struct{})
	for _, t := range tools.List() {
		known[t.Name()] = struct{}{}
	}
	if len(known) == 0 {
		return nil
	}
	var out []string
	for _, s := range reg.List() {
		var missing []string
		for _, want := range s.AllowedTools {
			want = strings.TrimSpace(want)
			if want == "" {
				continue
			}
			if _, ok := known[want]; !ok {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			out = append(out, fmt.Sprintf("skill: %s declares unknown allowed-tools: %s", s.Name, strings.Join(missing, ", ")))
		}
	}
	return out
}
