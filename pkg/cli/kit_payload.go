package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/payloads"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	kitPayloadClasses []string
	kitPayloadList    bool
)

var kitPayloadCmd = &cobra.Command{
	Use:   "payload",
	Short: "Emit built-in payload sets by vulnerability class",
	Long: `Print vigolium's built-in fuzzing payloads for one or more vulnerability classes,
one per line — the same catalog that backs 'vigolium fuzz --class' and the JS
extension API. With --list (or no flags) it prints the available class names.

  vigolium kit payload --list                  # list classes
  vigolium kit payload --class sqli            # SQLi payloads
  vigolium kit payload --class sqli,xss -j     # two classes, as JSON

Class names accept aliases (e.g. "sql"→sqli, "traversal"→path_traversal). This
is a payload source, not a scanner: it makes no request and no decision.`,
	RunE: runKitPayload,
}

func init() {
	f := kitPayloadCmd.Flags()
	f.StringSliceVarP(&kitPayloadClasses, "class", "c", nil, "Vulnerability class(es), comma-separated (see --list)")
	f.BoolVar(&kitPayloadList, "list", false, "List available payload classes")
	kitCmd.AddCommand(kitPayloadCmd)
}

func runKitPayload(cmd *cobra.Command, args []string) error {
	classes := payloads.Classes()

	if kitPayloadList || len(kitPayloadClasses) == 0 {
		if globalJSON {
			return writeAgentJSON(struct {
				Classes []string `json:"classes"`
			}{classes})
		}
		fmt.Fprintf(os.Stderr, "%s %d payload classes:\n", terminal.InfoSymbol(), len(classes))
		for _, c := range classes {
			list, _ := payloads.ByClass(c)
			fmt.Printf("%s\t%d payloads\n", terminal.Bold(c), len(list))
		}
		return nil
	}

	var out []string
	seen := make(map[string]bool)
	var used []string
	for _, c := range kitPayloadClasses {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		list, ok := payloads.ByClass(c)
		if !ok {
			return usageErrorf("unknown payload class %q (available: %s)", c, strings.Join(classes, ", "))
		}
		used = append(used, c)
		for _, p := range list {
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}

	if globalJSON {
		return writeAgentJSON(struct {
			Classes  []string `json:"classes"`
			Count    int      `json:"count"`
			Payloads []string `json:"payloads"`
		}{used, len(out), out})
	}
	for _, p := range out {
		fmt.Println(p)
	}
	fmt.Fprintf(os.Stderr, "\n%s %d payload(s) from %s\n", terminal.InfoSymbol(), len(out), strings.Join(used, ", "))
	return nil
}
