package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/audit/bin"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// runListModes prints the embedded vigolium-audit binary's mode graph. audit
// owns the canonical graph, so shelling out keeps `--list-modes` in lock-step
// with whatever audit ships rather than re-rendering (which would drift).
//
// Human output streams audit's own `list` text verbatim. Under -j the
// binary's NDJSON (`list --json`, one mode per line) is parsed into the rows
// of a read envelope, so `--list-modes -j` is one document like every other
// -j answer rather than a passthrough stream.
func runListModes(cmd *cobra.Command, jsonOut bool) error {
	binPath, err := bin.Path()
	if err != nil {
		return fmt.Errorf("vigolium-audit binary not embedded — run `make build-audit` and rebuild vigolium: %w", err)
	}

	if jsonOut {
		var out bytes.Buffer
		c := exec.CommandContext(context.Background(), binPath, "list", "--json")
		c.Stdout = &out
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("audit list failed: %w", err)
		}
		modes, err := parseListModesNDJSON(out.Bytes())
		if err != nil {
			return err
		}
		return emitRead(cmd, "modes", modes, int64(len(modes)), 0, len(modes),
			withExtra("piolium_modes", pioliumListModes))
	}

	c := exec.CommandContext(context.Background(), binPath, "list")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("audit list failed: %w", err)
	}
	_, _ = fmt.Fprintln(os.Stdout)
	_, _ = fmt.Fprintln(os.Stdout, "Note: this is audit's mode graph. piolium (driver=piolium) supports")
	_, _ = fmt.Fprintln(os.Stdout, strings.Join(pioliumListModes, ", ")+" — it does")
	_, _ = fmt.Fprintln(os.Stdout, "not support reinvest/mock/refresh. With --modes on driver=auto/both,")
	_, _ = fmt.Fprintln(os.Stdout, "modes a driver can't run are skipped on that driver's leg.")
	return nil
}

// pioliumListModes are the modes the piolium driver runs (the note under the
// human table; a field of the -j document).
var pioliumListModes = []string{"lite", "balanced", "deep", "revisit", "confirm", "merge", "diff", "longshot"}

// parseListModesNDJSON parses `vigolium-audit list --json`: one JSON object
// per line. A single JSON array is accepted too, should audit ever switch.
func parseListModesNDJSON(raw []byte) ([]map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	modes := []map[string]any{}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &modes); err != nil {
			return nil, fmt.Errorf("audit list --json: %w", err)
		}
		return modes, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, fmt.Errorf("audit list --json: line %q: %w", truncateForError(string(line)), err)
		}
		modes = append(modes, m)
	}
	return modes, sc.Err()
}

func truncateForError(s string) string {
	if len(s) > 80 {
		return textutil.TruncateUTF8(s, 80) + "…"
	}
	return s
}
