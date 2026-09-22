package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var tmpCleanMaxAge time.Duration

var kitTmpCleanCmd = &cobra.Command{
	Use:   "tmp-clean",
	Short: "Remove vigolium scratch left in the system temp directory",
	Long: `Remove the temporary scratch vigolium left behind in the system temp directory.

Every scan now allocates its scratch under one root and removes the whole thing
on exit, so a run that finishes - or is interrupted - cleans up after itself.
This command is for what is already there: scratch from runs that were killed,
and the loose per-store directories versions before the scratch root allocated
straight into the temp directory.

That backlog can be very large. One workstation had accumulated 71,614 leftover
dedup directories totalling 108 GB, which is also a startup cost: vigolium's own
dependencies sweep the whole temp directory at startup, so the litter made every
invocation slower in proportion to how much of it there was.

Only names vigolium itself allocates are touched, and only entries that have
gone untouched for --max-age, so scratch belonging to a scan running right now
is never taken.

Examples:
  vigolium kit tmp-clean                   # collect scratch idle for 6h or more
  vigolium kit tmp-clean --max-age 0       # collect everything not currently held
  vigolium kit tmp-clean -j                # the same, as JSON`,
	Args: cobra.NoArgs,
	RunE: runKitTmpClean,
}

func init() {
	kitCmd.AddCommand(kitTmpCleanCmd)
	kitTmpCleanCmd.Flags().DurationVar(&tmpCleanMaxAge, "max-age", scratch.DefaultMaxAge,
		"Only remove scratch untouched for at least this long (0 removes everything not held by a running scan)")
}

type kitTmpCleanResult struct {
	TempDir  string `json:"temp_dir"`
	Root     string `json:"scratch_root"`
	Abandnd  int    `json:"abandoned_removed"`
	Legacy   int    `json:"legacy_removed"`
	Total    int    `json:"total_removed"`
	Duration string `json:"duration"`
}

func runKitTmpClean(cmd *cobra.Command, args []string) error {
	started := time.Now()

	// Abandoned process directories first: cheap, and it is the case that
	// recurs. The legacy pass walks the whole temp directory and is the one
	// that can take a while on a large backlog.
	abandoned, err := scratch.SweepRoot(tmpCleanMaxAge)
	if err != nil {
		return fmt.Errorf("could not sweep the scratch root: %w", err)
	}
	legacy, err := scratch.SweepLegacy(tmpCleanMaxAge)
	if err != nil {
		return fmt.Errorf("could not sweep the temp directory: %w", err)
	}

	result := kitTmpCleanResult{
		TempDir:  os.TempDir(),
		Root:     scratch.Root(),
		Abandnd:  abandoned,
		Legacy:   legacy,
		Total:    abandoned + legacy,
		Duration: time.Since(started).Round(time.Millisecond).String(),
	}

	if globalJSON {
		return writeAgentJSON(result)
	}

	fmt.Fprintf(os.Stderr, "  %s Removed %s scratch entr%s from %s %s\n",
		terminal.SuccessSymbol(),
		terminal.Orange(fmt.Sprintf("%d", result.Total)),
		plural(result.Total, "y", "ies"),
		terminal.Cyan(result.TempDir),
		terminal.Gray("in "+result.Duration))
	if result.Total > 0 {
		fmt.Fprintf(os.Stderr, "    %s abandoned by interrupted runs, %s left by versions before the scratch root\n",
			terminal.Orange(fmt.Sprintf("%d", result.Abandnd)),
			terminal.Orange(fmt.Sprintf("%d", result.Legacy)))
	}
	return nil
}
