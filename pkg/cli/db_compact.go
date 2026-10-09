package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var dbCompactCmd = &cobra.Command{
	Use:   "compact",
	Short: "Shrink stored bodies over a size limit to their head, keeping every record",
	Long: "Replace each stored request or response body larger than --body-over with its first --keep-head bytes. " +
		"The record stays: URL, method, status, headers, content type, content length, hashes and timing are untouched, " +
		"and http_records.body_compaction records the original body length and SHA-256. Nothing is deleted, and a body " +
		"already compacted is never compacted again, so repeating a pass is a no-op.\n\n" +
		"Select records with --older-than, --skip-content-type / --only-content-type (globs over the response media type) " +
		"and --skip-path / --only-path (globs over the URL path); a skip glob always wins. With --max-db-size the pass " +
		"compacts the oldest records first and stops once the database would be at or under that size after VACUUM. " +
		"Sizes take a plain byte count or a k/m/g suffix (binary: 64k = 65536). SQLite only. A real pass asks for " +
		"confirmation on a terminal and needs --force otherwise; --dry-run never does.",
	Example: `  vigolium db compact --db traffic.sqlite --dry-run
  vigolium db compact --db traffic.sqlite --older-than 30d --force
  vigolium db compact --db traffic.sqlite --max-db-size 2g --skip-content-type '*javascript*' --skip-path '*.js' --force -j`,
	Args: cobra.NoArgs,
	RunE: runDBCompact,
}

var (
	compactBodyOver         string
	compactKeepHead         string
	compactSkipContentTypes []string
	compactOnlyContentTypes []string
	compactSkipPaths        []string
	compactOnlyPaths        []string
	compactOlderThan        string
	compactMaxDBSize        string
	compactAllProjects      bool
	compactDryRun           bool
	compactNoVacuum         bool
)

func init() {
	dbCmd.AddCommand(dbCompactCmd)

	f := dbCompactCmd.Flags()
	f.StringVar(&compactBodyOver, "body-over", "64k", "Compact a request or response body larger than this size")
	f.StringVar(&compactKeepHead, "keep-head", "4k", "Bytes of each compacted body to keep (must be smaller than --body-over)")
	f.StringSliceVar(&compactSkipContentTypes, "skip-content-type", nil, "Never compact a record whose response media type matches one of these globs (e.g. '*javascript*')")
	f.StringSliceVar(&compactOnlyContentTypes, "only-content-type", nil, "Compact only records whose response media type matches one of these globs (OR'ed with --only-path)")
	f.StringSliceVar(&compactSkipPaths, "skip-path", nil, "Never compact a record whose URL path matches one of these globs (e.g. '*.js')")
	f.StringSliceVar(&compactOnlyPaths, "only-path", nil, "Compact only records whose URL path matches one of these globs (OR'ed with --only-content-type)")
	f.StringVar(&compactOlderThan, "older-than", "", fmt.Sprintf("Compact only records sent strictly before this time — %s", clicommon.TimeFilterSyntax))
	f.StringVar(&compactMaxDBSize, "max-db-size", "", "Size budget: compact the oldest records first until the database is at most this size after VACUUM")
	f.BoolVar(&compactAllProjects, "all-projects", false, "Compact records of every project in the database (default: the active project only)")
	f.BoolVar(&compactDryRun, "dry-run", false, "Report what would be compacted without changing anything")
	f.BoolVar(&compactNoVacuum, "no-vacuum", false, "Skip the VACUUM that returns freed pages to the filesystem")
}

// resolveCompactOptions validates the flags and builds the options. It performs
// no I/O, so a bad command line never opens a writable connection.
func resolveCompactOptions(projectUUID string) (database.CompactOptions, error) {
	opts := database.CompactOptions{
		ProjectUUID:      projectUUID,
		SkipContentTypes: compactSkipContentTypes,
		OnlyContentTypes: compactOnlyContentTypes,
		SkipPaths:        compactSkipPaths,
		OnlyPaths:        compactOnlyPaths,
		DryRun:           compactDryRun,
		Vacuum:           !compactNoVacuum,
	}
	var err error
	if opts.BodyOver, err = parseByteSize(compactBodyOver); err != nil {
		return opts, usageErrorf("invalid --body-over: %v", err)
	}
	if opts.KeepHead, err = parseByteSize(compactKeepHead); err != nil {
		return opts, usageErrorf("invalid --keep-head: %v", err)
	}
	if compactMaxDBSize != "" {
		if opts.MaxDBSize, err = parseByteSize(compactMaxDBSize); err != nil {
			return opts, usageErrorf("invalid --max-db-size: %v", err)
		}
		if opts.MaxDBSize <= 0 {
			return opts, usageErrorf("invalid --max-db-size: must be positive")
		}
	}
	if compactOlderThan != "" {
		// ParseSince, as `db clean --before` uses: "30d" is thirty days ago,
		// and a bare date means that day's midnight, excluding the day itself.
		t, err := clicommon.ParseSince(compactOlderThan)
		if err != nil {
			return opts, usageErrorf("invalid --older-than: %v", err)
		}
		opts.OlderThan = &t
	}
	if err := opts.Validate(); err != nil {
		return opts, usageErrorf("%v", err)
	}
	return opts, nil
}

func runDBCompact(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	projectUUID := ""
	if !compactAllProjects {
		var err error
		if projectUUID, err = resolveProjectUUID(); err != nil {
			return err
		}
	}
	opts, err := resolveCompactOptions(projectUUID)
	if err != nil {
		return err
	}

	// Compaction discards body bytes for good, so a real pass goes through the
	// same gate as every other destructive db command: a prompt on a terminal,
	// --force otherwise. Asked before the database is opened, so a refused
	// command line never takes a write connection. A dry run changes nothing
	// and is not gated.
	if !opts.DryRun {
		if done, err := handleConfirmation(describeCompaction(opts)); done {
			return err
		}
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	started := time.Now()
	sum, err := db.CompactBodies(context.Background(), opts)
	if err != nil {
		if errors.Is(err, database.ErrCompactUnsupported) {
			return usageErrorf("%v (current driver: %s)", err, db.Driver())
		}
		return fmt.Errorf("compaction failed: %w", err)
	}

	if globalJSON {
		env := newAgentEnvelope("db compact", "compaction", sum, 1, 0, 1)
		env.DBPath = clicommon.OpenedDBPath()
		env.WithProjectScope(projectUUID)
		return writeAgentJSON(env)
	}
	printCompactSummary(sum, projectUUID, time.Since(started))
	return nil
}

// describeCompaction is the phrase the confirmation prompt asks about.
func describeCompaction(o database.CompactOptions) string {
	scope := "every project"
	if o.ProjectUUID != "" {
		scope = "project " + o.ProjectUUID
	}
	return fmt.Sprintf("replacing stored bodies over %s with their first %s in %s",
		humanize.IBytes(uint64(o.BodyOver)), humanize.IBytes(uint64(o.KeepHead)), scope)
}

// printCompactSummary is the human rendering. It goes to stderr, like every
// other db maintenance report, so stdout stays clean for -j.
func printCompactSummary(sum *database.CompactSummary, projectUUID string, took time.Duration) {
	scope := "every project"
	if projectUUID != "" {
		scope = "project " + projectUUID
	}
	verb := "Compacted"
	if sum.DryRun {
		verb = "Would compact"
	}
	fmt.Fprintf(os.Stderr, "%s %s %d record(s) in %s: %d response and %d request bodies, %s -> %s of body bytes.\n",
		terminal.InfoSymbol(), verb, sum.RecordsCompacted, scope,
		sum.ResponseBodiesCompacted, sum.RequestBodiesCompacted,
		humanize.IBytes(uint64(sum.BodyBytesBefore)), humanize.IBytes(uint64(sum.BodyBytesAfter)))
	estimated := ""
	if sum.DryRun {
		estimated = " (estimated)"
	}
	fmt.Fprintf(os.Stderr, "  %s Database: %s -> %s%s\n", terminal.InfoSymbol(),
		humanize.IBytes(uint64(sum.DBBytesBefore)), humanize.IBytes(uint64(sum.DBBytesAfter)), estimated)
	if sum.MaxDBSize > 0 {
		state := "met"
		if !sum.BudgetMet {
			state = "NOT met: nothing compactable is left"
		}
		fmt.Fprintf(os.Stderr, "  %s Budget %s: %s\n", terminal.InfoSymbol(),
			humanize.IBytes(uint64(sum.MaxDBSize)), state)
	}
	if sum.Remaining > 0 {
		fmt.Fprintf(os.Stderr, "  %s %d selected record(s) left uncompacted.\n", terminal.InfoSymbol(), sum.Remaining)
	}
	fmt.Fprintf(os.Stderr, "  %s Took %s.\n", terminal.InfoSymbol(), took.Round(time.Millisecond))
}

// byteSizeUnits maps a size suffix to its multiplier. Binary throughout: a body
// limit written "64k" means 65536, the way an operator sizing a buffer means it.
var byteSizeUnits = map[string]int64{
	"": 1, "b": 1,
	"k": 1 << 10, "kb": 1 << 10, "kib": 1 << 10,
	"m": 1 << 20, "mb": 1 << 20, "mib": 1 << 20,
	"g": 1 << 30, "gb": 1 << 30, "gib": 1 << 30,
}

// parseByteSize reads a plain byte count or a number with a k/m/g suffix.
func parseByteSize(raw string) (int64, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9') {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("%q does not start with a number", raw)
	}
	n, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q: %w", raw, err)
	}
	mult, ok := byteSizeUnits[strings.TrimSpace(s[i:])]
	if !ok {
		return 0, fmt.Errorf("%q has an unknown unit (use b, k, m or g)", raw)
	}
	if n > (1<<62)/mult {
		return 0, fmt.Errorf("%q is too large", raw)
	}
	return n * mult, nil
}
