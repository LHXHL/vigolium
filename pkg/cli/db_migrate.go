package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var dbMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Upgrade the database schema to this vigolium's version",
	Long: `Bring the database up to the schema this vigolium expects, and report what changed.

Read commands (traffic, finding, log, db ls, ...) open a read-only pool and never
take the write lock. When they meet a store written by an older vigolium they
migrate it first through a short-lived writer, as long as
database.auto_migrate_on_read is true (the default for this release). With it
off they fail with error.code "schema_outdated" and point here.

A store a newer vigolium already migrated is refused with "schema_too_new":
upgrade vigolium instead.`,
	Example: `  vigolium db migrate
  vigolium db migrate --db ./engagement.sqlite -j`,
	Args: cobra.NoArgs,
	RunE: runDBMigrate,
}

func init() {
	dbCmd.AddCommand(dbMigrateCmd)
}

func runDBMigrate(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	cfg, err := clicommon.ResolveDatabaseConfig(globalConfig, globalDB)
	if err != nil {
		return err
	}
	// Migrating a path that is not there would create a new, empty store and
	// report it "migrated" — a typo answered with success.
	if cfg.Driver == "sqlite" {
		path := database.ExpandPath(cfg.SQLite.Path)
		if _, statErr := os.Stat(path); errors.Is(statErr, fs.ErrNotExist) {
			return &clicommon.SourceMissingError{Path: path}
		}
	}

	db, err := database.NewDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() { _ = db.Close() }()

	res, err := db.Migrate(context.Background())
	if err != nil {
		return err
	}

	dbPath := cfg.Driver
	if cfg.Driver == "sqlite" {
		dbPath = database.ExpandPath(cfg.SQLite.Path)
	}

	if globalJSON {
		action := "migrate"
		if res.AlreadyCurrent {
			action = "noop"
		}
		return emitMutation(cmd, "", mutationResult{
			Changed: !res.AlreadyCurrent,
			Action:  action,
			Items:   res,
		}, withDBPath(dbPath))
	}

	if res.AlreadyCurrent {
		fmt.Printf("%s Database schema already current (v%d, min reader v%d): %s\n",
			terminal.SuccessSymbol(), res.ToVersion, res.MinReaderVersion, terminal.ShortenHome(dbPath))
		return nil
	}
	fmt.Printf("%s Database schema migrated v%d → v%d (min reader v%d): %s\n",
		terminal.SuccessSymbol(), res.FromVersion, res.ToVersion, res.MinReaderVersion, terminal.ShortenHome(dbPath))
	fmt.Printf("  applied: %s\n", strings.Join(res.Applied, ", "))
	return nil
}
