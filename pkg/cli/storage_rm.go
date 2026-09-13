package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var storageRmCmd = &cobra.Command{
	Use:     "rm <key> [<key>...]",
	Aliases: []string{"delete"},
	Short:   "Delete one or more objects from cloud storage",
	Long:    "Permanently delete objects from the active project's storage. Prompts for confirmation unless --force is set.",
	Args:    cobra.MinimumNArgs(1),
	RunE:    runStorageRm,
}

func init() {
	storageCmd.AddCommand(storageRmCmd)
}

func runStorageRm(_ *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	sc, projectUUID, err := openStorageClient()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s Will delete %d object(s) from project %s:\n",
		terminal.WarningSymbol(), len(args), terminal.Cyan(projectUUID))
	for _, key := range args {
		fmt.Fprintf(os.Stderr, "  - %s\n", terminal.Gray(key))
	}

	if done, err := handleConfirmation(fmt.Sprintf("deleting %d stored object(s) from project %s",
		len(args), projectUUID)); done {
		return err
	}

	ctx := context.Background()
	var failures int
	for _, key := range args {
		if err := sc.Delete(ctx, projectUUID, key); err != nil {
			failures++
			fmt.Printf("%s %s: %s\n", terminal.ErrorSymbol(), terminal.Gray(key), err)
			continue
		}
		fmt.Printf("%s Deleted %s\n", terminal.SuccessSymbol(), terminal.Gray(key))
	}

	if failures > 0 {
		return fmt.Errorf("%d of %d deletion(s) failed", failures, len(args))
	}
	return nil
}
