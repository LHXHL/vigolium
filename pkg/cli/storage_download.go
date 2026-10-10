package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var storageDownloadCmd = &cobra.Command{
	Use:     "download <key>",
	Aliases: []string{"get"},
	Short:   "Download an object from cloud storage",
	Long:    "Download an object from the active project's storage by full key (e.g. ugc/foo.tar.gz). Streams to stdout by default; use -o to write to a file.",
	Args:    cobra.ExactArgs(1),
	RunE:    runStorageDownload,
}

func init() {
	storageDownloadCmd.Flags().StringP("output", "o", "", "Write to this file instead of stdout")
	storageCmd.AddCommand(storageDownloadCmd)
}

func runStorageDownload(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	key := args[0]
	output, _ := cmd.Flags().GetString("output")
	// Without -o the object's bytes ARE stdout, so a -j document has nowhere to
	// go: two protocols on one stream. Refused before anything is fetched.
	if globalJSON && output == "" {
		return usageErrorf("storage download -j needs -o <file>: without it the object's bytes are written to stdout")
	}

	sc, projectUUID, err := openStorageClient()
	if err != nil {
		return err
	}

	if output != "" {
		if err := sc.DownloadToFile(context.Background(), projectUUID, key, output); err != nil {
			return err
		}
		abs, _ := filepath.Abs(output)
		fmt.Fprintf(os.Stderr, "%s Downloaded %s → %s\n",
			terminal.SuccessSymbol(), terminal.Cyan(key), terminal.Gray(abs))
		if globalJSON {
			// The bytes went to the file; stdout carries the receipt.
			view := storageObjectView{Key: key, Path: abs}
			if fi, statErr := os.Stat(abs); statErr == nil {
				view.Size = fi.Size()
			}
			return emitObject(cmd, ".", view, withProjectScope(projectUUID))
		}
		return nil
	}

	reader, err := sc.Download(context.Background(), projectUUID, key)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	_, err = io.Copy(os.Stdout, reader)
	return err
}
