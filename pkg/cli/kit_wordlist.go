package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var kitWordlistCmd = &cobra.Command{
	Use:   "wordlist [name]",
	Short: "List the built-in wordlists or print one to stdout",
	Long: `List vigolium's embedded wordlists, or print a named list's entries to stdout so
they can be piped into another tool. With no argument (or "list") it prints the
available lists with entry/byte counts.

  vigolium kit wordlist                    # list available wordlists
  vigolium kit wordlist -j                 # the same, as JSON
  vigolium kit wordlist fuzz               # print the fuzz list to stdout
  vigolium kit wordlist jwt > jwt.txt      # materialize a list to a file

A name matches the embedded filename, its basename without extension, or a short
alias (e.g. "jwt" for jwt.secrets.list).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runKitWordlist,
}

func init() {
	kitCmd.AddCommand(kitWordlistCmd)
}

type kitWordlistInfo struct {
	Name    string `json:"name"`
	Entries int    `json:"entries"`
	Bytes   int    `json:"bytes"`
}

type kitWordlistCatResult struct {
	Name    string   `json:"name"`
	Count   int      `json:"count"`
	Entries []string `json:"entries"`
}

func runKitWordlist(cmd *cobra.Command, args []string) error {
	names, err := listEmbeddedWordlists()
	if err != nil {
		return err
	}

	// No argument (or the literal "list") → inventory.
	if len(args) == 0 || strings.EqualFold(args[0], "list") {
		return printKitWordlistIndex(names)
	}

	file, ok := resolveWordlistName(args[0], names)
	if !ok {
		return usageErrorf("unknown wordlist %q (available: %s)", args[0], strings.Join(names, ", "))
	}
	data, err := wordlists.ReadList(file)
	if err != nil {
		return err
	}

	if globalJSON {
		entries := splitWordlistEntries(data)
		return writeAgentJSON(kitWordlistCatResult{Name: file, Count: len(entries), Entries: entries})
	}
	// Print raw bytes verbatim so redirection reproduces the list exactly.
	_, werr := os.Stdout.Write(data)
	if werr == nil && len(data) > 0 && data[len(data)-1] != '\n' {
		fmt.Println()
	}
	return werr
}

func printKitWordlistIndex(names []string) error {
	infos := make([]kitWordlistInfo, 0, len(names))
	for _, n := range names {
		data, err := wordlists.ReadList(n)
		if err != nil {
			continue
		}
		infos = append(infos, kitWordlistInfo{Name: n, Entries: len(splitWordlistEntries(data)), Bytes: len(data)})
	}
	if globalJSON {
		return writeAgentJSON(struct {
			Wordlists []kitWordlistInfo `json:"wordlists"`
		}{infos})
	}
	for _, in := range infos {
		fmt.Printf("%s\t%d entries\t%d bytes\n", terminal.Bold(in.Name), in.Entries, in.Bytes)
	}
	return nil
}

// listEmbeddedWordlists returns the sorted names of the embedded wordlists.
// Gzip-embedded lists appear under their decompressed name; read them with
// wordlists.ReadList.
func listEmbeddedWordlists() ([]string, error) {
	return wordlists.ListNames()
}

// resolveBuiltinWordlist reports whether name refers to an embedded wordlist and
// returns its filename. Convenience wrapper over listEmbeddedWordlists +
// resolveWordlistName, shared by `kit jwt-crack -w`.
func resolveBuiltinWordlist(name string) (string, bool) {
	names, err := listEmbeddedWordlists()
	if err != nil {
		return "", false
	}
	return resolveWordlistName(name, names)
}

// resolveWordlistName maps a user-supplied name to an embedded filename. It
// accepts the exact filename, the basename with any single extension stripped,
// or the "jwt" alias for jwt.secrets.list.
func resolveWordlistName(name string, available []string) (string, bool) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "jwt" {
		name = "jwt.secrets"
	}
	for _, f := range available {
		if strings.EqualFold(f, name) {
			return f, true
		}
		if strings.EqualFold(strings.TrimSuffix(f, filepath.Ext(f)), name) {
			return f, true
		}
	}
	return "", false
}

// splitWordlistEntries returns the non-empty, non-comment lines of a wordlist.
func splitWordlistEntries(data []byte) []string {
	var out []string
	sc := kitLineScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
