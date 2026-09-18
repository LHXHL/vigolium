package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// parseErr runs the command's flag parser over args and returns whatever
// FlagErrorFunc produced, mirroring the real cobra execute() path.
func parseErr(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()
	err := cmd.ParseFlags(args)
	if err == nil {
		return nil
	}
	return cmd.FlagErrorFunc()(cmd, err)
}

func TestFlagErrorFuncSuggestsClosestFlag(t *testing.T) {
	newCmd := func() *cobra.Command {
		c := &cobra.Command{Use: "scan-url"}
		c.SetFlagErrorFunc(flagErrorFunc)
		c.Flags().StringSlice("modules", nil, "")
		c.Flags().Bool("verbose", false, "")
		c.Flags().Bool("stateless", false, "")
		hidden := "secret"
		c.Flags().String(hidden, "", "")
		_ = c.Flags().MarkHidden(hidden)
		return c
	}

	cases := []struct {
		name       string
		args       []string
		wantSuggst string // substring the hint must contain, "" = no hint
	}{
		{"long typo", []string{"--module", "xss"}, "Did you mean --modules?"},
		{"inherited-style flag typo", []string{"--verbos"}, "Did you mean --verbose?"},
		{"no close match", []string{"--xyzzy", "1"}, ""},
		{"exact flag ok", []string{"--verbose"}, ""},
		{"never suggests a hidden flag", []string{"--secre"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseErr(t, newCmd(), tc.args...)
			if tc.name == "exact flag ok" {
				if err != nil {
					t.Fatalf("valid flag returned error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a flag error for %v", tc.args)
			}
			msg := err.Error()
			if tc.wantSuggst == "" {
				if strings.Contains(msg, "Did you mean") {
					t.Fatalf("expected no suggestion, got: %q", msg)
				}
				return
			}
			if !strings.Contains(msg, tc.wantSuggst) {
				t.Fatalf("expected suggestion %q in error, got: %q", tc.wantSuggst, msg)
			}
		})
	}
}

// A mistyped shorthand must not crash and must not fabricate a long-flag
// suggestion — it carries a shortname group, not a long name.
func TestFlagErrorFuncIgnoresShorthand(t *testing.T) {
	c := &cobra.Command{Use: "scan-url"}
	c.SetFlagErrorFunc(flagErrorFunc)
	c.Flags().StringSliceP("modules", "m", nil, "")

	err := parseErr(t, c, "-Q")
	if err == nil {
		t.Fatal("expected an unknown-shorthand error")
	}
	if strings.Contains(err.Error(), "Did you mean") {
		t.Fatalf("shorthand error should not carry a long-flag suggestion: %q", err.Error())
	}
	// Sanity: it really was the shorthand error type.
	var notExist *pflag.NotExistError
	if !errors.As(err, &notExist) {
		t.Fatalf("expected a pflag.NotExistError, got %T", err)
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"module", "module", 0},
		{"module", "modules", 1},
		{"modul", "modules", 2},
		{"", "abc", 3},
		{"abc", "", 3},
		{"kitten", "sitting", 3},
	}
	for _, tc := range cases {
		if got := levenshtein(tc.a, tc.b); got != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestSuggestionBudgetRejectsUnrelatedShortFlags is the regression.
//
// `vigolium traffic --url https://…` was answered with "Did you mean --all?".
// Three characters, edit distance two: under the old max(2, len/3) floor that
// counted as a typo. It is not one — --all lifts the -n result cap, so a caller
// who took the hint would get every stored record back and no indication that
// they had asked a different question than they meant to.
func TestSuggestionBudgetRejectsUnrelatedShortFlags(t *testing.T) {
	cases := []struct {
		typed string
		want  int
	}{
		// Short names must match within one edit.
		{"url", 1},
		{"all", 1},
		{"host", 1},
		{"limit", 1},
		// Longer ones can afford a third of their length.
		{"modules", 2},
		{"full-body", 3},
	}
	for _, tc := range cases {
		if got := suggestionBudget(tc.typed); got != tc.want {
			t.Errorf("suggestionBudget(%q) = %d, want %d", tc.typed, got, tc.want)
		}
	}

	// levenshtein("url", "all") is 2, which must now exceed the budget.
	if d := levenshtein("url", "all"); d <= suggestionBudget("url") {
		t.Errorf("--url is still within suggestion range of --all (distance %d)", d)
	}
}

func TestFlagErrorFuncDoesNotSuggestAllForURL(t *testing.T) {
	c := &cobra.Command{Use: "traffic"}
	c.SetFlagErrorFunc(flagErrorFunc)
	c.Flags().Bool("all", false, "")
	c.Flags().String("host", "", "")
	c.Flags().Int("limit", 100, "")

	err := parseErr(t, c, "--url", "https://example.invalid/")
	if err == nil {
		t.Fatal("expected an unknown-flag error")
	}
	msg := err.Error()
	if strings.Contains(msg, "Did you mean") {
		t.Errorf("a flag with no near-miss must not be guessed at, got: %q", msg)
	}
	// A dead end is not an improvement either: say where the answer lives.
	if !strings.Contains(msg, "--help") {
		t.Errorf("expected a pointer to the command's help, got: %q", msg)
	}
}

// Real typos must keep working; the tightened budget is not allowed to turn
// every near-miss into a dead end.
func TestFlagErrorFuncStillCatchesRealTypos(t *testing.T) {
	c := &cobra.Command{Use: "traffic"}
	c.SetFlagErrorFunc(flagErrorFunc)
	c.Flags().String("host", "", "")
	c.Flags().Bool("full-body", false, "")

	for _, tc := range []struct{ typed, want string }{
		{"--hosts", "Did you mean --host?"},
		{"--full-bod", "Did you mean --full-body?"},
	} {
		err := parseErr(t, c, tc.typed, "x")
		if err == nil {
			t.Fatalf("expected an error for %s", tc.typed)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: expected %q, got %q", tc.typed, tc.want, err.Error())
		}
	}
}
