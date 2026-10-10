package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/public"
)

// skillBundleDir is the vigolium-scanner bundle inside public.StaticFS.
const skillBundleDir = embedSkillsRoot + "/vigolium-scanner"

// The committed flags.generated.md is what an agent greps to find out what
// exists; a stale copy makes a flag invisible. Rendering in-process replaces
// the `go run … skills gen-flags -o /tmp/…` diff (a full link of the binary and
// a shared /tmp path): `make skill-flags-check` now runs this test.
func TestFlagsGeneratedIsCurrent(t *testing.T) {
	prepareCommandTree(rootCmd)

	committed, err := public.StaticFS.ReadFile(skillBundleDir + "/references/flags.generated.md")
	if err != nil {
		t.Fatalf("read embedded flags.generated.md: %v", err)
	}
	rendered := renderFlagsReference(rootCmd)
	if string(committed) == rendered {
		return
	}

	want := strings.Split(rendered, "\n")
	got := strings.Split(string(committed), "\n")
	var diffs []string
	for i := 0; i < max(len(want), len(got)) && len(diffs) < 10; i++ {
		var w, g string
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w != g {
			diffs = append(diffs, fmt.Sprintf("line %d:\n    committed: %s\n    generated: %s", i+1, g, w))
		}
	}
	t.Errorf("flags.generated.md is stale; run `make skill-flags` and commit the result. First differences:\n  %s",
		strings.Join(diffs, "\n  "))
}

var skillReferenceLink = regexp.MustCompile(`references/([A-Za-z0-9_.-]+\.md)`)

// SKILL.md is the router: every reference file it names must ship, and every
// reference that ships must be reachable from it.
func TestSkillReferenceRouter(t *testing.T) {
	skill, err := public.StaticFS.ReadFile(skillBundleDir + "/SKILL.md")
	if err != nil {
		t.Fatalf("read SKILL.md: %v", err)
	}
	named := map[string]bool{}
	for _, m := range skillReferenceLink.FindAllStringSubmatch(string(skill), -1) {
		named[m[1]] = true
	}

	entries, err := fs.ReadDir(public.StaticFS, skillBundleDir+"/references")
	if err != nil {
		t.Fatalf("read references: %v", err)
	}
	shipped := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			shipped[e.Name()] = true
		}
	}

	for name := range named {
		if !shipped[name] {
			t.Errorf("SKILL.md routes to references/%s, which is not in the embedded bundle", name)
		}
	}
	for name := range shipped {
		if !named[name] {
			t.Errorf("references/%s ships but SKILL.md never routes to it (orphan)", name)
		}
	}

	t.Run("line budget", func(t *testing.T) {
		lines := strings.Count(string(skill), "\n")
		if lines > 300 {
			// TODO(H8): the SKILL.md rewrite cuts it to ~250 lines; make this
			// an error then.
			t.Skipf("SKILL.md is %d lines; budget is 300 (enforced once H8 lands)", lines)
		}
	})

	t.Run("no version-skew narration", func(t *testing.T) {
		// "On older builds …" / "pre-v0.5.2 …" belong in invariants.md#history
		// once the installed skill is version-stamped. TODO(H8): make this an
		// error when that file exists.
		stale := regexp.MustCompile(`(?i)older build|pre-v\d`)
		_ = fs.WalkDir(public.StaticFS, skillBundleDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || path.Base(p) == "invariants.md" {
				return nil
			}
			data, _ := public.StaticFS.ReadFile(p)
			for i, line := range strings.Split(string(data), "\n") {
				if stale.MatchString(line) {
					t.Logf("%s:%d: version-skew narration: %s", p, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
	})
}

// presetConsumers says who reads each directory under public/presets/. A
// directory nothing reads is shipped weight that drifts unnoticed (the deleted
// agents-md preset documented commands that no longer existed). A "code"
// consumer must appear as a literal "presets/<dir>" in Go source; a "docs"
// consumer is example material that README.md or docs/ must point at.
var presetConsumers = map[string]string{
	"extensions": "code",
	"profiles":   "code",
	"prompts":    "code",
	"sessions":   "docs", // auth-file examples, linked from README and the auth guide
	// TODO(H5 follow-up): no loader reads sast-rules and no doc points at it
	// (`vigolium init` says it installs "SAST rules" but never copies them).
	// Wire it into init or delete it.
	"sast-rules": "orphan",
}

func TestNoOrphanPresets(t *testing.T) {
	entries, err := fs.ReadDir(public.StaticFS, "presets")
	if err != nil {
		t.Fatalf("read presets: %v", err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	for _, d := range dirs {
		if _, ok := presetConsumers[d]; !ok {
			t.Errorf("public/presets/%s has no consumer in presetConsumers; wire a loader to it or delete it", d)
		}
	}
	for d := range presetConsumers {
		if !slices.Contains(dirs, d) {
			t.Errorf("presetConsumers names presets/%s, which does not exist", d)
		}
	}

	goSource := readRepoText(t, []string{"../../pkg", "../../internal", "../../cmd"}, ".go")
	docs := readRepoText(t, []string{"../../README.md", "../../docs"}, ".md")
	if goSource == "" {
		t.Skip("repository source not available")
	}
	for d, kind := range presetConsumers {
		needle := "presets/" + d
		switch kind {
		case "code":
			if !strings.Contains(goSource, `"`+needle) {
				t.Errorf("presets/%s is marked code-consumed but no Go source reads %q", d, needle)
			}
		case "docs":
			if docs != "" && !strings.Contains(docs, needle) {
				t.Errorf("presets/%s is marked doc-consumed but README.md/docs never mention %q", d, needle)
			}
		case "orphan":
			if strings.Contains(goSource, `"`+needle) {
				t.Errorf("presets/%s now has a loader; mark it \"code\" in presetConsumers", d)
			}
		}
	}
}

// readRepoText concatenates every file with the suffix under roots (files or
// directories), skipping test files. Missing roots are ignored.
func readRepoText(t *testing.T, roots []string, suffix string) string {
	t.Helper()
	var b strings.Builder
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, suffix) || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			data, readErr := os.ReadFile(p)
			if readErr == nil {
				b.Write(data)
				b.WriteByte('\n')
			}
			return nil
		})
	}
	return b.String()
}
