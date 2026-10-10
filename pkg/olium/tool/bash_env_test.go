package tool

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
)

// TestBashUsesEnvBuilder: with a builder installed, a command sees exactly
// the environment it returns (the CLI pins vigolium's binary, DB, project and
// config through it); without one it inherits the process environment.
func TestBashUsesEnvBuilder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell syntax")
	}
	t.Setenv("B7_INHERITED", "from-process")
	SetBashEnvBuilder(func() []string {
		return []string{"PATH=" + os.Getenv("PATH"), "VIGOLIUM_DB=/tmp/pinned.sqlite"}
	})
	t.Cleanup(func() { SetBashEnvBuilder(nil) })

	res, err := NewBash(nil).Execute(context.Background(), map[string]any{
		"command": `printf '%s|%s' "$VIGOLIUM_DB" "$B7_INHERITED"`,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(res.Content); !strings.HasPrefix(got, "/tmp/pinned.sqlite|") || strings.Contains(got, "from-process") {
		t.Fatalf("output %q: want the builder's env only", got)
	}

	SetBashEnvBuilder(nil)
	res, err = NewBash(nil).Execute(context.Background(), map[string]any{"command": `printf '%s' "$B7_INHERITED"`}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Content, "from-process") {
		t.Fatalf("output %q: without a builder the process env is inherited", res.Content)
	}
}

// TestBashIsNotALoginShell: a login shell's profile can reorder PATH ahead of
// the pinned vigolium; the tool runs `bash -c`.
func TestBashIsNotALoginShell(t *testing.T) {
	if bashFlag != "-c" {
		t.Fatalf("bash flag = %q, want -c", bashFlag)
	}
}
