//go:build unix

package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// feedFIFO creates a named pipe and writes content into it once a reader opens
// it. The cleanup unblocks a writer nobody ever read from.
func feedFIFO(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.fifo")
	require.NoError(t, syscall.Mkfifo(path, 0o600))
	done := make(chan struct{})
	go func() {
		defer close(done)
		w, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		_, _ = w.WriteString(content)
		_ = w.Close()
	}()
	t.Cleanup(func() {
		if r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = r.Close()
		}
		<-done
	})
	return path
}

func TestSpoolPathLeavesRegularFilesAndNonPathsAlone(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "hosts.txt")
	require.NoError(t, os.WriteFile(regular, []byte("https://a.example\n"), 0o600))

	for _, v := range []string{regular, "-", "", "https://a.example/x", "GET / HTTP/1.1"} {
		got, err := spoolPath("target-file", v)
		require.NoError(t, err)
		assert.Equal(t, v, got)
	}
}

func TestSpoolPathCopiesAPipeOnce(t *testing.T) {
	fifo := feedFIFO(t, "https://a.example\nhttps://b.example\n")

	got, err := spoolPath("target-file", fifo)
	require.NoError(t, err)
	require.NotEqual(t, fifo, got)
	data, err := os.ReadFile(got)
	require.NoError(t, err)
	assert.Equal(t, "https://a.example\nhttps://b.example\n", string(data))
	// The spooled copy is re-readable, which is the whole point.
	again, err := os.ReadFile(got)
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

func TestSpoolNonRegularInputsRewritesSliceAndStringFlags(t *testing.T) {
	var files []string
	var input string
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().StringArrayVarP(&files, "target-file", "T", nil, "")
	cmd.Flags().StringVarP(&input, "input", "i", "", "")

	regular := filepath.Join(t.TempDir(), "hosts.txt")
	require.NoError(t, os.WriteFile(regular, []byte("https://r.example\n"), 0o600))
	fifoT := feedFIFO(t, "https://p.example\n")
	fifoI := feedFIFO(t, "GET / HTTP/1.1\r\nHost: p.example\r\n\r\n")
	require.NoError(t, cmd.Flags().Parse([]string{"-T", regular, "-T", fifoT, "-i", fifoI}))

	require.NoError(t, spoolNonRegularInputs(cmd))
	require.Len(t, files, 2)
	assert.Equal(t, regular, files[0], "a regular file is untouched")
	assert.NotEqual(t, fifoT, files[1])
	got, err := os.ReadFile(files[1])
	require.NoError(t, err)
	assert.Equal(t, "https://p.example\n", string(got))
	assert.NotEqual(t, fifoI, input)
	got, err = os.ReadFile(input)
	require.NoError(t, err)
	assert.Contains(t, string(got), "Host: p.example")
}

// runA3WithPipe is runA3 with content already buffered in a pipe the child
// holds as fd 3 — exactly what a shell's `<(printf …)` hands a command as
// /dev/fd/N: the writer has finished before the reader opens it.
func runA3WithPipe(t *testing.T, home, content string, args ...string) (int, string, string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	defer func() { _ = r.Close() }()

	cmd := exec.Command(os.Args[0], "-test.run=^TestScopeAdmissionChild$", "-test.v=false")
	env := []string{a3ChildEnv + "=" + strings.Join(args, "\x1f"), "HOME=" + home, "NO_COLOR=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "VIGOLIUM_") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{r}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	}
	t.Fatalf("run child: %v", err)
	return -1, "", ""
}

// TestTargetFileFromPipeResolves: `-T <(…)` resolves through the dry-run plan,
// with no request sent.
func TestTargetFileFromPipeResolves(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, hits := countingServer(t)
	home := a3Home(t, "*")

	code, stdout, stderr := runA3WithPipe(t, home, srv.URL+"/\n", "run", "probe", "-T", "/dev/fd/3", "--dry-run", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Zero(t, hits.Load(), "a dry run must not contact the target")
	doc := decodeDryRunDoc(t, stdout)
	require.NotNil(t, doc.Plan)
	assert.Equal(t, 1, doc.Plan.Targets.Admitted)
}
