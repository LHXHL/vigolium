package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const testTOTPSecret = "JBSWY3DPEHPK3PXP"

// newTOTPCmd returns the real `auth totp` command with its flags reset to
// their defaults and args parsed, so Changed() reflects only this case (the
// command's flags are process state).
func newTOTPCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	// Only this command's own flags: Flags() also holds the inherited
	// persistent ones (--json), which the test sets itself.
	reset := func() {
		for _, name := range []string{"secret", "secret-env", "secret-file"} {
			f := sessionTotpCmd.Flags().Lookup(name)
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	}
	reset()
	t.Cleanup(reset)
	require.NoError(t, sessionTotpCmd.ParseFlags(args))
	return sessionTotpCmd
}

func wantCode(t *testing.T, got string) {
	t.Helper()
	// Tolerate a period boundary between our call and the command's.
	now := time.Now()
	a, _ := totp.GenerateCode(testTOTPSecret, now)
	b, _ := totp.GenerateCode(testTOTPSecret, now.Add(-time.Duration(totpPeriod)*time.Second))
	require.Contains(t, []string{a, b}, got)
}

func TestTOTP_DefaultEnv(t *testing.T) {
	withMachineDocumentState(t)
	t.Setenv(defaultTOTPSecretEnv, testTOTPSecret)
	cmd := newTOTPCmd(t)
	var err error
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() { err = runSessionTotp(cmd, nil) })
	})
	require.NoError(t, err)
	code := strings.TrimSpace(stdout)
	require.Regexp(t, regexp.MustCompile(`^\d{6}$`), code, "human mode prints the code alone")
	wantCode(t, code)
	require.Empty(t, stderr, "no warning for an environment secret")
}

func TestTOTP_NamedEnvAndFileAndStdin(t *testing.T) {
	withMachineDocumentState(t)
	t.Setenv("G2_OTHER_TOTP", "jbsw y3dp ehpk 3pxp") // as an authenticator app shows it

	_, source, err := resolveTOTPSecret(newTOTPCmd(t, "--secret-env", "G2_OTHER_TOTP"))
	require.NoError(t, err)
	require.Equal(t, "env:G2_OTHER_TOTP", source)

	f := filepath.Join(t.TempDir(), "totp.txt")
	require.NoError(t, os.WriteFile(f, []byte(testTOTPSecret+"\n"), 0o600))
	secret, source, err := resolveTOTPSecret(newTOTPCmd(t, "--secret-file", f))
	require.NoError(t, err)
	require.Equal(t, testTOTPSecret, secret)
	require.Equal(t, "file:"+f, source)

	w := withPipedStdin(t)
	_, _ = w.WriteString(testTOTPSecret + "\n")
	_ = w.Close()
	secret, source, err = resolveTOTPSecret(newTOTPCmd(t, "--secret", "-"))
	require.NoError(t, err)
	require.Equal(t, testTOTPSecret, secret)
	require.Equal(t, "stdin", source)
}

func TestTOTP_ArgvWarns(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true
	cmd := newTOTPCmd(t, "--secret", testTOTPSecret)
	var err error
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() { err = runSessionTotp(cmd, nil) })
	})
	require.NoError(t, err)
	require.Contains(t, stderr, "process list")
	require.NotContains(t, stderr, testTOTPSecret, "the warning must not echo the secret")

	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1)
	require.Equal(t, "auth totp", docs[0]["command"])
	require.Equal(t, "read", docs[0]["kind"])
	items := docs[0]["items"].([]any)
	require.Len(t, items, 1)
	item := items[0].(map[string]any)
	wantCode(t, item["code"].(string))
	require.Equal(t, "argv", item["secret_source"])
	require.EqualValues(t, totpPeriod, item["period"])
	require.NotContains(t, stdout, testTOTPSecret)
}

func TestTOTP_SourceErrors(t *testing.T) {
	withMachineDocumentState(t)
	t.Setenv(defaultTOTPSecretEnv, "")

	_, _, err := resolveTOTPSecret(newTOTPCmd(t))
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))
	require.Contains(t, err.Error(), defaultTOTPSecretEnv)

	_, _, err = resolveTOTPSecret(newTOTPCmd(t, "--secret", "X", "--secret-file", "/nope"))
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))

	t.Setenv(defaultTOTPSecretEnv, "not base32 !!")
	err = runSessionTotp(newTOTPCmd(t), nil)
	require.Error(t, err)
	require.Equal(t, ExitUsageError, classifyExitCode(err))
}
