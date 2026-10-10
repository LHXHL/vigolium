package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/terminal"
)

const totpPeriod = 30

// defaultTOTPSecretEnv is read when no secret source is named.
const defaultTOTPSecretEnv = "VIGOLIUM_TOTP_SECRET"

var (
	totpSecret     string
	totpSecretEnv  string
	totpSecretFile string
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication management utilities",
	Long:  "Manage authentication configurations and helpers used by scans (cookie/header/login flows). Subcommands list, load, and lint auth config files, and a totp helper generates RFC 6238 codes for 2FA flows.",
}

var sessionTotpCmd = &cobra.Command{
	Use:   "totp",
	Short: "Generate a TOTP code from a base32 secret",
	Long: `Generate a time-based one-time password (RFC 6238) from a base32-encoded secret.
Useful for automating 2FA login flows during authenticated scanning.

The secret is read from, in order of preference:
  --secret-env NAME   an environment variable (default ` + defaultTOTPSecretEnv + `)
  --secret-file PATH  a file (surrounding whitespace ignored)
  --secret -          stdin
--secret VALUE still works but puts the secret in the process list and shell
history, so it prints a warning. Name at most one source; with none,
$` + defaultTOTPSecretEnv + ` is used.

Prints the code alone. With -j: {code, expires_in, period, secret_source} as
the envelope's single item.`,
	RunE: runSessionTotp,
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(sessionTotpCmd)
	sessionTotpCmd.Flags().StringVar(&totpSecret, "secret", "", "Base32 TOTP secret, or - to read it from stdin (a literal value is visible in the process list; prefer --secret-env/--secret-file)")
	sessionTotpCmd.Flags().StringVar(&totpSecretEnv, "secret-env", defaultTOTPSecretEnv, "Environment variable holding the base32 TOTP secret")
	sessionTotpCmd.Flags().StringVar(&totpSecretFile, "secret-file", "", "File holding the base32 TOTP secret")
}

// totpResult is the -j item.
type totpResult struct {
	Code      string `json:"code"`
	ExpiresIn int    `json:"expires_in"`
	Period    int    `json:"period"`
	// SecretSource names where the secret came from (env:NAME, file:PATH,
	// stdin, argv), never the secret.
	SecretSource string `json:"secret_source"`
}

func runSessionTotp(cmd *cobra.Command, _ []string) error {
	secret, source, err := resolveTOTPSecret(cmd)
	if err != nil {
		return err
	}

	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		return usageErrorf("invalid TOTP secret from %s: %v", source, err)
	}
	expiresIn := totpPeriod - int(now.Unix()%int64(totpPeriod))

	if globalJSON {
		return emitObject(cmd, ".", totpResult{
			Code:         code,
			ExpiresIn:    expiresIn,
			Period:       totpPeriod,
			SecretSource: source,
		})
	}
	fmt.Println(code)
	return nil
}

// resolveTOTPSecret reads the secret from the one source the caller named, or
// from the default environment variable when none was named. It returns the
// normalised secret (spaces removed, upper-cased, as authenticator apps display
// it) and a description of its source.
func resolveTOTPSecret(cmd *cobra.Command) (secret, source string, err error) {
	flags := cmd.Flags()
	var named []string
	for _, f := range []string{"secret", "secret-file", "secret-env"} {
		if flags.Changed(f) {
			named = append(named, "--"+f)
		}
	}
	if len(named) > 1 {
		return "", "", usageErrorf("name one TOTP secret source, got %s", strings.Join(named, " and "))
	}

	var raw string
	switch {
	case flags.Changed("secret") && totpSecret == "-":
		data, readErr := readStdin()
		if readErr != nil {
			return "", "", fmt.Errorf("failed to read TOTP secret from stdin: %w", readErr)
		}
		raw, source = string(data), "stdin"
	case flags.Changed("secret"):
		fmt.Fprintf(os.Stderr, "%s --secret VALUE puts the TOTP secret in the process list and shell history; prefer --secret-env, --secret-file or --secret -\n",
			terminal.WarningSymbol())
		raw, source = totpSecret, "argv"
	case flags.Changed("secret-file"):
		data, readErr := os.ReadFile(totpSecretFile)
		if readErr != nil {
			return "", "", fmt.Errorf("failed to read TOTP secret file: %w", readErr)
		}
		raw, source = string(data), "file:"+totpSecretFile
	default:
		name := totpSecretEnv
		if name == "" {
			return "", "", usageErrorf("--secret-env needs a variable name")
		}
		raw, source = os.Getenv(name), "env:"+name
	}

	secret = strings.ToUpper(strings.Join(strings.Fields(raw), ""))
	if secret == "" {
		if source == "env:"+defaultTOTPSecretEnv && !flags.Changed("secret-env") {
			return "", "", usageErrorf("no TOTP secret: set %s, or pass --secret-env NAME, --secret-file PATH or --secret - (stdin)", defaultTOTPSecretEnv)
		}
		return "", "", usageErrorf("no TOTP secret in %s", source)
	}
	return secret, source, nil
}
