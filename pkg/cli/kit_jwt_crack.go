package cli

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/modules/shared/jwtutil"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	kitJWTWordlist    string
	kitJWTSecrets     []string
	kitJWTFailOnCrack bool
)

var kitJWTCrackCmd = &cobra.Command{
	Use:   "jwt-crack [token|-]",
	Short: "Recover a JWT's HMAC signing secret from a wordlist",
	Long: `Brute-force the HMAC signing secret of a JWT (HS256/384/512) against a wordlist.
For a token that declares an asymmetric algorithm (RS*/ES*/PS*) every HMAC
variant is tried — the algorithm-confusion attack — and the match is labelled
accordingly. The token is a positional argument, or '-'/no argument for stdin;
a leading "Bearer " is stripped.

  vigolium kit jwt-crack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...
  echo "$TOKEN" | vigolium kit jwt-crack -
  vigolium kit jwt-crack -w /path/rockyou.txt -p s3cr3t eyJ...
  vigolium kit jwt-crack -j --fail-on-crack eyJ...

Default candidates come from the embedded jwt.secrets.list; -w overrides with a
built-in name or a file path, and -p adds inline candidates. The recovered
secret is printed in full (it is the whole point of the operation).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runKitJWTCrack,
}

func init() {
	f := kitJWTCrackCmd.Flags()
	f.StringVarP(&kitJWTWordlist, "wordlist", "w", "", "Wordlist: a built-in name (see `kit wordlist`) or a file path (default: embedded jwt.secrets.list)")
	f.StringArrayVarP(&kitJWTSecrets, "secret", "p", nil, "Additional inline candidate secret (repeatable)")
	f.BoolVar(&kitJWTFailOnCrack, "fail-on-crack", false, "Exit 3 when the secret is recovered (for CI/agent gating)")
	kitCmd.AddCommand(kitJWTCrackCmd)
}

type kitJWTCrackResult struct {
	Alg             string         `json:"alg"`
	Cracked         bool           `json:"cracked"`
	Secret          string         `json:"secret,omitempty"`
	MatchedAlg      string         `json:"matched_alg,omitempty"`
	CandidatesTried int            `json:"candidates_tried"`
	Wordlist        string         `json:"wordlist"`
	Header          map[string]any `json:"header,omitempty"`
	Payload         map[string]any `json:"payload,omitempty"`
}

func runKitJWTCrack(cmd *cobra.Command, args []string) error {
	arg := "-"
	if len(args) == 1 {
		arg = args[0]
	}
	token, err := kitReadJWT(arg)
	if err != nil {
		return err
	}
	if !jwtutil.IsJWT(token) {
		return fmt.Errorf("input is not a well-formed JWT (need three base64url segments)")
	}

	secrets, wlLabel, err := kitLoadJWTCandidates()
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		return fmt.Errorf("no candidate secrets to try (empty wordlist and no -p)")
	}

	header, payload, _ := jwtutil.Decode(token)
	alg, _ := header["alg"].(string)

	secret, matchedAlg, ok := jwtutil.CrackHMAC(token, secrets)
	res := kitJWTCrackResult{
		Alg:             alg,
		Cracked:         ok,
		CandidatesTried: len(secrets),
		Wordlist:        wlLabel,
		Header:          header,
		Payload:         payload,
	}
	if ok {
		res.Secret = secret
		res.MatchedAlg = matchedAlg
	}

	if globalJSON {
		if err := writeAgentJSON(res); err != nil {
			return err
		}
	} else if ok {
		fmt.Printf("%s secret recovered: %s\n", terminal.Bold("[cracked]"), secret)
		fmt.Fprintf(os.Stderr, "%s alg=%s matched=%s (%d candidates)\n",
			terminal.InfoSymbol(), alg, matchedAlg, len(secrets))
	} else {
		fmt.Fprintf(os.Stderr, "%s not cracked: alg=%s, %d candidate(s) from %s\n",
			terminal.WarningSymbol(), alg, len(secrets), wlLabel)
	}

	if kitJWTFailOnCrack && ok {
		os.Exit(ExitFuzzMatch)
	}
	return nil
}

// kitReadJWT reads a token from an argument or stdin, trims whitespace, and
// strips a leading "Bearer " scheme.
func kitReadJWT(arg string) (string, error) {
	var raw string
	if arg == "" || arg == "-" {
		data, _, err := kitReadInput("-")
		if err != nil {
			return "", err
		}
		raw = string(data)
	} else {
		raw = arg
	}
	raw = strings.TrimSpace(raw)
	if f := strings.Fields(raw); len(f) == 2 && strings.EqualFold(f[0], "Bearer") {
		raw = f[1]
	}
	return raw, nil
}

// kitLoadJWTCandidates builds the candidate secret list from the wordlist (a
// built-in name, a file path, or the embedded jwt.secrets.list default) plus any
// inline -p secrets. The returned label describes the wordlist source.
func kitLoadJWTCandidates() (secrets [][]byte, label string, err error) {
	var data []byte
	if kitJWTWordlist == "" {
		data, err = wordlists.WordlistsFS.ReadFile("jwt.secrets.list")
		label = "builtin:jwt.secrets.list"
	} else if file, ok := resolveBuiltinWordlist(kitJWTWordlist); ok {
		data, err = wordlists.WordlistsFS.ReadFile(file)
		label = "builtin:" + file
	} else {
		data, err = os.ReadFile(kitJWTWordlist)
		label = kitJWTWordlist
	}
	if err != nil {
		return nil, label, fmt.Errorf("loading wordlist %q: %w", label, err)
	}

	sc := kitLineScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		cand := make([]byte, len(line))
		copy(cand, line)
		secrets = append(secrets, cand)
	}
	if serr := sc.Err(); serr != nil {
		return nil, label, serr
	}
	for _, s := range kitJWTSecrets {
		secrets = append(secrets, []byte(s))
	}
	return secrets, label, nil
}
