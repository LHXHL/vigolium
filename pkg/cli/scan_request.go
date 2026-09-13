package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// scan-request flags
var (
	scanReqInput  string
	scanReqTarget string
)

var scanRequestCmd = &cobra.Command{
	Use:   "scan-request",
	Short: "Scan a raw HTTP request for vulnerabilities",
	Long: `Read a raw HTTP request from file or stdin and run scanner modules against it.
Designed for pipeline integration and AI agent workflows.
Accepts raw HTTP requests, curl commands, and supports format auto-detection.`,
	Args: cobra.NoArgs,
	RunE: runScanRequestCmd,
}

func init() {
	rootCmd.AddCommand(scanRequestCmd)
	flags := scanRequestCmd.Flags()

	flags.StringVarP(&scanReqInput, "input", "i", "-", "Input file or - for stdin")
	flags.StringVarP(&scanReqTarget, "target", "t", "", "Override target URL (scheme://host)")
	flags.BoolVar(&scanURLNoPassive, "no-passive", false, "Skip passive modules")
	registerScanModuleFlags(flags)
	registerModuleSelectionFlags(flags)
	registerHTTPClientFlags(flags)
	registerPhaseFlags(flags)
	registerLightweightScanIOFlags(flags)
}

func runScanRequestCmd(_ *cobra.Command, _ []string) error {
	defer syncLogger()

	if err := resetFailOnGate(); err != nil {
		return err
	}
	if err := validateModuleSelectionFlags(scanURLNoPassive); err != nil {
		return err
	}
	// Validate --format before any network activity so an unknown format (or
	// fs/sqlite) fails fast instead of being silently ignored on the direct path.
	if err := validateGlobalFormats(); err != nil {
		return err
	}

	// Read raw HTTP request
	var raw []byte
	var err error

	if scanReqInput == "-" {
		raw, err = readStdin()
	} else {
		raw, err = os.ReadFile(scanReqInput)
	}
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	rawStr := strings.TrimSpace(string(raw))
	if rawStr == "" {
		return fmt.Errorf("empty request input")
	}

	// Detect format and parse request
	var rr *httpmsg.HttpRequestResponse
	detected := detect.DetectStdinFormat(rawStr)
	if detected == detect.FormatCurl {
		// Curl command detected — parse via curl parser
		items, parseErr := detect.ParseStdinContent(rawStr, detect.FormatCurl)
		if parseErr != nil {
			return fmt.Errorf("failed to parse curl command: %w", parseErr)
		}
		rr = items[0]
	} else {
		// Raw HTTP (or fallback) — use existing raw HTTP parser
		if scanReqTarget != "" {
			rr, err = httpmsg.ParseRawRequestWithURL(rawStr, scanReqTarget)
		} else {
			rr, err = httpmsg.ParseRawRequest(rawStr)
		}
		if err != nil {
			return fmt.Errorf("failed to parse raw request: %w", err)
		}
		if scanReqTarget == "" {
			// No -t override: the request line carries no scheme, so the scheme
			// was inferred. Surface how it was resolved (and how to override with
			// -t) so an http service on a non-standard port isn't silently hit
			// over https.
			warnInferredRequestScheme(rawStr, rr)
		}
	}

	// Extract method and target for output
	method := rr.Request().Method()
	target := rr.Target()

	// Route through the Runner when output/persistence/phase flags are in play;
	// otherwise take the fast in-memory direct path.
	return withFailOnGate(dispatchSingleScan(rr, target, method))
}

// warnInferredRequestScheme emits a heads-up when the scheme of a raw request had
// to be inferred (no scheme on the request line, no -t override) and the Host
// port is non-standard, so the choice is genuinely ambiguous. It names the
// resolved target, the signal used (a same-origin Origin/Referer header or the
// https default), and the -t flag to pin it explicitly. A well-known port
// (80/443) unambiguously fixes the scheme, so nothing is printed there.
func warnInferredRequestScheme(raw string, rr *httpmsg.HttpRequestResponse) {
	if rr == nil {
		return
	}
	svc := rr.Service()
	if svc == nil {
		return
	}
	// An absolute-form request line already carries the scheme — no inference.
	if requestLineHasScheme(raw) {
		return
	}
	port := svc.Port()
	if port == 80 || port == 443 {
		return
	}
	host := svc.Host()
	authority := fmt.Sprintf("%s:%d", host, port)
	target := rr.Target()
	if s, header, ok := httpmsg.OriginRefererScheme(raw, host, port); ok {
		fmt.Fprintf(os.Stderr, "%s request line has no scheme — inferred %s from the %s header; sending to %s\n",
			terminal.WarnPrefix(), terminal.BoldYellow(s+"://"), header, terminal.Cyan(target))
		fmt.Fprintf(os.Stderr, "  pass %s to pin the scheme (use %s to force TLS)\n",
			terminal.BoldCyan("-t "+s+"://"+authority), terminal.Cyan("https://"))
		return
	}
	fmt.Fprintf(os.Stderr, "%s request line has no scheme and no Origin/Referer to infer from — defaulting to %s; sending to %s\n",
		terminal.WarnPrefix(), terminal.BoldYellow("https://"), terminal.Cyan(target))
	fmt.Fprintf(os.Stderr, "  if the target is plain http, pass %s\n",
		terminal.BoldCyan("-t http://"+authority))
}

// requestLineHasScheme reports whether the request line uses absolute-form (an
// explicit http(s):// on the request target), in which case the scheme is
// already pinned and needs no inference.
func requestLineHasScheme(raw string) bool {
	line := raw
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	target := strings.ToLower(fields[1])
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}
