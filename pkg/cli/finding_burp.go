package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// findingRepeaterWarnThreshold is the selected-finding count above which
// --to-repeater warns about Burp's 30-tabs-per-minute cap.
const findingRepeaterWarnThreshold = 20

// pushFindingsToBurp hands each selected finding's evidence request (and, where
// available, its response) to Burp for manual confirmation. With --send-via-burp,
// Burp re-issues the request and stores the fresh response. This is a triage
// handoff: it never runs the scanner or emits findings.
//
// --push-to-burp and --to-repeater are INDEPENDENT destinations, exactly as they
// are on `vigolium replay`: one invocation can file a finding in the Organizer
// and open it in Repeater. They used to be mutually exclusive here and composable
// there — the same conceptual operation with two different rules, which is one
// rule too many for a consumer to remember. --to-repeater alone still means
// "Repeater only", so no existing command line changes meaning.
func pushFindingsToBurp(ctx context.Context, db *database.DB, findings []*database.Finding) error {
	if strings.TrimSpace(findingBurpBridgeURL) == "" {
		return fmt.Errorf("--push-to-burp/--to-repeater require --burp-bridge-url")
	}
	httpMode, err := burpbridge.ParseHTTPMode(findingHTTPMode)
	if err != nil {
		return fmt.Errorf("--http-mode: %w", err)
	}
	if findingHTTPMode != "" && !findingSendViaBurp {
		fmt.Fprintf(os.Stderr, "%s --http-mode only applies with --send-via-burp; ignoring\n", terminal.WarningSymbol())
	}
	validated, err := burpbridge.ValidateURL(findingBurpBridgeURL)
	if err != nil {
		return fmt.Errorf("--burp-bridge-url: %w", err)
	}
	client, err := burpbridge.New(validated)
	if err != nil {
		return err
	}
	if _, err := preflightBridge(ctx, client, findingSendViaBurp); err != nil {
		return err
	}

	// Neither flag set cannot happen (the caller gates on one of them); with only
	// --to-repeater, Repeater is the sole destination, which preserves the old
	// meaning of that flag on its own.
	toOrganizer := findingPushToBurp || !findingToRepeater

	var destinations []string
	if toOrganizer {
		destinations = append(destinations, "Organizer")
	}
	if findingToRepeater {
		destinations = append(destinations, "Repeater")
		if len(findings) > findingRepeaterWarnThreshold {
			fmt.Fprintf(os.Stderr, "%s %d findings selected — Burp caps Repeater at 30 tabs/min; consider --push-to-burp (Organizer) alone for a large batch\n",
				terminal.WarningSymbol(), len(findings))
		}
	}
	destination := strings.Join(destinations, " + ")

	byUUID := batchLoadFindingRecords(ctx, db, findings)
	pushed, skipped, failed := 0, 0, 0
	for _, f := range findings {
		req, resp, url := findingPushEvidence(f, byUUID)
		if len(req) == 0 || url == "" {
			skipped++
			continue
		}
		if err := pushOneFinding(ctx, client, f, req, resp, url, toOrganizer, findingToRepeater, httpMode); err != nil {
			failed++
			if failed <= 10 {
				fmt.Fprintf(os.Stderr, "%s finding #%d: %v\n", terminal.WarningSymbol(), f.ID, err)
			}
			continue
		}
		pushed++
	}

	if globalJSON {
		env := newAgentEnvelope("finding --push-to-burp", "", nil, int64(pushed), 0, len(findings))
		env.With("destinations", destinations).
			With("pushed_to_burp", pushed).
			With("skipped", skipped).
			With("failed", failed).
			With("via_burp", findingSendViaBurp)
		return writeAgentJSON(env)
	}
	fmt.Printf("%s pushed %d finding(s) to Burp %s", terminal.SuccessSymbol(), pushed, destination)
	if skipped > 0 {
		fmt.Printf(", skipped %d (no evidence request)", skipped)
	}
	if failed > 0 {
		fmt.Printf(", %d failed", failed)
	}
	fmt.Println()
	return nil
}

// pushOneFinding sends one finding's evidence to each requested Burp tool. Under
// --send-via-burp the request is re-issued by Burp (Send:true) and the supplied
// response is dropped so the stored item carries a fresh one.
//
// The Organizer leg runs first: it is the durable destination, so when both are
// requested and Repeater's tab budget is exhausted, the finding is still filed.
func pushOneFinding(
	ctx context.Context,
	client *burpbridge.Client,
	f *database.Finding,
	req, resp []byte,
	url string,
	toOrganizer, toRepeater bool,
	httpMode burpbridge.HTTPMode,
) error {
	if toOrganizer {
		// --send-via-burp fetches a fresh response (drop the stored one so
		// Send:true actually re-issues); otherwise store the stored pair as-is.
		organizerResp := resp
		if findingSendViaBurp {
			organizerResp = nil
		}
		notes := fmt.Sprintf("%s [%s] finding #%d", findingPushLabel(f), f.Severity, f.ID)
		if _, err := client.SendToOrganizer(ctx, url, "", req, organizerResp, burpbridge.OrganizerOptions{
			Source:    "vigolium-finding",
			Notes:     notes,
			Highlight: severityHighlight(f.Severity),
			Send:      findingSendViaBurp,
			Mode:      httpMode,
		}); err != nil {
			return err
		}
	}
	if toRepeater {
		if _, err := client.SendToRepeater(ctx, url, "", req, burpbridge.RepeaterOptions{
			TabName: fmt.Sprintf("finding-%d", f.ID),
			Send:    findingSendViaBurp,
			Mode:    httpMode,
		}); err != nil {
			return err
		}
	}
	return nil
}

// findingPushEvidence resolves the request/response bytes and URL to push for a
// finding, preferring its first linked HTTP record and falling back to the
// inline evidence stored on the finding itself.
func findingPushEvidence(f *database.Finding, byUUID map[string]*database.HTTPRecord) (req, resp []byte, url string) {
	records := recordsForFinding(byUUID, f)
	for _, rec := range records {
		if len(rec.RawRequest) == 0 {
			continue
		}
		var response []byte
		if rec.HasResponse {
			response = rec.RawResponse
		}
		return rec.RawRequest, response, rec.URL
	}
	// Fall back to the finding's inline evidence (e.g. when the linked record was
	// filtered out of the export).
	if f.Request != "" {
		return []byte(f.Request), []byte(f.Response), findingURLValue(f)
	}
	return nil, nil, ""
}

// findingPushLabel is the short human label used in the Burp note.
func findingPushLabel(f *database.Finding) string {
	if f.ModuleShort != "" {
		return f.ModuleShort
	}
	return f.ModuleName
}

// severityHighlight maps a finding severity to a Burp Organizer highlight colour
// so a pushed batch is visually triageable at a glance.
func severityHighlight(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "red"
	case "medium":
		return "orange"
	case "low":
		return "yellow"
	case "suspect":
		return "cyan"
	default:
		return "gray"
	}
}
