package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/time/rate"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/verify"
)

var (
	findingVerifyDryRun    bool
	findingVerifyNoWrite   bool
	findingVerifyMark      bool
	findingVerifyFailIf    string
	findingVerifyRefetch   bool
	findingVerifyRateLimit float64
	findingVerifyTimeout   time.Duration
)

// findingVerifyActor is recorded on status changes made by --mark.
const findingVerifyActor = "finding-verify"

// findingVerifyHTTPTimeout caps one request; --timeout bounds the whole run.
const findingVerifyHTTPTimeout = 15 * time.Second

var findingVerifyCmd = &cobra.Command{
	Use:   "verify <id|hash>... [--scan-uuid <uuid>]",
	Short: "Re-run a finding's module against its target and record whether it reproduces",
	Long: `Re-run the module behind each finding against the request it originally
scanned, and record the verdict on the finding:

  confirmed       the module reported the same finding again
  not_reproduced  the module ran against a responding target and did not
  inconclusive    no verdict: target unreachable, module timed out or failed,
                  or the baseline request could not be reconstructed
  unsupported     no deterministic re-run exists (agent, audit, OAST and
                  known-issue-scan findings; an ext-* module not loaded)

The baseline and insertion point come from the replay context stored with the
finding (origin_record_uuid, insertion_point) and, for findings written before
it existed, from the linked records: a scanned record is the baseline, and a
finding whose only record is its own payload request is matched to a scanned
record on the same host, method and path that differs from it in exactly one
insertion point. The module runs alone, on that one point, with cross-module
dedup off, against a fresh baseline response.

A passive finding is re-analyzed on its stored record without sending a
request; --refetch fetches a fresh response first. An ext-* module is loaded
from --ext / --ext-dir (or the configured extension directory).

The verdict is written to the finding's verification field (with verified_at);
the lifecycle status is not touched unless --mark is given, which moves
not_reproduced to false_positive and confirmed to confirmed through the same
audited path as 'finding mark'. --no-write runs without storing anything;
--dry-run prints the reconstruction and sends nothing.

--fail-if <verdict,...> exits 4 when any finding gets one of those verdicts,
after the result is written. An id or hash that matches nothing in the current
project exits 1.`,
	Example: `  vigolium finding verify 42
  vigolium finding verify 3f9a0c2b71de 43 --mark -j
  vigolium finding verify --scan-uuid 6f1c… --fail-if not_reproduced
  vigolium finding verify 42 --dry-run`,
	RunE: runFindingVerify,
}

func init() {
	findingCmd.AddCommand(findingVerifyCmd)
	f := findingVerifyCmd.Flags()
	f.BoolVar(&findingVerifyDryRun, "dry-run", false, "Print the reconstructed module, baseline request and insertion point; send nothing and write nothing")
	f.BoolVar(&findingVerifyNoWrite, "no-write", false, "Run the verification but do not store the verdict")
	f.BoolVar(&findingVerifyMark, "mark", false, "Also set the status: not_reproduced → false_positive, confirmed → confirmed")
	f.StringVar(&findingVerifyFailIf, "fail-if", "", "Exit 4 when any finding gets one of these verdicts: "+strings.Join(database.VerificationVerdicts, ",")+" (comma-separated)")
	f.BoolVar(&findingVerifyRefetch, "refetch", false, "Passive findings: fetch a fresh response instead of re-analyzing the stored one")
	f.Float64Var(&findingVerifyRateLimit, "rate-limit", 0, "Max requests/second across the verification (0 = unlimited; fractions allowed)")
	f.DurationVar(&findingVerifyTimeout, "timeout", 2*time.Minute, "Time limit for verifying one finding (one request is capped at 15s)")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Use the standalone .sqlite named by --db with project scoping off")
	// --scan-uuid is the finding command's persistent filter flag; here it
	// adds every finding of that scan (uuid, 8+ char prefix, latest, previous).
	f.StringVar(&globalGlobDB, "glob-db", "", "Not supported: a --glob-db merge is a temporary copy, so a verdict written there would be lost")
	_ = f.MarkHidden("glob-db")
}

// parseVerifyFailIf parses --fail-if into verdicts.
func parseVerifyFailIf(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		v := strings.ToLower(strings.TrimSpace(part))
		if v == "" {
			continue
		}
		if !slices.Contains(database.VerificationVerdicts, v) {
			return nil, usageErrorf("invalid --fail-if %q (want one of: %s)", part, strings.Join(database.VerificationVerdicts, ", "))
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

// findingVerifyWrites reports whether this run stores anything.
func findingVerifyWrites() bool { return !findingVerifyDryRun && !findingVerifyNoWrite }

func validateFindingVerifyFlags(args []string) (failIf []string, err error) {
	if len(args) == 0 && strings.TrimSpace(findingScanUUID) == "" {
		return nil, usageErrorf("finding verify needs at least one finding id or hash, or --scan-uuid")
	}
	if findingVerifyMark && !findingVerifyWrites() {
		return nil, usageErrorf("--mark writes the status, so it cannot be combined with --dry-run or --no-write")
	}
	if findingVerifyRateLimit < 0 {
		return nil, usageErrorf("--rate-limit must be >= 0")
	}
	if findingVerifyTimeout < 0 {
		return nil, usageErrorf("--timeout must be >= 0")
	}
	if failIf, err = parseVerifyFailIf(findingVerifyFailIf); err != nil {
		return nil, err
	}
	if findingVerifyWrites() {
		if strings.TrimSpace(globalGlobDB) != "" {
			return nil, usageErrorf("finding verify cannot write through --glob-db: the merge is a temporary copy that is discarded on exit. Use --no-write, or verify against one source with -S --db <file.sqlite>")
		}
		if path := strings.TrimSpace(globalDB); path != "" && isJSONLSource(path) {
			return nil, usageErrorf("finding verify cannot write to a .jsonl export (%s): it is loaded into a temporary database that is discarded on exit. Use --no-write, or verify in a .sqlite with -S --db", path)
		}
	}
	return failIf, nil
}

func runFindingVerify(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	failIf, err := validateFindingVerifyFlags(args)
	if err != nil {
		return err
	}
	var ids []int64
	var hashes []string
	if len(args) > 0 {
		if ids, hashes, err = findingSelectors(args); err != nil {
			return err
		}
	}

	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	var db *database.DB
	if statelessReadRequested() {
		db, err = openStatelessDB(globDBSkipSet{})
	} else {
		db, err = getDB()
	}
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	repo := database.NewRepository(db)
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	findings, notFound, err := loadFindingsToVerify(ctx, repo, projectUUID, ids, hashes, strings.TrimSpace(findingScanUUID))
	if err != nil {
		var amb *database.AmbiguousFindingHashError
		if errors.As(err, &amb) {
			return usageErrorf("%v", amb)
		}
		return err
	}

	stack := &verifyStack{}
	defer stack.close()
	resolve := stack.moduleResolver(findings)

	results := make([]*verify.Result, 0, len(findings))
	for _, f := range findings {
		if ctx.Err() != nil {
			break
		}
		results = append(results, verifyOneFinding(ctx, repo, projectUUID, f, resolve, stack))
	}

	if globalJSON {
		if err := emitFindingVerify(cmd, results, notFound, projectUUID); err != nil {
			return err
		}
	} else {
		printFindingVerifyResults(results, notFound)
	}

	if len(notFound) > 0 {
		where := ""
		if projectUUID != "" {
			where = " in the current project"
		}
		return codedErrorf(apicontract.CodeNotFound, "%d finding(s) not found%s: %s",
			len(notFound), where, strings.Join(notFound, ", "))
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return findingVerifyGate(results, failIf)
}

// loadFindingsToVerify resolves the selectors and --scan-uuid into findings,
// deduplicated and ordered by id.
func loadFindingsToVerify(ctx context.Context, repo *database.Repository, projectUUID string, ids []int64, hashes []string, scanUUID string) ([]*database.Finding, []string, error) {
	var out []*database.Finding
	var notFound []string
	if len(ids) > 0 || len(hashes) > 0 {
		found, nf, err := repo.ResolveFindings(ctx, projectUUID, ids, hashes)
		if err != nil {
			return nil, nil, err
		}
		out, notFound = found, nf
	}
	if scanUUID != "" {
		// A uuid, an 8+ char prefix, latest or previous; one not in scope is
		// scan_not_found, never an empty (successful) verification.
		scan, err := repo.ResolveScanRef(ctx, projectUUID, scanUUID)
		if err != nil {
			if errors.Is(err, database.ErrScanNotFound) {
				return nil, nil, codedErrorf(apicontract.CodeScanNotFound, "--scan-uuid %q: %v", scanUUID, err)
			}
			return nil, nil, err
		}
		inScan, err := repo.FindingsInScan(ctx, projectUUID, scan.UUID)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, inScan...)
	}
	slices.SortFunc(out, func(a, b *database.Finding) int { return int(a.ID - b.ID) })
	out = slices.CompactFunc(out, func(a, b *database.Finding) bool { return a.ID == b.ID })
	return out, notFound, nil
}

// verifyOneFinding reconstructs, runs and records one finding.
func verifyOneFinding(ctx context.Context, repo *database.Repository, projectUUID string, f *database.Finding, resolve verify.ModuleResolver, stack *verifyStack) *verify.Result {
	plan := verify.Reconstruct(ctx, repo, projectUUID, f, resolve)
	if findingVerifyDryRun {
		res := &verify.Result{ID: f.ID, FindingHash: f.FindingHash, ModuleID: f.ModuleID, Plan: plan,
			Verdict: plan.Verdict, Reason: plan.Reason}
		if plan.Verdict == "" {
			plan.Network = plan.ModuleType == database.ModuleTypeActive || findingVerifyRefetch
			res.Reason = "dry run: nothing sent"
		}
		return res
	}

	opts := verify.RunOptions{Refetch: findingVerifyRefetch, Timeout: findingVerifyTimeout}
	if plan.Verdict == "" && (plan.ModuleType == database.ModuleTypeActive || findingVerifyRefetch) {
		requester, svc, err := stack.get()
		if err != nil {
			plan.Verdict, plan.Reason = database.VerdictInconclusive, "HTTP setup failed: "+err.Error()
		}
		opts.Requester, opts.Services = requester, svc
	}
	res := verify.Run(ctx, plan, opts)
	if plan.Baseline != nil {
		plan.Baseline.Request = "" // shown by --dry-run only
	}

	if !findingVerifyWrites() || ctx.Err() != nil {
		return res
	}
	v := &database.FindingVerification{
		Verdict:       res.Verdict,
		At:            time.Now().UTC(),
		ModuleVersion: Version,
		ScanUUID:      f.ScanUUID,
		Reason:        res.Reason,
	}
	if err := repo.SetFindingVerification(ctx, projectUUID, f.ID, v); err != nil {
		res.Reason += "; verdict not stored: " + err.Error()
		return res
	}
	res.Written = true

	if findingVerifyMark {
		status := ""
		switch res.Verdict {
		case database.VerdictNotReproduced:
			status = database.StatusFalsePositive
		case database.VerdictConfirmed:
			status = database.StatusConfirmed
		}
		if status != "" {
			upd, err := repo.UpdateFindingStatusScoped(ctx, projectUUID, database.FindingStatusUpdate{
				IDs: []int64{f.ID}, Status: status, Note: "finding verify: " + res.Reason, Actor: findingVerifyActor,
			})
			if err != nil {
				res.Reason += "; status not set: " + err.Error()
			} else if len(upd.Changed) > 0 {
				res.Status = &upd.Changed[0]
			}
		}
	}
	return res
}

// findingVerifyGate trips --fail-if: a gate result (exit 4), returned only
// after the results were written.
func findingVerifyGate(results []*verify.Result, failIf []string) error {
	if len(failIf) == 0 {
		return nil
	}
	n := 0
	for _, r := range results {
		if slices.Contains(failIf, r.Verdict) {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	//vigolium:not-usage gate result (exit 4), not a usage error
	return gateError{err: fmt.Errorf("--fail-if %s: %d finding(s) matched", strings.Join(failIf, ","), n)}
}

// verdictCounts tallies results by verdict, every verdict present.
func verdictCounts(results []*verify.Result) map[string]int {
	counts := make(map[string]int, len(database.VerificationVerdicts))
	for _, v := range database.VerificationVerdicts {
		counts[v] = 0
	}
	for _, r := range results {
		if r.Verdict != "" {
			counts[r.Verdict]++
		}
	}
	return counts
}

func emitFindingVerify(cmd *cobra.Command, results []*verify.Result, notFound []string, projectUUID string) error {
	changed := false
	for _, r := range results {
		if r.Written {
			changed = true
		}
	}
	if notFound == nil {
		notFound = []string{}
	}
	return emitMutation(cmd, "", mutationResult{
		Changed: changed,
		Action:  "verify",
		DryRun:  findingVerifyDryRun,
		Items:   results,
		Extra: map[string]any{
			"verdicts":  verdictCounts(results),
			"not_found": notFound,
			"written":   findingVerifyWrites(),
		},
	}, withProjectScope(projectUUID), withDBPath(resolvedReadDBPath()))
}

func printFindingVerifyResults(results []*verify.Result, notFound []string) {
	short := func(h string) string {
		if len(h) > database.MinFindingHashPrefix {
			return h[:database.MinFindingHashPrefix]
		}
		return h
	}
	for _, r := range results {
		symbol := terminal.InfoSymbol()
		verdict := r.Verdict
		switch r.Verdict {
		case database.VerdictConfirmed:
			symbol, verdict = terminal.SuccessSymbol(), terminal.BoldGreen(r.Verdict)
		case database.VerdictNotReproduced:
			symbol, verdict = terminal.WarningSymbol(), terminal.BoldYellow(r.Verdict)
		case "":
			verdict = terminal.Gray("plan")
		}
		fmt.Printf("%s #%d %s %s  %s  %s\n", symbol, r.ID, terminal.Gray(short(r.FindingHash)), r.ModuleID, verdict, terminal.Gray(r.Reason))
		if p := r.Plan; p != nil && (findingVerifyDryRun || globalVerbose) && p.Baseline != nil {
			fmt.Printf("    baseline: %s %s (%s)\n", p.Baseline.Method, p.Baseline.URL, p.Baseline.Source)
			if p.InsertionPoint != nil {
				fmt.Printf("    insertion point: %s:%s (%s)\n", p.InsertionPoint.Type, p.InsertionPoint.Name, p.InsertionPointSource)
			}
			if p.Payload != "" {
				fmt.Printf("    payload: %s\n", p.Payload)
			}
			fmt.Printf("    network: %v\n", p.Network)
			if findingVerifyDryRun && p.Baseline.Request != "" {
				fmt.Printf("    request:\n%s\n", indentBlock(p.Baseline.Request, "      "))
			}
		}
		if !findingVerifyDryRun && r.Verdict != "" && r.Verdict != database.VerdictUnsupported {
			fmt.Printf("    %d request(s), %dms\n", r.Requests, r.DurationMs)
		}
		if r.Status != nil {
			fmt.Printf("    status %s → %s\n", r.Status.From, terminal.BoldYellow(r.Status.To))
		}
	}
	for _, n := range notFound {
		fmt.Printf("%s %s: no such finding\n", terminal.WarningSymbol(), n)
	}
	if len(results) > 0 && !findingVerifyDryRun && !findingVerifyWrites() {
		fmt.Fprintf(os.Stderr, "%s --no-write: verdicts were not stored\n", terminal.InfoSymbol())
	}
}

func indentBlock(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + strings.TrimRight(l, "\r")
	}
	return strings.Join(lines, "\n")
}

// verifyStack lazily builds the HTTP stack and, when an ext-* finding needs
// it, the extension engine — a passive-only or dry run never touches the
// network layer.
type verifyStack struct {
	once      sync.Once
	requester *http.Requester
	svc       *services.Services
	cleanup   func()
	err       error

	extOnce sync.Once
	ext     map[string]modules.Module
}

func (s *verifyStack) get() (*http.Requester, *services.Services, error) {
	s.once.Do(func() { s.requester, s.svc, s.cleanup, s.err = newVerifyHTTPStack() })
	return s.requester, s.svc, s.err
}

func (s *verifyStack) close() {
	if s.cleanup != nil {
		s.cleanup()
	}
}

// moduleResolver resolves built-in modules from the registry and ext-* ones
// from the extension engine, loaded only when a finding names one.
func (s *verifyStack) moduleResolver(findings []*database.Finding) verify.ModuleResolver {
	needExt := slices.ContainsFunc(findings, func(f *database.Finding) bool { return strings.HasPrefix(f.ModuleID, "ext-") })
	return func(id string) modules.Module {
		if !strings.HasPrefix(id, "ext-") {
			return verify.DefaultModuleResolver(id)
		}
		if !needExt {
			return nil
		}
		s.extOnce.Do(s.loadExtensions)
		return s.ext[id]
	}
}

func (s *verifyStack) loadExtensions() {
	s.ext = map[string]modules.Module{}
	settings, err := loadProjectSettings(globalConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s extensions not loaded: %v\n", terminal.WarnPrefix(), err)
		return
	}
	applyGlobalExtFlagsToSettings(settings)
	requester, _, err := s.get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s extensions not loaded: %v\n", terminal.WarnPrefix(), err)
		return
	}
	engine, err := jsext.NewEngine(&settings.DynamicAssessment.Extensions, requester, &jsext.EngineOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s extensions not loaded: %v\n", terminal.WarnPrefix(), err)
		return
	}
	for _, m := range engine.ActiveModules() {
		s.ext[m.ID()] = m
	}
	for _, m := range engine.PassiveModules() {
		if _, dup := s.ext[m.ID()]; !dup {
			s.ext[m.ID()] = m
		}
	}
}

// newVerifyHTTPStack builds the requester verify runs modules with: the
// proxy and debug globals, a per-request timeout, --rate-limit, and an egress
// gate so the request count can be reported.
func newVerifyHTTPStack() (*http.Requester, *services.Services, func(), error) {
	opts := types.DefaultOptions()
	opts.Timeout = findingVerifyHTTPTimeout
	if findingVerifyTimeout > 0 && findingVerifyTimeout < opts.Timeout {
		opts.Timeout = findingVerifyTimeout
	}
	opts.ProxyURL = globalProxy
	opts.Verbose = globalVerbose
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	if err := network.Init(opts); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize network: %w", err)
	}
	dedupMgr := dedup.NewManager()
	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    opts.MaxPerHost,
		MaxEntries:    100,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	})
	svc := &services.Services{Options: opts, DedupManager: dedupMgr, HostLimiter: hostLimiter}
	if findingVerifyRateLimit > 0 {
		svc.RateLimiter = rate.NewLimiter(rate.Limit(findingVerifyRateLimit), 1)
	}
	svc.Egress = egress.New(egress.Config{Rate: svc.RateLimiter, Hosts: hostLimiter, Breaker: svc.HostErrors})
	cleanup := func() {
		dedupMgr.Close()
		_ = hostLimiter.Close()
	}
	requester, err := http.NewRequester(opts, svc)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to create HTTP requester: %w", err)
	}
	return requester, svc, cleanup, nil
}
