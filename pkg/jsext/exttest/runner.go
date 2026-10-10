package exttest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/yamlext"
)

// Fixture layout, next to each extension <name>.js|.ts|.vgm.yaml:
//
//	<name>.fixtures/<case>.http             request + response (see httpFixture)
//	<name>.fixtures/<case>.expect.json      {"findings": n | [{"name~", "severity", "confidence"}], "errors": 0}
//	<name>.fixtures/<case>.responses/*.http canned responses for an active extension's requests
//
// A case without a .responses directory runs offline: every request the
// extension makes is refused and counted. A case with one runs against an
// in-process mock on 127.0.0.1 that answers from those files, and the case's
// request is pointed at the mock.

const (
	fixturesSuffix  = ".fixtures"
	caseSuffix      = ".http"
	expectSuffix    = ".expect.json"
	responsesSuffix = ".responses"
)

// Case statuses.
const (
	StatusPass = "pass"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// CaseResult is one fixture case, or one extension that could not run any.
type CaseResult struct {
	// Extension is the extension file, relative to the tested directory.
	Extension string `json:"extension"`
	ModuleID  string `json:"module_id,omitempty"`
	// Case is the fixture name (the .http file without its extension); empty
	// for an extension-level entry (no fixtures, a hook, an orphan fixture
	// directory).
	Case   string `json:"case"`
	Status string `json:"status"`
	// Failures says why a failed case failed, one line per mismatch.
	Failures []string `json:"failures,omitempty"`
	// SkipReason says why a skipped entry did not run.
	SkipReason string   `json:"skip_reason,omitempty"`
	Handlers   []string `json:"handlers,omitempty"`
	Findings   int      `json:"findings"`
	// FindingNames lists each result as "name (severity/confidence)".
	FindingNames []string    `json:"finding_names,omitempty"`
	Errors       []CallError `json:"errors,omitempty"`
	// NetworkCallsBlocked counts requests an offline case refused.
	NetworkCallsBlocked int64 `json:"network_calls_blocked"`
	// MockRequests counts requests the mock served; UnmatchedRequests are the
	// ones no canned response matched (answered 404).
	MockRequests      int      `json:"mock_requests"`
	UnmatchedRequests []string `json:"unmatched_requests,omitempty"`
	DurationMS        int64    `json:"duration_ms"`
}

// Report is a whole `ext test` run.
type Report struct {
	Passed  int          `json:"passed"`
	Failed  int          `json:"failed"`
	Skipped int          `json:"skipped"`
	Cases   []CaseResult `json:"cases"`
}

// FixtureOptions configures RunFixtures.
type FixtureOptions struct {
	// Base supplies extension variables and limits (see Options.Base).
	Base *config.ExtensionsConfig
}

// RunFixtures runs every fixture case under path: a directory of extensions,
// or one extension file. The error return is for a path that cannot be read;
// a case that fails is in the report.
func RunFixtures(path string, opts FixtureOptions) (*Report, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	dir, only := path, ""
	if !info.IsDir() {
		dir, only = filepath.Dir(path), filepath.Base(path)
		if !isExtensionFile(only) {
			return nil, fmt.Errorf("%s is not an extension (.js, .ts, .vgm.yaml) or a directory", path)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	r := &fixtureRun{opts: opts}
	defer r.close()
	report := &Report{Cases: []CaseResult{}}
	exts := map[string]bool{} // fixture dir base name → has an extension
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !isExtensionFile(name) || (only != "" && name != only) {
			continue
		}
		exts[extensionStem(name)] = true
		report.Cases = append(report.Cases, r.runExtension(dir, name)...)
	}
	if only == "" {
		for _, e := range entries {
			if !e.IsDir() || !strings.HasSuffix(e.Name(), fixturesSuffix) {
				continue
			}
			if stem := strings.TrimSuffix(e.Name(), fixturesSuffix); !exts[stem] {
				report.Cases = append(report.Cases, CaseResult{
					Extension: e.Name(), Status: StatusFail,
					Failures: []string{fmt.Sprintf("fixture directory has no extension named %s.js, %s.ts or %s.vgm.yaml", stem, stem, stem)},
				})
			}
		}
	}
	for _, c := range report.Cases {
		switch c.Status {
		case StatusPass:
			report.Passed++
		case StatusFail:
			report.Failed++
		default:
			report.Skipped++
		}
	}
	return report, nil
}

// isExtensionFile reports whether name is an extension a fixture can test.
func isExtensionFile(name string) bool {
	switch {
	case strings.HasSuffix(name, ".d.ts"):
		return false
	case strings.HasSuffix(name, ".js"), strings.HasSuffix(name, ".ts"):
		return true
	default:
		return yamlext.IsYAMLExtension(name)
	}
}

// extensionStem is the name a fixture directory is keyed by: foo.js,
// foo.ts and foo.vgm.yaml are all "foo".
func extensionStem(name string) string {
	for _, suffix := range []string{".vgm.yaml", ".vgm.yml", ".js", ".ts"} {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	return name
}

// fixtureRun holds what cases share: the loopback HTTP stack mock cases use.
type fixtureRun struct {
	opts      FixtureOptions
	network   *http.Requester
	netErr    error
	netClose  func()
	netInited bool
}

func (r *fixtureRun) close() {
	if r.netClose != nil {
		r.netClose()
	}
}

// networkRequester builds, once, the requester mock-backed cases send
// through: the scan's HTTP stack with request clustering off (a cached
// response would hide a request from the mock) and no proxy flag.
func (r *fixtureRun) networkRequester() (*http.Requester, error) {
	if r.netInited {
		return r.network, r.netErr
	}
	r.netInited = true
	opts := types.DefaultOptions()
	opts.ClusterRequests = false
	opts.Timeout = 10 * time.Second
	if err := network.Init(opts); err != nil {
		r.netErr = fmt.Errorf("initialize network: %w", err)
		return nil, r.netErr
	}
	dedupMgr := dedup.NewManager()
	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost: opts.MaxPerHost, MaxEntries: 100,
		EvictAfter: 30 * time.Second, EvictInterval: 10 * time.Second,
	})
	svc := &services.Services{Options: opts, DedupManager: dedupMgr, HostLimiter: hostLimiter}
	svc.Egress = egress.New(egress.Config{Hosts: hostLimiter, Breaker: svc.HostErrors})
	r.netClose = func() {
		dedupMgr.Close()
		_ = hostLimiter.Close()
		network.Close()
	}
	r.network, r.netErr = http.NewRequester(opts, svc)
	return r.network, r.netErr
}

// runExtension runs every case of one extension. The extension is loaded once
// up front, offline, so a hook or a load failure is one entry rather than one
// per case.
func (r *fixtureRun) runExtension(dir, name string) []CaseResult {
	ext, err := Load(filepath.Join(dir, name), Options{Base: r.opts.Base})
	switch {
	case errors.Is(err, ErrHook):
		return []CaseResult{{Extension: name, Status: StatusSkip, SkipReason: hookSkipReason}}
	case err != nil:
		return []CaseResult{{Extension: name, Status: StatusFail, Failures: []string{err.Error()}}}
	}
	moduleID := ext.Module().ID()

	fixDir := filepath.Join(dir, extensionStem(name)+fixturesSuffix)
	entries, err := os.ReadDir(fixDir)
	if err != nil {
		return []CaseResult{{Extension: name, ModuleID: moduleID, Status: StatusSkip,
			SkipReason: "no fixtures (add " + filepath.Base(fixDir) + "/<case>.http)"}}
	}
	var cases []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), caseSuffix) {
			cases = append(cases, strings.TrimSuffix(e.Name(), caseSuffix))
		}
	}
	sort.Strings(cases)
	if len(cases) == 0 {
		return []CaseResult{{Extension: name, ModuleID: moduleID, Status: StatusSkip,
			SkipReason: "fixture directory has no .http cases"}}
	}
	out := make([]CaseResult, 0, len(cases))
	for _, c := range cases {
		res := r.runCase(filepath.Join(dir, name), fixDir, c)
		res.Extension = name
		res.ModuleID = moduleID
		out = append(out, res)
	}
	return out
}

const hookSkipReason = "hook extension: pre_hook/post_hook have no scan handler for ext test to run"

// runCase runs one fixture case.
func (r *fixtureRun) runCase(extPath, fixDir, name string) (res CaseResult) {
	res = CaseResult{Case: name}
	start := time.Now()
	defer func() { res.DurationMS = time.Since(start).Milliseconds() }()
	fail := func(format string, args ...any) CaseResult {
		res.Status = StatusFail
		res.Failures = append(res.Failures, fmt.Sprintf(format, args...))
		return res
	}

	data, err := os.ReadFile(filepath.Join(fixDir, name+caseSuffix))
	if err != nil {
		return fail("read fixture: %v", err)
	}
	fx, err := parseHTTPFixture(data)
	if err != nil {
		return fail("fixture: %v", err)
	}

	var expect *Expectation
	if raw, err := os.ReadFile(filepath.Join(fixDir, name+expectSuffix)); err == nil {
		if expect, err = parseExpectation(raw); err != nil {
			return fail("%s: %v", name+expectSuffix, err)
		}
	} else if d := fx.Directives["expect"]; d != "" {
		if expect, err = parseExpectation([]byte(d)); err != nil {
			return fail("// expect: %v", err)
		}
	} else {
		return fail("no expectation: add %s or a // expect: {\"findings\": N} line", name+expectSuffix)
	}

	requester := NewOfflineRequester()
	origin := ""
	var mock *mockServer
	if respDir := filepath.Join(fixDir, name+responsesSuffix); isDir(respDir) {
		routes, err := loadMockRoutes(respDir)
		if err != nil {
			return fail("%s: %v", name+responsesSuffix, err)
		}
		if requester, err = r.networkRequester(); err != nil {
			return fail("mock HTTP stack: %v", err)
		}
		mock = newMockServer(routes)
		defer mock.close()
		fx.Request = withHost(fx.Request, mock.host())
		origin = "http://" + mock.host()
	}

	rr, err := fx.requestResponse(origin)
	if err != nil {
		return fail("fixture: %v", err)
	}
	// Loaded per case: the module is bound to this case's requester.
	ext, err := Load(extPath, Options{HTTPClient: requester, Base: r.opts.Base})
	if err != nil {
		return fail("%v", err)
	}

	handler := firstNonEmpty(expect.Handler, fx.Directives["handler"])
	insertion := firstNonEmpty(expect.Insertion, fx.Directives["insertion"])
	outcome, err := ext.Run(rr, RunOptions{Handler: handler, Insertion: insertion})
	if err != nil {
		return fail("%v", err)
	}
	res.Handlers = outcome.Handlers
	res.Findings = len(outcome.Results)
	for _, f := range outcome.Results {
		res.FindingNames = append(res.FindingNames, fmt.Sprintf("%s (%s/%s)", f.Info.Name, f.Info.Severity, f.Info.Confidence))
	}
	res.Errors = outcome.Errors
	if mock == nil {
		res.NetworkCallsBlocked = requester.RequestsRefused()
	} else {
		res.MockRequests, res.UnmatchedRequests = mock.stats()
	}

	if failures := expect.check(outcome.Results, len(outcome.Errors), res.NetworkCallsBlocked, res.MockRequests); len(failures) > 0 {
		res.Status, res.Failures = StatusFail, failures
		for _, e := range outcome.Errors {
			res.Failures = append(res.Failures, "handler error: "+e.Message)
		}
		return res
	}
	res.Status = StatusPass
	return res
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
