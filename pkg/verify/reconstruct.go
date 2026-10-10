// Package verify re-runs the module behind a stored finding against its target
// and reports whether the finding reproduces (`vigolium finding verify`).
//
// A run has two halves. Reconstruct rebuilds what the module originally saw —
// the module, the baseline request it scanned and the insertion point it
// mutated — from the finding row: the replay columns first
// (origin_record_uuid, insertion_point), legacy heuristics second. Run then
// drives a one-item executor (no store, no dedup, a single module, the point
// filter) and turns its results into a verdict. Writing the verdict and any
// status change is the caller's job.
package verify

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
)

// Baseline sources, reported in Plan.Baseline.Source.
const (
	// BaselineOriginRecord: findings.origin_record_uuid, written by the
	// executor since schema v3.
	BaselineOriginRecord = "origin_record"
	// BaselineLinkedRecord: the finding's linked http_record is a scanned
	// record (not the finding's own evidence), so it is what the module saw.
	BaselineLinkedRecord = "linked_record"
	// BaselineMatchedRecord: a scanned record on the same host, method and path
	// that differs from the finding's request in exactly one insertion point.
	BaselineMatchedRecord = "matched_record"
	// BaselineFindingRequest: the request stored on the finding itself (a
	// passive finding without a loadable record).
	BaselineFindingRequest = "finding_request"
)

// Insertion-point sources, reported in Plan.InsertionPointSource.
const (
	PointStored    = "stored"          // findings.insertion_point
	PointDiffering = "differing_point" // the one point where baseline and finding request differ
)

// Plan is a reconstructed finding: what verify will run, or why it will not.
type Plan struct {
	FindingID   int64  `json:"id"`
	FindingHash string `json:"finding_hash"`
	ModuleID    string `json:"module_id"`
	ModuleType  string `json:"module_type,omitempty"` // active | passive

	Baseline             *Baseline                       `json:"baseline,omitempty"`
	InsertionPoint       *database.FindingInsertionPoint `json:"insertion_point,omitempty"`
	InsertionPointSource string                          `json:"insertion_point_source,omitempty"`
	Payload              string                          `json:"payload,omitempty"`
	// Network is true when running the plan sends requests to the target.
	Network bool `json:"network"`

	// Verdict is set when reconstruction already decides the outcome
	// (unsupported, or inconclusive for lack of a baseline); Run returns it
	// without executing anything.
	Verdict string `json:"-"`
	Reason  string `json:"-"`

	finding *database.Finding
	module  modules.Module
	item    *httpmsg.HttpRequestResponse
}

// Baseline describes the request the module will be run against.
type Baseline struct {
	Source     string `json:"source"`
	RecordUUID string `json:"record_uuid,omitempty"`
	Method     string `json:"method,omitempty"`
	URL        string `json:"url,omitempty"`
	// Request is the raw baseline request, filled for --dry-run output.
	Request string `json:"request,omitempty"`
}

// ModuleResolver returns the module with the given id, or nil when no such
// module is loaded. The CLI wraps DefaultModuleResolver to add ext-* modules
// loaded from --ext.
type ModuleResolver func(id string) modules.Module

// DefaultModuleResolver looks the id up in the built-in registries.
func DefaultModuleResolver(id string) modules.Module {
	if active := modules.GetActiveModulesByIDs([]string{id}); len(active) > 0 {
		return active[0]
	}
	if passive := modules.GetPassiveModulesByIDs([]string{id}); len(passive) > 0 {
		return passive[0]
	}
	return nil
}

// unsupportedSources are finding producers whose findings a module re-run
// cannot reproduce, with the reason reported.
var unsupportedSources = map[string]string{
	database.FindingSourceOAST:           "out-of-band finding: its proof is a callback to a planted payload, which a re-run without OAST cannot observe",
	database.FindingSourceAgent:          "agent finding: there is no deterministic module to re-run",
	database.FindingSourceAudit:          "source-audit finding: there is no request to re-run",
	database.FindingSourceKnownIssueScan: "known-issue-scan finding: template checks are not re-run by finding verify",
}

// Reconstruct rebuilds the plan for one finding. repo may be nil, in which
// case only the request stored on the finding is available.
func Reconstruct(ctx context.Context, repo *database.Repository, projectUUID string, f *database.Finding, resolve ModuleResolver) *Plan {
	p := &Plan{FindingID: f.ID, FindingHash: f.FindingHash, ModuleID: f.ModuleID, finding: f, Payload: f.Payload}
	if reason, ok := unsupportedSources[f.FindingSource]; ok {
		return p.decide(database.VerdictUnsupported, reason)
	}
	if resolve == nil {
		resolve = DefaultModuleResolver
	}
	p.module = resolve(f.ModuleID)
	if p.module == nil {
		reason := fmt.Sprintf("module %q is not available", f.ModuleID)
		if strings.HasPrefix(f.ModuleID, "ext-") {
			reason += " - load its extension with --ext <file> (or --ext-dir)"
		}
		return p.decide(database.VerdictUnsupported, reason)
	}
	_, passive := p.module.(modules.PassiveModule)
	if _, active := p.module.(modules.ActiveModule); active {
		passive = false
	}
	if passive {
		p.ModuleType = database.ModuleTypePassive
	} else {
		p.ModuleType = database.ModuleTypeActive
	}

	if !p.findBaseline(ctx, repo, projectUUID, passive) {
		return p
	}
	p.findInsertionPoint(passive)
	if p.Verdict != "" {
		return p
	}
	if p.Baseline != nil && p.item != nil && p.item.Request() != nil {
		p.Baseline.Method = p.item.Request().Method()
		if u, err := p.item.URL(); err == nil && u != nil {
			p.Baseline.URL = u.String()
		}
		p.Baseline.Request = string(p.item.Request().Raw())
	}
	return p
}

func (p *Plan) decide(verdict, reason string) *Plan {
	p.Verdict, p.Reason = verdict, reason
	return p
}

// fail decides the plan and returns false, for the bool-returning steps.
func (p *Plan) fail(verdict, reason string) bool {
	p.decide(verdict, reason)
	return false
}

// findBaseline sets p.item and p.Baseline; false when the plan was decided.
func (p *Plan) findBaseline(ctx context.Context, repo *database.Repository, projectUUID string, passive bool) bool {
	f := p.finding

	if f.OriginRecordUUID != "" && repo != nil {
		if item, rec := loadRecord(ctx, repo, f.OriginRecordUUID); item != nil {
			p.item = item
			p.Baseline = &Baseline{Source: BaselineOriginRecord, RecordUUID: rec.UUID}
			return true
		}
	}

	var evidence *database.HTTPRecord
	if repo != nil {
		for _, uuid := range f.HTTPRecordUUIDs {
			item, rec := loadRecord(ctx, repo, uuid)
			if item == nil {
				continue
			}
			// A passive module analyzed the record itself, whatever saved it;
			// an active module's baseline is a scanned record, never the
			// finding's own evidence row.
			if passive || !database.IsEvidenceRecordSource(rec.Source) {
				p.item = item
				p.Baseline = &Baseline{Source: BaselineLinkedRecord, RecordUUID: rec.UUID}
				return true
			}
			evidence = rec
			break
		}
	}

	findingRaw := []byte(f.Request)
	if len(findingRaw) == 0 && evidence != nil {
		findingRaw = evidence.RawRequest
	}
	if len(findingRaw) == 0 {
		return p.fail(database.VerdictInconclusive, "no baseline: the finding has no loadable record and no stored request")
	}

	if passive {
		item, err := httpmsg.ParseRawRequestWithURL(string(findingRaw), f.URL)
		if err != nil {
			return p.fail(database.VerdictInconclusive, "no baseline: the stored request does not parse: "+err.Error())
		}
		if f.Response != "" {
			item = item.WithResponse(httpmsg.NewHttpResponse([]byte(f.Response)))
		}
		p.item = item
		p.Baseline = &Baseline{Source: BaselineFindingRequest}
		return true
	}

	// Active, and the only request on hand is the payload request: look for
	// the scanned record it was derived from.
	if repo != nil {
		if item, rec, ip := matchBaselineRecord(ctx, repo, projectUUID, f, findingRaw); item != nil {
			p.item = item
			p.Baseline = &Baseline{Source: BaselineMatchedRecord, RecordUUID: rec.UUID}
			if p.InsertionPoint == nil && f.InsertionPoint == nil && ip != nil {
				p.InsertionPoint = &database.FindingInsertionPoint{Type: ip.Type().String(), Name: ip.Name()}
				p.InsertionPointSource = PointDiffering
			}
			return true
		}
	}
	return p.fail(database.VerdictInconclusive,
		"no baseline: the finding's only request is its payload request and no scanned record on the same host, method and path differs from it in exactly one insertion point")
}

// findInsertionPoint fills p.InsertionPoint for an active plan and checks the
// baseline still carries it.
func (p *Plan) findInsertionPoint(passive bool) {
	if passive {
		return
	}
	f := p.finding
	if f.InsertionPoint != nil && (f.InsertionPoint.Name != "" || f.InsertionPoint.Type != "") {
		ip := *f.InsertionPoint
		p.InsertionPoint = &ip
		p.InsertionPointSource = PointStored
	} else if p.InsertionPoint == nil && f.Request != "" && p.item != nil && p.item.Request() != nil &&
		!bytes.Equal(p.item.Request().Raw(), []byte(f.Request)) {
		if ip := singleDifferingPoint(p.item.Request().Raw(), []byte(f.Request)); ip != nil {
			p.InsertionPoint = &database.FindingInsertionPoint{Type: ip.Type().String(), Name: ip.Name()}
			p.InsertionPointSource = PointDiffering
		}
	}
	if p.InsertionPoint == nil || p.InsertionPoint.Name == "" {
		return
	}
	// Only a per-insertion-point module is narrowed to the point; check the
	// baseline still has it so a renamed parameter is not reported as fixed.
	if am, ok := p.module.(modules.ActiveModule); ok && am.ScanScopes()&modules.ScanScopeInsertionPoint != 0 {
		ips, err := httpmsg.CreateAllInsertionPoints(p.item.Request().Raw(), true)
		if err != nil || httpmsg.FindInsertionPoint(ips, p.InsertionPoint.Type, p.InsertionPoint.Name) == nil {
			p.decide(database.VerdictInconclusive, fmt.Sprintf("insertion point %s:%s is not in the baseline request",
				p.InsertionPoint.Type, p.InsertionPoint.Name))
		}
	}
}

// loadRecord loads a record and converts it to an item; nil when either fails.
func loadRecord(ctx context.Context, repo *database.Repository, uuid string) (*httpmsg.HttpRequestResponse, *database.HTTPRecord) {
	rec, err := repo.GetRecordByUUID(ctx, uuid)
	if err != nil || rec == nil || len(rec.RawRequest) == 0 {
		return nil, nil
	}
	item, err := database.RecordToHttpRequestResponse(rec)
	if err != nil || item == nil {
		return nil, nil
	}
	return item, rec
}

// matchBaselineRecord searches the scanned records on the finding's host,
// method and path for one that differs from findingRaw in exactly one
// insertion point, newest first, preferring the finding's own scan.
func matchBaselineRecord(ctx context.Context, repo *database.Repository, projectUUID string, f *database.Finding, findingRaw []byte) (*httpmsg.HttpRequestResponse, *database.HTTPRecord, httpmsg.InsertionPoint) {
	req, err := httpmsg.ParseRawRequestWithURL(string(findingRaw), f.URL)
	if err != nil || req.Request() == nil {
		return nil, nil, nil
	}
	host := ""
	if req.Service() != nil {
		host = req.Service().Host()
	}
	if host == "" {
		host = f.Hostname
	}
	method := req.Request().Method()
	path := pathOnly(req.Request().Path())

	scans := []string{f.ScanUUID}
	if f.ScanUUID != "" {
		scans = append(scans, "")
	}
	for _, scan := range scans {
		cands, err := repo.ReplayBaselineCandidates(ctx, projectUUID, scan, host, method, 500)
		if err != nil {
			return nil, nil, nil
		}
		for _, rec := range cands {
			if pathOnly(rec.Path) != path || bytes.Equal(rec.RawRequest, findingRaw) {
				continue
			}
			if ip := singleDifferingPoint(rec.RawRequest, findingRaw); ip != nil {
				item, err := database.RecordToHttpRequestResponse(rec)
				if err != nil || item == nil {
					continue
				}
				return item, rec, ip
			}
		}
	}
	return nil, nil, nil
}

func pathOnly(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

// singleDifferingPoint returns the one insertion point of baselineRaw whose
// value differs in findingRaw, or nil when none or several differ. Nested
// points are compared first (a JSON field inside a parameter is the precise
// point); when that is ambiguous the top-level points decide.
// Content-Length always tracks a body change and is ignored.
func singleDifferingPoint(baselineRaw, findingRaw []byte) httpmsg.InsertionPoint {
	for _, nested := range []bool{true, false} {
		if ip := differingPoint(baselineRaw, findingRaw, nested); ip != nil {
			return ip
		}
	}
	return nil
}

func differingPoint(baselineRaw, findingRaw []byte, nested bool) httpmsg.InsertionPoint {
	base, err := httpmsg.CreateAllInsertionPoints(baselineRaw, nested)
	if err != nil {
		return nil
	}
	mutated, err := httpmsg.CreateAllInsertionPoints(findingRaw, nested)
	if err != nil {
		return nil
	}
	type key struct {
		t    httpmsg.InsertionPointType
		name string
	}
	norm := func(ip httpmsg.InsertionPoint) key {
		name := ip.Name()
		if ip.Type() == httpmsg.INS_HEADER {
			name = strings.ToLower(name)
		}
		return key{ip.Type(), name}
	}
	// Header points are also offered for headers a request does not carry
	// (X-Forwarded-Host, a Referer derived from the URL, ...); such a point's
	// value follows the URL, so it is compared only when one of the two
	// requests carries the header literally — which is what a header payload
	// does.
	literal := func(name string) bool {
		inBase, _ := httpmsg.HasHeader(baselineRaw, name)
		inMutated, _ := httpmsg.HasHeader(findingRaw, name)
		return inBase || inMutated
	}
	ignored := func(k key) bool {
		return k.t == httpmsg.INS_HEADER && (k.name == "content-length" || !literal(k.name))
	}

	values := make(map[key]string, len(mutated))
	for _, ip := range mutated {
		values[norm(ip)] = ip.BaseValue()
	}
	var diff httpmsg.InsertionPoint
	seen := make(map[key]bool, len(base))
	for _, ip := range base {
		k := norm(ip)
		seen[k] = true
		if ignored(k) {
			continue
		}
		if v, ok := values[k]; ok && v == ip.BaseValue() {
			continue
		}
		if diff != nil {
			return nil // more than one
		}
		diff = ip
	}
	// A point only the payload request has (an added header) is a second
	// difference the baseline cannot be narrowed to.
	for k := range values {
		if !seen[k] && !ignored(k) {
			return nil
		}
	}
	return diff
}
