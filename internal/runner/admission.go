package runner

import (
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// TargetAdmission and TargetVerdict are aliased from pkg/types so callers that
// already import the runner need not import types for them.
type (
	TargetAdmission = types.TargetAdmission
	TargetVerdict   = types.TargetVerdict
)

// AdmitTargets evaluates every CLI target against scope before any request is
// sent, and says which ones the scan will actually reach.
//
// The matcher is built exactly as the runner builds the one the executor
// enforces — config.NewScopeMatcher(scope, targets...) over the full target
// list — so origin mode is computed over the same index and the verdict here is
// the one sendItem will apply. Each target is checked as the executor sees its
// work item: the hostname without port, and the request-target (path plus
// query, "/" when empty).
//
// Exported so pkg/cli can call it before the runner exists. A target that does
// not parse as a URL is admitted: scope cannot evaluate it, and refusing it here
// would hide the real (input) error behind a scope one.
func AdmitTargets(scope config.ScopeConfig, targets []string) TargetAdmission {
	var adm TargetAdmission
	if len(targets) == 0 {
		return adm
	}
	matcher := config.NewScopeMatcher(scope, targets...)
	for _, target := range targets {
		host, path, ok := admissionHostPath(target)
		if !ok {
			adm.Admitted = append(adm.Admitted, target)
			continue
		}
		if rule := matcher.RejectReason(host, path); rule != "" {
			adm.Rejected = append(adm.Rejected, TargetVerdict{Target: target, Host: host, Rule: rule})
			continue
		}
		adm.Admitted = append(adm.Admitted, target)
	}
	return adm
}

// admissionHostPath splits a target into the (host, path) pair the executor's
// pre-send scope check evaluates. A schemeless target gets the same default
// scheme normalizeTargetSchemes gives it.
func admissionHostPath(target string) (host, path string, ok bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", false
	}
	normalized, _ := httpmsg.EnsureURLSchemeTracked(target, httpmsg.DefaultTargetScheme)
	u, err := url.Parse(normalized)
	if err != nil || u.Hostname() == "" {
		return "", "", false
	}
	return u.Hostname(), u.RequestURI(), true
}
