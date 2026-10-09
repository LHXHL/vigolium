package sqli_boolean_blind

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
)

// statusMode is how a baseline/TRUE/FALSE status triplet may be read as a
// boolean differential.
type statusMode int

const (
	// modeReject: the triplet cannot carry a boolean signal (TRUE left the
	// baseline status, a 5xx, an auth/WAF/rate-limit status, a login redirect,
	// or a status class boolean-blind never trusts).
	modeReject statusMode = iota
	// modeSameStatus: all three share one eligible status (200/200/200,
	// 201/201/201, a 404-with-body triplet, a 302 triplet with a body). The
	// content differential decides, exactly as it always did for 200 triplets.
	modeSameStatus
	// modeStatusOracle: baseline and TRUE share a 2xx status while FALSE returns
	// a different, non-auth, non-5xx status — the row-found / row-missing split
	// expressed as a status code. Confirmed by status alone, behind extra controls.
	modeStatusOracle
)

func (m statusMode) String() string {
	switch m {
	case modeSameStatus:
		return "same-status"
	case modeStatusOracle:
		return "status-oracle"
	default:
		return "reject"
	}
}

// syntaxBreakSuffix is appended to the base value for the status-oracle
// syntax-break control: it unbalances single quotes, double quotes and a
// parenthesis at once, so it is malformed SQL in any string or numeric context.
const syntaxBreakSuffix = `'")`

// isAuthOrThrottleStatus reports statuses that are an auth gate, a proxy auth
// challenge, a WAF refusal or a rate limit. None of them is application output
// that a SQL condition selected.
func isAuthOrThrottleStatus(code int) bool {
	switch code {
	case 401, 403, 407, 429:
		return true
	}
	return false
}

// statusEligible reports whether a response's status can anchor a
// boolean-blind differential: any 2xx; a 3xx with a body that is not a login
// redirect; a 4xx with a body that is not an auth/WAF/rate-limit status. 1xx,
// 5xx and empty 3xx/4xx responses carry nothing a content differential can use.
func statusEligible(sig responseSignature, location string) bool {
	s := sig.StatusCode
	switch {
	case s >= 200 && s < 300:
		return true
	case s >= 300 && s < 400:
		return sig.BodyLength > 0 && !authzutil.IsLoginRedirect(s, location)
	case s >= 400 && s < 500:
		return sig.BodyLength > 0 && !isAuthOrThrottleStatus(s)
	}
	return false
}

// classifyStatusPair decides how the baseline/TRUE/FALSE triplet is judged.
// The location arguments are each response's Location header (empty when
// absent), used to spot login redirects.
func classifyStatusPair(base, tru, fal responseSignature, baseLoc, trueLoc, falseLoc string) statusMode {
	if tru.StatusCode != base.StatusCode {
		return modeReject // TRUE must keep the original row's status
	}
	if !statusEligible(base, baseLoc) || !statusEligible(tru, trueLoc) {
		return modeReject
	}
	if fal.StatusCode == base.StatusCode {
		if !statusEligible(fal, falseLoc) {
			return modeReject
		}
		return modeSameStatus
	}

	// Status flip. Only a 2xx row-found page against a FALSE status that an
	// application plausibly returns for "no row" can be an oracle.
	if base.StatusCode < 200 || base.StatusCode >= 300 {
		return modeReject
	}
	f := fal.StatusCode
	switch {
	case f < 200, f >= 500:
		return modeReject
	case isAuthOrThrottleStatus(f):
		return modeReject
	case authzutil.IsLoginRedirect(f, falseLoc):
		return modeReject
	}
	return modeStatusOracle
}

// comparator reports whether two responses are "the same page" for a boolean
// differential: the per-branch stability check across confirmation rounds and
// the invalid-syntax probe both use it.
type comparator func(a, b responseSignature) bool

// sameStatus is the status-oracle comparator: two responses match when their
// status codes match, whatever the body says.
func sameStatus(a, b responseSignature) bool { return a.StatusCode == b.StatusCode }

// branchProfile is what each confirmation round demands of a TRUE/FALSE pair:
// the status each branch must return and the comparator deciding whether two
// responses match.
type branchProfile struct {
	trueStatus  int
	falseStatus int
	same        comparator
}

// contentProfile judges a same-status triplet: both branches keep status and
// the body ratio decides (ratioSimilar is status-aware).
func contentProfile(status int) branchProfile {
	return branchProfile{trueStatus: status, falseStatus: status, same: ratioSimilar}
}

// statusOracleProfile judges a status flip: each branch must return its own
// status and the status alone tells them apart.
func statusOracleProfile(trueStatus, falseStatus int) branchProfile {
	return branchProfile{trueStatus: trueStatus, falseStatus: falseStatus, same: sameStatus}
}

// isStatusOracle reports whether the profile tells branches apart by status.
func (p branchProfile) isStatusOracle() bool { return p.trueStatus != p.falseStatus }

// distinct reports whether a TRUE/FALSE pair returned the expected statuses and
// the two responses are distinguishable under the profile's comparator.
func (p branchProfile) distinct(t, f responseSignature) bool {
	return t.StatusCode == p.trueStatus && f.StatusCode == p.falseStatus && !p.same(t, f)
}

// locationOf returns the Location header from a full raw response string
// (status line + headers + body), or "" when there is none.
func locationOf(fullResp string) string {
	rest := fullResp
	// Skip the status line.
	if i := strings.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[i+1:]
	} else {
		return ""
	}
	for rest != "" {
		line := rest
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		line = strings.TrimRight(line, "\r")
		if line == "" {
			return "" // end of the header block
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "location") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
