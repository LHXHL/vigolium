package sqli_boolean_blind

import (
	"regexp"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// The curated, bypass and WAF-evasion payload pairs detect a differential with a
// fixed literal tautology (`1=1` vs `1=2`, `'1'='1` vs `'1'='2`). Re-running those
// exact strings — the old confirmRepeat behaviour — cannot tell a real boolean
// oracle from a deterministic *non-SQL* differential. The textbook false positive:
// a WAF/CDN with a standalone signature for the `1=1` tautology blocks/challenges
// the TRUE branch while letting `1=2` pass, producing a stable, reproducible
// differential that repeat-confirmation happily accepts. (This is exactly the
// Accept-Language `'/**/OR/**/1=1--` finding class: the comment evasion slips past
// the broad `OR \d+=\d+` rule that blocks both plain branches and the entire
// randomized matrix, leaving only the literal `1=1` signature to discriminate.)
//
// confirmRandomized closes that gap by regenerating the matched payload's
// comparison with fresh RANDOM operands while preserving everything around it —
// boundary, token separator, comment terminator, URL-encoding and any WAF-evasion
// mutation already baked into the string. A differential bound to boolean truth
// reproduces (the operator the matched pair used still decides the page); a
// differential bound to the literal `1=1` token vanishes and is rejected. An
// invalid-syntax probe additionally rejects endpoints that ignore SQL validity.

var (
	// operandSingleQuoteRe matches a single-quoted comparison ('1'='1). The
	// trailing operand's closing quote is supplied by the original query, so it is
	// intentionally unanchored on the right.
	operandSingleQuoteRe = regexp.MustCompile(`'\d+'\s*=\s*'\d+`)
	// operandDoubleQuoteRe matches a double-quoted comparison ("1"="1).
	operandDoubleQuoteRe = regexp.MustCompile(`"\d+"\s*=\s*"\d+`)
	// operandNumericRe matches an unquoted numeric comparison (1=1 / 1 = 2). The
	// optional surrounding whitespace tolerates spaced sqlmap-style payloads.
	operandNumericRe = regexp.MustCompile(`\d+\s*=\s*\d+`)
)

// operandRewriter rebuilds the single comparison inside a curated payload with
// arbitrary operands, leaving the surrounding boundary / separator / comment /
// encoding / evasion untouched (it only rewrites the matched span). quote is the
// operand quoting char ("" for numeric), used so the rebuilt comparison keeps the
// same string/numeric typing the original payload relied on.
type operandRewriter struct {
	pre   string
	post  string
	quote string
}

// newOperandRewriter locates the leftmost recognizable comparison in payload.
// Quoted forms are tried before the numeric form so the quoting is captured
// correctly (the numeric regex never matches inside `'1'='1` because the `'`
// breaks the `\d+\s*=\s*\d+` run). ok is false when no comparison is found, in
// which case the caller must not attempt randomized confirmation.
func newOperandRewriter(payload string) (operandRewriter, bool) {
	for _, c := range []struct {
		re    *regexp.Regexp
		quote string
	}{
		{operandSingleQuoteRe, "'"},
		{operandDoubleQuoteRe, "\""},
		{operandNumericRe, ""},
	} {
		if loc := c.re.FindStringIndex(payload); loc != nil {
			return operandRewriter{pre: payload[:loc[0]], post: payload[loc[1]:], quote: c.quote}, true
		}
	}
	return operandRewriter{}, false
}

// boolean renders the comparison with the given operands (left=right), preserving
// the original quoting; the right operand's closing quote, when quoted, comes from
// the surrounding query exactly as the matched payload relied on.
func (r operandRewriter) boolean(left, right string) string {
	if r.quote == "" {
		return r.pre + left + "=" + right + r.post
	}
	return r.pre + r.quote + left + r.quote + "=" + r.quote + right + r.post
}

// invalid renders a malformed expression — two bare literals with no operator —
// which is a syntax error on every SQL dialect. It deliberately drops the quotes
// so adjacent string literals cannot collapse into a valid concatenation.
func (r operandRewriter) invalid(a, b string) string {
	return r.pre + a + " " + b + r.post
}

// confirmRandomized re-derives the matched curated/bypass/WAF differential with
// fresh random operands across confirmRounds rounds and requires it to reproduce,
// then runs an invalid-syntax probe. requireOperands raises the bar: a pair whose
// operands cannot be re-derived is rejected outright rather than falling back to
// repeat-only confirmation. Callers set it for request headers (the
// highest-false-positive boolean-blind surface) and for status oracles (a
// status flip proven only by re-sending the same literal is not a boolean
// oracle). prof fixes each branch's status and the comparator, as in
// confirmLogic.
func (m *Module) confirmRandomized(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	truePayload, falsePayload string,
	requireOperands bool,
	prof branchProfile,
) (bool, error) {
	rw, ok := newOperandRewriter(truePayload)
	if !ok {
		if requireOperands {
			return false, nil
		}
		return m.confirmRepeat(ctx, httpClient, ip, truePayload, falsePayload, prof)
	}

	var trueSigs, falseSigs []responseSignature
	for i := 0; i < confirmRounds; i++ {
		a, b := distinctNums()

		_, tSig, tBlocked, err := m.sendPayload(ctx, httpClient, ip, rw.boolean(a, a))
		if err != nil {
			return false, err
		}
		_, fSig, fBlocked, err := m.sendPayload(ctx, httpClient, ip, rw.boolean(a, b))
		if err != nil {
			return false, err
		}

		// A blocked probe or a status drift is an edge/status artifact, not SQL.
		if tBlocked || fBlocked {
			return false, nil
		}
		// The differential must survive random operands; if TRUE and FALSE now look
		// alike (or left their classified statuses) it was bound to the literal
		// token, not boolean truth — reject.
		if !prof.distinct(tSig, fSig) {
			return false, nil
		}
		trueSigs = append(trueSigs, tSig)
		falseSigs = append(falseSigs, fSig)
	}

	// Each branch must be stable across rounds even though the operands changed —
	// it is the boolean truth value, not the literal tokens, that decides the page.
	if !roundsStable(trueSigs, falseSigs, prof.same) {
		return false, nil
	}

	// Invalid-syntax probe: a malformed expression must NOT render the TRUE page.
	// If it does, the endpoint ignores SQL validity and the differential is spurious.
	c, d := distinctNums()
	_, invSig, invBlocked, err := m.sendPayload(ctx, httpClient, ip, rw.invalid(c, d))
	if err != nil {
		return false, err
	}
	if invBlocked {
		return false, nil
	}
	if prof.same(invSig, trueSigs[0]) {
		return false, nil
	}

	return true, nil
}
