package password_reset_poisoning

import (
	"fmt"
	"regexp"
	"strings"

	httputil "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// injectionType is the OAST finding label. It carries "header" so a callback's
// finding rebuilds the planting request with the poisoned header
// (ParameterName is the header name). The callback is rated by
// oastclass.PasswordResetPoisoning, not by this wording.
const injectionType = "password reset poisoning header"

// maxBodyScan bounds how much of a request body is searched for the reset
// keywords (a GraphQL requestPasswordReset mutation, a JSON action field).
const maxBodyScan = 64 << 10

var (
	// resetRe matches the reset-request step of a password-reset flow in the
	// path or body.
	resetRe = regexp.MustCompile(`(?i)reset|forgot|recover`)
	// emailValueRe recognises an email address as a parameter value.
	emailValueRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// identityTokens are parameter-name tokens that name the account a reset is
// requested for (matched as whole tokens via infra.ParamNameTokens, so
// `user[email]`, `emailAddress` and `login_name` all qualify).
var identityTokens = map[string]bool{
	"email": true, "mail": true, "username": true, "user": true,
	"login": true, "uname": true, "account": true, "identifier": true,
}

// secretTokens mark the reset-completion step (token + new password). Replaying
// it does not send an email, so requests carrying these are skipped.
var secretTokens = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "pass": true,
}

// identityParamTypes are the insertion-point types that carry form/query/JSON
// fields; headers and cookies never name the reset target.
var identityParamTypes = modkit.NewInsertionPointTypeSet(
	httpmsg.INS_PARAM_URL,
	httpmsg.INS_PARAM_BODY,
	httpmsg.INS_PARAM_JSON,
	httpmsg.INS_PARAM_XML,
	httpmsg.INS_PARAM_MULTIPART_ATTR,
)

// routingRejectStatuses are the statuses a front end answers with when an
// overridden Host fails virtual-host routing, used when no recorded response
// is available to compare against.
var routingRejectStatuses = map[int]bool{400: true, 403: true, 404: true, 421: true, 502: true, 503: true, 504: true}

// Module implements the password-reset poisoning active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new password-reset poisoning module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("password_reset_poisoning"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// plant is one poisoned header and the OAST host it carries.
type plant struct {
	variant infra.HostHeaderVariant
	host    string
}

// ScanPerRequest replays a recorded password-reset request once with a unique
// OAST host in each link-building host header. Findings arrive asynchronously
// when the emailed link (or a mail link-scanner) reaches the callback host.
//
// Every replay sends a real reset email, so each endpoint is replayed at most
// once per scan. All poisoned headers ride on that one request, each with its
// own OAST host so a callback names the header the app trusted. Only when the
// overridden Host is rejected by routing (the front end answered with an error
// the recorded exchange did not) is the request re-sent once without the Host
// override; the rejected attempt never reached the reset handler.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) || ctx.Request().Method() == "HEAD" {
		return nil, nil
	}
	if !isResetRequest(urlx.Path, ctx.Request().Body()) {
		return nil, nil
	}
	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil || !hasIdentityParam(points) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	endpointKey := utils.Sha1(fmt.Sprintf("%s|%s|%s", ctx.Request().Method(), urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.Contains(endpointKey) {
		return nil, nil
	}

	// Mint before claiming the endpoint: while OAST registration is still in
	// flight GenerateURL returns "", and the endpoint must stay untested
	// rather than be marked done without a request.
	requestHash := ctx.Request().ID()
	var plants []plant
	for _, v := range infra.LinkHostHeaderVariants() {
		host := modkit.OASTURLFor(oast, oastclass.PasswordResetPoisoning, urlx.String(), v.Header, injectionType, ModuleID, requestHash)
		if host == "" {
			continue
		}
		oast.RecordPayload(host, v.Value(host))
		plants = append(plants, plant{variant: v, host: host})
	}
	if len(plants) == 0 {
		return nil, nil
	}
	if diskSet != nil && diskSet.IsSeen(endpointKey) {
		return nil, nil // another worker claimed this endpoint meanwhile
	}

	resp, err := m.send(ctx, httpClient, plants)
	if err != nil {
		return nil, nil
	}
	rejected := routingRejected(resp, ctx.Response())
	resp.Close()
	if !rejected || plants[0].variant.Header != "Host" || len(plants) == 1 {
		return nil, nil
	}

	// The Host override failed routing, so the reset handler never ran: send
	// the forwarding headers alone, keeping the original Host.
	if resp, err := m.send(ctx, httpClient, plants[1:]); err == nil {
		resp.Close()
	}
	return nil, nil
}

// send replays the recorded request with every plant's header set. Redirects
// are never followed: a Location built from the poisoned host would make the
// scanner itself fetch the callback host and fake a confirmation.
func (m *Module) send(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, plants []plant) (*httputil.ResponseChain, error) {
	raw := ctx.Request().Raw()
	for _, p := range plants {
		next, err := httpmsg.AddOrReplaceHeader(raw, p.variant.Header, p.variant.Value(p.host))
		if err != nil {
			continue
		}
		raw = next
	}
	// raw is well-formed, so wrap directly instead of re-parsing.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	return resp, err
}

// isResetRequest reports whether the path or (bounded) body names the
// reset-request step of a password-reset flow.
func isResetRequest(path string, body []byte) bool {
	if resetRe.MatchString(path) {
		return true
	}
	if len(body) > maxBodyScan {
		body = body[:maxBodyScan]
	}
	return resetRe.Match(body)
}

// hasIdentityParam reports whether the request names an account (an
// email/username field, or any field holding an email address) and is not the
// reset-completion step (which carries a new password).
func hasIdentityParam(points []httpmsg.InsertionPoint) bool {
	found := false
	for _, ip := range points {
		if !identityParamTypes.Contains(ip.Type()) {
			continue
		}
		for _, tok := range infra.ParamNameTokens(ip.Name()) {
			if secretTokens[tok] {
				return false
			}
			if identityTokens[tok] {
				found = true
			}
		}
		if emailValueRe.MatchString(strings.TrimSpace(ip.BaseValue())) {
			found = true
		}
	}
	return found
}

// routingRejected reports whether the poisoned replay was turned away before
// reaching the application: a WAF/challenge page, or an error status the
// recorded exchange did not have. Without a recorded response, the statuses
// front ends use for unknown virtual hosts count as a rejection.
func routingRejected(resp *httputil.ResponseChain, recorded *httpmsg.HttpResponse) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	if infra.IsBlockedResponse(resp) {
		return true
	}
	status := resp.Response().StatusCode
	if recorded != nil && recorded.StatusCode() > 0 {
		return status >= 400 && status != recorded.StatusCode()
	}
	return routingRejectStatuses[status]
}
