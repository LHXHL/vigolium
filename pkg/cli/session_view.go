package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// A stored session auth config is the densest concentration of live credentials
// vigolium holds: the bearer token it replays, the Authorization/Cookie headers
// it attaches, and the username/password pair it posts to re-login. Serializing
// the bun row straight to stdout under -j published all of it in plaintext, with
// no flag to ask for it and no flag to opt out — and the primary consumer of -j
// is an agent, so the credentials landed in a model transcript.
//
// authSessionView is the public projection: the fields that identify a session
// stay verbatim, and every field that can carry a secret is replaced by a
// presence flag plus a short fingerprint. The fingerprint is what makes the
// redacted form still useful — two rows sharing a token are visibly the same
// token, and a caller can confirm a rotation landed, without the value itself.
//
// --show-secrets reveals the raw row, matching the spelling `config ls` already
// uses for the same decision.
type authSessionView struct {
	ID          int64  `json:"id"`
	ProjectUUID string `json:"project_uuid"`
	ScanUUID    string `json:"scan_uuid,omitempty"`

	Hostname    string `json:"hostname"`
	SessionName string `json:"session_name"`
	SessionRole string `json:"session_role,omitempty"`
	Position    int    `json:"position"`

	// SessionToken is the redaction marker, never the token. Callers keying off
	// "does this host have a session" read HasSessionToken; callers correlating
	// two rows read SessionTokenFingerprint.
	SessionToken            string `json:"session_token,omitempty"`
	HasSessionToken         bool   `json:"has_session_token"`
	SessionTokenFingerprint string `json:"session_token_fingerprint,omitempty"`

	// Headers carries the header NAMES only when redacted. The names are the
	// useful half for debugging ("is Authorization attached at all?") and the
	// values are the half that leaks.
	Headers     map[string]string `json:"headers,omitempty"`
	HeaderNames []string          `json:"header_names,omitempty"`

	LoginURL         string `json:"login_url,omitempty"`
	LoginMethod      string `json:"login_method,omitempty"`
	LoginContentType string `json:"login_content_type,omitempty"`

	// LoginBody holds the credentials posted to the login endpoint, and
	// LoginRequest/LoginResponse embed that body plus the Set-Cookie the server
	// answered with. Redacted these become booleans: their presence is the
	// operational fact, their content never needs to reach stdout.
	LoginBody        string `json:"login_body,omitempty"`
	LoginRequest     string `json:"login_request,omitempty"`
	LoginResponse    string `json:"login_response,omitempty"`
	HasLoginBody     bool   `json:"has_login_body"`
	HasLoginRequest  bool   `json:"has_login_request"`
	HasLoginResponse bool   `json:"has_login_response"`

	// ExtractRules is a rule definition, not a secret, so it survives verbatim.
	ExtractRules string `json:"extract_rules,omitempty"`

	Source     string     `json:"source,omitempty"`
	HydratedAt *time.Time `json:"hydrated_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`

	// Redacted states which form this object is in, so a consumer never has to
	// infer it from whether a value happens to look like a placeholder.
	Redacted bool `json:"redacted"`
}

// newAuthSessionViews projects rows for display. reveal=true returns the stored
// values unchanged; the caller is responsible for having warned the operator.
func newAuthSessionViews(rows []*database.AuthenticationHostname, reveal bool) []authSessionView {
	out := make([]authSessionView, 0, len(rows))
	for _, r := range rows {
		if r == nil {
			continue
		}
		out = append(out, newAuthSessionView(r, reveal))
	}
	return out
}

func newAuthSessionView(r *database.AuthenticationHostname, reveal bool) authSessionView {
	v := authSessionView{
		ID:               r.ID,
		ProjectUUID:      r.ProjectUUID,
		ScanUUID:         r.ScanUUID,
		Hostname:         r.Hostname,
		SessionName:      r.SessionName,
		SessionRole:      r.SessionRole,
		Position:         r.Position,
		LoginURL:         r.LoginURL,
		LoginMethod:      r.LoginMethod,
		LoginContentType: r.LoginContentType,
		ExtractRules:     r.ExtractRules,
		Source:           r.Source,
		HydratedAt:       r.HydratedAt,
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,

		HasSessionToken:  r.SessionToken != "",
		HasLoginBody:     r.LoginBody != "",
		HasLoginRequest:  r.LoginRequest != "",
		HasLoginResponse: r.LoginResponse != "",
		Redacted:         !reveal,
	}

	if reveal {
		v.SessionToken = r.SessionToken
		v.Headers = r.Headers
		v.LoginBody = r.LoginBody
		v.LoginRequest = r.LoginRequest
		v.LoginResponse = r.LoginResponse
		return v
	}

	if v.HasSessionToken {
		v.SessionToken = clicommon.SecretPlaceholder
		v.SessionTokenFingerprint = secretFingerprint(r.SessionToken)
	}
	if v.HasLoginBody {
		v.LoginBody = clicommon.SecretPlaceholder
	}
	if v.HasLoginRequest {
		v.LoginRequest = clicommon.SecretPlaceholder
	}
	if v.HasLoginResponse {
		v.LoginResponse = clicommon.SecretPlaceholder
	}
	v.HeaderNames = sortedHeaderNames(r.Headers)
	return v
}

// secretFingerprint is a short, stable digest of a secret: enough to tell two
// values apart or confirm they match, not enough to recover either. It is a
// plain SHA-256 prefix with no salt on purpose — the point is that the same
// token fingerprints identically across rows, runs, and machines.
func secretFingerprint(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

// sortedHeaderNames lists header names in a stable order. Values are dropped;
// an Authorization or Cookie value is the secret the whole view exists to keep
// off stdout.
func sortedHeaderNames(h map[string]string) []string {
	if len(h) == 0 {
		return nil
	}
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})
	return names
}

// sessionTokenPreview renders the token cell of the human table. Redacted it is
// a fingerprint rather than a prefix of the value: a 37-character prefix of a
// JWT already exposes the header and most of the payload, which is not a
// "preview" in any useful sense.
func sessionTokenPreview(token string, reveal bool) string {
	if token == "" {
		return "-"
	}
	if !reveal {
		return secretFingerprint(token)
	}
	if len(token) > 40 {
		return token[:37] + "..."
	}
	return token
}
