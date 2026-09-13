package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

// fixtureAuthRow builds a session row carrying one of every secret-bearing
// field. The values are obvious fakes so a leak is unmistakable in a diff.
func fixtureAuthRow() *database.AuthenticationHostname {
	return &database.AuthenticationHostname{
		ID:          7,
		ProjectUUID: "proj-1",
		Hostname:    "api.example.invalid",
		SessionName: "admin",
		SessionRole: "primary",
		Position:    0,

		SessionToken: "FIXTURE-TOKEN-eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Headers: map[string]string{
			"Authorization": "Bearer FIXTURE-BEARER-VALUE",
			"Cookie":        "sid=FIXTURE-COOKIE-VALUE",
		},
		LoginURL:      "https://api.example.invalid/login",
		LoginMethod:   "POST",
		LoginBody:     `{"username":"admin","password":"FIXTURE-PASSWORD"}`,
		LoginRequest:  "POST /login HTTP/1.1\r\n\r\n{\"password\":\"FIXTURE-PASSWORD\"}",
		LoginResponse: "HTTP/1.1 200 OK\r\nSet-Cookie: sid=FIXTURE-COOKIE-VALUE\r\n\r\n",
		ExtractRules:  `[{"source":"body","name":"token"}]`,
		CreatedAt:     time.Unix(0, 0).UTC(),
		UpdatedAt:     time.Unix(0, 0).UTC(),
	}
}

// fixtureSecrets are the substrings that must never reach stdout unredacted.
var fixtureSecrets = []string{
	"FIXTURE-TOKEN",
	"FIXTURE-BEARER-VALUE",
	"FIXTURE-COOKIE-VALUE",
	"FIXTURE-PASSWORD",
}

func TestAuthSessionViewRedactsEverySecretField(t *testing.T) {
	raw, err := json.Marshal(newAuthSessionViews(
		[]*database.AuthenticationHostname{fixtureAuthRow()}, false))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(raw)

	for _, secret := range fixtureSecrets {
		if strings.Contains(got, secret) {
			t.Errorf("redacted view leaked %q:\n%s", secret, got)
		}
	}
}

func TestAuthSessionViewKeepsIdentifyingFields(t *testing.T) {
	v := newAuthSessionView(fixtureAuthRow(), false)

	if v.Hostname != "api.example.invalid" || v.SessionName != "admin" {
		t.Errorf("identity fields altered: %+v", v)
	}
	// Redaction must not erase the operational facts a caller reads the list for.
	if !v.HasSessionToken || !v.HasLoginBody || !v.HasLoginRequest || !v.HasLoginResponse {
		t.Errorf("presence flags lost: %+v", v)
	}
	if !v.Redacted {
		t.Error("Redacted must be true in the default view")
	}
	if v.SessionTokenFingerprint == "" {
		t.Error("fingerprint must survive redaction so rows stay correlatable")
	}
	// Header names are the debuggable half; values are the leaking half.
	if len(v.HeaderNames) != 2 || v.HeaderNames[0] != "Authorization" || v.HeaderNames[1] != "Cookie" {
		t.Errorf("header names = %v, want sorted [Authorization Cookie]", v.HeaderNames)
	}
	if v.Headers != nil {
		t.Errorf("header values must be dropped when redacted, got %v", v.Headers)
	}
	// Extract rules are a rule definition, not a credential.
	if v.ExtractRules == "" {
		t.Error("extract rules must survive redaction")
	}
}

func TestAuthSessionViewShowSecretsRevealsVerbatim(t *testing.T) {
	row := fixtureAuthRow()
	v := newAuthSessionView(row, true)

	if v.SessionToken != row.SessionToken || v.LoginBody != row.LoginBody {
		t.Error("--show-secrets must return stored values unchanged")
	}
	if v.Headers["Authorization"] != row.Headers["Authorization"] {
		t.Error("--show-secrets must return header values unchanged")
	}
	if v.Redacted {
		t.Error("Redacted must be false when secrets are revealed")
	}
}

func TestSecretFingerprintIsStableAndDistinguishing(t *testing.T) {
	a := secretFingerprint("token-a")
	b := secretFingerprint("token-b")

	if a == "" || a != secretFingerprint("token-a") {
		t.Error("fingerprint must be stable for the same value")
	}
	if a == b {
		t.Error("different tokens must fingerprint differently")
	}
	if secretFingerprint("") != "" {
		t.Error("an absent token has no fingerprint")
	}
	// Short enough to be non-recoverable, long enough not to collide by accident.
	if len(a) != len("sha256:")+12 {
		t.Errorf("fingerprint length = %d, want %d", len(a), len("sha256:")+12)
	}
}

func TestSessionTokenPreviewNeverPrefixesRedactedToken(t *testing.T) {
	row := fixtureAuthRow()

	// A 37-char prefix of a JWT exposes the header and most of the payload, so
	// the redacted table cell is a fingerprint, not a truncation.
	if got := sessionTokenPreview(row.SessionToken, false); strings.Contains(got, "FIXTURE-TOKEN") {
		t.Errorf("redacted preview leaked the token: %q", got)
	}
	if got := sessionTokenPreview("", false); got != "-" {
		t.Errorf("empty token cell = %q, want %q", got, "-")
	}
	if got := sessionTokenPreview(row.SessionToken, true); !strings.HasPrefix(got, "FIXTURE-TOKEN") {
		t.Errorf("revealed preview = %q, want the stored token", got)
	}
}
