package secret_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestIsValueShapeNoise(t *testing.T) {
	tests := []struct {
		name     string
		ruleID   string // set for vigolium.generic.* rules, whose guard scope keys off the id prefix
		ruleName string
		secret   string
		want     bool
	}{
		{
			name:     "reCAPTCHA site key on a non-reCAPTCHA rule is noise",
			ruleName: "Identified an AWS secret access key",
			secret:   "6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZb",
			want:     true,
		},
		{
			name:     "reCAPTCHA-shaped value on the reCAPTCHA rule is NOT dropped here (severity layer handles it)",
			ruleName: "Google reCAPTCHA site key",
			secret:   "6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZb",
			want:     false,
		},
		{
			name:     "HTML/markup fragment is noise",
			ruleName: "Generic Username and Password",
			secret:   `":"1234"}</li>`,
			want:     true,
		},
		{
			// The acme-component-library FP: a Stencil kebab-case attribute name
			// captured by the generic username/password proximity rule.
			name:     "kebab-case UI label slug on the generic credential rule is noise",
			ruleName: "Generic Username and Password",
			secret:   "label-password",
			want:     true,
		},
		{
			name:     "long kebab-case label slug on the generic credential rule is noise",
			ruleName: "Generic Username and Password",
			secret:   "label-unmatched-passwords",
			want:     true,
		},
		{
			name:     "camelCase prop identifier on the generic credential rule is noise",
			ruleName: "Generic Username and Password",
			secret:   "passwordConfirm",
			want:     true,
		},
		{
			name:     "snake_case identifier on the generic password rule is noise",
			ruleName: "Generic Password",
			secret:   "label_password_confirm",
			want:     true,
		},
		{
			// The acme/Salesforce-Aura FP: an Aura PROPERTY binding path captured
			// out of {"exprType":"PROPERTY","path":"v.userRecordStr"} next to a
			// "…Password" target name by the "Generic Password" rule.
			name:     "Aura dotted property path on the generic password rule is noise",
			ruleName: "Generic Password",
			secret:   "v.userRecordStr",
			want:     true,
		},
		{
			name:     "nested Aura property path on the generic password rule is noise",
			ruleName: "Generic Password",
			secret:   "v.translationObject.pageLabel",
			want:     true,
		},
		{
			// pOLD_PASSWORD_ELEM:"currentpassword" — the captured value is the DOM
			// element id / field name, spelling out the keyword itself.
			name:     "field-name keyword value on the generic password rule is noise",
			ruleName: "Generic Password",
			secret:   "currentpassword",
			want:     true,
		},
		{
			// The dotted-path guard is scoped to the generic-credential family: a
			// dotted path captured by a provider-specific rule is left alone.
			name:     "dotted path on a non-generic rule is NOT dropped here",
			ruleName: "Detected a Generic API Key",
			secret:   "v.userRecordStr",
			want:     false,
		},
		{
			// JS object-key capture: the identifier core `skipUserInfo` with a
			// dangling `:` delimiter the tokenizer left attached. A bare camelCase core
			// (no `-`/`_` separator) that does not spell out a credential keyword is no
			// longer dropped by shape — it is indistinguishable from a real weak
			// password like `IamUsedForTesting`, so it now surfaces at the Suspect tier
			// (folded into the per-host suspect bundle) instead of being suppressed.
			name:     "camelCase JS object key without a credential keyword is kept (Suspect)",
			ruleName: "Generic Username and Password",
			secret:   "skipUserInfo:",
			want:     false,
		},
		{
			// Minified-JS capture with a trailing string-escape backslash.
			name:     "camelCase identifier with trailing escape backslash is noise",
			ruleName: "Generic Password",
			secret:   `emailLabelChangeRedColor\`,
			want:     true,
		},
		{
			// Edge-punct trimming is edges-only: a genuinely structured value keeps
			// its interior `:`/`@` and so is NOT reduced to an identifier core.
			name:     "structured value with interior punctuation is kept",
			ruleName: "Generic Username and Password",
			secret:   "user:s3cr3tPass@host",
			want:     false,
		},
		{
			// i18n / CSS label-map pair captured by the generic rule.
			name:     "double-colon label pair on the generic rule is noise",
			ruleName: "Generic Password",
			secret:   "forgot_password::We",
			want:     true,
		},
		{
			// Generated SAP CDC / Gigya screen-set resource id.
			name:     "UI resource id with a long digit run is noise",
			ruleName: "Generic Password",
			secret:   "PASSWORD_21545675329847530_HIDE_TITLE",
			want:     true,
		},
		{
			name:     "gigya dropdown id with a long digit run is noise",
			ruleName: "Generic Password",
			secret:   "gigya-dropdown-26419547197752012",
			want:     true,
		},
		{
			// CSS-selector fragment — caught by the extended non-credential char set
			// (square brackets) regardless of rule family.
			name:     "CSS selector fragment is noise",
			ruleName: "Generic Password",
			secret:   "],input[type=",
			want:     true,
		},
		{
			// Minified-JS operator fragment — caught by the pipe in the char set.
			name:     "JS operator fragment is noise",
			ruleName: "Generic Password",
			secret:   "===g||c.ngTrim&&",
			want:     true,
		},
		{
			// A dotted host / version is not a chain of bare identifiers once a
			// segment starts with a digit.
			name:     "dotted IP-shaped value on the generic password rule is kept",
			ruleName: "Generic Password",
			secret:   "10.0.0.1",
			want:     false,
		},
		{
			// A bare UUID captured next to a token/id keyword is a correlation/request
			// id, not a credential — dropped for the generic-credential family.
			name:     "UUID on the generic credential rule is noise",
			ruleID:   "vigolium.generic.credential.1",
			ruleName: "Generic Credential Assignment",
			secret:   "1c186d04-d14a-424f-8132-0cae8c41435c",
			want:     true,
		},
		{
			// A UUID captured by a provider-specific rule is left alone (the guard is
			// scoped to the generic-credential family).
			name:     "UUID on a provider rule is kept",
			ruleName: "Detected a Generic API Key",
			secret:   "1c186d04-d14a-424f-8132-0cae8c41435c",
			want:     false,
		},
		{
			// A hardcoded Gigya/SAP-CDC apiKey (4_… prefix) is a real key-shaped value,
			// not a code identifier — kept (surfaces as Suspect).
			name:     "opaque apiKey value on the generic credential rule is kept",
			ruleID:   "vigolium.generic.credential.1",
			ruleName: "Generic Credential Assignment",
			secret:   "4_dB6QxkifUgbrmChRVgDE1Q",
			want:     false,
		},
		{
			// A real weak password carrying a digit is not treated as a field-name
			// keyword (the all-letters guard), so it still surfaces as Suspect.
			name:     "weak password with digits containing the keyword is kept",
			ruleName: "Generic Password",
			secret:   "password123",
			want:     false,
		},
		{
			// The slug guard is scoped to the generic-credential family: a clean
			// word-identifier captured by a provider-specific rule is left alone.
			name:     "identifier slug on a non-generic rule is NOT dropped here",
			ruleName: "Detected a Generic API Key",
			secret:   "label-password",
			want:     false,
		},
		{
			// A real low-entropy password with a digit is not an identifier slug.
			name:     "password with a digit on the generic credential rule is kept",
			ruleName: "Generic Username and Password",
			secret:   "hunter2000",
			want:     false,
		},
		{
			// A single unbroken lowercase word has no boundary — kept.
			name:     "single-word lowercase password on the generic rule is kept",
			ruleName: "Generic Password",
			secret:   "correcthorsebattery",
			want:     false,
		},
		{
			name:     "value with whitespace is noise",
			ruleName: "Generic Password",
			secret:   "correct horse battery",
			want:     true,
		},
		{
			// The acme CMS-slug FP: a loose IBM Cloud proximity rule captured an
			// HTML `key-src` image slug as a fake 44-char key and graded it High.
			name:     "hyphenated CMS resource slug on a provider rule is noise",
			ruleName: "IBM Cloud User API Key",
			secret:   "Engineering-Kkk2cg-yaC5K7-5LlHtk-ph-hero-block",
			want:     true,
		},
		{
			// A UUID is hyphenated but all-hex — no pure-letter word segment — so a
			// real UUID secret is NOT mistaken for a resource slug.
			name:     "UUID on a provider rule is kept",
			ruleName: "Generic API Key",
			secret:   "9a6bf21a-4846-4161-ab04-00ff945e5ad3",
			want:     false,
		},
		{
			// A diceware-style passphrase has words but no mixed alnum segment, so the
			// resource-slug guard leaves it (tested on a non-generic rule, since the
			// generic family's kebab-slug guard would drop it anyway).
			name:     "diceware passphrase on a provider rule is kept",
			ruleName: "Generic API Key",
			secret:   "correct-horse-battery-staple",
			want:     false,
		},
		{
			name:     "JS object fragment is noise",
			ruleName: "Detected a Generic API Key",
			secret:   "overrideMbox(1)",
			want:     true,
		},
		{
			name:     "clean opaque token is not noise",
			ruleName: "Generic Password",
			secret:   "Sk9fLp2Qw7Zx4Rt8Yv3Bn6Mc1Ha5Ke",
			want:     false,
		},
		{
			name:     "connection-string-shaped value is not noise (`:` `@` `/` allowed)",
			ruleName: "Generic Database URL",
			secret:   "postgres://user:s3cr3tPass@db.internal:5432/app",
			want:     false,
		},
		{
			name:     "base64 token with trailing padding is not noise",
			ruleName: "Generic API Key",
			secret:   "aGVsbG93b3JsZHNlY3JldA==",
			want:     false,
		},
		{
			name:     "blank value is not noise",
			ruleName: "Generic Password",
			secret:   "   ",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValueShapeNoise(tt.ruleID, tt.ruleName, tt.secret); got != tt.want {
				t.Errorf("IsValueShapeNoise(%q, %q, %q) = %v, want %v", tt.ruleID, tt.ruleName, tt.secret, got, tt.want)
			}
		})
	}
}

func TestIsIdentifierSlug(t *testing.T) {
	// Word-only identifiers with an EXPLICIT '-'/'_' separator — the FP shapes from
	// the compiled acme-component-library bundle.
	slugs := []string{
		"label-password", "label-password-confirm", "label-unmatched-passwords",
		"label_username", "reset-password", "OLD_PASSWORD",
	}
	for _, s := range slugs {
		assert.Truef(t, isIdentifierSlug(s), "%q should read as an identifier slug", s)
	}
	// Not slugs: a digit/symbol carries entropy, there's no separator at all, or it
	// is a bare camelCase word. A separator-less camelCase value (`passwordConfirm`,
	// `AdminUser`, `IamUsedForTesting`) is intentionally NOT a slug now — a real weak
	// password can look exactly like one, so it is left to the keyword-name guard and
	// the Suspect tier rather than dropped by shape (see isIdentifierSlug).
	notSlugs := []string{
		"hunter2", "P@ssw0rd", "Sk9fLp2Qw7Zx4Rt8Yv3Bn6Mc", // digit / symbol
		"admin", "correcthorsebattery", "PASSWORD", // single unbroken word
		"passwordConfirm", "AdminUser", "IamUsedForTesting", // bare camelCase, no separator
		"",
	}
	for _, s := range notSlugs {
		assert.Falsef(t, isIdentifierSlug(s), "%q should NOT read as an identifier slug", s)
	}
}

func TestIsDottedIdentifierPath(t *testing.T) {
	// Chains of word-only identifiers — the Aura/OutSystems/i18n property-path FPs.
	paths := []string{
		"v.userRecordStr", "v.showPdExpired", "v.encryptuserId",
		"v.translationObject", "v.translationObject.pageLabel", "$A.util",
		"OutSystemsUI.model$ErrorMessageRec", "login.loginpage.password",
	}
	for _, s := range paths {
		assert.Truef(t, isDottedIdentifierPath(s), "%q should read as a dotted identifier path", s)
	}
	// Not dotted identifier chains: no dot, a digit-bearing segment (version/IP, or
	// a base64/JWT part — the key guard against mistaking a dotted secret for code),
	// an empty segment, or a segment carrying a non-identifier char.
	notPaths := []string{
		"userRecordStr", "10.0.0.1", "1.5.3", "v.", ".v", "v..x",
		"db.internal:5432", "a.b/c", "a.b2", "obj_1.field",
		"eyJhbG0i.eyJzdW9i.SflKxw2c", // JWT-shaped: digit-bearing base64 segments
		"",
	}
	for _, s := range notPaths {
		assert.Falsef(t, isDottedIdentifierPath(s), "%q should NOT read as a dotted identifier path", s)
	}
}

func TestIsHyphenatedResourceSlug(t *testing.T) {
	slugs := []string{
		"Engineering-Kkk2cg-yaC5K7-5LlHtk-ph-hero-block",
		"hero-block-Ab12cd-view-Zz90yy-option", // 2+ words + mixed segs
	}
	for _, s := range slugs {
		assert.Truef(t, isHyphenatedResourceSlug(s), "%q should read as a resource slug", s)
	}
	notSlugs := []string{
		"9a6bf21a-4846-4161-ab04-00ff945e5ad3",                   // UUID: all-hex, no pure-letter word
		"correct-horse-battery-staple",                           // diceware: no mixed alnum segment
		"AIzaSyACWT" + "6Y3-lpoTMN" + "cqwQqhutbr" + "reMAmQJgU", // one hyphen, <4 segments
		"sk-proj-Abc123def456",                                   // real prefixed key: 3 segments
		"just-two-words",                                         // <4 segments
		"a-b-Cd1-e",                                              // words too short (<3 letters)
		"",
	}
	for _, s := range notSlugs {
		assert.Falsef(t, isHyphenatedResourceSlug(s), "%q should NOT read as a resource slug", s)
	}
}

func TestHasLongDigitRunSegment(t *testing.T) {
	hits := []string{
		"PASSWORD_21545675329847530_HIDE_TITLE", "gigya-dropdown-26419547197752012",
		"LABEL_107033077277870580_LABEL", "TEXTBOX_72105706170970860_PLACEHOLDER",
	}
	for _, s := range hits {
		assert.Truef(t, hasLongDigitRunSegment(s), "%q should carry a long digit-run segment", s)
	}
	misses := []string{
		"password2", "resetPasswordPopUpSubHeading2", "user_id_1",
		"AKIAIOSFODNN7EXAMPLE", "1234567", "abc123def", "",
	}
	for _, s := range misses {
		assert.Falsef(t, hasLongDigitRunSegment(s), "%q should NOT carry a long digit-run segment", s)
	}
}

func TestIsCredentialKeywordName(t *testing.T) {
	// All-letters tokens spelling out a credential keyword — field names / labels.
	names := []string{
		"currentpassword", "oldPassword", "confirmPassword", "userName",
		"confirmUsername", "PASSWORD", "newpasswd",
	}
	for _, s := range names {
		assert.Truef(t, isCredentialKeywordName(s), "%q should read as a credential keyword name", s)
	}
	// Not keyword names: carries a digit/symbol, or contains no keyword.
	notNames := []string{
		"password123", "P@ssw0rd", "current_password", "hunter2",
		"admin", "Sk9fLp2Qw7Zx4Rt8Yv3Bn6Mc", "",
	}
	for _, s := range notNames {
		assert.Falsef(t, isCredentialKeywordName(s), "%q should NOT read as a credential keyword name", s)
	}
}

func TestTrimEdgePunct(t *testing.T) {
	cases := map[string]string{
		"skipUserInfo:":             "skipUserInfo",
		`emailLabelChangeRedColor\`: "emailLabelChangeRedColor",
		`"path":"v.userRecordStr"`:  "path\":\"v.userRecordStr", // only the outer quotes are edges
		"v.userRecordStr":           "v.userRecordStr",          // interior dot preserved, no edges to trim
		"user:pass@host":            "user:pass@host",           // no edge punctuation
		"currentpassword":           "currentpassword",
		"...":                       "",
		"":                          "",
	}
	for in, want := range cases {
		if got := trimEdgePunct(in); got != want {
			t.Errorf("trimEdgePunct(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestModule_ValueShapeGuardDropsGenericMarkup proves the guard drops a
// code/markup-shaped capture from a low-confidence generic rule end-to-end,
// while a clean opaque token in the same generic context still surfaces (as
// Suspect). This is the r2 "Generic Username and Password on page markup" FP.
func TestModule_ValueShapeGuardDropsGenericMarkup(t *testing.T) {
	m := New()

	markup := `{"username":"admin","password":"</b>{tok}</b>"} more text here`
	ctx := modtest.HTTPCtx("/test", "text/html", markup)
	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, findings, "code/markup-shaped generic capture must be dropped, got %v", findingValues(findings))

	clean := `username: admin password: Sk9fLp2Qw7Zx4Rt8Yv3Bn6Mc1Ha5Ke more`
	ctx = modtest.HTTPCtx("/test", "text/html", clean)
	findings, err = m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "a clean opaque token from the same generic rule should still be reported")
	assert.Equal(t, severity.Suspect, findings[0].Info.Severity, "a low-confidence generic match is Suspect, not High")
}

// TestModule_ValueShapeGuardDropsAuraPropertyPath reproduces the acme/Salesforce
// FP: an Aura component descriptor serialises attribute bindings as
// {"exprType":"PROPERTY","path":"v.userRecordStr"} next to a "…Password" target
// name, and lists DOM element ids like pOLD_PASSWORD_ELEM:"currentpassword". The
// "Generic Password" proximity rule captures the dotted property path and the
// field-name keyword — neither a credential — which the value-shape guard drops.
func TestModule_ValueShapeGuardDropsAuraPropertyPath(t *testing.T) {
	m := New()

	aura := `{"exprType":"PROPERTY","target":"c:DLG_Access_ChangePassword","path":"v.userRecordStr"},` +
		`pOLD_PASSWORD_ELEM:"currentpassword",pQUESTION_ELEM:"question"`
	ctx := modtest.HTTPCtx("/test", "text/javascript", aura)
	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, findings, "Aura property path and field-name keyword must be dropped, got %v", findingValues(findings))
}

// TestModule_ValueShapeGuardDropsComponentLabelSlug reproduces the
// acme-component-library FP: a compiled Stencil web-component bundle whose prop
// metadata lists `labelUsername`/`labelPassword` next to their kebab-case
// attribute names. The generic username/password proximity rule captures the
// `label-password` attribute name — a UI identifier, not a credential — which the
// identifier-slug guard now drops.
func TestModule_ValueShapeGuardDropsComponentLabelSlug(t *testing.T) {
	m := New()

	bundle := `qs("acme-login",{labelUsername:[1,"label-username"],labelPassword:[1,"label-password"],labelSubmit:[1,"label-submit"]});`
	ctx := modtest.HTTPCtx("/test", "text/javascript", bundle)
	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, findings, "component-label identifier slug must be dropped, got %v", findingValues(findings))
}
