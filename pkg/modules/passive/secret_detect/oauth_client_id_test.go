package secret_detect

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/secretscan"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// salesforceConsumerKey is the verbatim value from the Zendesk QA / klausapp
// false positive: a Connected App Consumer Key served as one entry in the public
// front-end `window.__CONFIG__` blob, beside the other integration identifiers.
const salesforceConsumerKey = "3MVG9fTLmJ60pJ5KxSmtobJLmmeX3Yr9sJrDKgSb2xhl1znSnx8kH1.e7BbBcInj7bhGxZij011PyyEMAP23X"

func TestIsSalesforceConsumerKey(t *testing.T) {
	tests := []struct {
		name    string
		snippet string
		want    bool
	}{
		{"connected app consumer key", salesforceConsumerKey, true},
		{"consumer key with surrounding space", "  " + salesforceConsumerKey + "  ", true},
		{"consumer secret is not prefixed", "1955279925992207737", false},
		{"unrelated secret", "AKIAIOSFODNN7EXAMPLE", false},
		{"google client id", "1234-abc.apps.googleusercontent.com", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSalesforceConsumerKey(tt.snippet); got != tt.want {
				t.Errorf("IsSalesforceConsumerKey = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPublicOAuthClientID(t *testing.T) {
	tests := []struct {
		name    string
		snippet string
		want    bool
	}{
		{"salesforce consumer key", salesforceConsumerKey, true},
		{"google oauth client id", "1234-abc.apps.googleusercontent.com", true},
		{"aws key is a real secret", "AKIAIOSFODNN7EXAMPLE", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPublicOAuthClientID(tt.snippet); got != tt.want {
				t.Errorf("IsPublicOAuthClientID = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPublicIdentifierRule(t *testing.T) {
	public := []string{
		"Stripe Publishable Key",
		"Mapbox Public Access Token",
		"Auth0 Client ID",
		"Facebook App ID",
		"Microsoft Entra Application Client ID",
		"Supabase Publishable Key",
		"Segment Public API Token",
		"Algolia Application ID",
		"Google Client ID",
		"Lob Publishable API Key",
		"MongoDB API PUBLIC Key",
		"eBay Sandbox Client ID",
		// Client-side SDK keys: the "tokenization key" / "app key" markers, and
		// the two Branch.io families carried by publicIdentifierRuleNames.
		"Braintree Tokenization Key",
		"Pusher Channels App Key",
		"Branch.io Live Key",
		"Branch.io Test Key",
		"branch.io live key", // the curated set is matched case-insensitively
	}
	for _, name := range public {
		t.Run("public/"+name, func(t *testing.T) {
			if !IsPublicIdentifierRule(name) {
				t.Errorf("IsPublicIdentifierRule(%q) = false, want true", name)
			}
		})
	}

	// The sensitive half of every pair, plus ordinary credential families, must
	// keep full severity.
	sensitive := []string{
		"Stripe API Key",
		"Google OAuth Client Secret",
		"AWS Access Key ID",
		"Slack Bot Token",
		"RSA Private Key",
		"Twilio Auth Token",
		"Discord Bot Token",
		"Zhipu (BigModel) API Key",
		// A hypothetical combined rule must not be downgraded on its public half.
		"Acme Client ID and Secret",
		"Acme Public/Private Key Pair",
		// The paired server-side halves of the client-SDK families above.
		"Branch.io Secret",
		"Pusher Channels App Secret",
		// publicIdentifierRuleNames is a whole-name match, so a longer name that
		// merely contains a listed family does not inherit its carve-out.
		"Acme Branch.io Live Key Derivation Token",
	}
	for _, name := range sensitive {
		t.Run("sensitive/"+name, func(t *testing.T) {
			if IsPublicIdentifierRule(name) {
				t.Errorf("IsPublicIdentifierRule(%q) = true, want false", name)
			}
		})
	}
}

func TestPublicIdentifierRuleGradesInfo(t *testing.T) {
	for _, name := range []string{"Stripe Publishable Key", "Auth0 Client ID", "Mapbox Public Access Token"} {
		t.Run(name, func(t *testing.T) {
			sev, conf := SecretFindingSeverity(
				false, false, false, false, false, false, false, false, false, false,
				IsPublicIdentifier(name, "pk_live_51H8xExampleValue0000000000"),
			)
			if sev != severity.Info || conf != severity.Tentative {
				t.Errorf("got %v/%v, want Info/Tentative", sev, conf)
			}
		})
	}
	// A real credential family is untouched by the public-identifier floor.
	sev, _ := SecretFindingSeverity(
		false, false, false, false, false, false, false, false, false, false,
		IsPublicIdentifier("Stripe API Key", pushProtectedFixture(t, "stripe_secret_key")),
	)
	if sev != severity.High {
		t.Errorf("Stripe API Key graded %v, want High", sev)
	}
}

func TestPublicIdentifierDescription(t *testing.T) {
	desc := secretFindingDescription("Stripe Publishable Key", "pk_live_51H8xExampleValue0000000000", `pk_live_[0-9a-zA-Z]{24}`)
	if !strings.Contains(desc, "public half of a credential pair") {
		t.Errorf("description does not explain the public-identifier impact:\n%s", desc)
	}
	if strings.Contains(desc, "Leaked secret detected") {
		t.Errorf("description still uses the generic leaked-secret wording:\n%s", desc)
	}
}

// TestSalesforceConsumerKeyGradesInfo pins the end-to-end outcome: a named
// provider family baselines High, but the public-identifier floor overrides it.
func TestSalesforceConsumerKeyGradesInfo(t *testing.T) {
	sev, conf := SecretFindingSeverity(
		false, false, false, false, false, false, false, false, false, false,
		IsPublicOAuthClientID(salesforceConsumerKey),
	)
	if sev != severity.Info {
		t.Errorf("severity = %v, want Info", sev)
	}
	if conf != severity.Tentative {
		t.Errorf("confidence = %v, want Tentative", conf)
	}
}

func TestSalesforceConsumerKeyLabelAndDescription(t *testing.T) {
	if got := PatternLabel("Salesforce Connected App Consumer Key (Prefixed)", salesforceConsumerKey); got != "Salesforce consumer key (client ID)" {
		t.Errorf("PatternLabel = %q, want the Salesforce client-ID label", got)
	}
	desc := secretFindingDescription("Salesforce Connected App Consumer Key (Prefixed)", salesforceConsumerKey, `\b(3MVG9[A-Za-z0-9._~-]{20,180})\b`)
	if !strings.Contains(desc, "public half of an OAuth client") {
		t.Errorf("description does not explain the public-identifier impact:\n%s", desc)
	}
	if strings.Contains(desc, "Leaked secret detected") {
		t.Errorf("description still uses the generic leaked-secret wording:\n%s", desc)
	}
}

// The client-side SDK keys below are synthetic values shaped to match their
// catalog rules. Both come from the same false positive: a blog served by a
// hosted publishing platform inlined its public front-end config blob into the
// page HTML, and the two integration keys sitting in it graded High while the
// Google client id and reCAPTCHA site key beside them were already floored to
// Info. Neither is a credential — see publicIdentifierRuleNames and the
// "tokenization key" marker for the vendor documentation each rests on.
const (
	braintreeTokenizationKey = "production_qw83hs21_kd94mzp67vbx2r"
	branchLiveKey            = "key_live_hK4mZq8tRw2vNp6xLb3yFc9sJd5g"
)

// publicFrontEndConfig reproduces that blob: the vendor integration identifiers
// a single-page front end cannot boot without, side by side in one JSON object.
const publicFrontEndConfig = `<script>window.__APOLLO_STATE__={"config":` +
	`{"nodeEnv":"production","productName":"Example",` +
	`"authGoogleClientId":"111111111111-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.apps.googleusercontent.com",` +
	`"branchKey":"` + branchLiveKey + `",` +
	`"braintreeClientKey":"` + braintreeTokenizationKey + `",` +
	`"braintree":{"enabled":true,"braintreeEnvironment":"production"}}}</script>`

// TestPublicIdentifierRuleNamesExistInCatalog pins every curated entry to a rule
// the module actually RUNS. These are whole-name matches against a GENERATED
// catalog (`make update-secret-rules`), so an upstream rename would silently drop
// the carve-out and the family would grade High again — the exact false positive
// it fixes. Membership alone is not enough: a rule the catalog carries but ships
// `visible: false` never reaches the detector, so the enabled set is what counts.
func TestPublicIdentifierRuleNamesExistInCatalog(t *testing.T) {
	cat, err := secretscan.LoadCatalog()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	enabled := make(map[string]struct{}, len(cat.Rules))
	present := make(map[string]struct{}, len(cat.Rules))
	for _, r := range cat.Rules {
		name := strings.ToLower(strings.TrimSpace(r.Name))
		present[name] = struct{}{}
		if r.Visible {
			enabled[name] = struct{}{}
		}
	}
	for name := range publicIdentifierRuleNames {
		if _, ok := enabled[name]; !ok {
			t.Errorf("publicIdentifierRuleNames entry %q matches no ENABLED catalog rule — renamed or disabled upstream?", name)
		}
	}

	// Known gap, asserted so it surfaces the day it closes rather than silently:
	// kingfisher carries "Branch.io Secret" (the `secret_live_…` half the Branch
	// key carve-out defers to) but ships it disabled, so vigolium does not detect
	// a leaked Branch secret today. Downgrading the public half is still correct —
	// the key is public regardless — but the pair is not covered end to end.
	if _, ok := present["branch.io secret"]; !ok {
		t.Error(`the "Branch.io Secret" rule is gone from the catalog entirely`)
	}
	if _, ok := enabled["branch.io secret"]; ok {
		t.Log(`"Branch.io Secret" is now enabled upstream — the Branch pair is covered end to end; drop this note`)
	}
}

// TestModule_PublicFrontEndConfigGradesInfo is the end-to-end pin: the whole
// passive path over a real-shaped front-end config blob must report the Braintree
// tokenization key and the Branch key as Info, not High.
func TestModule_PublicFrontEndConfigGradesInfo(t *testing.T) {
	m := New()
	ctx := modtest.HTTPCtx("/test", "text/html; charset=utf-8", publicFrontEndConfig)
	if !m.CanProcess(ctx) {
		t.Fatal("module cannot process the config blob response")
	}
	findings, err := m.ScanPerRequest(ctx, nil)
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}

	graded := map[string]severity.Severity{}
	for _, f := range findings {
		for _, v := range f.ExtractedResults {
			graded[v] = f.Info.Severity
		}
	}
	for label, value := range map[string]string{
		"braintree tokenization key": braintreeTokenizationKey,
		"branch key":                 branchLiveKey,
	} {
		t.Run(label, func(t *testing.T) {
			sev, ok := graded[value]
			if !ok {
				t.Fatalf("no finding for %s (%q) — the detector stopped matching it, so the downgrade is untested", label, value)
			}
			if sev != severity.Info {
				t.Errorf("%s graded %v, want Info", label, sev)
			}
		})
	}
}
