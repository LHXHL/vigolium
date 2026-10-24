package xml_saml_security

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const signedSAML = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
	`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example/</saml:Issuer>` +
	`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
	`<saml:Issuer>https://idp.example/</saml:Issuer>` +
	`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>` +
	`<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>` +
	`</saml:Assertion></samlp:Response>`

// signedAuthnRequest is an SP-signed AuthnRequest — a SAMLRequest sent to an IdP's
// SSO endpoint. It has an <Issuer> and a request-level <Signature> but NO
// <Assertion>: the IdP mints assertions, it does not consume one. Stripping this
// signature is not an authentication bypass. This is the wam.acme.com IdP shape.
const signedAuthnRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
	`Destination="https://idp.example/idp/SSO.saml2" ID="_abc123" Version="2.0">` +
	`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example/prweb/sp/123</saml:Issuer>` +
	`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>` +
	`</samlp:AuthnRequest>`

// samlDecode decodes the SAMLResponse query param the way the module re-encodes it
// (plain base64), tolerating a '+' that a form/query decode turned into a space.
func samlDecode(v string) string {
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(v, " ", "+"))
	if err != nil {
		return ""
	}
	return string(b)
}

// TestSignatureBypass_DetectsStripping: a vulnerable SP validates the assertion
// content (rejecting a wrong-issuer/NameID) but not the signature (accepting the
// signature-stripped assertion) — reported.
func TestSignatureBypass_DetectsStripping(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xml := samlDecode(r.URL.Query().Get("SAMLResponse"))
		if strings.Contains(xml, "vigolium-bogus") { // wrong identity/issuer → reject
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("access denied"))
			return
		}
		w.WriteHeader(http.StatusOK) // accepts regardless of signature presence
		_, _ = w.Write([]byte("Welcome, authenticated user — dashboard"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	value := base64.StdEncoding.EncodeToString([]byte(signedSAML))
	rr := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(value))
	ip := modtest.InsertionPoint(t, rr, "SAMLResponse")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a SAML signature-stripping finding")
	assert.Contains(t, res[0].Info.Name, "Signature Not Verified")
}

// TestSignatureBypass_SecureSP: an SP that rejects an assertion missing its
// signature must not be flagged.
func TestSignatureBypass_SecureSP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xml := samlDecode(r.URL.Query().Get("SAMLResponse"))
		if !strings.Contains(xml, "Signature") || strings.Contains(xml, "vigolium-bogus") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("access denied"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome, authenticated user — dashboard"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	value := base64.StdEncoding.EncodeToString([]byte(signedSAML))
	rr := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(value))
	ip := modtest.InsertionPoint(t, rr, "SAMLResponse")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an SP that rejects unsigned assertions must not be flagged")
}

// TestSignatureBypass_AcceptsEverything: an SP that authenticates regardless of
// assertion content (accepts even the wrong-identity control) is not a signature
// bug — the bogus control suppresses the finding.
func TestSignatureBypass_AcceptsEverything(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome, authenticated user — dashboard"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	value := base64.StdEncoding.EncodeToString([]byte(signedSAML))
	rr := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(value))
	ip := modtest.InsertionPoint(t, rr, "SAMLResponse")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an SP that accepts any assertion (bogus control passes) must not be flagged")
}

// TestSignatureBypass_AuthnRequestSkipped: an IdP SSO endpoint receiving a
// SAMLRequest (AuthnRequest — no assertion) behaves exactly like the vulnerable SP
// mock (accepts the signature-stripped request, "rejects" the garbage-Issuer one),
// but must NOT be flagged: stripping an AuthnRequest's SP signature is not an
// authentication bypass. This is the wam.acme.com/idp/SSO.saml2 false positive.
func TestSignatureBypass_AuthnRequestSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xml := samlDecode(r.URL.Query().Get("SAMLRequest"))
		if strings.Contains(xml, "vigolium-bogus") { // unknown SP Issuer → error
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unknown service provider"))
			return
		}
		w.WriteHeader(http.StatusOK) // IdP login page, regardless of request signature
		_, _ = w.Write([]byte("<html>Sign in to continue</html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	value := base64.StdEncoding.EncodeToString([]byte(signedAuthnRequest))
	rr := modtest.Request(t, srv.URL+"/idp/SSO.saml2?SAMLRequest="+url.QueryEscape(value))
	ip := modtest.InsertionPoint(t, rr, "SAMLRequest")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an AuthnRequest (no assertion) must not be flagged for signature stripping")
}

// TestSignatureBypass_BogusServerErrorNotRejection: the negative (bogus-identity)
// control differs from the accepted baseline only by crashing the server (500),
// not by a deliberate rejection. A 500 means the mutated Issuer/NameID broke
// request processing (an unknown-partner lookup), which says nothing about whether
// the signature is verified — so it must NOT be read as "content validated" and no
// finding is produced. This is the bogus_status=500 shape from wam.acme.com.
func TestSignatureBypass_BogusServerErrorNotRejection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xml := samlDecode(r.URL.Query().Get("SAMLResponse"))
		if strings.Contains(xml, "vigolium-bogus") { // garbage identity → server crash
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("java.lang.NullPointerException"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome, authenticated user — dashboard"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	value := base64.StdEncoding.EncodeToString([]byte(signedSAML))
	rr := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(value))
	ip := modtest.InsertionPoint(t, rr, "SAMLResponse")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 5xx bogus control is a server crash, not a content-validation rejection")
}
