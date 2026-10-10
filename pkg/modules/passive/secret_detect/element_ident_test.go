package secret_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestIsElementIdentifierMatch(t *testing.T) {
	drop := []struct{ body, snip string }{
		{`<input id="password2" type="password">`, "password2"},
		{`<input name="password2">`, "password2"},
		{`<label for="password2">`, "password2"},
		{`document.getElementById("password2val")`, "password2val"},
		{`getElementsByName('password3')`, "password3"},
		{`querySelector("loginToken")`, "loginToken"},
		{`v.controltovalidate = "password2";`, "password2"},
		{`createElement(v.default,{name:"password1",label`, "password1"}, // React name prop (':')
		{`createElement("label",{htmlFor:"password1",cls`, "password1"},  // React htmlFor prop (':')
	}
	for _, d := range drop {
		assert.Truef(t, IsElementIdentifierMatch([]byte(d.body), d.snip, -1, -1),
			"%q in %q should read as an element-identifier position", d.snip, d.body)
	}
	// Positions that CAN carry a secret must be left alone — the attribute/function
	// whitelist is the safety boundary.
	keep := []struct{ body, snip string }{
		{`data-api-key="AKIAABCDEF` + `0123456789"`, "AKIAABCDEF" + "0123456789"},
		{`{apiKey:"AIzaSyABCdef"}`, "AIzaSyABCdef"},
		{`content="SECRETTOKENVALUE"`, "SECRETTOKENVALUE"},
		{`password = "hunter2000"`, "hunter2000"},
		{`value="s3cr3tPassword"`, "s3cr3tPassword"},
		{`{password:"password123"}`, "password123"}, // real cred value: key not whitelisted
	}
	for _, k := range keep {
		assert.Falsef(t, IsElementIdentifierMatch([]byte(k.body), k.snip, -1, -1),
			"%q in %q should NOT read as an element-identifier position", k.snip, k.body)
	}
}

func TestIsIdentifierNameReference(t *testing.T) {
	// Identifier-NAME positions — field/state references, not credential values.
	names := []struct{ body, snip string }{
		{`name="ctl00$password2"`, "password2"},         // fragment: preceded by '$'
		{`id="password2req"`, "password2"},              // fragment: followed by 'r'
		{`getElementById("password2val")`, "password2"}, // fragment: followed by 'v'
		{`n.state.password1`, "password1"},              // property access
		{`r=a.password1,userName`, "password1"},         // property access
		{`n.state={password1:"",focused`, "password1"},  // object/state key (unquoted)
		{`{"password1":""}`, "password1"},               // object key (quoted)
		{`case"password2":case"text"`, "password2"},     // switch-case label
	}
	for _, n := range names {
		assert.Truef(t, isIdentifierNameReference([]byte(n.body), n.snip, -1, -1),
			"%q in %q should read as an identifier-name reference", n.snip, n.body)
	}
	// VALUE positions — a genuine weak password used as a credential must survive.
	values := []struct{ body, snip string }{
		{`password:"password123"}`, "password123"},   // credential-value assignment
		{`da="password123",ma=async`, "password123"}, // variable assignment
		{`"password123"===a.pw`, "password123"},      // comparison operand
		{`flag ? "password123" : ""`, "password123"}, // ternary value branch (not a key)
		{`login(u,"password2")`, "password2"},        // call argument
		{`password2 next`, "password2"},              // space-delimited standalone
	}
	for _, v := range values {
		assert.Falsef(t, isIdentifierNameReference([]byte(v.body), v.snip, -1, -1),
			"%q in %q should NOT read as an identifier-name reference (it is a value)", v.snip, v.body)
	}
}

// TestModule_DropsWeakPasswordFieldNames reproduces the acme ASP.NET
// change-password form FP: its `password2`/`password3` field ids and DOM lookups
// were reported as leaked weak passwords. The element-identifier + fragment guards
// now drop them, while a genuine weak password used as a VALUE still surfaces.
func TestModule_DropsWeakPasswordFieldNames(t *testing.T) {
	m := New()

	form := `<form><input name="ctl00$password2" id="password2" type="password">` +
		`<span id="password2req"></span>` +
		`<script>document.getElementById("password2val");getElementsByName("password3");` +
		`n.state={password1:""};var x=a.password1;createElement(d,{name:"password2"});</script></form>`
	ctx := modtest.HTTPCtx("/test", "text/html", form)
	findings, err := m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, findings, "weak-password field/state references must be dropped, got %v", findingValues(findings))

	// A weak password as an actual quoted VALUE (not an element id) still surfaces —
	// this is the hardcoded-credential leak the rule exists to catch.
	leak := `{"email":"admin@example.com","password":"password123"}`
	ctx = modtest.HTTPCtx("/test", "application/json", leak)
	findings, err = m.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "a weak password used as a credential value should still be reported")
}
