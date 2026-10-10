package jsext

import (
	"regexp"
	"strings"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
)

func newOASTVM(t *testing.T, svc *oast.Service) *sobek.Runtime {
	t.Helper()
	vm := sobek.New()
	_ = vm.Set("vigolium", vm.NewObject())
	registerFuncs(vm, APIOptions{OASTService: svc, ScriptID: "t"}, oastFuncDefs())
	return vm
}

func TestOASTURL(t *testing.T) {
	// Fixed-URL mode is enabled without any network registration.
	svc, err := oast.New(&config.OASTConfig{Enabled: true, OastURL: "cb.example.test"}, nil, nil, "", "", nil)
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	vm := newOASTVM(t, svc)

	v, err := vm.RunString(`vigolium.oast.url({class: "ssrf", target: "http://t/", param: "next"})`)
	require.NoError(t, err)
	assert.Equal(t, "cb.example.test", v.String())

	v, err = vm.RunString(`vigolium.oast.url()`)
	require.NoError(t, err)
	assert.Equal(t, "cb.example.test", v.String())

	_, err = vm.RunString(`vigolium.oast.url({class: "rce"})`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown class "rce"`)
}

func TestOASTURLUnavailable(t *testing.T) {
	// A service that never registered: valid classes yield null, unknown ones
	// still throw so a typo is not hidden by an offline run.
	vm := newOASTVM(t, &oast.Service{})

	v, err := vm.RunString(`vigolium.oast.url({class: "xxe"})`)
	require.NoError(t, err)
	assert.True(t, sobek.IsNull(v))

	_, err = vm.RunString(`vigolium.oast.url({class: "nope"})`)
	require.Error(t, err)
}

func TestLintSource_OASTClass(t *testing.T) {
	src := `
var a = vigolium.oast.url({class: "ssrf", target: ctx.url});
var b = vigolium.oast.url({ target: ctx.url, class: 'rce' });
// vigolium.oast.url({class: "commented"})
`
	res := LintSource(src, "t.js")
	var oastIssues []LintIssue
	for _, is := range res.Issues {
		if strings.Contains(is.Message, "OAST class") {
			oastIssues = append(oastIssues, is)
		}
	}
	require.Len(t, oastIssues, 1, "issues: %+v", res.Issues)
	assert.Equal(t, LintError, oastIssues[0].Severity)
	assert.Equal(t, 3, oastIssues[0].Line)
	assert.Contains(t, oastIssues[0].Message, `"rce"`)
}

// TestDTSOASTClassUnion keeps the d.ts OASTClass union in sync with
// oastclass.All().
func TestDTSOASTClassUnion(t *testing.T) {
	src := TypeDefinitions()
	start := strings.Index(src, "type OASTClass =")
	require.GreaterOrEqual(t, start, 0, "vigolium.d.ts has no OASTClass type")
	end := strings.Index(src[start:], ";")
	require.Greater(t, end, 0)
	var got []string
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(src[start:start+end], -1) {
		got = append(got, m[1])
	}
	assert.Equal(t, oastclass.Names(), got)
}
