package sqli_boolean_blind

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_SkipsParamAlreadyFoundForClass: a request-scope module
// must honor the cross-module (param, class) registry inside its own
// insertion-point loop — a param another sqli module already confirmed here
// receives no payloads, while --no-param-dedup restores full testing.
func TestScanPerRequest_SkipsParamAlreadyFoundForClass(t *testing.T) {
	t.Parallel()
	var idProbes int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "1" {
			atomic.AddInt32(&idProbes, 1)
		}
		_, _ = fmt.Fprint(w, evalBool(r.URL.Query().Get("id")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")
	scanCtx := &modkit.ScanContext{ParamFindings: &modkit.ParameterFindingRegistry{}}
	scanCtx.MarkParamFound(rr, "id", modkit.VulnClassSQLi)

	res, err := New().ScanPerRequest(rr, client, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, atomic.LoadInt32(&idProbes), "a param pre-marked sqli must not be probed")

	other := &modkit.ScanContext{ParamFindings: &modkit.ParameterFindingRegistry{}, NoParamDedup: true}
	other.ParamFindings.MarkFound(modkit.ParamFindingKey(rr), "id", modkit.VulnClassSQLi)
	res, err = New().ScanPerRequest(rr, client, other)
	require.NoError(t, err)
	assert.NotEmpty(t, res, "--no-param-dedup must test the param anyway")
	assert.NotZero(t, atomic.LoadInt32(&idProbes))
}
