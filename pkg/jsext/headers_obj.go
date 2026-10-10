package jsext

import (
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/jsext/jsheaders"
)

// newHeadersObject returns the JS header object used for every header map the
// extension API exposes: case-insensitive property access, lowercase keys in
// first-occurrence order, repeated headers joined with ", " (set-cookie reads
// as the last value), and get/getAll/has/entries/raw on its prototype. The
// implementation lives in pkg/jsext/jsheaders so pkg/yamlext can share it.
func newHeadersObject(vm *sobek.Runtime, hs []httpmsg.HttpHeader) *sobek.Object {
	return jsheaders.New(vm, hs)
}

// headersArg flattens a script-supplied headers value (a plain object or a
// header object) into the map used to build an outgoing request, merging
// names case-insensitively.
func headersArg(vm *sobek.Runtime, v sobek.Value) map[string]string {
	return jsheaders.ToMap(vm, v)
}

// mapHasHeader reports whether m holds name, compared case-insensitively.
func mapHasHeader(m map[string]string, name string) bool {
	for k := range m {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}
