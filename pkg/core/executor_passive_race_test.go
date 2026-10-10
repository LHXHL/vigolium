package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
)

// paramIteratingPassiveModule mimics the passive modules (sensitive_url_params,
// openredirect_params, ...) that walk the item's ordered query params.
type paramIteratingPassiveModule struct {
	trackingPassiveModule
}

func (m *paramIteratingPassiveModule) ScanPerRequest(item *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.called.Add(1)
	for i := 0; i < 20; i++ {
		urlx, err := item.URL()
		if err != nil {
			return nil, err
		}
		urlx.Params.Iterate(func(string, []string) bool { return true })
		_ = urlx.Clone()
		_ = item.Target()
	}
	return nil, nil
}

// TestParallelPassiveModulesShareItemURL runs several param-iterating passive
// modules concurrently over one item (parallel_passive). Under -race this
// failed while HttpRequest.URL() handed every module the same cached URL,
// whose OrderedParams.Iterate writes internal state.
func TestParallelPassiveModulesShareItemURL(t *testing.T) {
	var mods []modules.PassiveModule
	var tracked []*paramIteratingPassiveModule
	for i := 0; i < 8; i++ {
		m := &paramIteratingPassiveModule{trackingPassiveModule{id: fmt.Sprintf("param-iter-%d", i)}}
		mods = append(mods, m)
		tracked = append(tracked, m)
	}
	e, _ := newTestExecutor(ExecutorConfig{ParallelPassive: true}, mods)

	item, _ := makeTestItem("example.com", "/search?q=1&next=%2Fhome&token=abc", "<html>x</html>")
	e.processItem(context.Background(), item)

	for _, m := range tracked {
		if m.called.Load() == 0 {
			t.Fatalf("module %s was not run", m.id)
		}
	}
}
