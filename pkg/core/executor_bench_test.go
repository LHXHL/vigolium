package core

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

// sleepyRequestModule is a per-request active module that sleeps for delay on
// items whose path contains "/slow/" and returns at once for every other item.
type sleepyRequestModule struct {
	activeStub
	delay time.Duration
}

func (m *sleepyRequestModule) ScanPerRequest(item *httpmsg.HttpRequestResponse, _ *protohttp.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	if strings.Contains(item.Request().Path(), "/slow/") {
		time.Sleep(m.delay)
	}
	return nil, nil
}

// BenchmarkExecutorHeadOfLine measures throughput when a few items carry a slow
// active task: 1000 items, 5% of them with a 2s task, W=8. With per-item
// g.Wait() every slow item pinned its worker for the whole 2s; with
// dispatch-and-detach the worker returns to the queue and the slow tasks
// overlap under the global active-task budget. Run with -benchtime=1x.
func BenchmarkExecutorHeadOfLine(b *testing.B) {
	const (
		total   = 1000
		slowPct = 5
		workers = 8
	)
	for i := 0; i < b.N; i++ {
		items := make([]*work.WorkItem, total)
		for j := range items {
			path := fmt.Sprintf("/fast/%d", j)
			if j%(100/slowPct) == 0 {
				path = fmt.Sprintf("/slow/%d", j)
			}
			items[j], _ = makeTestItem("bench.example.test", path, "<html>ok</html>")
		}
		mod := &sleepyRequestModule{
			activeStub: activeStub{id: "sleepy", scopes: modules.ScanScopeRequest, canProc: true},
			delay:      2 * time.Second,
		}
		e := NewExecutor(ExecutorConfig{Workers: workers, SkipBaseline: true},
			&sliceSource{items: items}, []modules.ActiveModule{mod}, nil)

		start := time.Now()
		if _, err := e.Execute(context.Background()); err != nil {
			b.Fatalf("Execute: %v", err)
		}
		elapsed := time.Since(start)
		if got := e.Processed(); got != total {
			b.Fatalf("processed %d items, want %d", got, total)
		}
		b.ReportMetric(float64(total)/elapsed.Seconds(), "items/s")
		b.ReportMetric(elapsed.Seconds(), "s/run")
	}
}
