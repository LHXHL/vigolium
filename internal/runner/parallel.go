package runner

import (
	"context"
	"sync"
	"sync/atomic"
)

// parallelEach runs fn over items 0..n-1 on up to workers goroutines, handing
// out indexes in order and starting no new item once ctx is done. It returns
// how many items were never started.
func parallelEach(ctx context.Context, n, workers int, fn func(i int)) int64 {
	var next, skipped atomic.Int64
	var wg sync.WaitGroup
	for range min(workers, n) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				if ctx.Err() != nil {
					skipped.Add(1)
					continue
				}
				fn(i)
			}
		}()
	}
	wg.Wait()
	return skipped.Load()
}
