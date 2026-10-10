package jstangle

// ResolvedWorkers reports the worker count and memory budget a service
// configured with workerCount and memoryBudgetBytes runs with (0 = derived from
// the CPUs and usable RAM), exactly as NewService resolves them. Pure: it reads
// the machine's CPU count and RAM and starts nothing, so a scan plan can show
// the shaping before any helper process exists.
func ResolvedWorkers(workerCount int, memoryBudgetBytes int64) (workers int, budgetBytes int64) {
	resolved := resolveServiceConfig(&ServiceConfig{WorkerCount: workerCount, MemoryBudgetBytes: memoryBudgetBytes})
	return resolved.WorkerCount, resolved.MemoryBudgetBytes
}
