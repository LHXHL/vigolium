package hosterrors

import "sort"

// HostStatus is a snapshot of one tripped host.
type HostStatus struct {
	Key     string
	State   State
	Errors  int32
	Trips   int32
	LastErr error
}

// Tripped returns a snapshot of every host that has ever opened, sorted by key.
func (c *Cache) Tripped() []HostStatus {
	var out []HostStatus
	c.tripped.Range(func(k, v any) bool {
		it := v.(*cacheItem)
		st := HostStatus{
			Key:    k.(string),
			State:  State(it.state.Load()),
			Errors: it.errors.Load(),
			Trips:  it.trips.Load(),
		}
		if p := it.lastErr.Load(); p != nil {
			st.LastErr = *p
		}
		out = append(out, st)
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
