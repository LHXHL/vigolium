package network

// PostDataStats reports the lazy request-body fetches: bodies recovered, fetches
// that failed, and fetches dropped because the queue was full.
func (c *Capture) PostDataStats() (fetched, failed, dropped int64) {
	return c.postDataFetched.Load(), c.postDataFailed.Load(), c.postDataDropped.Load()
}
