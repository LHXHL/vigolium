package bulkhttp

import "os"

// quic-go log.Printf's a one-time "failed to sufficiently increase receive
// buffer size" line on the first UDP socket of most macOS and default-sized
// Linux hosts. For a scanner that is noise in the middle of its own output
// (the default buffers only cap throughput far above what discovery and fuzz
// run at), so it is silenced unless the operator set the variable themselves.
func init() {
	const env = "QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING"
	if _, set := os.LookupEnv(env); !set {
		_ = os.Setenv(env, "true")
	}
}
