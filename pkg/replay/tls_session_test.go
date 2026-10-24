package replay

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/core/network/networktest"
)

// TestDefaultClientResumesTLSSessions: replay and fuzz sends start from
// NewDefaultClient; a reconnect must resume rather than redo the handshake.
func TestDefaultClientResumesTLSSessions(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	networktest.AssertResumes(t, NewDefaultClient(nil, 0))
}
