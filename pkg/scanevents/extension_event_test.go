package scanevents

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestExtensionFailedFields: extension.failed carries path, stage and an
// explicit flag that is present even when false; other events never show them.
func TestExtensionFailedFields(t *testing.T) {
	var buf bytes.Buffer
	no := false
	New(&buf, "scan-1").Emit(Event{
		Type: TypeExtensionFailed, ModuleID: "ext-a", Path: "/x/a.js",
		Stage: "metadata", Explicit: &no, Message: "boom",
	})
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["path"] != "/x/a.js" || got["stage"] != "metadata" || got["explicit"] != false || got["module_id"] != "ext-a" {
		t.Errorf("extension.failed = %s", buf.String())
	}

	buf.Reset()
	New(&buf, "scan-1").Emit(Event{Type: TypePhaseStarted, Phase: "discovery"})
	for _, key := range []string{"path", "stage", "explicit"} {
		if strings.Contains(buf.String(), `"`+key+`"`) {
			t.Errorf("unset field %q is on the wire: %s", key, buf.String())
		}
	}
}
