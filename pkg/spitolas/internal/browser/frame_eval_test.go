package browser

import (
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

func TestContextIDFromObjectID(t *testing.T) {
	for _, tc := range []struct {
		id      proto.RuntimeRemoteObjectID
		want    proto.RuntimeExecutionContextID
		wantErr bool
	}{
		{id: "-3978074543916184533.4.3", want: 4},
		{id: "7.12.1", want: 12},
		{id: "", wantErr: true},
		{id: "opaque", wantErr: true},
		{id: "1.x.2", wantErr: true},
		{id: "1.0.2", wantErr: true},
		{id: "1.2.3.4", wantErr: true},
	} {
		got, err := contextIDFromObjectID(tc.id)
		if (err != nil) != tc.wantErr {
			t.Errorf("contextIDFromObjectID(%q) err = %v, wantErr %v", tc.id, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("contextIDFromObjectID(%q) = %d, want %d", tc.id, got, tc.want)
		}
	}
}
