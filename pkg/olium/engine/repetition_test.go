package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func TestDegenerateRepetition(t *testing.T) {
	loop := strings.Repeat("Wait, I'll call them.\n\nActually, I'll call them.\n\n", 60)
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"two-line loop after a real preamble", "I will enumerate the API first.\n" + loop, true},
		{"single sentence loop, no newlines", strings.Repeat("I'll call them. ", 200), true},
		{"short text", "Wait, I'll call them.\n", false},
		{"divider rule is not a loop", "Summary\n" + strings.Repeat("-", 4000), false},
		{"box drawing is not a loop", strings.Repeat("─", 2000), false},
		{"varied table rows", tableRows(200), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := degenerateRepetition(tc.in); got != tc.want {
				t.Fatalf("degenerateRepetition = %v, want %v", got, tc.want)
			}
		})
	}
}

func tableRows(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "| /api/v1/users/%d | GET | 200 |\n", i)
	}
	return b.String()
}

func TestTrimRepetitionKeepsPreambleAndOneCopy(t *testing.T) {
	unit := "Wait, I'll call them.\n\nActually, I'll call them.\n\n"
	s := "I will enumerate the API first.\n" + strings.Repeat(unit, 60)
	p, ok := degenerateRepetition(s)
	if !ok {
		t.Fatal("loop not detected")
	}
	got := trimRepetition(s, p)
	if !strings.HasPrefix(got, "I will enumerate the API first.\n") {
		t.Fatalf("preamble lost: %q", got)
	}
	if n := strings.Count(got, "Actually, I'll call them."); n != 1 {
		t.Fatalf("kept %d copies of the loop, want 1: %q", n, got)
	}
	if !strings.Contains(got, "[output cut") {
		t.Fatalf("missing cut marker: %q", got)
	}
}

// A model stuck in a loop streams until the server's output ceiling, which on
// Ollama is unlimited. The engine must cut the response itself, keep the run
// alive, and commit only one copy of the loop to history.
func TestEngine_CutsDegenerateLoopingStream(t *testing.T) {
	disconnected := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(disconnected)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for {
			for _, line := range []string{"Wait, I'll call them.\n\n", "Actually, I'll call them.\n\n"} {
				chunk, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": line}}}})
				if _, err := fmt.Fprintf(w, "data: %s\n\n", chunk); err != nil {
					return
				}
			}
			if flusher != nil {
				flusher.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}))
	defer srv.Close()

	eng := New(Config{
		Provider: provider.NewOpenAICompatible(srv.URL+"/v1", "", nil, nil),
		Tools:    tool.NewRegistry(),
		Model:    "test-model",
		MaxTurns: 3,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := drainEngine(t, eng.Run(ctx, "go"), 10*time.Second)
	if !got.runDone || got.errMsg != "" {
		t.Fatalf("want a clean run end, got runDone=%v err=%q", got.runDone, got.errMsg)
	}
	select {
	case <-disconnected:
	case <-time.After(5 * time.Second):
		t.Fatal("engine never dropped the looping stream")
	}
	hist := eng.History()
	last := hist[len(hist)-1]
	if last.Role != provider.RoleAssistant || !strings.Contains(last.Text, "[output cut") {
		t.Fatalf("history should end with the cut assistant turn, got %#v", last)
	}
	if n := strings.Count(last.Text, "Actually, I'll call them."); n > 1 {
		t.Fatalf("history kept %d copies of the loop", n)
	}
}
