package stream

import (
	"reflect"
	"testing"
)

func TestSSEEventJSONPayloads(t *testing.T) {
	cases := map[string]struct {
		data string
		want []string
	}{
		"empty":            {"", nil},
		"whitespace":       {"  \n ", nil},
		"single document":  {`{"a":1}`, []string{`{"a":1}`}},
		"done sentinel":    {"[DONE]", []string{"[DONE]"}},
		"pretty JSON kept": {"{\n  \"a\": 1\n}", []string{"{\n  \"a\": 1\n}"}},
		// Single-newline framing: several data: lines folded into one event.
		"folded events": {"{\"a\":1}\n{\"a\":2}\n[DONE]", []string{`{"a":1}`, `{"a":2}`, "[DONE]"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := (&SSEEvent{Data: tc.data}).JSONPayloads()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("JSONPayloads(%q) = %q, want %q", tc.data, got, tc.want)
			}
		})
	}
}
