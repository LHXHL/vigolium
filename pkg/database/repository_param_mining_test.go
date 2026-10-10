package database

import (
	"strings"
	"testing"
)

func TestJSFactQueryNames(t *testing.T) {
	doc := `{"source_url":"https://a.test/app.js","httpRequestHint":[
		{"query":[{"name":{"rendered":"debug","static":true}},{"name":{"rendered":"${k}","static":false}}]},
		{"query":[{"name":{"rendered":"token","static":true}}]}]}`
	got := jsFactQueryNames([]byte(doc))
	if strings.Join(got, ",") != "debug,token" {
		t.Errorf("names = %v, want static names only", got)
	}
	if jsFactQueryNames([]byte("not json")) != nil {
		t.Error("garbage should yield no names")
	}
}

func TestByFrequency(t *testing.T) {
	got := byFrequency(map[string]int{"b": 1, "a": 1, "hot": 5})
	if strings.Join(got, ",") != "hot,a,b" {
		t.Errorf("order = %v", got)
	}
}

func TestMarkHiddenParams(t *testing.T) {
	params := []EmbeddedParam{{Name: "q", Type: "url"}, {Name: "debug", Type: "url"}, {Name: "debug", Type: "cookie"}}
	markHiddenParams(params, []string{"debug"})
	if params[0].Hidden || !params[1].Hidden || params[2].Hidden {
		t.Errorf("hidden flags = %+v", params)
	}
}
