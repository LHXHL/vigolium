package contract_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
)

type testRow struct {
	Name  string   `json:"name"`
	Tags  []string `json:"tags"`           // nil marshals as null
	Note  *string  `json:"note,omitempty"` // absent, never null
	Inner *testSub `json:"inner"`
}

type testSub struct {
	N int `json:"n"`
}

type testCurl struct {
	Curl string `json:"curl"`
}

type testExtras struct {
	Count   int    `json:"count"`
	Comment string `json:"comment,omitempty"`
}

type testPayload struct {
	V    int    `json:"v"`
	Type string `json:"type"`
	A    string `json:"a,omitempty"`
	B    string `json:"b,omitempty"`
}

func init() {
	contract.RegisterCommand(contract.Command{Name: "test read", Kind: contract.KindRead, Item: testRow{},
		Variants: []contract.Variant{{Flag: "--curl", Item: testCurl{}}}, Extras: testExtras{}})
	contract.RegisterCommand(contract.Command{Name: "test mutate", Kind: contract.KindMutation, Item: testSub{}})
	contract.RegisterCommand(contract.Command{Name: "test object", Kind: contract.KindRead, Item: testSub{},
		ItemsKind: contract.ItemsObject})
	contract.SetEventPayload(testPayload{}, 3, []string{"v", "type"})
	contract.RegisterEvent("t.one", contract.EventFields{Required: []string{"a"}})
	contract.RegisterEvent("t.bad", contract.EventFields{Optional: []string{"nope"}})
}

func check(t *testing.T, s *contract.Schema, doc string) error {
	t.Helper()
	return contracttest.Check(s, []byte(doc))
}

func envelope(command, kind, items, extra string) string {
	k := ""
	if kind != "" {
		k = `"kind":"` + kind + `",`
	}
	return `{"schema_version":2,"command":"` + command + `",` + k + `"ok":true,"total":1,"offset":0,"limit":1,` +
		`"items":` + items + `,"project_source":"default"` + extra + `}`
}

func TestCommandSchemaValidates(t *testing.T) {
	s, err := contract.CommandSchema("test read")
	if err != nil {
		t.Fatal(err)
	}
	ok := envelope("test read", "read", `[{"name":"a","tags":null,"inner":null},{"curl":"curl x"}]`, `,"count":1`)
	if err := check(t, s, ok); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	for name, doc := range map[string]string{
		"unknown top-level key": envelope("test read", "read", `[]`, `,"count":1,"surprise":1`),
		"missing extra":         envelope("test read", "read", `[]`, ``),
		"wrong command":         envelope("other", "read", `[]`, `,"count":1`),
		"note null":             envelope("test read", "read", `[{"name":"a","tags":[],"inner":null,"note":null}]`, `,"count":1`),
		"unknown item key":      envelope("test read", "read", `[{"name":"a","tags":[],"inner":null,"x":1}]`, `,"count":1`),
		"changed on a read":     envelope("test read", "read", `[]`, `,"count":1,"changed":false`),
		"bad project source":    strings.Replace(envelope("test read", "read", `[]`, `,"count":1`), `"default"`, `"nope"`, 1),
	} {
		if err := check(t, s, doc); err == nil {
			t.Errorf("%s: validated, want rejected", name)
		}
	}
}

func TestMutationAndObjectShapes(t *testing.T) {
	m, err := contract.CommandSchema("test mutate")
	if err != nil {
		t.Fatal(err)
	}
	if err := check(t, m, envelope("test mutate", "mutation", `[]`, ``)); err == nil {
		t.Error("a mutation without changed/action validated")
	}
	if err := check(t, m, envelope("test mutate", "mutation", `[]`, `,"changed":false,"action":"noop"`)); err != nil {
		t.Errorf("mutation rejected: %v", err)
	}

	o, err := contract.CommandSchema("test object")
	if err != nil {
		t.Fatal(err)
	}
	if err := check(t, o, envelope("test object", "read", `[{"n":1},{"n":2}]`, ``)); err == nil {
		t.Error("an object document with two items validated")
	}
}

func TestEventSchemas(t *testing.T) {
	s, err := contract.EventSchema("t.one")
	if err != nil {
		t.Fatal(err)
	}
	if err := check(t, s, `{"v":3,"type":"t.one","a":"x"}`); err != nil {
		t.Errorf("valid event rejected: %v", err)
	}
	for _, doc := range []string{`{"v":3,"type":"t.one"}`, `{"v":3,"type":"t.one","a":"x","b":"y"}`, `{"v":2,"type":"t.one","a":"x"}`} {
		if check(t, s, doc) == nil {
			t.Errorf("%s validated", doc)
		}
	}
	if _, err := contract.EventSchema("t.bad"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("a row naming a key the payload lacks must fail, got %v", err)
	}
}

func TestErrorSchemaEnumeratesCodes(t *testing.T) {
	raw, err := json.Marshal(contract.ErrorSchema())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range apicontract.ErrorCodes() {
		if !strings.Contains(string(raw), `"`+string(c)+`"`) {
			t.Errorf("error schema lacks code %q", c)
		}
	}
	doc := `{"schema_version":2,"command":"x","ok":false,"error":{"code":"usage_error","message":"m","exit_code":2},"generated_at":"t","generated_at_ms":1}`
	if err := check(t, contract.ErrorSchema(), doc); err != nil {
		t.Errorf("valid error rejected: %v", err)
	}
	if check(t, contract.ErrorSchema(), strings.Replace(doc, "usage_error", "made_up", 1)) == nil {
		t.Error("an unknown error code validated")
	}
}
