package yamlschema

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

type inner struct {
	Contains string `yaml:"contains"`
}

type outer struct {
	Name     string            `yaml:"name"`
	Matchers []inner           `yaml:"matchers"`
	Headers  map[string]string `yaml:"headers"`
	Skipped  string            `yaml:"-"`
}

func walk(t *testing.T, src string, opts Options) (known map[string]int, unknown map[string][]string) {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	known, unknown = map[string]int{}, map[string][]string{}
	Walk(doc.Content[0], reflect.TypeOf(outer{}), "", opts, func(path string, key *yaml.Node, k []string) {
		if k == nil {
			known[path] = key.Line
			return
		}
		unknown[path] = k
	})
	return known, unknown
}

func TestWalk(t *testing.T) {
	src := "name: x\nmatchers:\n  - contans: y\nheaders:\n  X-A: b\nNAME: z\n"
	known, unknown := walk(t, src, Options{})
	if known["name"] != 1 || known["matchers"] != 2 || known["headers"] != 4 {
		t.Errorf("known = %v", known)
	}
	if _, ok := known["headers.X-A"]; ok {
		t.Error("map keys visited without MapKeys")
	}
	if got := unknown["matchers[0].contans"]; !reflect.DeepEqual(got, []string{"contains"}) {
		t.Errorf("unknown[matchers[0].contans] = %v", got)
	}
	if got := unknown["NAME"]; !reflect.DeepEqual(got, []string{"headers", "matchers", "name"}) {
		t.Errorf("unknown[NAME] = %v", got)
	}

	known, unknown = walk(t, src, Options{CaseFold: true, MapKeys: true})
	if known["headers.X-A"] != 5 || known["NAME"] != 6 {
		t.Errorf("known = %v", known)
	}
	if _, ok := unknown["NAME"]; ok {
		t.Error("NAME reported unknown under CaseFold")
	}
}

func TestClosest(t *testing.T) {
	known := []string{"contains", "name"}
	if got := Closest("Contans", known, 2); got != "contains" {
		t.Errorf("Closest = %q", got)
	}
	if got := Closest("zzzz", known, 2); got != "" {
		t.Errorf("Closest = %q, want none", got)
	}
}
