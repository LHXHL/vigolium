package browser

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

func TestLocatorRoundTrip(t *testing.T) {
	cases := []Locator{
		{InnerXPath: "/html[1]/body[1]/div[2]/a[1]"},
		{HostChain: []string{"/html[1]/body[1]/x-card[1]"}, InnerXPath: "/div[1]/button[1]"},
		{HostChain: []string{"/html[1]/body[1]/x-app[1]", "/main[1]/x-menu[3]", "/iframe[1]"}, InnerXPath: "/html[1]/body[1]/a[2]"},
	}
	for _, want := range cases {
		enc := want.String()
		if !IsLocatorSelector(enc) {
			t.Fatalf("encoded locator %q not recognised as a locator selector", enc)
		}
		got, ok := ParseLocator(enc)
		if !ok {
			t.Fatalf("ParseLocator(%q) failed", enc)
		}
		if got.InnerXPath != want.InnerXPath || len(got.HostChain) != len(want.HostChain) {
			t.Fatalf("round trip: got %+v, want %+v", got, want)
		}
		for i := range want.HostChain {
			if got.HostChain[i] != want.HostChain[i] {
				t.Fatalf("round trip hop %d: got %q, want %q", i, got.HostChain[i], want.HostChain[i])
			}
		}
		// Deterministic: re-encoding the parsed value yields the same string
		// (the identification value state identity and dedup key on).
		if again := got.String(); again != enc {
			t.Fatalf("re-encode drifted: %q vs %q", again, enc)
		}
		if got.IsLight() != (len(want.HostChain) == 0) {
			t.Fatalf("IsLight mismatch for %+v", want)
		}
	}
}

func TestLocatorEncodingShape(t *testing.T) {
	l := Locator{HostChain: []string{"/html[1]/body[1]/x-a[1]"}, InnerXPath: "/button[1]"}
	want := `{"hostChain":["/html[1]/body[1]/x-a[1]"],"innerXPath":"/button[1]"}`
	if got := l.String(); got != want {
		t.Fatalf("String() = %s, want %s", got, want)
	}
	// A nil chain still encodes with the prefix Page.Element dispatches on.
	if got := (Locator{InnerXPath: "/html[1]"}).String(); got != `{"hostChain":[],"innerXPath":"/html[1]"}` {
		t.Fatalf("light String() = %s", got)
	}
}

func TestParseLocatorRejectsNonLocators(t *testing.T) {
	for _, s := range []string{
		"", "#id", "/html[1]/body[1]", `[data-vgo-uid="3"]`,
		`{"hostChain":`, `{"hostChain":[],"innerXPath":""}`, `{"other":1}`,
	} {
		if _, ok := ParseLocator(s); ok {
			t.Errorf("ParseLocator(%q) accepted a non-locator", s)
		}
	}
}

func TestLocatorFromSegments(t *testing.T) {
	if _, ok := locatorFromSegments(nil); ok {
		t.Fatal("empty segments (detached element) must not yield a locator")
	}
	l, ok := locatorFromSegments([]string{"/html[1]/body[1]/x-a[1]", "/span[1]"})
	if !ok || !reflect.DeepEqual(l.HostChain, []string{"/html[1]/body[1]/x-a[1]"}) || l.InnerXPath != "/span[1]" {
		t.Fatalf("got %+v ok=%v", l, ok)
	}
	l, ok = locatorFromSegments([]string{"/html[1]/body[1]/a[1]"})
	if !ok || !l.IsLight() || l.InnerXPath != "/html[1]/body[1]/a[1]" {
		t.Fatalf("light: got %+v ok=%v", l, ok)
	}
}

// --- pierced snapshot -------------------------------------------------------

var nextBackendID proto.DOMBackendNodeID

func el(name string, children ...*proto.DOMNode) *proto.DOMNode {
	nextBackendID++
	return &proto.DOMNode{NodeType: 1, NodeName: name, LocalName: name, BackendNodeID: nextBackendID, Children: children}
}

func text() *proto.DOMNode { return &proto.DOMNode{NodeType: 3, NodeName: "#text"} }

func shadow(kind proto.DOMShadowRootType, children ...*proto.DOMNode) *proto.DOMNode {
	nextBackendID++
	return &proto.DOMNode{NodeType: 11, NodeName: "#document-fragment", ShadowRootType: kind, BackendNodeID: nextBackendID, Children: children}
}

func document(children ...*proto.DOMNode) *proto.DOMNode {
	nextBackendID++
	return &proto.DOMNode{NodeType: 9, NodeName: "#document", BackendNodeID: nextBackendID, Children: children}
}

func withShadow(n *proto.DOMNode, roots ...*proto.DOMNode) *proto.DOMNode {
	n.ShadowRoots = roots
	return n
}

func byLocator(s *PierceSnapshot) map[string]PiercedElement {
	out := make(map[string]PiercedElement, len(s.Elements))
	for _, e := range s.Elements {
		out[e.Locator.String()] = e
	}
	return out
}

func TestBuildPierceSnapshotLocators(t *testing.T) {
	openBtn := el("BUTTON")
	closedBtn := el("BUTTON")
	nestedBtn := el("BUTTON")
	frameLink := el("A")
	lightFrameLink := el("A")
	uaInner := el("DIV")

	frameDoc := document(el("HTML", el("HEAD"), el("BODY", text(), frameLink)))
	shadowFrame := el("IFRAME")
	shadowFrame.ContentDocument = frameDoc

	lightFrame := el("IFRAME")
	lightFrame.ContentDocument = document(el("HTML", el("BODY", lightFrameLink)))

	inner := withShadow(el("X-INNER"), shadow(proto.DOMShadowRootTypeOpen, nestedBtn))
	doc := document(
		el("HTML",
			el("HEAD", el("SCRIPT"), el("TITLE")),
			el("BODY",
				el("DIV"),
				el("DIV", el("A"), el("SCRIPT")),
				withShadow(el("X-OPEN"), shadow(proto.DOMShadowRootTypeOpen, el("DIV", openBtn), inner, shadowFrame)),
				withShadow(el("X-CLOSED"), shadow(proto.DOMShadowRootTypeClosed, el("SPAN"), closedBtn)),
				withShadow(el("INPUT"), shadow(proto.DOMShadowRootTypeUserAgent, uaInner)),
				lightFrame,
				el("svg", el("foreignObject")),
			),
		),
	)
	s := BuildPierceSnapshot(doc)
	got := byLocator(s)

	mustHave := func(l Locator, id proto.DOMBackendNodeID, closed bool) {
		t.Helper()
		pe, ok := got[l.String()]
		if !ok {
			t.Fatalf("missing element at %s", l)
		}
		if id != 0 && pe.BackendNodeID != id {
			t.Fatalf("%s: backend id %d, want %d", l, pe.BackendNodeID, id)
		}
		if pe.InClosedShadow != closed {
			t.Fatalf("%s: InClosedShadow=%v, want %v", l, pe.InClosedShadow, closed)
		}
	}
	// Light DOM: absolute XPaths with per-tag sibling indexes, as GetXPath.
	mustHave(Locator{InnerXPath: "/html[1]/body[1]/div[1]"}, 0, false)
	mustHave(Locator{InnerXPath: "/html[1]/body[1]/div[2]/a[1]"}, 0, false)
	mustHave(Locator{InnerXPath: "/html[1]/body[1]/svg[1]/foreignobject[1]"}, 0, false)
	// Open root, nested open root, closed root.
	mustHave(Locator{HostChain: []string{"/html[1]/body[1]/x-open[1]"}, InnerXPath: "/div[1]/button[1]"}, openBtn.BackendNodeID, false)
	mustHave(Locator{HostChain: []string{"/html[1]/body[1]/x-open[1]", "/x-inner[1]"}, InnerXPath: "/button[1]"}, nestedBtn.BackendNodeID, false)
	mustHave(Locator{HostChain: []string{"/html[1]/body[1]/x-closed[1]"}, InnerXPath: "/button[1]"}, closedBtn.BackendNodeID, true)
	// A frame inside a shadow root is walked behind a frame hop.
	mustHave(Locator{HostChain: []string{"/html[1]/body[1]/x-open[1]", "/iframe[1]"}, InnerXPath: "/html[1]/body[1]/a[1]"}, frameLink.BackendNodeID, false)

	for _, pe := range s.Elements {
		switch pe.BackendNodeID {
		case lightFrameLink.BackendNodeID:
			t.Errorf("a light-DOM frame's content must be left to the frame pages: %s", pe.Locator)
		case uaInner.BackendNodeID:
			t.Errorf("user-agent shadow content must be skipped: %s", pe.Locator)
		}
		switch pe.Tag {
		case "script", "head", "html", "title", "body":
			if pe.Locator.IsLight() {
				t.Errorf("light-DOM %s outside <body> descendants or skipped tag emitted: %s", pe.Tag, pe.Locator)
			}
		}
	}
	if len(s.ClosedRoots) != 1 || !reflect.DeepEqual(s.ClosedRoots[0].HostChain, []string{"/html[1]/body[1]/x-closed[1]"}) {
		t.Fatalf("closed roots = %+v", s.ClosedRoots)
	}
	if s.ShadowElements == 0 {
		t.Fatal("ShadowElements not counted")
	}
}

func TestApplyListenersCapAndOrder(t *testing.T) {
	var kids []*proto.DOMNode
	for i := 0; i < 10; i++ {
		kids = append(kids, el("DIV"))
	}
	doc := document(el("HTML", el("BODY", kids...)))
	s := BuildPierceSnapshot(doc)

	var ls []*proto.DOMDebuggerEventListener
	for i := len(kids) - 1; i >= 0; i-- { // reverse: output must still be document order
		ls = append(ls, &proto.DOMDebuggerEventListener{Type: "click", BackendNodeID: kids[i].BackendNodeID})
	}
	ls = append(ls,
		&proto.DOMDebuggerEventListener{Type: "click", BackendNodeID: kids[0].BackendNodeID}, // duplicate listener
		&proto.DOMDebuggerEventListener{Type: "mouseover", BackendNodeID: 999999},
		&proto.DOMDebuggerEventListener{Type: "click", BackendNodeID: 0}, // window/document level
	)

	s.applyListeners(ls, 4)
	if !s.ListenersProbed {
		t.Fatal("ListenersProbed not set")
	}
	if len(s.ClickListeners) != 4 || s.ListenerNodesDropped != 6 {
		t.Fatalf("kept %d dropped %d, want 4/6", len(s.ClickListeners), s.ListenerNodesDropped)
	}
	for i, pe := range s.ClickListeners {
		if want := fmt.Sprintf("/html[1]/body[1]/div[%d]", i+1); pe.Locator.InnerXPath != want {
			t.Fatalf("listener %d at %s, want %s (document order)", i, pe.Locator.InnerXPath, want)
		}
	}

	s.applyListeners(ls, -1)
	if len(s.ClickListeners) != 10 || s.ListenerNodesDropped != 0 {
		t.Fatalf("no cap: kept %d dropped %d, want 10/0", len(s.ClickListeners), s.ListenerNodesDropped)
	}
}

// buildWideTree makes a document of roughly n elements: rows of mixed tags with
// a web component (open root) every 50 rows.
func buildWideTree(n int) *proto.DOMNode {
	var rows []*proto.DOMNode
	count := 0
	for count < n {
		row := el("DIV", el("SPAN", text()), el("A"), el("BUTTON"), el("LI"))
		count += 5
		if len(rows)%50 == 0 {
			row.Children = append(row.Children, withShadow(el("X-WIDGET"), shadow(proto.DOMShadowRootTypeOpen, el("DIV", el("BUTTON")))))
			count += 3
		}
		rows = append(rows, row)
	}
	return document(el("HTML", el("HEAD"), el("BODY", rows...)))
}

// BenchmarkBuildPierceSnapshot5k measures the Go-side cost of flattening a
// 5k-node pierced tree into locators (the per-state work on top of the one
// DOM.describeNode round trip). The Chrome-backed end-to-end benchmark is
// BenchmarkExtractPierced5k (integration tag) in the action package.
func BenchmarkBuildPierceSnapshot5k(b *testing.B) {
	doc := buildWideTree(5000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := BuildPierceSnapshot(doc)
		if len(s.Elements) < 4000 {
			b.Fatalf("only %d elements", len(s.Elements))
		}
	}
}
