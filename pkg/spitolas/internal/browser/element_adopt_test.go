package browser

import (
	"os"
	"strings"
	"testing"
)

// TestElementHandlesAreAdoptedOntoTheCrawlContext is a structural guard: every
// *Element handed out by this package must be built through Page.adopt, and
// every frame *Page through Page.adoptFrame, so the handle is rebound to the
// page's crawl-bound context instead of inheriting the lookup's ElementTimeout.
//
// The dependency behavior this exists for:
//
//	func (p *Page) Timeout(d time.Duration) *Page {
//	    ctx, cancel := context.WithTimeout(p.ctx, d)   // DERIVES from p.ctx
//	    ...
//	}
//
// and rod's Page.ElementFromObject copies the querying page's context into every
// element it returns (`ctx: p.ctx`). Together those mean a handle produced by a
// bounded lookup can never be revived by a later Element.Timeout(...) — the
// earlier deadline always wins, because context.WithTimeout only ever shortens.
// The failure that follows is silent: candidate extraction spends several CDP
// round-trips per element and `continue`s on error, so once the shared lookup
// deadline expires the rest of the list is dropped.
//
// Structural rather than behavioral because reproducing the real defect needs a
// live renderer slow enough to outlast a 5s lookup budget mid-list; that belongs
// in the browser integration suite. What can be enforced cheaply and
// deterministically is that no future lookup wrapper reintroduces a raw literal
// and quietly re-inherits the deadline.
func TestElementHandlesAreAdoptedOntoTheCrawlContext(t *testing.T) {
	// Literals that bypass the adoption helpers. Plain substrings, not regexps —
	// neither contains a metacharacter.
	banned := []struct{ needle, helper string }{
		{"&Element{", "Page.adopt"},
		{"&Page{rodPage:", "Page.adoptFrame"},
	}

	for _, file := range []string{"page.go", "element.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}

		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			// A literal quoted in a comment is documentation, not code.
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			// The sanctioned construction sites are the helpers themselves, which
			// are the only lines that rebind a context.
			if strings.Contains(line, ".Context(p.rodPage.GetContext())") {
				continue
			}
			for _, b := range banned {
				if strings.Contains(line, b.needle) {
					t.Errorf("%s:%d constructs %s directly; use %s so the handle is "+
						"rebound to the crawl context instead of inheriting the lookup's "+
						"ElementTimeout:\n\t%s", file, i+1, b.needle, b.helper, trimmed)
				}
			}
		}
	}
}
