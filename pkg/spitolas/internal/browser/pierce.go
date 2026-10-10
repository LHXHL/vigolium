package browser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// DefaultMaxListenerProbeNodes is the per-state cap on the listener-bearing
// nodes the CDP listener pass turns into click candidates when the caller
// passes 0 (spidering.max_listener_probe_nodes).
const DefaultMaxListenerProbeNodes = 2000

// pierceObjectGroup scopes the remote objects one PierceDOM call creates (the
// document handle and every listener handler DOMDebugger wraps) so they are
// released together.
const pierceObjectGroup = "vgo-pierce"

// clickListenerTypes are the listener types that make an element a click
// candidate (the same rule the script-based pass applied).
var clickListenerTypes = map[string]bool{"click": true}

// pierceSkipTags are never candidates (the script-based XPath pass skipped them
// too).
var pierceSkipTags = map[string]bool{"script": true, "style": true, "noscript": true, "meta": true, "link": true}

// PiercedElement is one element of a pierced DOM snapshot.
type PiercedElement struct {
	BackendNodeID proto.DOMBackendNodeID
	Tag           string // lower-case tag name
	Locator       Locator
}

// PiercedRoot is a closed shadow root found by the snapshot, addressed by the
// backend node id of the root itself.
type PiercedRoot struct {
	BackendNodeID proto.DOMBackendNodeID
	HostChain     []string
}

// PierceSnapshot is the page's element tree as CDP sees it with pierce on:
// light DOM, open and closed shadow roots, and same-origin frame documents
// whose <iframe> sits inside a shadow tree. Frames in a plain document are left
// out — the crawler reaches those as separate frame pages.
type PierceSnapshot struct {
	// Elements are the candidate-eligible elements in document order: light-DOM
	// descendants of <body> plus everything behind a shadow or frame hop,
	// minus script/style/meta-like tags.
	Elements []PiercedElement
	// ClosedRoots are the closed shadow roots, for the selector pass to query.
	ClosedRoots []PiercedRoot

	// ClickListeners are the Elements carrying a click listener, in document
	// order, capped at the probe budget. Nil when listeners were not probed.
	ClickListeners []PiercedElement
	// ListenersProbed is true when the listener probe ran and succeeded.
	ListenersProbed bool
	// ListenerNodesDropped counts listener-bearing elements beyond the cap.
	ListenerNodesDropped int
}

type pierceRootKind int

const (
	pierceRootDocument pierceRootKind = iota
	pierceRootShadow
)

type pierceWalk struct {
	chain     []string
	prefix    string // XPath of the parent under the current root ("" at the root)
	depth     int    // element depth under the current root
	kind      pierceRootKind
	underBody bool
}

// BuildPierceSnapshot flattens a DOM.describeNode{depth:-1, pierce:true} tree
// rooted at a document into a PierceSnapshot. It is pure (no CDP) so the
// locator computation is unit-testable without a browser.
func BuildPierceSnapshot(doc *proto.DOMNode) *PierceSnapshot {
	s := &PierceSnapshot{}
	if doc == nil {
		return s
	}
	s.walkChildren(doc, pierceWalk{kind: pierceRootDocument})
	return s
}

func (s *PierceSnapshot) walkChildren(parent *proto.DOMNode, w pierceWalk) {
	counts := make(map[string]int, 4)
	for _, c := range parent.Children {
		if c == nil || c.NodeType != 1 {
			continue
		}
		counts[c.NodeName]++
		tag := strings.ToLower(c.NodeName)
		path := w.prefix + "/" + tag + "[" + strconv.Itoa(counts[c.NodeName]) + "]"

		if (w.underBody || w.kind == pierceRootShadow) && !pierceSkipTags[tag] {
			pe := PiercedElement{
				BackendNodeID: c.BackendNodeID,
				Tag:           tag,
				Locator:       Locator{InnerXPath: path},
			}
			if len(w.chain) > 0 {
				pe.Locator.HostChain = w.chain
			}
			s.Elements = append(s.Elements, pe)
		}

		child := w
		child.prefix = path
		child.depth = w.depth + 1
		// <body> directly under <html> directly under a document: its
		// descendants are the candidate scope, as in the script-based pass.
		if w.kind == pierceRootDocument && child.depth == 2 && tag == "body" {
			child.underBody = true
		}
		s.walkChildren(c, child)

		hostChain := func() []string {
			hc := make([]string, len(w.chain), len(w.chain)+1)
			copy(hc, w.chain)
			return append(hc, path)
		}
		for _, sr := range c.ShadowRoots {
			if sr == nil || sr.ShadowRootType == proto.DOMShadowRootTypeUserAgent {
				continue
			}
			hc := hostChain()
			if sr.ShadowRootType == proto.DOMShadowRootTypeClosed {
				s.ClosedRoots = append(s.ClosedRoots, PiercedRoot{BackendNodeID: sr.BackendNodeID, HostChain: hc})
			}
			s.walkChildren(sr, pierceWalk{chain: hc, kind: pierceRootShadow})
		}
		// A frame inside a shadow tree: no frame page is ever made for it, so
		// its document is walked here behind a frame hop.
		if c.ContentDocument != nil && w.kind == pierceRootShadow {
			s.walkChildren(c.ContentDocument, pierceWalk{chain: hostChain(), kind: pierceRootDocument})
		}
	}
}

// PierceDOM captures the page's pierced element tree (one DOM.describeNode on
// the page's own document — frame-scoped for a frame page, and unlike
// DOM.getDocument it does not reset the session's node ids). With
// probeListeners it also finds the elements carrying a click listener in one
// DOMDebugger.getEventListeners{depth:-1, pierce:true} call on that document,
// keeping at most maxListenerNodes of them (0 = DefaultMaxListenerProbeNodes,
// negative = no cap). A listener-probe failure is not an error: the snapshot
// comes back with ListenersProbed false so the caller can fall back.
func (p *Page) PierceDOM(probeListeners bool, maxListenerNodes int) (*PierceSnapshot, error) {
	var snap *PierceSnapshot
	err := safeRod("PierceDOM", func() error {
		ctxID, err := p.evalContextID()
		if err != nil {
			return err
		}
		bp := p.boundedPage(0)
		defer func() { _ = proto.RuntimeReleaseObjectGroup{ObjectGroup: pierceObjectGroup}.Call(bp) }()

		docRes, err := proto.RuntimeEvaluate{
			Expression:  "document",
			ContextID:   ctxID,
			ObjectGroup: pierceObjectGroup,
		}.Call(bp)
		if err != nil {
			return err
		}
		if docRes.ExceptionDetails != nil || docRes.Result == nil || docRes.Result.ObjectID == "" {
			return fmt.Errorf("pierce: no document object")
		}
		docObj := docRes.Result.ObjectID

		desc, err := proto.DOMDescribeNode{ObjectID: docObj, Depth: intPtr(-1), Pierce: true}.Call(bp)
		if err != nil {
			return err
		}
		snap = BuildPierceSnapshot(desc.Node)

		if probeListeners {
			res, lerr := proto.DOMDebuggerGetEventListeners{ObjectID: docObj, Depth: intPtr(-1), Pierce: true}.Call(bp)
			if lerr == nil {
				snap.applyListeners(res.Listeners, maxListenerNodes)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// applyListeners records which snapshot elements carry a click listener, in
// document order, keeping the first maxNodes (0 = default, negative = all).
func (s *PierceSnapshot) applyListeners(listeners []*proto.DOMDebuggerEventListener, maxNodes int) {
	if maxNodes == 0 {
		maxNodes = DefaultMaxListenerProbeNodes
	}
	hit := make(map[proto.DOMBackendNodeID]bool)
	for _, l := range listeners {
		if l != nil && l.BackendNodeID != 0 && clickListenerTypes[l.Type] {
			hit[l.BackendNodeID] = true
		}
	}
	s.ListenersProbed = true
	s.ListenerNodesDropped = 0
	s.ClickListeners = make([]PiercedElement, 0, min(len(hit), max(maxNodes, 0)))
	for _, el := range s.Elements {
		if !hit[el.BackendNodeID] {
			continue
		}
		if maxNodes > 0 && len(s.ClickListeners) >= maxNodes {
			s.ListenerNodesDropped++
			continue
		}
		s.ClickListeners = append(s.ClickListeners, el)
	}
}

// pierceQueryJS collects elements matching selector that live behind a shadow
// or frame hop: it walks every open shadow root below its start and every
// same-origin frame whose <iframe> sits in a shadow root (the rule the
// snapshot and locatorOfJS use). collect=false skips matches in the start root
// itself (the page's light DOM, which page.Elements already covers); a closed
// shadow root, invisible to script, is passed in as `this` by the caller.
const pierceQueryJS = `function(selector, collect) {
  const out = [];
  const visit = (root, take) => {
    if (take) {
      let m; try { m = root.querySelectorAll(selector); } catch (e) { m = []; }
      for (const el of m) out.push(el);
    }
    let all; try { all = root.querySelectorAll('*'); } catch (e) { all = []; }
    for (const el of all) {
      if (el.shadowRoot) { visit(el.shadowRoot, true); continue; }
      if (root.nodeType === 11 && (el.tagName === 'IFRAME' || el.tagName === 'FRAME')) {
        let d = null; try { d = el.contentDocument; } catch (e) { d = null; }
        if (d) visit(d, true);
      }
    }
  };
  visit(this && this.nodeType ? this : document, collect);
  return out;
}`

// PiercingElements returns the elements matching selector that sit behind a
// shadow-root or shadow-hosted frame boundary: one script walk over the open
// shadow trees, plus one per closed shadow root in snap (nil snap = open roots
// only). Light-DOM matches are not returned; page.Elements covers those.
// Identify each result with Element.Locator.
func (p *Page) PiercingElements(selector string, snap *PierceSnapshot) ([]*Element, error) {
	var rodElems rod.Elements
	if err := safeRod("PiercingElements", func() error {
		pg := p.rodPage.Timeout(p.config.ElementTimeout)
		open, err := pg.ElementsByJS(rod.Eval(pierceQueryJS, selector, false))
		if err != nil {
			return err
		}
		rodElems = append(rodElems, open...)
		if snap == nil {
			return nil
		}
		for _, root := range snap.ClosedRoots {
			res, rerr := proto.DOMResolveNode{BackendNodeID: root.BackendNodeID}.Call(pg)
			if rerr != nil || res.Object == nil {
				continue
			}
			rootEl, rerr := pg.ElementFromObject(res.Object)
			if rerr != nil {
				continue
			}
			closed, rerr := rootEl.ElementsByJS(rod.Eval(pierceQueryJS, selector, true))
			if rerr != nil {
				continue
			}
			rodElems = append(rodElems, closed...)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	elements := make([]*Element, len(rodElems))
	for i, re := range rodElems {
		elements[i] = p.adopt(re)
	}
	return elements, nil
}

func intPtr(v int) *int { return &v }
