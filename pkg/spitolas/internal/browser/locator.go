package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// Locator addresses an element that may sit behind one or more shadow-root or
// frame boundaries. An XPath cannot cross a shadow boundary, so the path is cut
// at each one:
//
//   - HostChain[0] is the absolute XPath of the outermost host in the page's
//     document ("/html[1]/body[1]/x-card[1]").
//   - Each later HostChain entry is the XPath of the next host relative to the
//     previous host's shadow root (or, for an <iframe> host, its document).
//   - InnerXPath is the element's XPath relative to the last root.
//
// Every step is "tag[n]", n counting earlier element siblings with the same tag
// — the same shape Element.GetXPath produces — so a locator is structural and
// stable across reloads, unlike a data-vgo-uid tag stamped in query order.
//
// A locator with an empty HostChain is a plain light-DOM XPath. The crawler
// keeps identifying light-DOM elements by that bare XPath (HowXPath), so state
// identity, form caches and MAB arms are unchanged for them; only elements
// behind a boundary use the encoded locator as their identification value.
type Locator struct {
	HostChain  []string `json:"hostChain"`
	InnerXPath string   `json:"innerXPath"`
}

// locatorPrefix is how an encoded Locator starts. Page.Element recognises a
// selector with this prefix and resolves it with ElementByLocator, so every
// caller that re-resolves an identification value as a selector (the click
// path, crawl-path replay, hover) handles locators without a separate branch.
const locatorPrefix = `{"hostChain":`

// IsLight reports whether the locator addresses a light-DOM element (no shadow
// or frame hop), i.e. InnerXPath alone is the element's absolute XPath.
func (l Locator) IsLight() bool { return len(l.HostChain) == 0 }

// String encodes the locator as compact JSON. The encoding is deterministic
// (fixed field order, no whitespace) because it is the identification value the
// crawl keys state identity and dedup on.
func (l Locator) String() string {
	chain := l.HostChain
	if chain == nil {
		chain = []string{}
	}
	b, err := json.Marshal(Locator{HostChain: chain, InnerXPath: l.InnerXPath})
	if err != nil {
		return ""
	}
	return string(b)
}

// ParseLocator decodes an encoded Locator. ok is false for anything that is not
// one (a CSS selector, an XPath, a malformed value).
func ParseLocator(s string) (Locator, bool) {
	if !IsLocatorSelector(s) {
		return Locator{}, false
	}
	var l Locator
	if err := json.Unmarshal([]byte(s), &l); err != nil || l.InnerXPath == "" {
		return Locator{}, false
	}
	return l, true
}

// IsLocatorSelector reports whether a selector string is an encoded Locator.
func IsLocatorSelector(s string) bool {
	return strings.HasPrefix(s, locatorPrefix)
}

// locatorFromSegments turns locatorOfJS output (host paths then the inner path)
// into a Locator. ok is false for an empty result (a detached element).
func locatorFromSegments(segs []string) (Locator, bool) {
	if len(segs) == 0 || segs[len(segs)-1] == "" || segs[len(segs)-1] == "/" {
		return Locator{}, false
	}
	l := Locator{InnerXPath: segs[len(segs)-1]}
	if len(segs) > 1 {
		l.HostChain = append([]string(nil), segs[:len(segs)-1]...)
	}
	return l, true
}

// locatorWalkJS resolves a "/tag[n]/tag[n]" path from `this` (a Document, a
// ShadowRoot, or an element) by walking element children. document.evaluate
// cannot take a ShadowRoot as its context, so the steps are matched by hand,
// with the same tag-and-index rule GetXPath uses to build them.
const locatorWalkJS = `function(path) {
  let cur = this;
  const steps = path.split('/').filter(Boolean);
  if (!steps.length) return null;
  for (const step of steps) {
    const m = /^(.+)\[(\d+)\]$/.exec(step);
    if (!m) return null;
    const tag = m[1], want = +m[2];
    let n = 0, found = null;
    for (let c = cur.firstElementChild; c; c = c.nextElementSibling) {
      if (c.tagName.toLowerCase() === tag && ++n === want) { found = c; break; }
    }
    if (!found) return null;
    cur = found;
  }
  return cur;
}`

// locatorEnterJS steps from a host into the root its children live under: the
// open shadow root, or a same-origin frame's document. null means a closed
// shadow root (invisible to script), which the caller opens through CDP.
const locatorEnterJS = `function() {
  if (this.shadowRoot) return this.shadowRoot;
  const t = this.tagName;
  if (t === 'IFRAME' || t === 'FRAME') { try { return this.contentDocument; } catch (e) { return null; } }
  return null;
}`

// locatorOfJS computes `this` element's locator segments: the XPath of each
// host, outermost first, then the element's XPath under the last root. It walks
// up through shadow roots (getRootNode().host works from inside a closed root
// too) and through a frame document whose <iframe> sits in a shadow tree — the
// frames the page-level frame recursion cannot see. A frame document whose
// <iframe> is in a plain document is the page's own root (the crawler reaches
// those frames as separate frame pages), so the walk stops there. A detached
// element yields [].
const locatorOfJS = `function() {
  const step = (el) => {
    let i = 1;
    for (let s = el.previousElementSibling; s; s = s.previousElementSibling) if (s.tagName === el.tagName) i++;
    return el.tagName.toLowerCase() + '[' + i + ']';
  };
  const segs = [];
  let parts = [];
  let cur = this;
  while (true) {
    if (!cur) return [];
    if (cur.nodeType === 1) { parts.unshift(step(cur)); cur = cur.parentNode; continue; }
    segs.unshift('/' + parts.join('/'));
    parts = [];
    if (cur.nodeType === 11 && cur.host) { cur = cur.host; continue; }
    if (cur.nodeType === 9) {
      let fe = null;
      try { fe = cur.defaultView && cur.defaultView.frameElement; } catch (e) { fe = null; }
      if (fe) {
        const r = fe.getRootNode();
        if (r && r.nodeType === 11 && r.host) { cur = fe; continue; }
      }
    }
    break;
  }
  return segs;
}`

// errLocatorMiss marks a locator that did not resolve on this attempt (the
// element is not, or not yet, in the DOM), as opposed to a CDP failure.
var errLocatorMiss = errors.New("locator did not resolve")

// Locator returns the element's locator: a light-DOM element gets an empty
// HostChain and its absolute XPath, one inside a shadow tree gets the host
// chain it sits behind. The light-DOM InnerXPath equals GetXPath.
func (e *Element) Locator() (Locator, error) {
	res, err := e.boundedElem().Eval(locatorOfJS)
	if err != nil {
		return Locator{}, err
	}
	arr := res.Value.Arr()
	segs := make([]string, 0, len(arr))
	for _, v := range arr {
		segs = append(segs, v.Str())
	}
	l, ok := locatorFromSegments(segs)
	if !ok {
		return Locator{}, fmt.Errorf("element has no locator (detached?)")
	}
	return l, nil
}

// ElementByLocator resolves a Locator to a live element, crossing open shadow
// roots and same-origin frames by script and closed shadow roots through CDP
// (DOM.describeNode exposes a closed root; DOM.resolveNode hands it back as an
// object a script can walk). Like Element, it waits up to ElementTimeout for
// the element to appear.
func (p *Page) ElementByLocator(loc Locator) (*Element, error) {
	if loc.InnerXPath == "" {
		return nil, fmt.Errorf("empty locator")
	}
	deadline := time.Now().Add(firstPositiveDuration(p.config.ElementTimeout, 5*time.Second))
	for {
		var found *rod.Element
		err := safeRod("ElementByLocator", func() (e error) {
			found, e = p.resolveLocatorOnce(loc)
			return e
		})
		if err == nil && found != nil {
			return p.adopt(found), nil
		}
		if err == nil {
			err = errLocatorMiss
		}
		if !errors.Is(err, errLocatorMiss) || time.Now().After(deadline) || p.crawlCtxDone() {
			return nil, fmt.Errorf("element not found by locator %s: %w", loc, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// resolveLocatorOnce makes one attempt at resolving loc. A step that finds
// nothing returns errLocatorMiss so the caller can retry until the deadline.
func (p *Page) resolveLocatorOnce(loc Locator) (*rod.Element, error) {
	pg := p.boundedPage(p.config.ElementTimeout).Sleeper(rod.NotFoundSleeper)
	root, err := pg.ElementByJS(rod.Eval(`() => document`))
	if err != nil {
		return nil, err
	}
	for _, hop := range loc.HostChain {
		host, herr := root.ElementByJS(rod.Eval(locatorWalkJS, hop))
		if herr != nil {
			return nil, missOr(herr)
		}
		isFrame, ferr := host.Eval(`() => this.tagName === 'IFRAME' || this.tagName === 'FRAME'`)
		if ferr != nil {
			return nil, ferr
		}
		if isFrame.Value.Bool() {
			// Continue inside the frame's own page, so the element is bound
			// to the frame's JS world: rod's click checks (element at point,
			// containment) pass objects between the page and the element,
			// and CDP refuses objects from two different worlds.
			fp, fpErr := host.Frame()
			if fpErr != nil {
				return nil, missOr(fpErr)
			}
			next, nerr := fp.Sleeper(rod.NotFoundSleeper).ElementByJS(rod.Eval(`() => document`))
			if nerr != nil {
				return nil, missOr(nerr)
			}
			root = next
			continue
		}
		next, nerr := host.ElementByJS(rod.Eval(locatorEnterJS))
		if nerr != nil {
			// A closed shadow root: script sees host.shadowRoot as null, CDP does
			// not.
			next, nerr = host.ShadowRoot()
			if nerr != nil {
				return nil, missOr(nerr)
			}
		}
		root = next
	}
	el, err := root.ElementByJS(rod.Eval(locatorWalkJS, loc.InnerXPath))
	if err != nil {
		return nil, missOr(err)
	}
	return el, nil
}

// missOr maps rod's "nothing there" errors to errLocatorMiss and passes any
// other failure through.
func missOr(err error) error {
	var notFound *rod.ElementNotFoundError
	var noShadow *rod.NoShadowRootError
	var notElem *rod.ExpectElementError
	if errors.As(err, &notFound) || errors.As(err, &noShadow) || errors.As(err, &notElem) {
		return errLocatorMiss
	}
	return err
}

// ElementByBackendNodeID resolves a CDP backend node id (from a pierced DOM
// snapshot) to a live element. It reaches nodes in closed shadow roots, which
// no selector or script can.
func (p *Page) ElementByBackendNodeID(id proto.DOMBackendNodeID) (*Element, error) {
	var rodElem *rod.Element
	if err := safeRod("ElementByBackendNodeID", func() error {
		bp := p.boundedPage(p.config.ElementTimeout)
		res, err := proto.DOMResolveNode{BackendNodeID: id}.Call(bp)
		if err != nil {
			return err
		}
		rodElem, err = bp.ElementFromObject(res.Object)
		return err
	}); err != nil {
		return nil, err
	}
	return p.adopt(rodElem), nil
}
