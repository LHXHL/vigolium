package crawler

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// tabCloseTimeout caps closing one extra tab at the end of a crawl. Tabs close
// in parallel, so a cancelled crawl with a wedged tab still returns promptly.
const tabCloseTimeout = 5 * time.Second

// tabWorker is one browser tab crawling the shared frontier (Crawljax's
// multi-consumer model). Everything on it is owned by the one goroutine that
// runs the tab; what the tabs share — the state graph, the candidate queue,
// the fragment manager, form/link dedup, stats — stays on Crawler.
type tabWorker struct {
	// id is 0 for the primary tab and 1..tabs-1 for the others (logging).
	id int
	// page is the tab. Set when the tab opens and not replaced afterwards,
	// except on the primary when reset finds no page.
	page *browser.Page
	// stateMachine tracks the state this tab is at; replaced on every reset.
	stateMachine *state.StateMachine
	// crawlPath is the action path since this tab's last reset.
	crawlPath *state.CrawlPath
	// resetCalled decides whether the tab still owes a final reload edge.
	resetCalled bool
	// formHandler fills this tab's forms. Its random source is not safe for
	// concurrent use, so each tab has its own; the fill context is shared.
	formHandler *form.Handler
	// extractor extracts this tab's candidates (ForTab copy on extra tabs).
	extractor *action.CandidateElementExtractor
}

// tabWorkers returns the crawl's tabs, primary first. The extra tabs are opened
// on the first call, once the index state exists; a tab that cannot be opened
// is skipped with a warning and the crawl runs with fewer.
func (c *Crawler) tabWorkers(ctx context.Context) []*tabWorker {
	c.tabsMu.Lock()
	defer c.tabsMu.Unlock()
	if !c.tabsOpened {
		c.tabsOpened = true
		c.openExtraTabsLocked(ctx)
	}
	workers := make([]*tabWorker, 0, 1+len(c.extraTabs))
	workers = append(workers, c.primary)
	return append(workers, c.extraTabs...)
}

// openExtraTabsLocked opens tabs 1..Tabs-1. Must be called with tabsMu held.
func (c *Crawler) openExtraTabsLocked(ctx context.Context) {
	want := c.config.TabsCount()
	if want <= 1 || c.browser == nil || c.primary.stateMachine == nil {
		return
	}
	index := c.graph.GetIndexState()
	if index == nil {
		return
	}
	onURL := c.primary.stateMachine.GetOnURLSet()
	isolated := c.config.TabIsolation == config.TabIsolationContext

	// An isolated tab starts with an empty jar; carry what the first tab has
	// earned so far (a login, a WAF clearance) along with the configured auth.
	var carried []*http.Cookie
	if isolated {
		cookies, err := c.browser.HarvestCookies()
		if err != nil {
			zap.L().Debug("Could not read cookies to carry into isolated tabs", zap.Error(err))
		}
		carried = cookies
	}

	for id := 1; id < want; id++ {
		if ctx.Err() != nil {
			break
		}
		page, err := c.openTabPage(isolated, carried)
		if err != nil {
			zap.L().Warn("Spidering: could not open a crawl tab, continuing with fewer",
				zap.Int("opened", len(c.extraTabs)+1), zap.Int("requested", want), zap.Error(err))
			break
		}
		c.extraTabs = append(c.extraTabs, c.newTabWorker(id, page, index, onURL))
	}
	zap.L().Debug("Crawl tabs open",
		zap.Int("tabs", len(c.extraTabs)+1), zap.Bool("isolated", isolated))
}

// openTabPage opens one extra tab's page and installs the configured auth on
// it (extra headers are per page in CDP; cookies are per browser context).
func (c *Crawler) openTabPage(isolated bool, carried []*http.Cookie) (*browser.Page, error) {
	var page *browser.Page
	var err error
	// A window per tab: a tab hidden behind another in the same window stops
	// rendering, and a click there waits for a repaint that never comes.
	if isolated {
		page, err = c.browser.NewIsolatedPage()
	} else {
		page, err = c.browser.NewWindowPage()
	}
	if err != nil {
		return nil, err
	}
	_ = c.applyPageAuth(page)
	if len(carried) > 0 {
		if err := page.SetCookies(carried); err != nil {
			zap.L().Debug("Could not carry cookies into an isolated tab", zap.Error(err))
		}
	}
	return page, nil
}

// newTabWorker builds an extra tab around page. It starts at no state — the
// page is blank — so its first task resets it to the start URL. It inherits
// the primary's URL-reachable states, which its own resets then extend.
func (c *Crawler) newTabWorker(id int, page *browser.Page, index *state.State, onURL []*state.State) *tabWorker {
	sm := state.NewStateMachineWithOnURLSet(c.graph, index, onURL)
	sm.SetCurrentState(nil)
	handler := form.NewHandler(c.config)
	handler.SetFillContext(c.formHandler.FillContext())
	return &tabWorker{
		id:           id,
		page:         page,
		stateMachine: sm,
		formHandler:  handler,
		extractor:    c.extractor.ForTab(),
	}
}

// extraTabPages returns the extra tabs' pages, which a tab's popup cleanup
// must keep.
func (c *Crawler) extraTabPages() []*browser.Page {
	c.tabsMu.Lock()
	defer c.tabsMu.Unlock()
	pages := make([]*browser.Page, 0, len(c.extraTabs))
	for _, w := range c.extraTabs {
		if w.page != nil {
			pages = append(pages, w.page)
		}
	}
	return pages
}

// closeExtraTabs hands the extra tabs' crawl paths to the session and closes
// their pages in parallel, each capped at tabCloseTimeout. Idempotent; the
// primary page belongs to the browser and is left open. Call only once the
// crawl loops have returned.
func (c *Crawler) closeExtraTabs() {
	c.tabsMu.Lock()
	tabs := c.extraTabs
	c.extraTabs = nil
	c.tabsMu.Unlock()

	var wg sync.WaitGroup
	for _, w := range tabs {
		c.recordCrawlPath(w)
		if w.page == nil {
			continue
		}
		wg.Add(1)
		go func(w *tabWorker) {
			defer wg.Done()
			if err := w.page.CloseWithin(tabCloseTimeout); err != nil {
				zap.L().Debug("Crawl tab close failed", zap.Int("tab", w.id), zap.Error(err))
			}
		}(w)
	}
	wg.Wait()
}

// recordCrawlPath closes w's current crawl path and adds it to the session.
func (c *Crawler) recordCrawlPath(w *tabWorker) {
	if w == nil || w.crawlPath == nil || c.session == nil {
		return
	}
	w.crawlPath.Close()
	c.session.AddCrawlPath(w.crawlPath.ImmutableCopy())
	w.crawlPath = nil
}
