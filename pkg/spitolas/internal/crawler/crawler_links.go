package crawler

import (
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/fragment"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// extractFragments extracts fragments from the page.
// Uses the configured fragmentation mode: landmark (default, fast) or vips.
func (c *Crawler) extractFragments(page *browser.Page, s *state.State) {
	var frags []*fragment.Fragment
	var err error

	switch c.config.FragmentationMode {
	case config.FragmentationVIPS:
		vips := fragment.NewVIPS().
			WithPDoC(c.config.VIPSPDoC).
			WithIterations(c.config.VIPSIterations)
		frags, err = vips.Extract(page)
	default: // config.FragmentationLandmark or empty
		extractor := fragment.NewExtractor()
		frags, err = extractor.Extract(page)
	}

	if err != nil {
		zap.L().Debug("Failed to extract fragments", zap.Error(err))
		return
	}

	c.fragManager.AddFragments(s.ID, frags)
	zap.L().Debug("Extracted fragments from state", zap.Int("count", len(frags)), zap.String("state", s.Name), zap.String("mode", string(c.config.FragmentationMode)))
}

// extractLinksFromPage extracts all links from the current page for metrics tracking.
func (c *Crawler) extractLinksFromPage(page *browser.Page) []string {
	if page == nil {
		return nil
	}

	// Use the page's current URL as base
	baseURL, err := page.URL()
	if err != nil || baseURL == "" {
		return nil
	}

	// Extract all anchor hrefs as JSON array
	result, err := page.Eval(`(() => {
		const links = [];
		const anchors = document.querySelectorAll('a[href]');
		for (const a of anchors) {
			const href = a.getAttribute('href');
			if (href && !href.startsWith('javascript:') && !href.startsWith('#')) {
				try {
					const url = new URL(href, window.location.href);
					links.push(url.href);
				} catch (e) {
					// Invalid URL, skip
				}
			}
		}
		return JSON.stringify(links);
	})()`)
	if err != nil {
		return nil
	}

	// Parse result as JSON string
	jsonStr, ok := result.(string)
	if !ok || jsonStr == "" || jsonStr == "<nil>" {
		return nil
	}

	// Parse JSON array
	var links []string
	if err := parseJSONLinks(jsonStr, &links); err != nil {
		return nil
	}

	return links
}

// parseJSONLinks parses a JSON array string into a slice of strings.
func parseJSONLinks(jsonStr string, links *[]string) error {
	// Simple JSON array parsing (avoid importing encoding/json for this)
	// Format: ["url1", "url2", ...]
	if len(jsonStr) < 2 || jsonStr[0] != '[' || jsonStr[len(jsonStr)-1] != ']' {
		return fmt.Errorf("invalid JSON array")
	}

	// Empty array
	if jsonStr == "[]" {
		return nil
	}

	// Remove brackets
	inner := jsonStr[1 : len(jsonStr)-1]

	// Split by comma (simple approach, doesn't handle escaped quotes)
	inQuote := false
	start := 0
	for i := 0; i < len(inner); i++ {
		if inner[i] == '"' {
			inQuote = !inQuote
		} else if inner[i] == ',' && !inQuote {
			s := strings.TrimSpace(inner[start:i])
			if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
				*links = append(*links, s[1:len(s)-1])
			}
			start = i + 1
		}
	}

	// Last element
	s := strings.TrimSpace(inner[start:])
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		*links = append(*links, s[1:len(s)-1])
	}

	return nil
}
