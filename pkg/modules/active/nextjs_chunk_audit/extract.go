package nextjs_chunk_audit

import (
	"regexp"
	"sort"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle/sourcemap"
)

var (
	chunkRefRe = regexp.MustCompile(`/_next/static/chunks/[A-Za-z0-9._/\-]+\.js`)

	absoluteURLRe = regexp.MustCompile(`https?://[A-Za-z0-9._\-]+(?:\:[0-9]+)?(?:/[^\s"'<>` + "`" + `\\)]*)?`)
)

func ExtractChunkPaths(body []byte) []string {
	return uniqueSortedMatches(body, chunkRefRe, nil)
}

func ExtractAbsoluteURLs(body []byte) []string {
	return uniqueSortedMatches(body, absoluteURLRe, trimURLTail)
}

// ExtractSourceMapRefs returns the external source-map references in a chunk.
//
// It delegates to the shared extractor so this module, the discovery crawl and
// sourcemap_ingest cannot disagree about what a reference looks like — three
// near-identical regexes previously described the same syntax, and only one of
// them handled the CSS and eval-string forms. Inline data: maps are omitted:
// callers here fetch by URL.
func ExtractSourceMapRefs(body []byte) []string {
	references := sourcemap.ExtractReferences(body)
	if len(references) == 0 {
		return nil
	}
	out := make([]string, 0, len(references))
	for _, reference := range references {
		if reference.URL == "" {
			continue
		}
		out = append(out, reference.URL)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedMatches(body []byte, re *regexp.Regexp, transform func(string) string) []string {
	if len(body) == 0 {
		return nil
	}
	matches := re.FindAll(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		s := string(m)
		if transform != nil {
			s = transform(s)
		}
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func trimURLTail(u string) string {
	for len(u) > 0 {
		last := u[len(u)-1]
		switch last {
		case '.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '"', '`':
			u = u[:len(u)-1]
		default:
			return u
		}
	}
	return u
}
