package spider

import (
	"net/url"
)

// LinkCallback is invoked for each discovered link during extraction.
type LinkCallback func(link *DiscoveredLink)

// DiscoveredLink represents an extracted URL with metadata about its source and type.
type DiscoveredLink struct {
	// SourceType indicates where the link was found (HTML, JavaScript, etc.)
	SourceType LinkSourceType

	// URL is the fully resolved and normalized URL
	URL *url.URL

	// RawURL is the original URL string as it appeared in the source
	RawURL string

	// ResourceType indicates the type of resource (HTML, Image, Script, etc.)
	ResourceType ResourceType

	// StartPos is the byte position in the response body where the link starts
	StartPos int

	// EndPos is the byte position in the response body where the link ends
	EndPos int

	// Element is the HTML tag name if the link was found in HTML (e.g., "a", "img")
	Element string

	// Attribute is the HTML attribute name if applicable (e.g., "href", "src")
	Attribute string
}

// LinkSourceType indicates where a link was discovered.
type LinkSourceType byte

const (
	SourceInlineURL LinkSourceType = iota
	SourceHTMLAttribute
	SourceJavaScript
	SourceComment
	SourceHTTPHeader
	SourceRobotsTxt
	SourceFlashSWF
	SourceMetaRefresh
	SourceEventHandler
	SourceScriptContent
	// SourceSitemap marks a <loc> read from an XML/text sitemap (sitemap.go).
	// Appended last: the numeric value is persisted as extraction source_sub.
	SourceSitemap
)

// String returns the human-readable name of the link source type.
func (t LinkSourceType) String() string {
	switch t {
	case SourceInlineURL:
		return "InlineURL"
	case SourceHTMLAttribute:
		return "HTMLAttribute"
	case SourceJavaScript:
		return "JavaScript"
	case SourceComment:
		return "Comment"
	case SourceHTTPHeader:
		return "HTTPHeader"
	case SourceRobotsTxt:
		return "RobotsTxt"
	case SourceFlashSWF:
		return "FlashSWF"
	case SourceMetaRefresh:
		return "MetaRefresh"
	case SourceEventHandler:
		return "EventHandler"
	case SourceScriptContent:
		return "ScriptContent"
	case SourceSitemap:
		return "Sitemap"
	default:
		return "Unknown"
	}
}

// IsGenuineReference reports whether a link from this source is one the
// application actually references — an HTML attribute, a meta-refresh, an HTTP
// header, a robots.txt entry, or a sitemap <loc>. URL-like strings scavenged from JS/HTML body
// text (the inline scanner, JS string/script/comment/event-handler/SWF
// extractors) are not genuine references: they may be dead constants, library
// data, or legacy path tables baked into a bundle, and are no proof the server
// serves that path.
func (t LinkSourceType) IsGenuineReference() bool {
	switch t {
	case SourceHTMLAttribute, SourceMetaRefresh, SourceHTTPHeader, SourceRobotsTxt, SourceSitemap:
		return true
	default:
		return false
	}
}

// ResourceType indicates the type of resource referenced by a URL.
type ResourceType uint16

const (
	ResourceUnknown ResourceType = 0
	ResourceHTML    ResourceType = 256
	ResourceScript  ResourceType = 259
	ResourceImage   ResourceType = 512
	ResourceJPEG    ResourceType = 513
	ResourceGIF     ResourceType = 514
	ResourcePNG     ResourceType = 515
	ResourceBMP     ResourceType = 516
	ResourceTIFF    ResourceType = 517
	ResourceAudio   ResourceType = 768
	ResourceVideo   ResourceType = 769
	ResourceBinary  ResourceType = 1025
	// ResourceSitemap is an XML/text sitemap document (a robots.txt Sitemap:
	// line or a <sitemapindex> child). Discovery fetches and parses these itself
	// (see ParseSitemap) instead of spidering them as opaque files.
	ResourceSitemap ResourceType = 1026
)

// String returns the human-readable name of the resource type.
func (t ResourceType) String() string {
	switch t {
	case ResourceHTML:
		return "HTML"
	case ResourceScript:
		return "Script"
	case ResourceImage:
		return "Image"
	case ResourceJPEG:
		return "JPEG"
	case ResourceGIF:
		return "GIF"
	case ResourcePNG:
		return "PNG"
	case ResourceBMP:
		return "BMP"
	case ResourceTIFF:
		return "TIFF"
	case ResourceAudio:
		return "Audio"
	case ResourceVideo:
		return "Video"
	case ResourceBinary:
		return "Binary"
	case ResourceSitemap:
		return "Sitemap"
	default:
		return "Unknown"
	}
}
