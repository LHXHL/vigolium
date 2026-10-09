package browser

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"go.uber.org/zap"
)

// Stealth (spidering.stealth) removes the automation markers a trivial bot wall
// checks for: the enable-automation switch, navigator.webdriver, an empty
// plugin list, a "HeadlessChrome" client-hint brand, and so on. Without it such
// a wall serves the crawler a challenge page and the crawl reports an empty
// application — a false negative. It is not an evasion feature: anything that
// fingerprints harder than this still sees an automated browser.
//
// Three layers, all gated on config.StealthEnabled:
//   - launcher flags (applyStealthFlags)
//   - an init script registered per page (stealth.js, installStealth)
//   - User-Agent client hints on the per-page UA override (stealthUserAgentMetadata)

//go:embed stealth.js
var stealthScriptSource string

// stealthOptsPlaceholder is the marker in stealth.js that stealthScript
// replaces with the JSON options object.
const stealthOptsPlaceholder = "/*__VGO_STEALTH_OPTS__*/ {}"

// defaultAcceptLanguage is the Accept-Language every page presents. The
// stealth script derives navigator.languages from it so the two agree.
const defaultAcceptLanguage = "en-US,en;q=0.9"

// stealthOptions is the JSON object stealth.js reads.
type stealthOptions struct {
	Languages     []string `json:"languages"`
	Headless      bool     `json:"headless"`
	WebGLVendor   string   `json:"webglVendor,omitempty"`
	WebGLRenderer string   `json:"webglRenderer,omitempty"`
}

// stealthScript renders stealth.js with opts.
func stealthScript(opts stealthOptions) string {
	raw, err := json.Marshal(opts)
	if err != nil {
		raw = []byte("{}")
	}
	return strings.Replace(stealthScriptSource, stealthOptsPlaceholder, string(raw), 1)
}

// stealthOptionsFor builds the script options for a browser on goos/goarch.
func stealthOptionsFor(headless bool, goos, goarch string) stealthOptions {
	vendor, renderer := webGLIdentity(goos, goarch)
	return stealthOptions{
		Languages:     acceptLanguageList(defaultAcceptLanguage),
		Headless:      headless,
		WebGLVendor:   vendor,
		WebGLRenderer: renderer,
	}
}

// webGLIdentity is the WebGL vendor/renderer pair a common GPU on goos/goarch
// reports through ANGLE. It replaces only a software (SwiftShader) renderer.
func webGLIdentity(goos, goarch string) (vendor, renderer string) {
	switch {
	case goos == "darwin" && goarch == "arm64":
		return "Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)"
	case goos == "darwin":
		return "Google Inc. (Intel Inc.)", "ANGLE (Intel Inc., Intel(R) UHD Graphics 630, OpenGL 4.1)"
	case goos == "windows":
		return "Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)"
	default:
		return "Google Inc. (Intel)", "ANGLE (Intel, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.6)"
	}
}

// acceptLanguageList turns an Accept-Language header into the ordered tag
// list navigator.languages reports ("en-US,en;q=0.9" → [en-US en]).
func acceptLanguageList(header string) []string {
	var out []string
	for _, part := range strings.Split(header, ",") {
		tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if tag != "" && tag != "*" {
			out = append(out, tag)
		}
	}
	return out
}

// applyStealthFlags drops the launcher switches that announce automation:
// enable-automation (rod's default; it sets navigator.webdriver and shows the
// "controlled by automated test software" bar) and the AutomationControlled
// blink feature.
func applyStealthFlags(l *launcher.Launcher) *launcher.Launcher {
	l = l.Delete("enable-automation")
	if !hasFlagValue(l, "disable-blink-features", "AutomationControlled") {
		l = l.Append("disable-blink-features", "AutomationControlled")
	}
	return l
}

// appendDisableFeatures adds features to the launcher's disable-features list
// without dropping what is already there. rod's launcher.New carries
// site-per-process and TranslateUI in it; a Set would have replaced them.
func appendDisableFeatures(l *launcher.Launcher, features ...string) *launcher.Launcher {
	for _, f := range features {
		if !hasFlagValue(l, "disable-features", f) {
			l = l.Append("disable-features", f)
		}
	}
	return l
}

// hasFlagValue reports whether a comma-list flag already carries value.
func hasFlagValue(l *launcher.Launcher, name flags.Flag, value string) bool {
	vals, _ := l.GetFlags(name)
	for _, v := range vals {
		for _, item := range strings.Split(v, ",") {
			if item == value {
				return true
			}
		}
	}
	return false
}

// stealthUserAgentMetadata is the client-hint metadata (navigator.userAgentData,
// Sec-CH-UA*) for the browser whose Browser.getVersion product is product
// ("HeadlessChrome/131.0.6778.85" or "Chrome/…"). The brand list is the one a
// normal Chrome of that version sends — no "HeadlessChrome" brand. nil when the
// version cannot be parsed, which leaves Chrome's own hints in place.
func stealthUserAgentMetadata(product, goos, goarch string) *proto.EmulationUserAgentMetadata {
	_, full, ok := strings.Cut(product, "/")
	if !ok {
		return nil
	}
	majorStr, _, _ := strings.Cut(full, ".")
	major, err := strconv.Atoi(majorStr)
	if err != nil || major <= 0 {
		return nil
	}
	brands, fullList := chromeBrandVersionLists(major, full)
	platform, arch := clientHintPlatform(goos, goarch)
	return &proto.EmulationUserAgentMetadata{
		Brands:          brands,
		FullVersionList: fullList,
		FullVersion:     full,
		Platform:        platform,
		PlatformVersion: "",
		Architecture:    arch,
		Model:           "",
		Mobile:          false,
		Bitness:         "64",
	}
}

// chromeBrandVersionLists reproduces Chromium's brand-list GREASE
// (components/embedder_support/user_agent_utils.cc): the "Not A Brand" name,
// its version and the order of the three entries are all a function of the
// major version, so the list matches what a normal Chrome of that version
// sends.
func chromeBrandVersionLists(major int, full string) (brands, fullList []*proto.EmulationUserAgentBrandVersion) {
	greaseyChars := []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greasedVersions := []string{"8", "99", "24"}
	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}

	greaseBrand := "Not" + greaseyChars[major%len(greaseyChars)] + "A" + greaseyChars[(major+1)%len(greaseyChars)] + "Brand"
	greaseVersion := greasedVersions[major%len(greasedVersions)]
	order := orders[major%len(orders)]
	majorStr := strconv.Itoa(major)

	build := func(grease, chromium, chrome string) []*proto.EmulationUserAgentBrandVersion {
		list := make([]*proto.EmulationUserAgentBrandVersion, 3)
		list[order[0]] = &proto.EmulationUserAgentBrandVersion{Brand: greaseBrand, Version: grease}
		list[order[1]] = &proto.EmulationUserAgentBrandVersion{Brand: "Chromium", Version: chromium}
		list[order[2]] = &proto.EmulationUserAgentBrandVersion{Brand: "Google Chrome", Version: chrome}
		return list
	}
	return build(greaseVersion, majorStr, majorStr), build(greaseVersion+".0.0.0", full, full)
}

// clientHintPlatform maps GOOS/GOARCH to Sec-CH-UA-Platform and
// Sec-CH-UA-Arch values. The UA string itself already names the real OS, so
// the hints must name the same one.
func clientHintPlatform(goos, goarch string) (platform, arch string) {
	switch goos {
	case "darwin":
		platform = "macOS"
	case "windows":
		platform = "Windows"
	default:
		platform = "Linux"
	}
	arch = "x86"
	if strings.HasPrefix(goarch, "arm") {
		arch = "arm"
	}
	return platform, arch
}

// installStealth registers the stealth init script for every document the
// page loads from now on. Best-effort: a failure is logged and the crawl
// continues with the launcher-level stealth only.
func (p *Page) installStealth(opts stealthOptions) {
	if _, err := p.rodPage.EvalOnNewDocument(stealthScript(opts)); err != nil {
		zap.L().Debug("Could not install the stealth init script", zap.Error(err))
	}
}
