package browser

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// launcherFor builds the real launcher newLauncher would use for cfg, and
// removes the scratch profile it allocates.
func launcherFor(t *testing.T, mutate func(*config.Config)) *launcher.Launcher {
	t.Helper()
	cfg, err := config.New("http://127.0.0.1")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if mutate != nil {
		mutate(cfg)
	}
	b := &Browser{config: cfg}
	l := b.newLauncher("/nonexistent/chrome", cfg.BrowserCompat)
	t.Cleanup(func() { discardLauncherProfile(l) })
	return l
}

func flagValues(l *launcher.Launcher, name flags.Flag) []string {
	vals, _ := l.GetFlags(name)
	var out []string
	for _, v := range vals {
		out = append(out, strings.Split(v, ",")...)
	}
	return out
}

func TestNewLauncherStealthFlags(t *testing.T) {
	l := launcherFor(t, nil) // default: chromium engine, stealth auto → on

	if l.Has("enable-automation") {
		t.Error("stealth launcher must not carry enable-automation")
	}
	if got := flagValues(l, "disable-blink-features"); !slices.Contains(got, "AutomationControlled") {
		t.Errorf("disable-blink-features = %v, want AutomationControlled", got)
	}
	for _, arg := range l.FormatArgs() {
		if arg == "--enable-automation" {
			t.Errorf("command line carries %s", arg)
		}
	}
}

func TestNewLauncherDisableFeaturesKeepsRodDefaults(t *testing.T) {
	l := launcherFor(t, nil)
	got := flagValues(l, "disable-features")
	// rod's own defaults survive, alongside ours.
	for _, want := range []string{"site-per-process", "TranslateUI", "HttpsUpgrades", "HttpsFirstModeV2", "LensOverlay"} {
		if !slices.Contains(got, want) {
			t.Errorf("disable-features = %v, missing %s", got, want)
		}
	}
	// AutomationControlled is a blink feature, not a base::Feature.
	if slices.Contains(got, "AutomationControlled") {
		t.Errorf("disable-features = %v must not carry AutomationControlled", got)
	}
	// One flag on the command line, not several overriding each other.
	n := 0
	for _, arg := range l.FormatArgs() {
		if strings.HasPrefix(arg, "--disable-features=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("--disable-features appears %d times, want 1", n)
	}
}

func TestNewLauncherStealthOff(t *testing.T) {
	for name, mutate := range map[string]func(*config.Config){
		"off":            func(c *config.Config) { c.Stealth = config.StealthOff },
		"auto ungoogled": func(c *config.Config) { c.BrowserEngine = "ungoogled" },
	} {
		l := launcherFor(t, mutate)
		if !l.Has("enable-automation") {
			t.Errorf("%s: stealth off keeps rod's enable-automation", name)
		}
		if l.Has("disable-blink-features") {
			t.Errorf("%s: stealth off must not set disable-blink-features", name)
		}
	}
}

func TestAppendDisableFeaturesIdempotent(t *testing.T) {
	l := appendDisableFeatures(launcher.New(), "A", "B")
	l = appendDisableFeatures(l, "A", "C")
	got := flagValues(l, "disable-features")
	want := []string{"site-per-process", "TranslateUI", "A", "B", "C"}
	if !slices.Equal(got, want) {
		t.Errorf("disable-features = %v, want %v", got, want)
	}
}

func brandString(list []*proto.EmulationUserAgentBrandVersion) string {
	var parts []string
	for _, b := range list {
		parts = append(parts, b.Brand+"="+b.Version)
	}
	return strings.Join(parts, ", ")
}

// The brand lists below are what real Chrome sends in Sec-CH-UA for these
// versions; the GREASE algorithm must reproduce them exactly.
func TestChromeBrandVersionLists(t *testing.T) {
	cases := map[int]string{
		120: "Not_A Brand=8, Chromium=120, Google Chrome=120",
		124: "Chromium=124, Google Chrome=124, Not-A.Brand=99",
		131: "Google Chrome=131, Chromium=131, Not_A Brand=24",
	}
	for major, want := range cases {
		brands, full := chromeBrandVersionLists(major, "x.0.0.0")
		if got := brandString(brands); got != want {
			t.Errorf("major %d: brands = %q, want %q", major, got, want)
		}
		for _, b := range full {
			if b.Brand != "Chromium" && b.Brand != "Google Chrome" && !strings.HasSuffix(b.Version, ".0.0.0") {
				t.Errorf("major %d: GREASE full version %q", major, b.Version)
			}
		}
	}
}

func TestStealthUserAgentMetadata(t *testing.T) {
	md := stealthUserAgentMetadata("HeadlessChrome/131.0.6778.85", "darwin", "arm64")
	if md == nil {
		t.Fatal("metadata is nil")
	}
	for _, b := range append(md.Brands, md.FullVersionList...) {
		if strings.Contains(b.Brand, "Headless") {
			t.Errorf("brand %q names headless", b.Brand)
		}
	}
	if md.FullVersion != "131.0.6778.85" || md.Platform != "macOS" || md.Architecture != "arm" || md.Mobile || md.Bitness != "64" {
		t.Errorf("metadata = %+v", md)
	}
	if !strings.Contains(brandString(md.FullVersionList), "Google Chrome=131.0.6778.85") {
		t.Errorf("full version list = %s", brandString(md.FullVersionList))
	}
	if p, a := clientHintPlatform("linux", "amd64"); p != "Linux" || a != "x86" {
		t.Errorf("linux/amd64 = %s/%s", p, a)
	}
	if p, _ := clientHintPlatform("windows", "amd64"); p != "Windows" {
		t.Errorf("windows = %s", p)
	}
	for _, bad := range []string{"", "Chrome", "Chrome/abc"} {
		if stealthUserAgentMetadata(bad, "linux", "amd64") != nil {
			t.Errorf("product %q: want nil metadata", bad)
		}
	}
}

func TestAcceptLanguageList(t *testing.T) {
	if got := acceptLanguageList(defaultAcceptLanguage); !slices.Equal(got, []string{"en-US", "en"}) {
		t.Errorf("acceptLanguageList(%q) = %v", defaultAcceptLanguage, got)
	}
	if got := acceptLanguageList("fr-CH, fr;q=0.9, *;q=0.5"); !slices.Equal(got, []string{"fr-CH", "fr"}) {
		t.Errorf("got %v", got)
	}
}

func TestStealthScriptRendersOptions(t *testing.T) {
	opts := stealthOptionsFor(true, "linux", "amd64")
	js := stealthScript(opts)
	if strings.Contains(js, "__VGO_STEALTH_OPTS__") {
		t.Fatal("placeholder left in the rendered script")
	}
	raw, _ := json.Marshal(opts)
	if !strings.Contains(js, "const opts = "+string(raw)+";") {
		t.Errorf("rendered script does not carry the options %s", raw)
	}
	if !strings.Contains(stealthScriptSource, stealthOptsPlaceholder) {
		t.Error("stealth.js lost its options placeholder")
	}
}
