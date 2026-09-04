package cli

import (
	"strings"
	"testing"
)

func TestTranslateFFUFStripsFuzzMarker(t *testing.T) {
	// Discovery fuzzes paths from a wordlist by construction; carrying the literal
	// FUZZ through would make the target a URL containing the word FUZZ.
	got, err := translateFFUF([]string{"-u", "https://t/FUZZ", "-w", "words.txt"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "FUZZ") {
		t.Errorf("FUZZ marker survived: %s", joined)
	}
	if !strings.Contains(joined, "-t https://t") {
		t.Errorf("target not translated: %s", joined)
	}
	if !strings.Contains(joined, "--discovery-wordlist words.txt") {
		t.Errorf("wordlist not translated: %s", joined)
	}
}

func TestTranslateFFUFMapsPaceFlags(t *testing.T) {
	got, err := translateFFUF([]string{"-u", "https://t/FUZZ", "-t", "5", "-rate", "20"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"--concurrency 5", "--rate-limit 20"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
}

func TestTranslateFFUFAcceptsEqualsForm(t *testing.T) {
	got, err := translateFFUF([]string{"-u=https://t/FUZZ", "-w=words.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(got, " "), "-t https://t") {
		t.Errorf("-u=VALUE not handled: %v", got)
	}
}

func TestTranslateFFUFStripsWordlistKeyword(t *testing.T) {
	// ffuf allows `-w list:KEYWORD`; only the path means anything here.
	got, err := translateFFUF([]string{"-u", "https://t/FUZZ", "-w", "words.txt:FUZZ"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(got, " "), "--discovery-wordlist words.txt") {
		t.Errorf("keyword suffix not stripped: %v", got)
	}
}

func TestShimRefusesUnknownFlagAndNamesNativeCommand(t *testing.T) {
	// A dropped flag is a scan that ran with a scope nobody chose — the exact
	// failure the shims exist to prevent — so an unmapped argument is a hard
	// error, and it has to say where to go next.
	_, err := translateFFUF([]string{"-u", "https://t/FUZZ", "--mc", "200"})
	if err == nil {
		t.Fatal("unknown flag accepted")
	}
	if !strings.Contains(err.Error(), "run discovery") {
		t.Errorf("error does not name the native command: %v", err)
	}
}

func TestTranslateFFUFRequiresTarget(t *testing.T) {
	if _, err := translateFFUF([]string{"-w", "words.txt"}); err == nil {
		t.Error("missing -u accepted")
	}
}

func TestTranslateNucleiMapsSeverityAndTags(t *testing.T) {
	got, err := translateNuclei([]string{"-u", "https://t", "-severity", "high,critical", "-tags", "cve"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{
		"run known-issue-scan",
		"--known-issue-scan-severities high,critical",
		"--known-issue-scan-tags cve",
		"-t https://t",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
}

func TestTranslateKatanaRefusesDepth(t *testing.T) {
	// The spider is a state machine over DOM snapshots, not a depth-limited link
	// follower. Accepting -d silently would be a different crawl than asked for.
	_, err := translateKatana([]string{"-u", "https://t", "-d", "3"})
	if err == nil {
		t.Fatal("-d accepted")
	}
	if !strings.Contains(err.Error(), "--spider-max-time") {
		t.Errorf("error does not name the knob that does bound the crawl: %v", err)
	}
}

func TestTranslateGauAddsSchemeToBareDomain(t *testing.T) {
	got, err := translateGau([]string{"target.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(got, " "), "-t https://target.example.com") {
		t.Errorf("bare domain not promoted to a URL: %v", got)
	}
}

func TestTranslateGauRequiresTarget(t *testing.T) {
	if _, err := translateGau([]string{"--subs"}); err == nil {
		t.Error("gau with no domain accepted")
	}
}

func TestTranslateArjunTargetsParamNames(t *testing.T) {
	got, err := translateArjun([]string{"-u", "https://t/api", "-m", "post"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"fuzz", "--fuzz param-name", "-X POST", "--anomaly", "https://t/api"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
}

func TestShimValueMissingIsAnError(t *testing.T) {
	// A flag whose value silently became "" is a scope nobody chose.
	if _, err := translateFFUF([]string{"-u"}); err == nil {
		t.Error("dangling -u accepted")
	}
}

func TestFlagNameNormalizesDashesAndEquals(t *testing.T) {
	for in, want := range map[string]string{
		"-u":        "u",
		"--url":     "url",
		"-u=x":      "u",
		"--url=x":   "url",
		"-severity": "severity",
	} {
		if got := flagName(in); got != want {
			t.Errorf("flagName(%q) = %q, want %q", in, got, want)
		}
	}
}
