package modules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sharedHelperRedefinition matches a package-level re-declaration of a helper
// that already has a shared home. Each copy drifts on its own ("…" vs "...",
// byte cuts that split UTF-8 runes, time-seeded RNGs that repeat), so modules
// must call the shared version instead:
//
//   - truncate      -> modkit.Truncate / TruncateWith / TruncateNoEllipsis / TruncateRunes
//   - randomString  -> modkit.RandomAlnum (or utils.RandomOf for another alphabet)
//   - isBlockedResponse / isBlockedOrThrottled -> infra.IsBlockedResponse / infra.IsBlockedOrThrottled
var sharedHelperRedefinition = regexp.MustCompile(`(?m)^func (truncate|randomString|isBlockedResponse|isBlockedOrThrottled)\(`)

// TestNoPrivateCopiesOfSharedHelpers walks every Go file under pkg/modules
// (tests included) and fails on a private redefinition of a shared helper.
func TestNoPrivateCopiesOfSharedHelpers(t *testing.T) {
	scanned := 0
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for _, m := range sharedHelperRedefinition.FindAllStringSubmatch(string(src), -1) {
			t.Errorf("%s: declares private %s(); use the shared modkit/infra helper instead", path, m[1])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk pkg/modules: %v", err)
	}
	if scanned < 500 {
		t.Fatalf("scanned only %d Go files under pkg/modules; walk root is wrong", scanned)
	}
}
