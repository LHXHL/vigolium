package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"gopkg.in/yaml.v3"
)

// SettingPath returns the setting a SetField key writes: the key itself, or the
// list path for a `<list>.add` / `<list>.clear` op.
func SettingPath(key string) string {
	parent, last, ok := cutLast(key)
	if ok && (last == "add" || last == "clear") {
		if t, valid := resolveSettingType(parent); valid && isListType(t) {
			return parent
		}
	}
	return key
}

func cutLast(key string) (string, string, bool) {
	i := strings.LastIndex(key, ".")
	if i < 0 {
		return "", key, false
	}
	return key[:i], key[i+1:], true
}

// SetProjectOverlayValue writes the value settings holds at key into the
// project's overlay file (ProjectConfigPath), leaving every other key in that
// file as it was, and returns the file path.
//
// Only that one key is written, not the whole section: copying the effective
// section would freeze the global values of every sibling key into the
// project, so a later global change would stop applying to it. An overlay that
// exists but does not parse is refused rather than replaced — overwriting it
// would discard whatever the operator had in it. The write is atomic.
func SetProjectOverlayValue(projectUUID, key string, settings *Settings) (string, error) {
	if strings.TrimSpace(projectUUID) == "" {
		return "", fmt.Errorf("project overlay: no project selected")
	}
	key = SettingPath(key)
	parts := strings.Split(key, ".")
	if _, ok := yamlFieldType(reflect.TypeOf(ProfileSettings{}), parts[0]); !ok {
		return "", fmt.Errorf("%w: %q cannot be set in a project config (allowed sections are the scanning-profile ones)", ErrUnknownKey, parts[0])
	}

	data, err := yaml.Marshal(settings)
	if err != nil {
		return "", fmt.Errorf("failed to marshal settings: %w", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return "", fmt.Errorf("failed to unmarshal settings: %w", err)
	}
	parent, leaf, err := navigateToParent(raw, parts)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %v", ErrUnknownKey, key, err)
	}
	value := parent[leaf]

	path := ProjectConfigPath(projectUUID)
	overlay := map[string]any{}
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(existing, &overlay); err != nil {
			return "", fmt.Errorf("project config %s does not parse, refusing to overwrite it: %w", ContractPath(path), err)
		}
		if overlay == nil {
			overlay = map[string]any{}
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return "", fmt.Errorf("failed to read project config %s: %w", ContractPath(path), err)
	}

	cur := overlay
	for _, seg := range parts[:len(parts)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value

	out, err := yaml.Marshal(overlay)
	if err != nil {
		return "", fmt.Errorf("failed to marshal project config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("failed to create project config directory: %w", err)
	}
	if err := atomicfile.WriteFile(path, 0o600, func(w *bufio.Writer) error {
		_, err := w.Write(out)
		return err
	}); err != nil {
		return "", fmt.Errorf("failed to write project config: %w", err)
	}
	return path, nil
}
