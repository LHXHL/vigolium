package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

// ApplyProjectOverlay layers a project's config overlay (ProjectConfigPath)
// onto settings, completing the global → project step of the documented
// precedence (global → project → scanning profile → CLI). An empty projectUUID
// or a project without an overlay file leaves settings unchanged.
//
// It is the one implementation every entry point shares: LoadSettingsWithProject,
// the CLI settings loader, the REST server (per X-Project-UUID) and the agent
// launcher all call it, so one project resolves to the same effective settings
// wherever a scan starts. The overlay is applied key-preservingly by
// ApplyProfile, so a key the overlay does not set keeps its global value.
//
// An overlay that exists but cannot be read or parsed is an error, not a
// silent no-op: the file usually narrows scope, and running a scan with the
// global (wider) scope because the narrowing file had a typo is exactly the
// outcome an operator who wrote it could not detect.
//
// The parsed overlay is cached per file and revalidated by mtime/size on every
// call, so a `scope set --project` from another process is picked up by a
// long-running server on its next scan without a restart.
func ApplyProjectOverlay(settings *Settings, projectUUID string) error {
	projectUUID = strings.TrimSpace(projectUUID)
	if settings == nil || projectUUID == "" {
		return nil
	}
	profile, err := projectOverlays.load(ProjectConfigPath(projectUUID))
	if err != nil {
		return fmt.Errorf("failed to load project config for %s: %w", projectUUID, err)
	}
	if profile == nil {
		return nil
	}
	if err := ApplyProfile(settings, profile); err != nil {
		return fmt.Errorf("failed to apply project config %s: %w", ContractPath(ProjectConfigPath(projectUUID)), err)
	}
	return nil
}

// overlayCache memoizes parsed project overlays by file path. Keyed by path,
// not UUID, so a different HOME (tests, a server started under another user)
// never reads another tree's overlay.
type overlayCache struct {
	mu      sync.Mutex
	entries map[string]overlayEntry
}

type overlayEntry struct {
	modTime time.Time
	size    int64
	profile *ProfileSettings
}

var projectOverlays = &overlayCache{entries: map[string]overlayEntry{}}

// load returns the parsed overlay at path, nil when the file does not exist.
// The stat on every call is the invalidation: a cached parse is reused only
// while the file's mtime and size are unchanged.
func (c *overlayCache) load(path string) (*ProfileSettings, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.invalidate(path)
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", ContractPath(path))
	}

	c.mu.Lock()
	e, ok := c.entries[path]
	c.mu.Unlock()
	if ok && e.size == info.Size() && e.modTime.Equal(info.ModTime()) {
		return e.profile, nil
	}

	profile, err := LoadProfile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	c.mu.Lock()
	c.entries[path] = overlayEntry{modTime: info.ModTime(), size: info.Size(), profile: profile}
	c.mu.Unlock()
	return profile, nil
}

func (c *overlayCache) invalidate(path string) {
	c.mu.Lock()
	delete(c.entries, path)
	c.mu.Unlock()
}

// InvalidateProjectOverlay drops the cached parse of a project's overlay. The
// in-process writers call it so a write followed by a load within the same
// mtime tick can never return the previous content.
func InvalidateProjectOverlay(projectUUID string) {
	projectOverlays.invalidate(ProjectConfigPath(projectUUID))
}

// CloneSettings returns a deep copy of s: every pointer, slice and map reachable
// through exported fields is duplicated, so the copy can be mutated — including
// by ApplyProfile, whose YAML decode writes through existing pointers and merges
// into existing maps — without touching s. A shallow `*s` copy shares those, so
// overlaying a project onto it would leak the project's values into s.
func CloneSettings(s *Settings) *Settings {
	if s == nil {
		return nil
	}
	out := deepCopyValue(reflect.ValueOf(s)).Interface().(*Settings)
	return out
}

func deepCopyValue(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		cp := reflect.New(v.Elem().Type())
		cp.Elem().Set(deepCopyValue(v.Elem()))
		return cp
	case reflect.Struct:
		// Start from a value copy so unexported fields (which reflection cannot
		// set) keep their values, then replace each exported field with a deep
		// copy of itself.
		cp := reflect.New(v.Type()).Elem()
		cp.Set(v)
		for i := 0; i < v.NumField(); i++ {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			cp.Field(i).Set(deepCopyValue(v.Field(i)))
		}
		return cp
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		cp := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			cp.Index(i).Set(deepCopyValue(v.Index(i)))
		}
		return cp
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		cp := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			cp.SetMapIndex(iter.Key(), deepCopyValue(iter.Value()))
		}
		return cp
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		cp := reflect.New(v.Type()).Elem()
		cp.Set(deepCopyValue(v.Elem()))
		return cp
	case reflect.Array:
		cp := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			cp.Index(i).Set(deepCopyValue(v.Index(i)))
		}
		return cp
	default:
		return v
	}
}
