package modules

import (
	"fmt"
	"strings"
	"sync"
)

// Registry manages all scanner modules.
// Thread-safe for concurrent access.
type Registry struct {
	mu             sync.RWMutex
	activeModules  []ActiveModule
	passiveModules []PassiveModule
	activeIDs      map[string]struct{}
	passiveIDs     map[string]struct{}
}

// NewRegistry creates a new registry.
func NewRegistry() *Registry {
	return &Registry{
		activeIDs:  make(map[string]struct{}),
		passiveIDs: make(map[string]struct{}),
	}
}

// RegisterActive adds an active module to the registry.
// Panics if a module with the same ID is already registered or if the ID is not lowercase.
// Returns the registry to support fluent API.
func (r *Registry) RegisterActive(m ActiveModule) *Registry {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := m.ID()
	if id != strings.ToLower(id) {
		panic(fmt.Sprintf("module ID %q must be lowercase", id))
	}
	if _, exists := r.activeIDs[id]; exists {
		panic(fmt.Sprintf("duplicate active module ID: %q", id))
	}

	r.activeIDs[id] = struct{}{}
	r.activeModules = append(r.activeModules, m)
	return r
}

// RegisterPassive adds a passive module to the registry.
// Panics if a module with the same ID is already registered or if the ID is not lowercase.
// Returns the registry to support fluent API.
func (r *Registry) RegisterPassive(m PassiveModule) *Registry {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := m.ID()
	if id != strings.ToLower(id) {
		panic(fmt.Sprintf("module ID %q must be lowercase", id))
	}
	if _, exists := r.passiveIDs[id]; exists {
		panic(fmt.Sprintf("duplicate passive module ID: %q", id))
	}

	r.passiveIDs[id] = struct{}{}
	r.passiveModules = append(r.passiveModules, m)
	return r
}

// GetActiveModules returns all active modules.
func (r *Registry) GetActiveModules() []ActiveModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ActiveModule, len(r.activeModules))
	copy(result, r.activeModules)
	return result
}

// GetPassiveModules returns all passive modules.
func (r *Registry) GetPassiveModules() []PassiveModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]PassiveModule, len(r.passiveModules))
	copy(result, r.passiveModules)
	return result
}

// GetActiveModulesByIDs filters active modules by IDs.
// Input IDs are lowercased for user-input normalization; registered module IDs
// are guaranteed lowercase by RegisterActive.
func (r *Registry) GetActiveModulesByIDs(ids []string) []ActiveModule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idSet[strings.ToLower(id)] = struct{}{}
	}

	var result []ActiveModule
	for _, m := range r.activeModules {
		if _, ok := idSet[m.ID()]; ok {
			result = append(result, m)
		}
	}
	return result
}

// GetPassiveModulesByIDs filters passive modules by IDs.
// Input IDs are lowercased for user-input normalization; registered module IDs
// are guaranteed lowercase by RegisterPassive.
func (r *Registry) GetPassiveModulesByIDs(ids []string) []PassiveModule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idSet[strings.ToLower(id)] = struct{}{}
	}

	var result []PassiveModule
	for _, m := range r.passiveModules {
		if _, ok := idSet[m.ID()]; ok {
			result = append(result, m)
		}
	}
	return result
}

// GetActiveModulesID returns IDs of all active modules.
func (r *Registry) GetActiveModulesID() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, len(r.activeModules))
	for i, m := range r.activeModules {
		ids[i] = m.ID()
	}
	return ids
}

// GetPassiveModulesID returns IDs of all passive modules.
func (r *Registry) GetPassiveModulesID() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, len(r.passiveModules))
	for i, m := range r.passiveModules {
		ids[i] = m.ID()
	}
	return ids
}

// ResolveModuleTags returns deduplicated module IDs for all modules that have
// at least one of the given tags (OR condition). Tags are matched case-insensitively.
func (r *Registry) ResolveModuleTags(tags []string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return MatchModuleTags(tags, r.allModulesLocked())
}

// ResolveModulePatterns resolves user-provided patterns into exact module IDs
// using fuzzy matching; see MatchModulePatterns. Returns deduplicated matched
// module IDs (both active and passive), or ["all"] when a pattern is "all".
func (r *Registry) ResolveModulePatterns(patterns []string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return MatchModulePatterns(patterns, r.allModulesLocked())
}

// allModulesLocked lists active modules then passive modules. Caller holds r.mu.
func (r *Registry) allModulesLocked() []Module {
	all := make([]Module, 0, len(r.activeModules)+len(r.passiveModules))
	for _, m := range r.activeModules {
		all = append(all, m)
	}
	for _, m := range r.passiveModules {
		all = append(all, m)
	}
	return all
}

// MatchModuleTags returns the deduplicated IDs of the modules in mods that carry
// at least one of the given tags (OR condition, case-insensitive), in mods order.
// It is the matcher behind --module-tag, shared by the registry and by callers
// that hold modules the registry does not know about (loaded JS/YAML extensions).
func MatchModuleTags(tags []string, mods []Module) []string {
	tagSet := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		tagSet[strings.ToLower(t)] = struct{}{}
	}

	seen := make(map[string]struct{})
	var result []string
	for _, m := range mods {
		id := m.ID()
		if _, ok := seen[id]; ok {
			continue
		}
		for _, mt := range m.Tags() {
			if _, ok := tagSet[strings.ToLower(mt)]; ok {
				seen[id] = struct{}{}
				result = append(result, id)
				break
			}
		}
	}
	return result
}

// MatchModulePatterns resolves -m patterns against mods. Each pattern is matched
// (case-insensitive) against:
//   - Exact module ID match (when any module matches exactly, the pattern stops there)
//   - Substring match on module ID
//   - Substring match on module name
//
// Returns deduplicated matched module IDs in match order, or ["all"] as soon as
// a pattern is "all". Patterns that match nothing are silently ignored. Shared by
// the registry and by callers holding modules the registry does not know about
// (loaded JS/YAML extensions, so `-m ext-csp` and `-m csp` reach them).
func MatchModulePatterns(patterns []string, mods []Module) []string {
	seen := make(map[string]struct{})
	var result []string

	addModule := func(id string) {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			result = append(result, id)
		}
	}

	for _, pattern := range patterns {
		p := strings.ToLower(pattern)
		if p == "all" {
			return []string{"all"}
		}

		// Pass 1: exact ID match
		exactMatch := false
		for _, m := range mods {
			if m.ID() == p {
				addModule(m.ID())
				exactMatch = true
			}
		}
		if exactMatch {
			continue
		}

		// Pass 2: substring match on ID, then name
		for _, m := range mods {
			if strings.Contains(m.ID(), p) || strings.Contains(strings.ToLower(m.Name()), p) {
				addModule(m.ID())
			}
		}
	}

	return result
}

// ActiveModuleCount returns the number of active modules.
func (r *Registry) ActiveModuleCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.activeModules)
}

// PassiveModuleCount returns the number of passive modules.
func (r *Registry) PassiveModuleCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.passiveModules)
}
