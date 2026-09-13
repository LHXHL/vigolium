package modules

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/passive/surface_scoring"
)

// TestRegistryWiresSurfaceScoring guards the two links the surface score depends
// on end to end. Neither failure is visible at runtime: an unregistered module
// simply never runs, and a module that stops implementing Flusher buffers every
// record and writes none of them — in both cases surface_score stays 0 for the
// whole corpus, which is indistinguishable from "nothing scored above zero".
func TestRegistryWiresSurfaceScoring(t *testing.T) {
	var found PassiveModule
	for _, m := range DefaultRegistry.GetPassiveModules() {
		if m.ID() == surface_scoring.ModuleID {
			found = m
			break
		}
	}
	if found == nil {
		t.Fatalf("passive module %q is not registered in the default registry", surface_scoring.ModuleID)
	}
	if _, ok := found.(Flusher); !ok {
		t.Errorf("%q does not implement modules.Flusher; the executor would never flush its buffer and no score would ever be written", surface_scoring.ModuleID)
	}
}
