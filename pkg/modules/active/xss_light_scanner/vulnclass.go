package xss_light_scanner

import "github.com/vigolium/vigolium/pkg/modules/modkit"

// Every xss-light variant shares the reflected-XSS class with xss_dom_confirm:
// once any of them reports a parameter, the others (and the browser-confirm
// module) skip it at that location. Each per-parameter loop checks
// ScanContext.ParamAlreadyFound before probing.

func (m *Module) VulnClass() string               { return modkit.VulnClassXSS }
func (m *URLParamsModule) VulnClass() string      { return modkit.VulnClassXSS }
func (m *PathModule) VulnClass() string           { return modkit.VulnClassXSS }
func (m *ParamDiscoveryModule) VulnClass() string { return modkit.VulnClassXSS }
func (m *EncodedModule) VulnClass() string        { return modkit.VulnClassXSS }

// ClassPriority: HTTP-only canary reflection is the cheap in-band technique.
func (m *Module) ClassPriority() int               { return modkit.ClassCostInBand }
func (m *URLParamsModule) ClassPriority() int      { return modkit.ClassCostInBand }
func (m *PathModule) ClassPriority() int           { return modkit.ClassCostInBand }
func (m *ParamDiscoveryModule) ClassPriority() int { return modkit.ClassCostInBand }
func (m *EncodedModule) ClassPriority() int        { return modkit.ClassCostInBand }
